// ponytail: durable target scan workflow with render gating and failure recording

import { WorkflowEntrypoint, WorkflowEvent, WorkflowStep } from "cloudflare:workers";
import { assertInScope } from "../core/scope.js";
import { resolveHostDoh, DnsResolutionResult } from "../core/doh.js";
import { syncDetectorFindings, FindingInput } from "../core/findings.js";
import { saveScreenshot } from "../core/evidence.js";
import { runNoAuthGateDetector } from "../detectors/no-auth-gate.js";
import { runUnauthAdminDetector } from "../detectors/unauth-admin.js";
import { runLeakedArtifactDetector } from "../detectors/leaked-artifact.js";
import { runDevStagingOriginDetector } from "../detectors/dev-staging-origin.js";
import { DetectorContext, ProbeResponse, RenderedPage, PathProbeResult } from "../detectors/types.js";

export interface TargetWorkflowParams {
  host: string;
  scanId?: string;
}

const PROBE_PATHS = [
  "/.git/HEAD", "/.env", "/swagger.json", "/openapi.json", "/api-docs",
  "/actuator/health", "/actuator/env", "/server-status", "/.DS_Store", "/robots.txt",
];

export class TargetWorkflow extends WorkflowEntrypoint<Env, TargetWorkflowParams> {
  async run(event: WorkflowEvent<TargetWorkflowParams>, step: WorkflowStep) {
    const rawHost = event.payload.host;
    const scanId = event.payload.scanId || crypto.randomUUID();

    await step.do("mark-running", async () => {
      await this.env.DB.prepare(
        `INSERT INTO scans (id, target_host, status, started_at)
         VALUES (?, ?, 'running', ?)
         ON CONFLICT(id) DO UPDATE SET status = 'running', error = NULL`
      ).bind(scanId, rawHost, Date.now()).run();
      return true;
    });

    try {
      return await this.scan(event, step, scanId);
    } catch (error) {
      await this.env.DB.prepare(
        "UPDATE scans SET status = 'failed', completed_at = ?, error = ? WHERE id = ?"
      ).bind(Date.now(), error instanceof Error ? error.message : String(error), scanId).run();
      throw error;
    }
  }

  private async scan(event: WorkflowEvent<TargetWorkflowParams>, step: WorkflowStep, scanId: string) {
    const host = await step.do("assert-scope", async () => assertInScope(event.payload.host, this.env.DB));

    const dohResult: DnsResolutionResult = await step.do("resolve-dns", async () => resolveHostDoh(host));

    const probe: ProbeResponse = await step.do("probe-root", async () => {
      await assertInScope(host, this.env.DB);
      let targetUrl = `https://${host}`;
      let resp: Response;
      try {
        resp = await fetch(targetUrl, {
          redirect: "manual",
          headers: { "User-Agent": "Mozilla/5.0 (ExposureAgent/1.0)" },
        });
      } catch {
        await assertInScope(host, this.env.DB);
        targetUrl = `http://${host}`;
        resp = await fetch(targetUrl, {
          redirect: "manual",
          headers: { "User-Agent": "Mozilla/5.0 (ExposureAgent/1.0)" },
        });
      }
      const headers = Object.fromEntries(resp.headers);
      return { url: targetUrl, status: resp.status, headers, body: (await resp.text()).slice(0, 100000) };
    });

    const render: RenderedPage = await step.do("render-browser", async () => {
      if (probe.status < 200 || probe.status >= 300 || !this.env.BROWSER) {
        return { markdown: "", html: "", screenshotKey: null };
      }
      await assertInScope(probe.url, this.env.DB);
      try {
        const [contentResponse, markdownResponse, screenshotResponse] = await Promise.all([
          this.env.BROWSER.quickAction("content", { url: probe.url }),
          this.env.BROWSER.quickAction("markdown", { url: probe.url }),
          this.env.BROWSER.quickAction("screenshot", { url: probe.url }),
        ]);
        if (!contentResponse.ok || !markdownResponse.ok || !screenshotResponse.ok) {
          throw new Error("Browser Run Quick Action failed");
        }
        const content = (await contentResponse.json()) as { result: string };
        const markdown = (await markdownResponse.json()) as { result: string };
        const screenshotKey = this.env.EVIDENCE
          ? await saveScreenshot(
              this.env.EVIDENCE,
              host,
              await screenshotResponse.arrayBuffer(),
              screenshotResponse.headers.get("content-type") || "image/png"
            )
          : null;
        return {
          html: (content.result || "").slice(0, 100000),
          markdown: (markdown.result || "").slice(0, 10000),
          screenshotKey,
        };
      } catch {
        return { markdown: "", html: "", screenshotKey: null };
      }
    });

    const paths: PathProbeResult[] = await step.do("probe-paths", async () => {
      const results: PathProbeResult[] = [];
      const baseUrl = probe.url.replace(/\/+$/, "");
      for (const path of PROBE_PATHS) {
        const pathUrl = `${baseUrl}${path}`;
        await assertInScope(pathUrl, this.env.DB);
        const resp = await fetch(pathUrl, {
          method: "GET", redirect: "manual",
          headers: { "User-Agent": "Mozilla/5.0 (ExposureAgent/1.0)" },
        });
        const headers = Object.fromEntries(resp.headers);
        results.push({
          path, url: pathUrl, status: resp.status, headers,
          body: (await resp.text()).slice(0, 20000), contentType: headers["content-type"] || "",
        });
      }
      return results;
    });

    const allFindings: FindingInput[] = await step.do("classify-findings", async () => {
      const detectorCtx: DetectorContext = { host, probe, render, doh: dohResult, paths };
      const findingsList: FindingInput[] = [
        ...runNoAuthGateDetector(detectorCtx),
        ...runUnauthAdminDetector(detectorCtx),
        ...runLeakedArtifactDetector(detectorCtx),
        ...runDevStagingOriginDetector(detectorCtx),
      ];

      if (this.env.AI && probe.status === 200 && probe.body.length > 200 && findingsList.length === 0) {
        try {
          const aiResp: any = await this.env.AI.run("@cf/meta/llama-3.3-70b-instruct-fp8-fast", {
            messages: [{ role: "user", content: `Classify whether this anonymously rendered application is an exposed internal service. Return JSON with isExposed, confidence, and reason.\nHost: ${host}\nRendered markdown:\n${(render.markdown || "").slice(0, 5000)}` }],
            response_format: { type: "json_object" },
          });
          const parsed = typeof aiResp?.response === "string" ? JSON.parse(aiResp.response) : aiResp?.response;
          if (parsed?.isExposed === true && Number(parsed.confidence) > 0.8) {
            findingsList.push({
              detector: "no-auth-gate", severity: "high",
              title: `AI Identified Potentially Exposed Internal Service (${host})`,
              description: `Workers AI evaluated rendered content with high confidence: ${String(parsed.reason || "")}`,
              evidence: { host, aiClassification: parsed }, r2_screenshot_key: render.screenshotKey,
            });
          }
        } catch {
          // AI is advisory; deterministic scanning and persistence still complete.
        }
      }
      return findingsList;
    });

    await step.do("persist-findings", async () => {
      for (const detector of ["no-auth-gate", "unauth-admin", "leaked-artifact", "dev-staging-origin"]) {
        await syncDetectorFindings(this.env.DB, host, detector, allFindings.filter((finding) => finding.detector === detector));
      }
      const now = Date.now();
      await this.env.DB.prepare(
        `UPDATE scans SET status = 'completed', completed_at = ?, findings_count = ?, error = NULL WHERE id = ?`
      ).bind(now, allFindings.length, scanId).run();
    });

    return { host, scanId, findingsCount: allFindings.length };
  }
}
