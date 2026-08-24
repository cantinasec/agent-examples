// ponytail: authenticated Agent callables with Quick Actions and scope checks

import { Agent, callable } from "agents";
import { assertInScope, listTargets } from "../core/scope.js";
import { listFindings, getFinding, triageFinding, FindingState } from "../core/findings.js";
import { requireCurrentAgentPermission } from "../auth/authorization.js";
import { saveScreenshot } from "../core/evidence.js";

export class TriageAgent extends Agent<Env> {
  @callable()
  async getTargets(filter?: { status?: "active" | "retired"; includeExpired?: boolean }) {
    await requireCurrentAgentPermission(this.env, "read");
    return await listTargets(this.env.DB, filter);
  }

  @callable()
  async getFindings(filter?: { host?: string; detector?: string; severity?: any; state?: any }) {
    await requireCurrentAgentPermission(this.env, "read");
    return await listFindings(this.env.DB, filter);
  }

  @callable()
  async getFindingDetail(id: string) {
    await requireCurrentAgentPermission(this.env, "read");
    const finding = await getFinding(this.env.DB, id);
    if (!finding) {
      throw new Error(`Finding '${id}' not found`);
    }
    return finding;
  }

  @callable()
  async triageFindingState(id: string, state: FindingState, notes?: string) {
    await requireCurrentAgentPermission(this.env, "admin");
    return await triageFinding(this.env.DB, id, state, notes);
  }

  @callable()
  async browseTargetUrl(url: string) {
    await requireCurrentAgentPermission(this.env, "read");
    const targetUrl = url.startsWith("http") ? url : `https://${url}`;
    const host = await assertInScope(targetUrl, this.env.DB);

    if (!this.env.BROWSER) {
      throw new Error("Browser Run binding is required");
    }
    const [markdownResponse, screenshotResponse] = await Promise.all([
      this.env.BROWSER.quickAction("markdown", { url: targetUrl }),
      this.env.BROWSER.quickAction("screenshot", { url: targetUrl }),
    ]);
    if (!markdownResponse.ok || !screenshotResponse.ok) {
      throw new Error("Browser Run Quick Action failed");
    }
    const markdown = ((await markdownResponse.json()) as { result: string }).result || "";
    const screenshotKey = this.env.EVIDENCE
      ? await saveScreenshot(
          this.env.EVIDENCE,
          host,
          await screenshotResponse.arrayBuffer(),
          screenshotResponse.headers.get("content-type") || "image/png"
        )
      : null;
    return { host, url: targetUrl, markdown: markdown.slice(0, 10000), screenshotKey };
  }

  @callable()
  async scanTargetHost(hostInput: string) {
    await requireCurrentAgentPermission(this.env, "scan");
    const host = await assertInScope(hostInput, this.env.DB);
    const scanId = crypto.randomUUID();

    await this.env.DB.prepare(
      "INSERT INTO scans (id, target_host, status, started_at) VALUES (?, ?, 'pending', ?)"
    )
      .bind(scanId, host, Date.now())
      .run();

    const instance = await this.env.TARGET_WORKFLOW.create({
      id: scanId,
      params: { host, scanId },
    });

    return { scanId, instanceId: instance.id, host, status: "launched" };
  }
}
