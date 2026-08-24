// ponytail: pattern matching over bounded path probe results

import { DetectorContext, PathProbeResult } from "./types.js";
import { FindingInput } from "../core/findings.js";
import { redactBodyValues } from "../core/evidence.js";

/**
 * Detects publicly exposed artifacts: .git repos, .env files, OpenAPI specs,
 * Spring Actuators, Apache server-status, .DS_Store files, source maps, and
 * directory listings.
 */
export function runLeakedArtifactDetector(ctx: DetectorContext): FindingInput[] {
  const findings: FindingInput[] = [];
  const paths = ctx.paths || [];

  for (const item of paths) {
    if (item.status !== 200) {
      continue;
    }

    const trimmedBody = item.body.trim();

    if (item.path.includes("/.git/HEAD") || item.path.endsWith("/HEAD")) {
      if (/^ref:\s+refs\//.test(trimmedBody) || /^[0-9a-f]{40}$/i.test(trimmedBody)) {
        findings.push({
          detector: "leaked-artifact",
          severity: "critical",
          title: `Exposed Git Repository (${ctx.host})`,
          description: `The file '${item.path}' on ${ctx.host} is publicly accessible and contains Git HEAD metadata. Source code and commit history may be downloadable.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
            contentSnippet: trimmedBody.slice(0, 300),
          },
        });
      }
    }

    if (item.path.includes("/.env")) {
      const hasEnvKeys =
        /(?:DB_|DATABASE_|PASSWORD=|SECRET=|API_KEY=|AUTH_TOKEN=|PRIVATE_KEY=|AWS_)/i.test(
          trimmedBody
        );
      if (hasEnvKeys && trimmedBody.includes("=")) {
        findings.push({
          detector: "leaked-artifact",
          severity: "critical",
          title: `Exposed Environment Configuration File (.env) (${ctx.host})`,
          description: `The environment file '${item.path}' on ${ctx.host} is publicly accessible and contains secret keys or database configuration variables.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
            // Redact before slicing so a value cut mid-token cannot survive
            contentSnippet: redactBodyValues(trimmedBody).slice(0, 500),
          },
        });
      }
    }

    if (item.path.includes("swagger") || item.path.includes("openapi") || item.path.includes("api-docs")) {
      if (
        (trimmedBody.includes('"swagger":') || trimmedBody.includes('"openapi":') || trimmedBody.includes('"paths":')) &&
        (trimmedBody.startsWith("{") || trimmedBody.startsWith("["))
      ) {
        findings.push({
          detector: "leaked-artifact",
          severity: "medium",
          title: `Exposed OpenAPI / Swagger Documentation (${ctx.host})`,
          description: `API schema specification '${item.path}' on ${ctx.host} is publicly exposed, revealing internal API routes, models, and endpoints.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
            contentSnippet: trimmedBody.slice(0, 500),
          },
        });
      }
    }

    if (item.path.includes("/actuator")) {
      if (
        (trimmedBody.includes('"status":"UP"') || trimmedBody.includes('"components":') || trimmedBody.includes('"_links":')) &&
        trimmedBody.startsWith("{")
      ) {
        const isEnvActuator = item.path.includes("/env");
        const snippet = isEnvActuator ? redactBodyValues(trimmedBody) : trimmedBody;
        findings.push({
          detector: "leaked-artifact",
          severity: isEnvActuator ? "critical" : "high",
          title: `Exposed Spring Boot Actuator (${ctx.host}${item.path})`,
          description: `Spring Boot Actuator endpoint '${item.path}' on ${ctx.host} is publicly accessible, leaking application runtime internals and metrics.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
            contentSnippet: snippet.slice(0, 500),
          },
        });
      }
    }

    if (item.path.includes("/server-status")) {
      if (
        trimmedBody.includes("Apache Server Status") ||
        trimmedBody.includes("Server Version: Apache") ||
        trimmedBody.includes("Total accesses:")
      ) {
        findings.push({
          detector: "leaked-artifact",
          severity: "high",
          title: `Exposed Apache Server Status (${ctx.host})`,
          description: `Apache server-status page on ${ctx.host} is publicly reachable, leaking active worker requests, client IPs, and server statistics.`,
          // No snippet: this page lists the client IPs of the target's real
          // visitors, and the path and status already prove the exposure.
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
          },
        });
      }
    }

    if (item.path.includes("/.DS_Store")) {
      if (trimmedBody.includes("Bud1") || trimmedBody.includes("\x00\x00\x00\x01Bud1") || item.body.length > 30) {
        findings.push({
          detector: "leaked-artifact",
          severity: "low",
          title: `Exposed macOS .DS_Store File (${ctx.host})`,
          description: `A .DS_Store file is exposed on ${ctx.host}${item.path}, revealing directory contents and file structures.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
          },
        });
      }
    }

    if (item.path.endsWith(".map")) {
      if (trimmedBody.includes('"version":') && trimmedBody.includes('"sources":')) {
        findings.push({
          detector: "leaked-artifact",
          severity: "low",
          title: `Exposed JavaScript Source Map (${ctx.host}${item.path})`,
          description: `Source map '${item.path}' on ${ctx.host} is publicly accessible, allowing reconstruction of original frontend source code.`,
          evidence: {
            path: item.path,
            url: item.url,
            status: item.status,
            contentSnippet: trimmedBody.slice(0, 400),
          },
        });
      }
    }

    if (
      (/<title>Index of \/[^<]*<\/title>/i.test(trimmedBody) ||
        /<h1>Index of \/[^<]*<\/h1>/i.test(trimmedBody)) &&
      (trimmedBody.includes("Parent Directory") || trimmedBody.includes("../") || trimmedBody.includes("Directory Listing"))
    ) {
      findings.push({
        detector: "leaked-artifact",
        severity: "medium",
        title: `Exposed Directory Listing on ${ctx.host}${item.path}`,
        description: `Web server directory indexing is enabled for '${item.path}' on ${ctx.host}, allowing visitors to browse and download server files.`,
        evidence: {
          path: item.path,
          url: item.url,
          status: item.status,
          contentSnippet: trimmedBody.slice(0, 600),
        },
      });
    }
  }

  if (ctx.probe && ctx.probe.status === 200) {
    const rootBody = ctx.probe.body;
    if (
      (/<title>Index of \/[^<]*<\/title>/i.test(rootBody) ||
        /<h1>Index of \/[^<]*<\/h1>/i.test(rootBody)) &&
      (rootBody.includes("Parent Directory") || rootBody.includes("../") || rootBody.includes("Directory Listing"))
    ) {
      // Avoid duplicate if already caught in paths
      if (!findings.some((f) => f.title.startsWith("Exposed Directory Listing on") && f.evidence.path === "/")) {
        findings.push({
          detector: "leaked-artifact",
          severity: "medium",
          title: `Exposed Directory Listing on ${ctx.host}/`,
          description: `Web server directory indexing is enabled on the root of ${ctx.host}, exposing server files to anonymous visitors.`,
          evidence: {
            path: "/",
            url: ctx.probe.url,
            status: ctx.probe.status,
            contentSnippet: rootBody.slice(0, 600),
          },
        });
      }
    }
  }

  return findings;
}
