// ponytail: simple regex and status check for missing auth boundaries

import { DetectorContext } from "./types.js";
import { FindingInput } from "../core/findings.js";

const LOGIN_REDIRECT_PATTERNS = [
  /\/login/i,
  /\/signin/i,
  /\/auth/i,
  /\/oauth/i,
  /\/sso/i,
  /accounts\.google\.com/i,
  /auth0\.com/i,
  /okta\.com/i,
  /keycloak/i,
  /cloudflareaccess\.com/i,
  /login\.microsoftonline\.com/i,
];

const SENSITIVE_KEYWORDS = [
  "admin",
  "dashboard",
  "internal",
  "console",
  "management",
  "metrics",
  "cluster",
  "control panel",
  "settings",
];

/**
 * Flags hosts that serve application content without any authentication gate
 * (no 401/403, no WWW-Authenticate, no login redirect, no Cloudflare Access).
 */
export function runNoAuthGateDetector(ctx: DetectorContext): FindingInput[] {
  const findings: FindingInput[] = [];
  const { probe, render } = ctx;

  if (probe.status === 401 || probe.status === 403) {
    return findings;
  }

  const authHeader = Object.entries(probe.headers).find(
    ([k]) => k.toLowerCase() === "www-authenticate"
  );
  if (authHeader) {
    return findings;
  }

  const hasAccessHeader = Object.keys(probe.headers).some(
    (k) => k.toLowerCase().startsWith("cf-access-") || k.toLowerCase() === "cf-mitigated"
  );
  if (hasAccessHeader) {
    return findings;
  }

  const locationHeader = Object.entries(probe.headers).find(
    ([k]) => k.toLowerCase() === "location"
  )?.[1];
  if (locationHeader && LOGIN_REDIRECT_PATTERNS.some((p) => p.test(locationHeader))) {
    return findings;
  }
  if (probe.redirectChain?.some((u) => LOGIN_REDIRECT_PATTERNS.some((p) => p.test(u)))) {
    return findings;
  }

  if (probe.status >= 200 && probe.status < 300) {
    const combinedContent = `${probe.body} ${render?.html || ""} ${render?.markdown || ""}`;

    if (/<input[^>]+type=["']?password["']?/i.test(combinedContent)) {
      return findings;
    }

    if (probe.body.trim().length < 80) {
      return findings;
    }
    if (/<title>(?:404 Not Found|Not Found|Error)<\/title>/i.test(combinedContent)) {
      return findings;
    }

    const isSensitive = SENSITIVE_KEYWORDS.some((kw) =>
      combinedContent.toLowerCase().includes(kw)
    );

    findings.push({
      detector: "no-auth-gate",
      severity: isSensitive ? "critical" : "high",
      title: isSensitive
        ? `Exposed Application with Sensitive Keywords (${ctx.host})`
        : `Unprotected Web Application (${ctx.host})`,
      description: `The host ${ctx.host} returned HTTP status ${probe.status} and served application content without any authentication gate (no 401/403, no WWW-Authenticate header, no login redirect, and no Cloudflare Access protection).`,
      evidence: {
        host: ctx.host,
        status: probe.status,
        headers: probe.headers,
        hasPasswordForm: false,
        sensitiveKeywordsFound: isSensitive,
        bodySnippet: probe.body.slice(0, 1000),
      },
      r2_screenshot_key: render?.screenshotKey,
    });
  }

  return findings;
}
