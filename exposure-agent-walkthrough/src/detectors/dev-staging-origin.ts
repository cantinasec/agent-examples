// ponytail: hostname heuristics and DNS/robots analysis

import { DetectorContext } from "./types.js";
import { FindingInput } from "../core/findings.js";

const DEV_STAGING_PATTERNS = [
  /^(?:.*\.)?dev\./i,
  /^(?:.*\.)?staging\./i,
  /^(?:.*\.)?stage\./i,
  /^(?:.*\.)?test\./i,
  /^(?:.*\.)?qa\./i,
  /^(?:.*\.)?uat\./i,
  /^(?:.*\.)?sandbox\./i,
  /^(?:.*\.)?preprod\./i,
  /^(?:.*\.)?internal\./i,
  /^(?:.*\.)?corp\./i,
];

/**
 * Detects publicly reachable dev/staging hosts, bare IP origins, search-engine
 * indexable pre-production assets, and DNS records leaking private IPs.
 */
export function runDevStagingOriginDetector(ctx: DetectorContext): FindingInput[] {
  const findings: FindingInput[] = [];
  const { host, probe, doh, paths } = ctx;

  const isDevStagingHost = DEV_STAGING_PATTERNS.some((p) => p.test(host));

  if (isDevStagingHost && probe.status >= 200 && probe.status < 400) {
    findings.push({
      detector: "dev-staging-origin",
      severity: "medium",
      title: `Pre-Production Environment Publicly Accessible (${host})`,
      description: `The host ${host} exhibits development or staging naming conventions and is reachable over the public internet with HTTP status ${probe.status}.`,
      evidence: {
        host,
        status: probe.status,
        headers: probe.headers,
        matchedPattern: DEV_STAGING_PATTERNS.find((p) => p.test(host))?.toString(),
      },
      r2_screenshot_key: ctx.render?.screenshotKey,
    });
  }

  const isBareIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || (host.includes(":") && /^[0-9a-fA-F:]+$/.test(host));
  if (isBareIp && probe.status >= 200 && probe.status < 400) {
    findings.push({
      detector: "dev-staging-origin",
      severity: "low",
      title: `Direct Origin IP Publicly Reachable (${host})`,
      description: `The application is accessible directly via bare IP address (${host}) with HTTP status ${probe.status}, bypassing domain-level firewalls, CDN caching, and access controls.`,
      evidence: {
        host,
        status: probe.status,
        headers: probe.headers,
      },
      r2_screenshot_key: ctx.render?.screenshotKey,
    });
  }

  if (isDevStagingHost) {
    const robotsPath = paths?.find((p) => p.path === "/robots.txt");
    const xRobotsTag = Object.entries(probe.headers).find(
      ([k]) => k.toLowerCase() === "x-robots-tag"
    )?.[1];

    const hasNoIndexHeader = xRobotsTag && /noindex/i.test(xRobotsTag);
    const hasRobotsDisallowAll = robotsPath && robotsPath.status === 200 && /Disallow:\s*\/\s*$/m.test(robotsPath.body);

    if (!hasNoIndexHeader && !hasRobotsDisallowAll) {
      findings.push({
        detector: "dev-staging-origin",
        severity: "low",
        title: `Dev/Staging Host Indexable by Search Engines (${host})`,
        description: `Pre-production host ${host} lacks 'X-Robots-Tag: noindex' headers and a 'Disallow: /' robots.txt policy, allowing search engine crawlers to index non-production data.`,
        evidence: {
          host,
          xRobotsTag: xRobotsTag || "None",
          robotsTxtFound: Boolean(robotsPath && robotsPath.status === 200),
        },
      });
    }
  }

  if (doh && doh.status === "resolved") {
    const privateIps = doh.allIps.filter((ip) =>
      /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/.test(ip)
    );
    if (privateIps.length > 0) {
      findings.push({
        detector: "dev-staging-origin",
        severity: "info",
        title: `Host Resolves to Private RFC1918 Address on Public DNS (${host})`,
        description: `Host ${host} has DNS records pointing to private/internal IP address(es) (${privateIps.join(", ")}).`,
        evidence: {
          host,
          privateIps,
          allDnsIps: doh.allIps,
        },
      });
    }
  }

  return findings;
}
