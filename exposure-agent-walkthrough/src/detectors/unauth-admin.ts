// ponytail: declarative fingerprint table for admin UIs

import { DetectorContext } from "./types.js";
import { FindingInput } from "../core/findings.js";

interface AdminFingerprint {
  name: string;
  patterns: RegExp[];
  headerPatterns?: Array<{ header: string; pattern: RegExp }>;
}

const ADMIN_FINGERPRINTS: AdminFingerprint[] = [
  {
    name: "Grafana Dashboard",
    patterns: [
      /window\.grafanaBootData/i,
      /\/public\/app\/boot/i,
      /<title>.*Grafana.*<\/title>/i,
      /grafana-app/i,
    ],
  },
  {
    name: "Kibana Console",
    patterns: [
      /kbn-name=["']?kibana["']?/i,
      /window\.__kbn__/i,
      /<title>.*Kibana.*<\/title>/i,
    ],
  },
  {
    name: "Jenkins CI/CD",
    patterns: [
      /id=["']?jenkins["']?/i,
      /<title>.*Dashboard \[Jenkins\]<\/title>/i,
    ],
    headerPatterns: [{ header: "x-jenkins", pattern: /.+/ }],
  },
  {
    name: "Prometheus Monitoring",
    patterns: [
      /<title>Prometheus Time Series Collection<\/title>/i,
      /window\.PATH_PREFIX/i,
    ],
  },
  {
    name: "Portainer Management",
    patterns: [
      /portainer\.min\.js/i,
      /<title>.*Portainer.*<\/title>/i,
      /<meta name=["']?author["']? content=["']?Portainer/i,
    ],
  },
  {
    name: "phpMyAdmin Database Console",
    patterns: [
      /pma_version/i,
      /<title>.*phpMyAdmin.*<\/title>/i,
      /pma_absolute_uri/i,
    ],
  },
  {
    name: "Home Assistant Dashboard",
    patterns: [
      /<title>.*Home Assistant.*<\/title>/i,
      /homeassistant\.min\.js/i,
      /<ha-app-layout/i,
    ],
  },
  {
    name: "RabbitMQ Management Console",
    patterns: [
      /<title>RabbitMQ Management<\/title>/i,
      /rabbitmq\.js/i,
    ],
  },
  {
    name: "Apache Airflow Webserver",
    patterns: [
      /<title>.*Airflow.*<\/title>/i,
      /airflow_version/i,
      /Airflow - DAGs/i,
    ],
  },
  {
    name: "Proxmox VE Console",
    patterns: [
      /<title>Proxmox Virtual Environment<\/title>/i,
      /pvemanagerlib\.js/i,
      /PVEAuthCookie/i,
    ],
  },
  {
    name: "Traefik Dashboard",
    patterns: [
      /<title>Traefik(?: Dashboard)?<\/title>/i,
      /traefik-ui/i,
    ],
  },
];

/**
 * Detects unauthenticated admin UIs (Grafana, Kibana, Jenkins, etc.) by
 * fingerprinting known patterns in HTML responses and response headers.
 */
export function runUnauthAdminDetector(ctx: DetectorContext): FindingInput[] {
  const findings: FindingInput[] = [];
  const { probe, render } = ctx;

  if (probe.status === 401 || probe.status === 403) {
    return findings;
  }
  const hasWwwAuth = Object.keys(probe.headers).some(
    (k) => k.toLowerCase() === "www-authenticate"
  );
  if (hasWwwAuth) {
    return findings;
  }

  const combinedContent = `${probe.body} ${render?.html || ""} ${render?.markdown || ""}`;

  const hasPasswordForm = /<input[^>]+type=["']?password["']?/i.test(combinedContent);
  if (hasPasswordForm) {
    return findings;
  }

  for (const fp of ADMIN_FINGERPRINTS) {
    let matched = false;
    let matchedSnippet = "";

    for (const pat of fp.patterns) {
      if (pat.test(combinedContent)) {
        matched = true;
        matchedSnippet = pat.toString();
        break;
      }
    }

    if (!matched && fp.headerPatterns) {
      for (const hp of fp.headerPatterns) {
        const headerVal = Object.entries(probe.headers).find(
          ([k]) => k.toLowerCase() === hp.header.toLowerCase()
        )?.[1];
        if (headerVal && hp.pattern.test(headerVal)) {
          matched = true;
          matchedSnippet = `Header ${hp.header}: ${headerVal}`;
          break;
        }
      }
    }

    if (matched) {
      findings.push({
        detector: "unauth-admin",
        severity: "critical",
        title: `Unauthenticated ${fp.name} (${ctx.host})`,
        description: `Detected unauthenticated ${fp.name} on ${ctx.host}. The admin interface is publicly accessible without credentials or authentication gate.`,
        evidence: {
          adminType: fp.name,
          matchedRule: matchedSnippet,
          httpStatus: probe.status,
          headers: probe.headers,
          snippet: combinedContent.slice(0, 1000),
        },
        r2_screenshot_key: render?.screenshotKey,
      });
    }
  }

  return findings;
}
