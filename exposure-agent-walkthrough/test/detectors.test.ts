import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runUnauthAdminDetector } from "../src/detectors/unauth-admin.js";
import { runNoAuthGateDetector } from "../src/detectors/no-auth-gate.js";
import { runLeakedArtifactDetector } from "../src/detectors/leaked-artifact.js";
import { runDevStagingOriginDetector } from "../src/detectors/dev-staging-origin.js";
import { DetectorContext } from "../src/detectors/types.js";

function loadFixture(name: string): string {
  return readFileSync(join(process.cwd(), "test", "fixtures", name), "utf-8");
}

describe("unauth-admin Detector", () => {
  it("detects unauthenticated Grafana dashboard", () => {
    const html = loadFixture("grafana-unauth.html");
    const ctx: DetectorContext = {
      host: "grafana.example.com",
      probe: {
        url: "https://grafana.example.com",
        status: 200,
        headers: { "content-type": "text/html" },
        body: html,
      },
    };

    const findings = runUnauthAdminDetector(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].detector).toBe("unauth-admin");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].title).toContain("Grafana");
  });

  it("detects unauthenticated Kibana console", () => {
    const html = loadFixture("kibana-unauth.html");
    const ctx: DetectorContext = {
      host: "kibana.example.com",
      probe: {
        url: "https://kibana.example.com",
        status: 200,
        headers: { "content-type": "text/html" },
        body: html,
      },
    };

    const findings = runUnauthAdminDetector(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("Kibana");
  });

  it("detects unauthenticated Jenkins CI/CD", () => {
    const html = loadFixture("jenkins-unauth.html");
    const ctx: DetectorContext = {
      host: "ci.example.com",
      probe: {
        url: "https://ci.example.com",
        status: 200,
        headers: { "x-jenkins": "2.401.1" },
        body: html,
      },
    };

    const findings = runUnauthAdminDetector(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("Jenkins");
  });

  it("detects unauthenticated Prometheus dashboard", () => {
    const html = loadFixture("prometheus-unauth.html");
    const ctx: DetectorContext = {
      host: "prometheus.example.com",
      probe: {
        url: "https://prometheus.example.com",
        status: 200,
        headers: {},
        body: html,
      },
    };

    const findings = runUnauthAdminDetector(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].title).toContain("Prometheus");
  });

  it("suppresses finding when login form is present", () => {
    const html = loadFixture("login-form.html");
    const ctx: DetectorContext = {
      host: "admin.example.com",
      probe: {
        url: "https://admin.example.com",
        status: 200,
        headers: {},
        body: html,
      },
    };

    const findings = runUnauthAdminDetector(ctx);
    expect(findings.length).toBe(0);
  });

  it("suppresses finding when 401 or 403 status is returned", () => {
    const html = loadFixture("grafana-unauth.html");
    const ctx401: DetectorContext = {
      host: "grafana.example.com",
      probe: {
        url: "https://grafana.example.com",
        status: 401,
        headers: { "www-authenticate": "Basic" },
        body: html,
      },
    };
    expect(runUnauthAdminDetector(ctx401).length).toBe(0);
  });
});

describe("no-auth-gate Detector", () => {
  it("flags application served with 200 OK and no auth boundary", () => {
    const ctx: DetectorContext = {
      host: "app.internal.example.com",
      probe: {
        url: "https://app.internal.example.com",
        status: 200,
        headers: { "content-type": "text/html" },
        body: "<html><body><h1>Internal Management Dashboard</h1><p>Welcome operator. Active nodes: 12</p></body></html>",
      },
    };

    const findings = runNoAuthGateDetector(ctx);
    expect(findings.length).toBe(1);
    expect(findings[0].detector).toBe("no-auth-gate");
    expect(findings[0].severity).toBe("critical"); // sensitive keyword 'dashboard' / 'management'
  });

  it("suppresses when WWW-Authenticate header is returned", () => {
    const ctx: DetectorContext = {
      host: "app.example.com",
      probe: {
        url: "https://app.example.com",
        status: 401,
        headers: { "www-authenticate": 'Basic realm="Restricted"' },
        body: "Unauthorized",
      },
    };

    expect(runNoAuthGateDetector(ctx).length).toBe(0);
  });

  it("suppresses when redirected to login endpoint", () => {
    const ctx: DetectorContext = {
      host: "app.example.com",
      probe: {
        url: "https://app.example.com",
        status: 302,
        headers: { location: "https://auth0.com/authorize?client_id=123" },
        body: "",
      },
    };

    expect(runNoAuthGateDetector(ctx).length).toBe(0);
  });

  it("suppresses when Cloudflare Access headers are present", () => {
    const ctx: DetectorContext = {
      host: "app.example.com",
      probe: {
        url: "https://app.example.com",
        status: 200,
        headers: { "cf-access-app-id": "123-abc" },
        body: "<html><body>App protected by Access</body></html>",
      },
    };

    expect(runNoAuthGateDetector(ctx).length).toBe(0);
  });
});

describe("leaked-artifact Detector", () => {
  it("detects exposed .git/HEAD repository", () => {
    const ctx: DetectorContext = {
      host: "app.example.com",
      probe: { url: "https://app.example.com", status: 200, headers: {}, body: "" },
      paths: [
        {
          path: "/.git/HEAD",
          url: "https://app.example.com/.git/HEAD",
          status: 200,
          headers: {},
          body: "ref: refs/heads/main\n",
        },
      ],
    };

    const findings = runLeakedArtifactDetector(ctx);
    expect(findings.some((f) => f.title.includes("Git Repository"))).toBe(true);
    expect(findings[0].severity).toBe("critical");
  });

  it("detects exposed .env file with credentials", () => {
    const ctx: DetectorContext = {
      host: "app.example.com",
      probe: { url: "https://app.example.com", status: 200, headers: {}, body: "" },
      paths: [
        {
          path: "/.env",
          url: "https://app.example.com/.env",
          status: 200,
          headers: {},
          body: "DB_PASSWORD=secret123\nAWS_SECRET_KEY=supersecret",
        },
      ],
    };

    const findings = runLeakedArtifactDetector(ctx);
    expect(findings.some((f) => f.title.includes(".env"))).toBe(true);
    expect(findings[0].severity).toBe("critical");

    // Evidence is stored durably, so the target's secrets must not reach it.
    const evidence = JSON.stringify(findings[0].evidence);
    expect(evidence).not.toContain("secret123");
    expect(evidence).not.toContain("supersecret");
    expect(evidence).toContain("DB_PASSWORD");
    expect(evidence).toContain("[REDACTED]");
  });

  it("redacts values but keeps property names for /actuator/env", () => {
    const ctx: DetectorContext = {
      host: "spring.example.com",
      probe: { url: "https://spring.example.com", status: 200, headers: {}, body: "" },
      paths: [
        {
          path: "/actuator/env",
          url: "https://spring.example.com/actuator/env",
          status: 200,
          headers: {},
          body: '{"_links":{},"propertySources":[{"properties":{"spring.datasource.password":{"value":"hunter2"}}}]}',
        },
      ],
    };

    const findings = runLeakedArtifactDetector(ctx);
    const actuator = findings.find((f) => f.title.includes("Actuator"));
    expect(actuator?.severity).toBe("critical");

    const evidence = JSON.stringify(actuator?.evidence);
    expect(evidence).not.toContain("hunter2");
    expect(evidence).toContain("spring.datasource.password");
    expect(evidence).toContain("[REDACTED]");
  });

  it("detects exposed Swagger/OpenAPI spec", () => {
    const ctx: DetectorContext = {
      host: "api.example.com",
      probe: { url: "https://api.example.com", status: 200, headers: {}, body: "" },
      paths: [
        {
          path: "/swagger.json",
          url: "https://api.example.com/swagger.json",
          status: 200,
          headers: { "content-type": "application/json" },
          body: '{"swagger":"2.0","paths":{"/admin/users":{}}}',
        },
      ],
    };

    const findings = runLeakedArtifactDetector(ctx);
    expect(findings.some((f) => f.title.includes("OpenAPI / Swagger"))).toBe(true);
  });

  it("detects exposed Spring Actuator", () => {
    const ctx: DetectorContext = {
      host: "spring.example.com",
      probe: { url: "https://spring.example.com", status: 200, headers: {}, body: "" },
      paths: [
        {
          path: "/actuator/health",
          url: "https://spring.example.com/actuator/health",
          status: 200,
          headers: { "content-type": "application/json" },
          body: '{"status":"UP","components":{"db":{"status":"UP"}}}',
        },
      ],
    };

    const findings = runLeakedArtifactDetector(ctx);
    expect(findings.some((f) => f.title.includes("Spring Boot Actuator"))).toBe(true);
  });

  it("detects directory listing", () => {
    const dirHtml = loadFixture("directory-listing.html");
    const ctx: DetectorContext = {
      host: "files.example.com",
      probe: {
        url: "https://files.example.com",
        status: 200,
        headers: {},
        body: dirHtml,
      },
      paths: [],
    };

    const findings = runLeakedArtifactDetector(ctx);
    expect(findings.some((f) => f.title.includes("Directory Listing"))).toBe(true);
  });
});

describe("dev-staging-origin Detector", () => {
  it("detects dev/staging naming reachable publicly", () => {
    const ctx: DetectorContext = {
      host: "dev.api.internal.example",
      probe: {
        url: "https://dev.api.internal.example",
        status: 200,
        headers: {},
        body: "OK",
      },
    };

    const findings = runDevStagingOriginDetector(ctx);
    expect(findings.some((f) => f.title.includes("Pre-Production Environment"))).toBe(true);
  });

  it("detects direct origin bare IP reachability", () => {
    const ctx: DetectorContext = {
      host: "198.51.100.2",
      probe: {
        url: "http://198.51.100.2",
        status: 200,
        headers: {},
        body: "Hello Origin",
      },
    };

    const findings = runDevStagingOriginDetector(ctx);
    expect(findings.some((f) => f.title.includes("Direct Origin IP"))).toBe(true);
  });

  it("detects dev host indexable by search engines", () => {
    const ctx: DetectorContext = {
      host: "staging.example.com",
      probe: {
        url: "https://staging.example.com",
        status: 200,
        headers: {},
        body: "<html><body>Staging site</body></html>",
      },
      paths: [
        {
          path: "/robots.txt",
          url: "https://staging.example.com/robots.txt",
          status: 200,
          headers: {},
          body: "User-agent: *\nAllow: /",
        },
      ],
    };

    const findings = runDevStagingOriginDetector(ctx);
    expect(findings.some((f) => f.title.includes("Indexable by Search Engines"))).toBe(true);
  });
});
