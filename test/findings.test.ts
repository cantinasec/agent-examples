import { describe, it, expect, beforeEach } from "vitest";
import { createTestDb } from "./mock-d1.js";
import {
  syncDetectorFindings,
  listFindings,
  getFinding,
  triageFinding,
  generateFindingId,
  FindingInput,
} from "../src/core/findings.js";
import { addTarget } from "../src/core/scope.js";

describe("Findings Lifecycle & Diffing", () => {
  let db: D1Database;
  const host = "app.example.com";

  beforeEach(async () => {
    db = createTestDb();
    await addTarget(db, "admin", { host }, "TICKET-1");
  });

  it("generates deterministic finding ID", () => {
    const id1 = generateFindingId("app.example.com", "unauth-admin", "Unauthenticated Grafana Dashboard");
    const id2 = generateFindingId("app.example.com", "unauth-admin", "Unauthenticated Grafana Dashboard");
    expect(id1).toBe(id2);
    expect(id1).toBe("app.example.com:unauth-admin:unauthenticated-grafana-dashboard");
  });

  it("inserts new open findings on first scan", async () => {
    const findings: FindingInput[] = [
      {
        detector: "unauth-admin",
        severity: "critical",
        title: "Unauthenticated Grafana Dashboard",
        description: "Grafana is open",
        evidence: { status: 200 },
      },
    ];

    const res = await syncDetectorFindings(db, host, "unauth-admin", findings);
    expect(res.added).toBe(1);
    expect(res.updated).toBe(0);
    expect(res.resolved).toBe(0);

    const list = await listFindings(db, { host });
    expect(list.length).toBe(1);
    expect(list[0].state).toBe("open");
    expect(list[0].severity).toBe("critical");
    expect(list[0].resolved_at).toBeNull();
  });

  it("marks previous finding fixed when exposure is no longer detected (diffing)", async () => {
    const findings: FindingInput[] = [
      {
        detector: "unauth-admin",
        severity: "critical",
        title: "Unauthenticated Grafana Dashboard",
        description: "Grafana is open",
        evidence: { status: 200 },
      },
    ];

    await syncDetectorFindings(db, host, "unauth-admin", findings);

    // Scan 2: no findings detected (e.g. auth was added)
    const res2 = await syncDetectorFindings(db, host, "unauth-admin", []);
    expect(res2.added).toBe(0);
    expect(res2.updated).toBe(0);
    expect(res2.resolved).toBe(1);

    const list = await listFindings(db, { host });
    expect(list.length).toBe(1);
    expect(list[0].state).toBe("fixed");
    expect(list[0].resolved_at).not.toBeNull();
  });

  it("reopens fixed finding if exposure reappears", async () => {
    const finding: FindingInput = {
      detector: "unauth-admin",
      severity: "critical",
      title: "Unauthenticated Grafana Dashboard",
      description: "Grafana is open",
      evidence: { status: 200 },
    };

    await syncDetectorFindings(db, host, "unauth-admin", [finding]);
    await syncDetectorFindings(db, host, "unauth-admin", []);
    const res3 = await syncDetectorFindings(db, host, "unauth-admin", [finding]);
    expect(res3.updated).toBe(1);

    const list = await listFindings(db, { host });
    expect(list[0].state).toBe("open");
    expect(list[0].resolved_at).toBeNull();
  });

  it("triages findings to accepted_risk and false_positive", async () => {
    const finding: FindingInput = {
      detector: "unauth-admin",
      severity: "critical",
      title: "Unauthenticated Grafana Dashboard",
      description: "Grafana is open",
      evidence: { status: 200 },
    };

    await syncDetectorFindings(db, host, "unauth-admin", [finding]);
    const id = generateFindingId(host, "unauth-admin", finding.title);

    const triaged = await triageFinding(db, id, "accepted_risk", "Intentionally public demo dashboard");
    expect(triaged.state).toBe("accepted_risk");
    expect(triaged.resolved_at).not.toBeNull();

    const stored = await getFinding(db, id);
    expect(stored?.state).toBe("accepted_risk");
    expect(stored?.evidence_json).toContain("Intentionally public demo dashboard");
  });
});
