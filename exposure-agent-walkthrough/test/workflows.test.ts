import { describe, it, expect, beforeEach, vi } from "vitest";
import { createTestDb } from "./mock-d1.js";
import { addTarget } from "../src/core/scope.js";
import { TargetWorkflow } from "../src/workflows/target.js";
import { SweepWorkflow } from "../src/workflows/sweep.js";
import { listFindings, syncDetectorFindings } from "../src/core/findings.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

describe("Workflow Execution End-to-End", () => {
  let db: D1Database;
  const host = "dashboard.example.com";

  beforeEach(async () => {
    db = createTestDb();
    await addTarget(db, "admin-user", { host }, "TICKET-E2E-1");
  });

  it("TargetWorkflow executes 7 steps and records findings", async () => {
    const grafanaHtml = readFileSync(
      join(process.cwd(), "test", "fixtures", "grafana-unauth.html"),
      "utf-8"
    );

    // Mock fetch for target host probe and DoH
    vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlStr = url.toString();
      if (urlStr.includes("dns-query")) {
        return new Response(
          JSON.stringify({
            Status: 0,
            Question: [{ name: host, type: 1 }],
            Answer: [{ name: host, type: 1, TTL: 300, data: "192.0.2.10" }],
          })
        );
      }
      if (urlStr.includes("/.git/HEAD")) {
        return new Response("Not Found", { status: 404 });
      }
      return new Response(grafanaHtml, {
        status: 200,
        headers: { "Content-Type": "text/html" },
      });
    });

    const mockEvidence: any = {
      put: vi.fn().mockResolvedValue({}),
      get: vi.fn().mockResolvedValue(null),
    };

    const env: any = {
      DB: db,
      EVIDENCE: mockEvidence,
    };

    const workflow = new TargetWorkflow({} as any, env);

    const mockStep: any = {
      do: async (_name: string, fn: Function) => await fn(),
    };

    const result = await workflow.run(
      {
        payload: { host, scanId: "test-scan-1" },
      } as any,
      mockStep
    );

    expect(result.host).toBe(host);
    expect(result.findingsCount).toBeGreaterThan(0);

    const findings = await listFindings(db, { host });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.detector === "unauth-admin")).toBe(true);

    const scanRow = await db
      .prepare("SELECT * FROM scans WHERE id = 'test-scan-1'")
      .first<any>();
    expect(scanRow?.status).toBe("completed");
  });

  it("SweepWorkflow fans out target workflows for all active scope hosts", async () => {
    await addTarget(db, "admin-user", { host: "site2.example.com" }, "TICKET-2");
    await addTarget(db, "admin-user", { host: "site3.example.com" }, "TICKET-3");

    const createdBatches: any[] = [];
    const mockTargetWorkflow: any = {
      createBatch: vi.fn().mockImplementation(async (items: any[]) => {
        createdBatches.push(items);
      }),
    };

    const env: any = {
      DB: db,
      TARGET_WORKFLOW: mockTargetWorkflow,
    };

    const sweep = new SweepWorkflow({} as any, env);
    const mockStep: any = {
      do: async (_name: string, fn: Function) => await fn(),
    };

    const res = await sweep.run({} as any, mockStep);
    expect(res.swept).toBe(3);
    expect(mockTargetWorkflow.createBatch).toHaveBeenCalled();
  });

  it("leaves findings open when a path probe fails", async () => {
    await syncDetectorFindings(db, host, "leaked-artifact", [
      {
        detector: "leaked-artifact",
        severity: "critical",
        title: `Exposed Git Repository (${host})`,
        description: "Existing finding",
        evidence: { path: "/.git/HEAD" },
      },
    ]);

    vi.spyOn(globalThis, "fetch").mockImplementation(async (url: any) => {
      const urlString = url.toString();
      if (urlString.includes("dns-query")) {
        return new Response(JSON.stringify({
          Status: 0,
          Answer: [{ name: host, type: 1, TTL: 300, data: "192.0.2.10" }],
        }));
      }
      if (urlString === `https://${host}`) {
        return new Response("public application", { status: 200 });
      }
      throw new Error("path probe failed");
    });

    const workflow = new TargetWorkflow({} as any, { DB: db } as any);
    const step = { do: async (_name: string, fn: Function) => await fn() } as any;

    await expect(
      workflow.run({ payload: { host, scanId: "failed-scan" } } as any, step)
    ).rejects.toThrow("path probe failed");

    const [finding] = await listFindings(db, { host, detector: "leaked-artifact" });
    expect(finding.state).toBe("open");
  });
});
