import { describe, it, expect, beforeEach } from "vitest";
import { createTestDb } from "./mock-d1.js";
import {
  assertInScope,
  putTargets,
  addTarget,
  removeTarget,
  listTargets,
  retireExpiredTargets,
  normalizeHost,
} from "../src/core/scope.js";

describe("Scope Registry & assertInScope", () => {
  let db: D1Database;

  beforeEach(() => {
    db = createTestDb();
  });

  it("normalizes URLs and hostnames strictly", () => {
    expect(normalizeHost("https://example.com/some/path?query=1")).toBe("example.com");
    expect(normalizeHost("http://api.sub.example.com:8080/")).toBe("api.sub.example.com");
    expect(normalizeHost("EXAMPLE.COM")).toBe("example.com");
    expect(normalizeHost("192.0.2.1")).toBe("192.0.2.1");
    expect(() => normalizeHost("")).toThrow();
  });

  it("asserts in scope for valid active target", async () => {
    await addTarget(
      db,
      "principal-1",
      { host: "example.com", notes: "main site" },
      "TICKET-123",
      7
    );

    const verified = await assertInScope("https://example.com/dashboard", db);
    expect(verified).toBe("example.com");
  });

  it("rejects unknown host not in registry", async () => {
    await expect(assertInScope("unknown.invalid", db)).rejects.toThrow(
      "Host 'unknown.invalid' is not in the scope registry"
    );
  });

  it("rejects lookalike hostnames (e.g. example.com.attacker.invalid)", async () => {
    await addTarget(
      db,
      "principal-1",
      { host: "example.com" },
      "TICKET-123",
      7
    );

    await expect(assertInScope("example.com.attacker.invalid", db)).rejects.toThrow(
      "Host 'example.com.attacker.invalid' is not in the scope registry"
    );
    await expect(assertInScope("attacker-example.invalid", db)).rejects.toThrow(
      "Host 'attacker-example.invalid' is not in the scope registry"
    );
  });

  it("rejects bare IP not explicitly in registry", async () => {
    await addTarget(
      db,
      "principal-1",
      { host: "example.com" },
      "TICKET-123",
      7
    );

    await expect(assertInScope("192.0.2.1", db)).rejects.toThrow(
      "Host '192.0.2.1' is not in the scope registry"
    );
  });

  it("rejects retired targets", async () => {
    await addTarget(
      db,
      "principal-1",
      { host: "example.com" },
      "TICKET-123",
      7
    );

    await removeTarget(db, "example.com");

    await expect(assertInScope("example.com", db)).rejects.toThrow(
      "Host 'example.com' is retired from scope"
    );
  });

  it("rejects expired targets and retires them on sweep", async () => {
    // Add target with past expiry directly
    const past = Date.now() - 10000;
    await db
      .prepare(
        "INSERT INTO targets (host, status, added_by_principal, authorization_ref, added_at, expires_at) VALUES ('expired.example', 'active', 'p1', 'ref1', ?, ?)"
      )
      .bind(past - 86400000, past)
      .run();

    await expect(assertInScope("expired.example", db)).rejects.toThrow(
      "scope attestation expired"
    );

    const retiredCount = await retireExpiredTargets(db);
    expect(retiredCount).toBe(1);

    const targets = await listTargets(db, { status: "retired", includeExpired: true });
    expect(targets.some((t) => t.host === "expired.example")).toBe(true);
  });

  it("put_targets atomically replaces scope and marks omitted targets retired", async () => {
    await putTargets(
      db,
      "principal-1",
      [
        { host: "host1.example.com" },
        { host: "host2.example.com" },
        { host: "host3.example.com" },
      ],
      "TICKET-BATCH-1"
    );

    let activeList = await listTargets(db, { status: "active" });
    expect(activeList.length).toBe(3);

    // Replace with host2 and host4 (host1 and host3 should be retired, host4 added)
    const result = await putTargets(
      db,
      "principal-1",
      [{ host: "host2.example.com" }, { host: "host4.example.com" }],
      "TICKET-BATCH-2"
    );

    expect(result.added).toBe(2);
    expect(result.retired).toBe(2);
    expect(result.totalActive).toBe(2);

    activeList = await listTargets(db, { status: "active" });
    const activeHosts = activeList.map((t) => t.host);
    expect(activeHosts).toEqual(["host2.example.com", "host4.example.com"]);

    // Check that omitted host1 and host3 are still in DB as retired (not deleted)
    const allRetired = await listTargets(db, { status: "retired", includeExpired: true });
    const retiredHosts = allRetired.map((t) => t.host);
    expect(retiredHosts).toContain("host1.example.com");
    expect(retiredHosts).toContain("host3.example.com");
  });

  it("enforces maxExpiryDays bounds", async () => {
    await expect(
      addTarget(
        db,
        "principal-1",
        { host: "example.com", expiryDays: 999 },
        "TICKET-123",
        7,
        30
      )
    ).rejects.toThrow("expiryDays must be between 1 and 30");

    await expect(
      putTargets(
        db,
        "principal-1",
        [{ host: "example.com", expiryDays: 45 }],
        "TICKET-123",
        7,
        30
      )
    ).rejects.toThrow("expiryDays for example.com must be between 1 and 30");
  });
});
