import { describe, it, expect } from "vitest";
import { redactHeaders, redactBodyValues } from "../src/core/evidence.js";

describe("redactHeaders", () => {
  it("masks credential-bearing values and keeps every key", () => {
    const safe = redactHeaders({
      "set-cookie": "session=abc123; HttpOnly",
      "Authorization": "Bearer abc123",
      "content-type": "text/html",
      "www-authenticate": 'Basic realm="admin"',
    });

    expect(safe["set-cookie"]).toBe("[REDACTED]");
    expect(safe["Authorization"]).toBe("[REDACTED]");
    expect(JSON.stringify(safe)).not.toContain("abc123");

    // Detectors branch on these, so key presence and value must both survive.
    expect(safe["content-type"]).toBe("text/html");
    expect(safe["www-authenticate"]).toBe('Basic realm="admin"');
    expect(Object.keys(safe)).toHaveLength(4);
  });
});

describe("redactBodyValues", () => {
  it("masks dotenv values and keeps key names", () => {
    const out = redactBodyValues(
      "# comment\nDB_PASSWORD=hunter2\nexport AWS_SECRET_KEY = supersecret\nEMPTY=\n"
    );

    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("supersecret");
    expect(out).toContain("DB_PASSWORD=[REDACTED]");
    expect(out).toContain("AWS_SECRET_KEY = [REDACTED]");
    expect(out).toContain("# comment");
  });

  it("masks actuator JSON values and keeps property names", () => {
    const out = redactBodyValues(
      '{"propertySources":[{"properties":{"spring.datasource.password":{"value":"hunter2"}}}]}'
    );

    expect(out).not.toContain("hunter2");
    expect(out).toContain("spring.datasource.password");
    expect(out).toContain('"value":"[REDACTED]"');
  });
});
