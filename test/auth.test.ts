import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPair, SignJWT, createLocalJWKSet, exportJWK } from "jose";
import { verifyAccessJwt } from "../src/auth/access-jwt.js";
import {
  ensurePrincipal,
  getPrincipal,
  hasPermission,
  requirePerm,
} from "../src/auth/principals.js";
import { authenticateRequest, requireRequestPermission } from "../src/auth/authorization.js";
import { createTestDb } from "./mock-d1.js";

describe("Auth & Cloudflare Access JWT Verification", () => {
  const teamDomain = "myteam.cloudflareaccess.com";
  const expectedAud = "aud-tag-12345";
  let keyPair: any;
  let jwks: any;

  beforeEach(async () => {
    keyPair = await generateKeyPair("RS256");
    const jwk = await exportJWK(keyPair.publicKey);
    jwk.kid = "test-key-id";
    jwk.alg = "RS256";
    jwks = createLocalJWKSet({ keys: [jwk] });
  });

  it("verifies valid Cloudflare Access JWT successfully", async () => {
    const token = await new SignJWT({
      sub: "service-token-client-id",
      common_name: "my-service-token",
      email: "agent@myteam.com",
      type: "service",
    })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
      .setIssuer(`https://${teamDomain}`)
      .setAudience(expectedAud)
      .setExpirationTime("2h")
      .sign(keyPair.privateKey);

    const identity = await verifyAccessJwt(token, teamDomain, expectedAud, jwks);
    expect(identity.clientId).toBe("my-service-token");
    expect(identity.sub).toBe("service-token-client-id");
    expect(identity.email).toBe("agent@myteam.com");
  });

  it("rejects request missing Access JWT header", async () => {
    await expect(verifyAccessJwt("", teamDomain, expectedAud, jwks)).rejects.toThrow(
      "Missing Cf-Access-Jwt-Assertion header"
    );
    await expect(verifyAccessJwt(undefined, teamDomain, expectedAud, jwks)).rejects.toThrow(
      "Missing Cf-Access-Jwt-Assertion header"
    );
  });

  it("rejects JWT with wrong audience", async () => {
    const token = await new SignJWT({ sub: "client-id" })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
      .setIssuer(`https://${teamDomain}`)
      .setAudience("wrong-aud")
      .setExpirationTime("1h")
      .sign(keyPair.privateKey);

    await expect(verifyAccessJwt(token, teamDomain, expectedAud, jwks)).rejects.toThrow();
  });

  it("rejects JWT signed by untrusted key", async () => {
    const otherKeyPair = await generateKeyPair("RS256");
    const token = await new SignJWT({ sub: "client-id" })
      .setProtectedHeader({ alg: "RS256", kid: "other-key" })
      .setIssuer(`https://${teamDomain}`)
      .setAudience(expectedAud)
      .setExpirationTime("1h")
      .sign(otherKeyPair.privateKey);

    await expect(verifyAccessJwt(token, teamDomain, expectedAud, jwks)).rejects.toThrow();
  });

  it("rejects expired JWT", async () => {
    const token = await new SignJWT({ sub: "client-id" })
      .setProtectedHeader({ alg: "RS256", kid: "test-key-id" })
      .setIssuer(`https://${teamDomain}`)
      .setAudience(expectedAud)
      .setExpirationTime("-10s")
      .sign(keyPair.privateKey);

    await expect(verifyAccessJwt(token, teamDomain, expectedAud, jwks)).rejects.toThrow();
  });
});

describe("Principal Roles & Permission Hierarchy", () => {
  let db: D1Database;

  beforeEach(() => {
    db = createTestDb();
  });

  it("evaluates role hierarchy correctly", () => {
    expect(hasPermission("read", "read")).toBe(true);
    expect(hasPermission("read", "scan")).toBe(false);
    expect(hasPermission("read", "admin")).toBe(false);

    expect(hasPermission("scan", "read")).toBe(true);
    expect(hasPermission("scan", "scan")).toBe(true);
    expect(hasPermission("scan", "admin")).toBe(false);

    expect(hasPermission("admin", "read")).toBe(true);
    expect(hasPermission("admin", "scan")).toBe(true);
    expect(hasPermission("admin", "admin")).toBe(true);
  });

  it("enforces permissions in D1 database", async () => {
    await ensurePrincipal(db, "read-agent", "Read Agent", "read");
    await ensurePrincipal(db, "scan-agent", "Scan Agent", "scan");
    await ensurePrincipal(db, "admin-agent", "Admin Agent", "admin");

    await expect(requirePerm(db, "read-agent", "read")).resolves.toBeDefined();
    await expect(requirePerm(db, "read-agent", "scan")).rejects.toThrow(
      "Principal 'read-agent' has role 'read', but role 'scan' is required"
    );
    await expect(requirePerm(db, "read-agent", "admin")).rejects.toThrow(
      "Principal 'read-agent' has role 'read', but role 'admin' is required"
    );

    await expect(requirePerm(db, "scan-agent", "read")).resolves.toBeDefined();
    await expect(requirePerm(db, "scan-agent", "scan")).resolves.toBeDefined();
    await expect(requirePerm(db, "scan-agent", "admin")).rejects.toThrow(
      "Principal 'scan-agent' has role 'scan', but role 'admin' is required"
    );

    await expect(requirePerm(db, "admin-agent", "read")).resolves.toBeDefined();
    await expect(requirePerm(db, "admin-agent", "scan")).resolves.toBeDefined();
    await expect(requirePerm(db, "admin-agent", "admin")).resolves.toBeDefined();
  });

  it("rejects requests without an Access assertion", async () => {
    const mockEnv = { DB: db } as any;
    const req = new Request("https://exposure.example.com/mcp");

    await expect(authenticateRequest(mockEnv, req)).rejects.toThrow(
      "Missing Cf-Access-Jwt-Assertion header"
    );
  });

  it("rejects unregistered principal", async () => {
    await expect(requirePerm(db, "ghost-agent", "read")).rejects.toThrow(
      "Principal 'ghost-agent' is not registered in the system"
    );
  });
});
