// ponytail: jose createRemoteJWKSet with in-memory memoization

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from "jose";

export interface AccessJwtIdentity {
  clientId: string;
  sub: string;
  email?: string;
  type?: string;
  payload: JWTPayload;
}

// In-memory cache of remote JWKS sets by team domain
const jwksCache = new Map<string, JWTVerifyGetKey>();

export function getJwksForTeam(teamDomain: string): JWTVerifyGetKey {
  const normalizedDomain = teamDomain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  let jwks = jwksCache.get(normalizedDomain);
  if (!jwks) {
    const certsUrl = new URL(`https://${normalizedDomain}/cdn-cgi/access/certs`);
    jwks = createRemoteJWKSet(certsUrl);
    jwksCache.set(normalizedDomain, jwks);
  }
  return jwks;
}

/**
 * Verifies the Cloudflare Access JWT assertion header.
 */
export async function verifyAccessJwt(
  jwt: string | null | undefined,
  teamDomain: string,
  expectedAud: string,
  jwksOverride?: JWTVerifyGetKey
): Promise<AccessJwtIdentity> {
  if (!jwt || jwt.trim() === "") {
    throw new Error("Missing Cf-Access-Jwt-Assertion header");
  }

  const normalizedDomain = teamDomain.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const expectedIssuer = `https://${normalizedDomain}`;
  const jwks = jwksOverride || getJwksForTeam(normalizedDomain);

  const { payload } = await jwtVerify(jwt, jwks, {
    audience: expectedAud,
    issuer: expectedIssuer,
  });

  // Client ID / identity resolution:
  // For Service Tokens: payload.sub or payload.common_name carries the service token client id
  // For Users: payload.email or payload.sub
  const clientId = (payload.common_name as string) || (payload.email as string) || payload.sub;
  if (!clientId) {
    throw new Error("JWT payload missing identity (sub/common_name/email)");
  }

  return {
    clientId,
    sub: payload.sub || clientId,
    email: payload.email as string | undefined,
    type: payload.type as string | undefined,
    payload,
  };
}
