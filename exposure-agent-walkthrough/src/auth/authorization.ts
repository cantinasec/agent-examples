import { verifyAccessJwt } from "./access-jwt.js";
import { getPrincipal, hasPermission, type Principal, type Role } from "./principals.js";

/**
 * Authenticate a request using the JWT Cloudflare Access adds after its
 * user or service-token policy succeeds.
 * @throws if the assertion is missing, invalid, or not registered.
 */
export async function authenticateRequest(env: Env, request: Request): Promise<Principal> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");
  if (assertion) {
    const identity = await verifyAccessJwt(assertion, env.ACCESS_TEAM_DOMAIN, env.ACCESS_AUD);
    const principal = await getPrincipal(env.DB, identity.clientId);
    if (!principal) {
      throw new Error(`Principal '${identity.clientId}' is not registered in the system`);
    }
    return principal;
  }

  throw new Error("Missing Cf-Access-Jwt-Assertion header");
}

export async function requireRequestPermission(
  env: Env,
  request: Request,
  requiredRole: Role
): Promise<Principal> {
  const principal = await authenticateRequest(env, request);
  if (!hasPermission(principal.role, requiredRole)) {
    throw new Error(
      `Principal '${principal.client_id}' has role '${principal.role}', but role '${requiredRole}' is required`
    );
  }
  return principal;
}

/**
 * Callable Agent methods do not receive the route request as an argument.
 * Resolve it from the Agents SDK context and fail closed if invoked without one.
 */
export async function requireCurrentAgentPermission(env: Env, requiredRole: Role): Promise<Principal> {
  const { getCurrentAgent } = await import("agents");
  const { request } = getCurrentAgent();
  if (!request) {
    throw new Error("Authenticated request context is required");
  }
  return requireRequestPermission(env, request, requiredRole);
}
