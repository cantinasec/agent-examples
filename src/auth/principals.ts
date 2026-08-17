// ponytail: numeric role levels for simple <= comparisons

export type Role = "read" | "scan" | "admin";

const ROLE_HIERARCHY: Record<Role, number> = {
  read: 1,
  scan: 2,
  admin: 3,
};

export interface Principal {
  client_id: string;
  name: string;
  role: Role;
  created_at: number;
}

export function hasPermission(principalRole: Role, requiredRole: Role): boolean {
  return ROLE_HIERARCHY[principalRole] >= ROLE_HIERARCHY[requiredRole];
}

export async function getPrincipal(db: D1Database, clientId: string): Promise<Principal | null> {
  return await db
    .prepare("SELECT client_id, name, role, created_at FROM principals WHERE client_id = ?")
    .bind(clientId)
    .first<Principal>();
}

/**
 * Register a principal if not already present (idempotent upsert).
 */
export async function ensurePrincipal(
  db: D1Database,
  clientId: string,
  name: string,
  role: Role = "read"
): Promise<Principal> {
  const existing = await getPrincipal(db, clientId);
  if (existing) {
    return existing;
  }

  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO principals (client_id, name, role, created_at)
       VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT(client_id) DO NOTHING`
    )
    .bind(clientId, name, role, now)
    .run();

  return (await getPrincipal(db, clientId)) || {
    client_id: clientId,
    name,
    role,
    created_at: now,
  };
}

export async function requirePerm(
  db: D1Database,
  clientId: string,
  requiredRole: Role
): Promise<Principal> {
  const principal = await getPrincipal(db, clientId);
  if (!principal) {
    throw new Error(`Principal '${clientId}' is not registered in the system`);
  }

  if (!hasPermission(principal.role, requiredRole)) {
    throw new Error(
      `Principal '${clientId}' has role '${principal.role}', but role '${requiredRole}' is required`
    );
  }

  return principal;
}
