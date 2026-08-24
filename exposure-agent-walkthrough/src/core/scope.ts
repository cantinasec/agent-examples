// ponytail: exact hostname matching and single assertInScope chokepoint

export interface TargetRow {
  host: string;
  status: "active" | "retired";
  added_by_principal: string;
  authorization_ref: string;
  added_at: number;
  expires_at: number;
  notes: string | null;
}

export interface PutTargetInput {
  host: string;
  notes?: string;
  expiryDays?: number;
}

/**
 * Normalizes a URL or hostname to a clean lowercase FQDN without port or path.
 * Strict parsing prevents domain suffix hijacking (e.g. attacker.invalid?host=example.com).
 */
export function normalizeHost(urlOrHost: string): string {
  const trimmed = urlOrHost.trim();
  if (!trimmed) {
    throw new Error("Invalid empty host");
  }

  let hostname = trimmed;
  if (trimmed.includes("://")) {
    try {
      const parsed = new URL(trimmed);
      hostname = parsed.hostname;
    } catch {
      throw new Error(`Invalid URL format: ${urlOrHost}`);
    }
  } else {
    try {
      const parsed = new URL(`http://${trimmed}`);
      hostname = parsed.hostname;
    } catch {
      throw new Error(`Invalid host format: ${urlOrHost}`);
    }
  }

  hostname = hostname.replace(/\.$/, "").toLowerCase();

  if (!hostname || hostname.includes("/") || hostname.includes("@") || hostname.includes(":")) {
    throw new Error(`Invalid parsed hostname: ${hostname}`);
  }

  return hostname;
}

/**
 * Single chokepoint for all outbound requests in the system.
 * Verifies that the host exists in the D1 targets table with status='active' AND expires_at > now.
 */
export async function assertInScope(urlOrHost: string, db: D1Database): Promise<string> {
  const host = normalizeHost(urlOrHost);
  const now = Date.now();

  const row = await db
    .prepare("SELECT host, status, expires_at FROM targets WHERE host = ?")
    .bind(host)
    .first<{ host: string; status: string; expires_at: number }>();

  if (!row) {
    throw new Error(`Host '${host}' is not in the scope registry`);
  }

  if (row.status !== "active") {
    throw new Error(`Host '${host}' is retired from scope`);
  }

  if (row.expires_at <= now) {
    throw new Error(`Host '${host}' scope attestation expired at ${new Date(row.expires_at).toISOString()}`);
  }

  return host;
}

/**
 * Atomically replaces the whole scope set.
 * Existing active hosts omitted from the new set are marked 'retired', preserving finding history.
 */
export async function putTargets(
  db: D1Database,
  principal: string,
  newTargets: PutTargetInput[],
  authRef: string,
  defaultExpiryDays = 7,
  maxExpiryDays = 30
): Promise<{ added: number; retired: number; totalActive: number }> {
  if (!authRef || authRef.trim() === "") {
    throw new Error("authorization_ref is required for scope modification");
  }

  const now = Date.now();
  const normalizedNewHosts = new Map<string, PutTargetInput>();

  for (const item of newTargets) {
    const host = normalizeHost(item.host);
    const expiryDays = item.expiryDays ?? defaultExpiryDays;
    if (expiryDays <= 0 || expiryDays > maxExpiryDays) {
      throw new Error(`expiryDays for ${host} must be between 1 and ${maxExpiryDays}`);
    }
    normalizedNewHosts.set(host, { ...item, host, expiryDays });
  }

  const currentActiveResult = await db
    .prepare("SELECT host FROM targets WHERE status = 'active'")
    .all<{ host: string }>();

  const currentActiveHosts = new Set((currentActiveResult.results || []).map((r) => r.host));
  const statements: D1PreparedStatement[] = [];

  let retiredCount = 0;
  for (const activeHost of currentActiveHosts) {
    if (!normalizedNewHosts.has(activeHost)) {
      statements.push(
        db.prepare("UPDATE targets SET status = 'retired' WHERE host = ?").bind(activeHost)
      );
      retiredCount++;
    }
  }

  let addedCount = 0;
  for (const [host, item] of normalizedNewHosts.entries()) {
    const expiresAt = now + (item.expiryDays ?? defaultExpiryDays) * 86400 * 1000;
    statements.push(
      db
        .prepare(
          `INSERT INTO targets (host, status, added_by_principal, authorization_ref, added_at, expires_at, notes)
           VALUES (?1, 'active', ?2, ?3, ?4, ?5, ?6)
           ON CONFLICT(host) DO UPDATE SET
             status = 'active',
             added_by_principal = ?2,
             authorization_ref = ?3,
             added_at = ?4,
             expires_at = ?5,
             notes = ?6`
        )
        .bind(host, principal, authRef, now, expiresAt, item.notes ?? null)
    );
    addedCount++;
  }

  if (statements.length > 0) {
    await db.batch(statements);
  }

  return {
    added: addedCount,
    retired: retiredCount,
    totalActive: normalizedNewHosts.size,
  };
}

/**
 * Adds or reactivates a single target in the scope registry.
 */
export async function addTarget(
  db: D1Database,
  principal: string,
  input: PutTargetInput,
  authRef: string,
  defaultExpiryDays = 7,
  maxExpiryDays = 30
): Promise<TargetRow> {
  if (!authRef || authRef.trim() === "") {
    throw new Error("authorization_ref is required for scope modification");
  }

  const host = normalizeHost(input.host);
  const expiryDays = input.expiryDays ?? defaultExpiryDays;
  if (expiryDays <= 0 || expiryDays > maxExpiryDays) {
    throw new Error(`expiryDays must be between 1 and ${maxExpiryDays}`);
  }

  const now = Date.now();
  const expiresAt = now + expiryDays * 86400 * 1000;
  const notes = input.notes ?? null;

  await db
    .prepare(
      `INSERT INTO targets (host, status, added_by_principal, authorization_ref, added_at, expires_at, notes)
       VALUES (?1, 'active', ?2, ?3, ?4, ?5, ?6)
       ON CONFLICT(host) DO UPDATE SET
         status = 'active',
         added_by_principal = ?2,
         authorization_ref = ?3,
         added_at = ?4,
         expires_at = ?5,
         notes = ?6`
    )
    .bind(host, principal, authRef, now, expiresAt, notes)
    .run();

  return {
    host,
    status: "active",
    added_by_principal: principal,
    authorization_ref: authRef,
    added_at: now,
    expires_at: expiresAt,
    notes,
  };
}

/**
 * Retires a single target from active scope without deleting finding history.
 */
export async function removeTarget(db: D1Database, urlOrHost: string): Promise<boolean> {
  const host = normalizeHost(urlOrHost);
  const res = await db.prepare("UPDATE targets SET status = 'retired' WHERE host = ?").bind(host).run();
  return (res.meta.changes ?? 0) > 0;
}

export async function listTargets(
  db: D1Database,
  filter?: { status?: "active" | "retired"; includeExpired?: boolean }
): Promise<TargetRow[]> {
  let query = "SELECT host, status, added_by_principal, authorization_ref, added_at, expires_at, notes FROM targets WHERE 1=1";
  const params: unknown[] = [];

  if (filter?.status) {
    query += " AND status = ?";
    params.push(filter.status);
  }

  if (!filter?.includeExpired) {
    query += " AND expires_at > ?";
    params.push(Date.now());
  }

  query += " ORDER BY host ASC";
  const stmt = db.prepare(query);
  const res = await (params.length ? stmt.bind(...params) : stmt).all<TargetRow>();
  return res.results || [];
}

export async function isPaused(db: D1Database): Promise<boolean> {
  const row = await db.prepare("SELECT value FROM settings WHERE key = 'paused'").first<{ value: string }>();
  return row?.value === "true";
}

/**
 * Periodic cleanup that marks expired targets as retired.
 */
export async function retireExpiredTargets(db: D1Database): Promise<number> {
  const now = Date.now();
  const res = await db
    .prepare("UPDATE targets SET status = 'retired' WHERE status = 'active' AND expires_at <= ?")
    .bind(now)
    .run();
  return res.meta.changes ?? 0;
}
