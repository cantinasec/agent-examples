// ponytail: deterministic finding IDs and clean diff-based lifecycle

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingState = "open" | "fixed" | "accepted_risk" | "false_positive";

export interface Finding {
  id: string;
  target_host: string;
  detector: string;
  severity: Severity;
  state: FindingState;
  title: string;
  description: string;
  evidence_json: string;
  r2_screenshot_key: string | null;
  first_seen_at: number;
  last_seen_at: number;
  resolved_at: number | null;
}

export interface FindingInput {
  detector: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: Record<string, any>;
  r2_screenshot_key?: string | null;
}

/**
 * Creates a deterministic finding ID based on host, detector, and title.
 */
export function generateFindingId(host: string, detector: string, title: string): string {
  const normalizedTitle = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `${host}:${detector}:${normalizedTitle}`;
}

/**
 * Upserts findings for a specific target and detector.
 * Performs diffing: any existing open findings for this host & detector not present in the new batch are marked fixed.
 */
export async function syncDetectorFindings(
  db: D1Database,
  host: string,
  detector: string,
  newFindings: FindingInput[]
): Promise<{ added: number; updated: number; resolved: number }> {
  const now = Date.now();

  const existingRows = await db
    .prepare("SELECT id, state FROM findings WHERE target_host = ? AND detector = ?")
    .bind(host, detector)
    .all<{ id: string; state: FindingState }>();

  const existingMap = new Map((existingRows.results || []).map((r) => [r.id, r.state]));
  const seenIds = new Set<string>();

  const statements: D1PreparedStatement[] = [];
  let added = 0;
  let updated = 0;

  for (const input of newFindings) {
    const id = generateFindingId(host, detector, input.title);
    seenIds.add(id);

    const evidenceStr = JSON.stringify(input.evidence);
    const screenshotKey = input.r2_screenshot_key ?? null;
    const currentState = existingMap.get(id);

    if (!currentState) {
      statements.push(
        db
          .prepare(
            `INSERT INTO findings (id, target_host, detector, severity, state, title, description, evidence_json, r2_screenshot_key, first_seen_at, last_seen_at, resolved_at)
             VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?9, ?9, NULL)`
          )
          .bind(id, host, detector, input.severity, input.title, input.description, evidenceStr, screenshotKey, now)
      );
      added++;
    } else {
      const newState = currentState === "fixed" ? "open" : currentState;
      statements.push(
        db
          .prepare(
            `UPDATE findings
             SET severity = ?2,
                 state = ?3,
                 description = ?4,
                 evidence_json = ?5,
                 r2_screenshot_key = COALESCE(?6, r2_screenshot_key),
                 last_seen_at = ?7,
                 resolved_at = CASE WHEN ?3 = 'open' THEN NULL ELSE resolved_at END
             WHERE id = ?1`
          )
          .bind(id, input.severity, newState, input.description, evidenceStr, screenshotKey, now)
      );
      updated++;
    }
  }

  let resolved = 0;
  for (const [id, state] of existingMap.entries()) {
    if (!seenIds.has(id) && state === "open") {
      statements.push(
        db.prepare("UPDATE findings SET state = 'fixed', resolved_at = ? WHERE id = ?").bind(now, id)
      );
      resolved++;
    }
  }

  if (statements.length > 0) {
    await db.batch(statements);
  }

  return { added, updated, resolved };
}

export interface ListFindingsFilter {
  host?: string;
  detector?: string;
  severity?: Severity;
  state?: FindingState;
  since?: number;
}

export async function listFindings(db: D1Database, filter?: ListFindingsFilter): Promise<Finding[]> {
  let query = "SELECT id, target_host, detector, severity, state, title, description, evidence_json, r2_screenshot_key, first_seen_at, last_seen_at, resolved_at FROM findings WHERE 1=1";
  const params: unknown[] = [];

  if (filter?.host) {
    query += " AND target_host = ?";
    params.push(filter.host);
  }
  if (filter?.detector) {
    query += " AND detector = ?";
    params.push(filter.detector);
  }
  if (filter?.severity) {
    query += " AND severity = ?";
    params.push(filter.severity);
  }
  if (filter?.state) {
    query += " AND state = ?";
    params.push(filter.state);
  }
  if (filter?.since) {
    query += " AND last_seen_at >= ?";
    params.push(filter.since);
  }

  query += " ORDER BY last_seen_at DESC";
  const stmt = db.prepare(query);
  const res = await (params.length ? stmt.bind(...params) : stmt).all<Finding>();
  return res.results || [];
}

export async function getFinding(db: D1Database, id: string): Promise<Finding | null> {
  return await db
    .prepare("SELECT id, target_host, detector, severity, state, title, description, evidence_json, r2_screenshot_key, first_seen_at, last_seen_at, resolved_at FROM findings WHERE id = ?")
    .bind(id)
    .first<Finding>();
}

export async function triageFinding(
  db: D1Database,
  id: string,
  state: FindingState,
  notes?: string
): Promise<Finding> {
  const existing = await getFinding(db, id);
  if (!existing) {
    throw new Error(`Finding '${id}' not found`);
  }

  const now = Date.now();
  const resolvedAt = state === "open" ? null : now;

  let evidence = {};
  try {
    evidence = JSON.parse(existing.evidence_json);
  } catch {
    // Falls through with empty evidence when existing JSON is corrupt.
  }

  if (notes) {
    (evidence as Record<string, unknown>).triage_notes = notes;
  }

  await db
    .prepare(
      "UPDATE findings SET state = ?, resolved_at = ?, evidence_json = ? WHERE id = ?"
    )
    .bind(state, resolvedAt, JSON.stringify(evidence), id)
    .run();

  return {
    ...existing,
    state,
    resolved_at: resolvedAt,
    evidence_json: JSON.stringify(evidence),
  };
}
