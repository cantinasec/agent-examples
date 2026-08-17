-- Scope targets registry
CREATE TABLE IF NOT EXISTS targets (
    host TEXT PRIMARY KEY NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', -- 'active' | 'retired'
    added_by_principal TEXT NOT NULL,
    authorization_ref TEXT NOT NULL,
    added_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_targets_status_expires ON targets(status, expires_at);

-- Principals for role-based authorization
CREATE TABLE IF NOT EXISTS principals (
    client_id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'read', -- 'read' | 'scan' | 'admin'
    created_at INTEGER NOT NULL
);

-- Findings registry
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY NOT NULL,
    target_host TEXT NOT NULL,
    detector TEXT NOT NULL,
    severity TEXT NOT NULL, -- 'critical' | 'high' | 'medium' | 'low' | 'info'
    state TEXT NOT NULL DEFAULT 'open', -- 'open' | 'fixed' | 'accepted_risk' | 'false_positive'
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    r2_screenshot_key TEXT,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    resolved_at INTEGER,
    FOREIGN KEY(target_host) REFERENCES targets(host)
);

CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(target_host);
CREATE INDEX IF NOT EXISTS idx_findings_state ON findings(state);
CREATE INDEX IF NOT EXISTS idx_findings_detector ON findings(detector);

-- Scans history
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY NOT NULL,
    target_host TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'running' | 'completed' | 'failed'
    started_at INTEGER NOT NULL,
    completed_at INTEGER,
    findings_count INTEGER DEFAULT 0,
    error TEXT,
    FOREIGN KEY(target_host) REFERENCES targets(host)
);

CREATE INDEX IF NOT EXISTS idx_scans_host ON scans(target_host);
