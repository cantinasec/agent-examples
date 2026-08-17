CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT INTO settings (key, value, updated_at)
VALUES ('paused', 'false', unixepoch() * 1000)
ON CONFLICT(key) DO NOTHING;
