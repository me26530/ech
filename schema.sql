CREATE TABLE IF NOT EXISTS do_instances (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  target TEXT
);

CREATE INDEX IF NOT EXISTS idx_do_instances_created_at
ON do_instances(created_at);
