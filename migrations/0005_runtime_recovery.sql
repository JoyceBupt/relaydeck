ALTER TABLE runtime_states ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runtime_states ADD COLUMN retry_at INTEGER;
