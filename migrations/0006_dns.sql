ALTER TABLE rules ADD COLUMN dns_checked_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rules ADD COLUMN dns_resolved_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rules ADD COLUMN dns_error TEXT;
UPDATE rules SET dns_checked_at=updated_at,dns_resolved_at=updated_at;
