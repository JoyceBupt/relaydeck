-- Existing grants remain unlimited; subsequent accounts receive an explicit budget.
ALTER TABLE users ADD COLUMN traffic_limit_bytes INTEGER CHECK (traffic_limit_bytes IS NULL OR traffic_limit_bytes BETWEEN 1 AND 1000000000000000);
ALTER TABLE users ADD COLUMN traffic_mode TEXT NOT NULL DEFAULT 'both' CHECK (traffic_mode IN ('both','ingress','egress'));
ALTER TABLE users ADD COLUMN traffic_in_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN traffic_out_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN traffic_period_start INTEGER;
ALTER TABLE users ADD COLUMN traffic_reset_at INTEGER;
ALTER TABLE users ADD COLUMN traffic_blocked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN traffic_observed_at INTEGER;
ALTER TABLE users ADD COLUMN traffic_used_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN traffic_ready INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN traffic_error TEXT;
