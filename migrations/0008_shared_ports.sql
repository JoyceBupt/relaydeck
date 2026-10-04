-- Keep legacy grant columns for rollback compatibility. Every account now
-- shares the high-port pool; max_rules is the quota of distinct listening ports
-- (one port per rule, including disabled rules). Preserve existing quotas.
UPDATE users SET port_start=1024, port_end=65535, desired_revision=desired_revision+1;
INSERT INTO apply_jobs(owner_id,revision,created_at)
SELECT id,desired_revision,unixepoch() FROM users;
