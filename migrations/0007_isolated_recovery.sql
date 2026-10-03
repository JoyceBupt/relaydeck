ALTER TABLE runtime_states ADD COLUMN healthy_since INTEGER;
ALTER TABLE rules ADD COLUMN dns_blocked INTEGER NOT NULL DEFAULT 0 CHECK(dns_blocked IN (0,1));
-- Restore the user's desired state for rules stopped by the old DNS worker.
UPDATE rules SET enabled=1,dns_blocked=1 WHERE enabled=0 AND dns_error IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE authentication_failures (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    bucket INTEGER NOT NULL,
    count INTEGER NOT NULL CHECK(count>0),
    last_seen INTEGER NOT NULL,
    UNIQUE(user_id,action,bucket)
);
INSERT INTO authentication_failures(user_id,username,action,bucket,count,last_seen)
SELECT actor_id,actor_username,action,created_at/3600,COUNT(*),MAX(created_at)
FROM audit_events WHERE action IN ('login_failed','login_mfa_failed','mfa_confirmation_failed','mfa_disable_failed')
GROUP BY actor_id,action,created_at/3600;

CREATE TABLE audit_events_new (
    id INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES users(id),
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id INTEGER,
    created_at INTEGER NOT NULL,
    resource_kind TEXT,
    resource_name TEXT,
    resource_port INTEGER
);
INSERT INTO audit_events_new SELECT * FROM audit_events
WHERE action NOT IN ('login_failed','login_mfa_failed','mfa_confirmation_failed','mfa_disable_failed');
DROP TABLE audit_events;
ALTER TABLE audit_events_new RENAME TO audit_events;
DELETE FROM authentication_failures WHERE id IN (SELECT id FROM authentication_failures ORDER BY last_seen DESC,id DESC LIMIT -1 OFFSET 1000);
