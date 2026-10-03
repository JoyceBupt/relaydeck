ALTER TABLE users ADD COLUMN mfa_failures INTEGER NOT NULL DEFAULT 0 CHECK (mfa_failures >= 0);
ALTER TABLE users ADD COLUMN mfa_locked_until INTEGER NOT NULL DEFAULT 0 CHECK (mfa_locked_until >= 0);
ALTER TABLE audit_events ADD COLUMN resource_kind TEXT;
ALTER TABLE audit_events ADD COLUMN resource_name TEXT;
ALTER TABLE audit_events ADD COLUMN resource_port INTEGER;
-- Existing events can only recover the last stored name. New events snapshot it.
UPDATE audit_events SET resource_kind=CASE WHEN resource_id IS NULL THEN NULL WHEN action LIKE 'rule!_%' ESCAPE '!' THEN 'rule' ELSE 'user' END;
UPDATE audit_events SET resource_name=(SELECT name FROM rules WHERE id=resource_id),resource_port=(SELECT listen_port FROM rules WHERE id=resource_id) WHERE resource_kind='rule';
UPDATE audit_events SET resource_name=(SELECT username FROM users WHERE id=resource_id) WHERE resource_kind='user';
