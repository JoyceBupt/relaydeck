-- Public account IDs never recycle; runtime slots recycle only after confirmed stop.
CREATE TABLE runtime_slots (id INTEGER PRIMARY KEY CHECK(id BETWEEN 1 AND 11), revision INTEGER NOT NULL DEFAULT 0);
INSERT INTO runtime_slots(id) VALUES(1),(2),(3),(4),(5),(6),(7),(8),(9),(10),(11);
ALTER TABLE users ADD COLUMN runtime_slot INTEGER REFERENCES runtime_slots(id);
ALTER TABLE users ADD COLUMN subscription_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN subscription_started_at INTEGER;
ALTER TABLE users ADD COLUMN deletion_requested_at INTEGER;
UPDATE users SET runtime_slot=id,subscription_id=id,subscription_started_at=created_at,
 expires_at=CASE WHEN role='user' THEN COALESCE(expires_at,created_at+2592000) ELSE expires_at END;
CREATE UNIQUE INDEX users_runtime_slot ON users(COALESCE(runtime_slot,id));
UPDATE runtime_slots SET revision=COALESCE((SELECT desired_revision FROM users WHERE runtime_slot=runtime_slots.id),0);
CREATE TABLE identity_sequences (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT INTO identity_sequences VALUES('account',COALESCE((SELECT MAX(id) FROM users),0)),('subscription',COALESCE((SELECT MAX(subscription_id) FROM users),0));

INSERT INTO identity_sequences VALUES('rule',COALESCE((SELECT MAX(id) FROM rules),0));
