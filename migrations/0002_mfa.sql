ALTER TABLE users ADD COLUMN mfa_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_pending_secret TEXT;
ALTER TABLE users ADD COLUMN mfa_pending_at INTEGER CHECK (mfa_pending_at IS NULL OR mfa_pending_at >= 0);
ALTER TABLE users ADD COLUMN mfa_last_step INTEGER CHECK (mfa_last_step IS NULL OR mfa_last_step >= 0);

CREATE TABLE mfa_recovery_codes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL CHECK (length(code_hash) = 64),
    used_at INTEGER,
    PRIMARY KEY (user_id, code_hash)
);
