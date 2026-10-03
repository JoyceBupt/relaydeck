CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    must_change_password INTEGER NOT NULL DEFAULT 1 CHECK (must_change_password IN (0, 1)),
    expires_at INTEGER,
    port_start INTEGER NOT NULL CHECK (port_start BETWEEN 1024 AND 65535),
    port_end INTEGER NOT NULL CHECK (port_end BETWEEN port_start AND 65535),
    max_rules INTEGER NOT NULL DEFAULT 0 CHECK (max_rules BETWEEN 0 AND 30),
    auth_version INTEGER NOT NULL DEFAULT 1,
    view_mode TEXT NOT NULL DEFAULT 'table' CHECK (view_mode IN ('table', 'cards')),
    desired_revision INTEGER NOT NULL DEFAULT 0,
    applied_revision INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    auth_version INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1024 AND 65535),
    target_host TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    target_port INTEGER NOT NULL CHECK (target_port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp', 'both')),
    source_cidrs TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
);
CREATE INDEX rules_owner ON rules(owner_id, deleted_at);

-- Reservations survive edits and soft deletion until an executor confirms the
-- owner's applied revision. HTTP requests cannot release a live runtime port.
CREATE TABLE port_leases (
    port INTEGER PRIMARY KEY CHECK (port BETWEEN 1024 AND 65535),
    owner_id INTEGER NOT NULL REFERENCES users(id),
    rule_id INTEGER NOT NULL REFERENCES rules(id),
    created_at INTEGER NOT NULL
);

CREATE TABLE apply_jobs (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    revision INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'failed')),
    created_at INTEGER NOT NULL,
    UNIQUE (owner_id, revision)
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY,
    actor_id INTEGER NOT NULL REFERENCES users(id),
    actor_username TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id INTEGER,
    created_at INTEGER NOT NULL
);
