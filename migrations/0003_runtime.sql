CREATE TABLE runtime_states (
    owner_id INTEGER PRIMARY KEY REFERENCES users(id),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    status TEXT NOT NULL CHECK(status IN ('active', 'stopped', 'failed')),
    last_error TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE executor_status (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    last_seen INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('running', 'failed'))
);
