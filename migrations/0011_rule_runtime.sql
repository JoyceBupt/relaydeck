CREATE TABLE rule_runtime_states (
    rule_id INTEGER PRIMARY KEY REFERENCES rules(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    active INTEGER NOT NULL CHECK(active IN(0,1)),
    observed_at INTEGER NOT NULL
);
