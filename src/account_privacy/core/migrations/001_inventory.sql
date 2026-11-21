CREATE TABLE accounts (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT NOT NULL CHECK (length(email) > 0),
    provider TEXT NOT NULL CHECK (provider IN ('gmail', 'graph', 'imap', 'local')),
    credential_ref TEXT
);

CREATE TABLE services (
    domain TEXT PRIMARY KEY NOT NULL
);

CREATE TABLE service_accounts (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL REFERENCES services(domain) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    username TEXT NOT NULL DEFAULT '',
    origin TEXT,
    review TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (review IN ('unreviewed', 'confirmed', 'dismissed')),
    UNIQUE (domain, account_id, username)
);

CREATE TABLE evidence (
    service_account_id INTEGER NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (length(source) > 0),
    item_id TEXT NOT NULL CHECK (length(item_id) > 0),
    category TEXT NOT NULL CHECK (category IN ('import', 'signup', 'reset', 'receipt', 'unsubscribe')),
    observed_at TEXT,
    ambiguous INTEGER NOT NULL DEFAULT 0 CHECK (ambiguous IN (0, 1)),
    PRIMARY KEY (service_account_id, source, item_id, category)
) WITHOUT ROWID;

CREATE TABLE scan_runs (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    source TEXT NOT NULL CHECK (length(source) > 0),
    selection TEXT NOT NULL
);

CREATE TABLE scan_checkpoints (
    run_id TEXT PRIMARY KEY NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    cursor TEXT,
    revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    processed INTEGER NOT NULL DEFAULT 0 CHECK (processed >= 0),
    complete INTEGER NOT NULL DEFAULT 0 CHECK (complete IN (0, 1))
);

CREATE INDEX scan_runs_account_source ON scan_runs(account_id, source);
CREATE INDEX service_accounts_account ON service_accounts(account_id);
