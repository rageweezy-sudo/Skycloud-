CREATE TABLE requests (
    id TEXT PRIMARY KEY NOT NULL,
    service_account_id INTEGER NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('access', 'delete', 'follow_up')),
    jurisdiction TEXT NOT NULL CHECK (jurisdiction IN ('GDPR', 'UK GDPR', 'CCPA')),
    template_version INTEGER NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('email', 'portal')),
    destination TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'uncertain', 'failed', 'portal_pending', 'reply', 'fulfilled')),
    created_at TEXT NOT NULL,
    sent_at TEXT,
    message_id TEXT,
    thread_id TEXT,
    adjusted_due TEXT,
    parent_id TEXT REFERENCES requests(id)
);

CREATE INDEX requests_service_time ON requests(service_account_id, created_at);
CREATE INDEX requests_uncertain ON requests(service_account_id, kind, state);

CREATE TABLE request_events (
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    item_id TEXT,
    UNIQUE (request_id, kind, item_id)
);
