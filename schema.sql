-- Submissions table. Columns are intentionally minimal:
-- nothing here can identify a submitter.
CREATE TABLE IF NOT EXISTS submissions (
    id            TEXT PRIMARY KEY,             -- random UUIDv4, not sequential
    content       TEXT NOT NULL,                -- the tip text, plain text only
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied
    created_at    INTEGER NOT NULL,             -- unix seconds, ROUNDED TO THE HOUR
    reviewed_at   INTEGER,                      -- unix seconds, rounded to the hour
    deny_reason   TEXT,                         -- optional reviewer note (denied only)
    slack_posted  INTEGER NOT NULL DEFAULT 0,   -- 0/1; only set after successful post
    slack_ts      TEXT,                         -- Slack message id (ts); needed for delete
    flagged       INTEGER NOT NULL DEFAULT 0    -- 0/1; pre-submission moderation flag
);

CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_reviewed_at ON submissions(reviewed_at);

-- Outstanding one-time password-reset tokens. We store only the SHA-256
-- hash of the token, never the token itself, so a DB read can't be used
-- to reset the admin password.
CREATE TABLE IF NOT EXISTS password_resets (
    token_hash  TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0
);

-- The currently active admin password (PBKDF2-SHA256). At most one row.
-- If absent, admin login falls back to the ADMIN_PASSWORD env var. Once a
-- row exists here, the env var is ignored entirely.
CREATE TABLE IF NOT EXISTS admin_credentials (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    updated_at    INTEGER NOT NULL
);
