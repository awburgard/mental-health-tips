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
    slack_ts      TEXT                          -- Slack message id (ts); needed for delete
);

CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
CREATE INDEX IF NOT EXISTS idx_submissions_reviewed_at ON submissions(reviewed_at);
