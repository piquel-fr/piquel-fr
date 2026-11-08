-- What the admin dashboard keeps of the changes its forms post.
--
-- A draft is a posted form that needed a newer passkey confirmation, or a new
-- sign-in, which sends the browser through auth's handoff page: its page shows it
-- again once, the next time it opens, so what was typed, such as a reason, is
-- not lost. It holds
-- what the administrator typed, which may name people, so it lives minutes.
CREATE TABLE dashboard_drafts (
    -- The administrator who posted it, the only one it is shown to.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The dashboard page it was posted to, the only one that shows it.
    path TEXT NOT NULL,
    -- The form, as JSON.
    form TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    -- One per administrator and page: a later one replaces it.
    PRIMARY KEY (user_id, path)
);
CREATE INDEX dashboard_drafts_expires_idx ON dashboard_drafts (expires_at);

-- A change the dashboard made or is making, by the digest of its administrator,
-- page, query and form, for a few seconds: the same form posted again meanwhile,
-- such as by a double click, changes nothing. One being made is `made` once it
-- is; one refused is deleted, so posting it again tries again.
CREATE TABLE dashboard_submissions (
    digest BYTEA PRIMARY KEY,
    made BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX dashboard_submissions_expires_idx ON dashboard_submissions (expires_at);
