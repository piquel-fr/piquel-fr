-- A change the dashboard made or is making, by the digest of its administrator,
-- page, query and form, for a few seconds: the same form posted again meanwhile,
-- such as by a double click, changes nothing. One being made is `made` once it
-- is; one refused is deleted, so posting it again tries again.
CREATE TABLE dashboard_submissions (
    digest BYTEA PRIMARY KEY,
    -- The administrator who posted it.
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- This claim's own, so a request whose claim expired and was taken by a
    -- repeat cannot mark or release the repeat's.
    token UUID NOT NULL,
    made BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX dashboard_submissions_expires_idx ON dashboard_submissions (expires_at);
