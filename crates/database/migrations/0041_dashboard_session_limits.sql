-- A dashboard session ends after 30 minutes without a request, and 12 hours
-- after its sign-in however busy, so an unattended browser or a stolen cookie
-- stops working within a working day. Auth sets both on each sign-in, and
-- refreshes `last_used_at` on each request. The defaults serve the previous
-- release, which inserts neither, during a deploy.
ALTER TABLE dashboard_sessions
    ADD COLUMN last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '12 hours';

-- A session signed in more than 12 hours ago has ended already.
UPDATE dashboard_sessions SET expires_at = created_at + interval '12 hours';

-- Cleanup deletes the sessions that ended.
CREATE INDEX dashboard_sessions_expires_idx ON dashboard_sessions (expires_at);
