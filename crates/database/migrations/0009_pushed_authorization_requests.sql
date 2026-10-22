-- Pushed authorization requests (RFC 9126). A client stores its request through
-- the back channel, then the browser claims it once with the returned
-- request_uri. A pushed row is not a pending authorization until it is claimed:
-- claiming replaces its secret, so the request_uri itself never continues one.
-- The previous release does not know the flag, and would take an unclaimed
-- pushed request_uri as a transaction; it only learns one from a client that
-- already holds it, so this needs no extra step during the deploy.
ALTER TABLE authorization_requests
    ADD COLUMN pushed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN claimed_at TIMESTAMPTZ,
    -- `prompt=none`, kept so a pushed request answers silently when claimed.
    ADD COLUMN prompt_none BOOLEAN NOT NULL DEFAULT FALSE;

-- Clients that may start an authorization only from a pushed request.
ALTER TABLE oidc_clients
    ADD COLUMN require_pushed_authorization_requests BOOLEAN NOT NULL DEFAULT FALSE;
