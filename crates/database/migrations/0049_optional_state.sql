-- An authorization request's state is optional (RFC 6749 §4.1.1): client_state
-- is NULL when the client sent none, so no empty state goes back to it.
ALTER TABLE authorization_requests ALTER COLUMN client_state DROP NOT NULL;
