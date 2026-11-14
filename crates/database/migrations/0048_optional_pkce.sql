-- A confidential client may leave PKCE out of an authorization request, as
-- RFC 9700 allows: it authenticates at the token endpoint. pkce_challenge is
-- NULL for such a request and the code it issues.
ALTER TABLE authorization_requests ALTER COLUMN pkce_challenge DROP NOT NULL;
ALTER TABLE authorization_codes ALTER COLUMN pkce_challenge DROP NOT NULL;
