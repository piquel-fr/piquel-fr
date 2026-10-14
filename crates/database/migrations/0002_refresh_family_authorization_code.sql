-- Links each refresh family to the authorization code it was redeemed from, so
-- redeeming that code again revokes the family (RFC 6749 section 4.1.2).
-- Families created before this migration have no link. Cleanup keeps a redeemed
-- code while a family it produced can still refresh; purging it afterwards
-- clears the link rather than failing on it.
ALTER TABLE refresh_token_families
    ADD COLUMN authorization_code_id UUID REFERENCES authorization_codes(id) ON DELETE SET NULL;
-- Serves replay revocation, cleanup's live-family check and the ON DELETE SET
-- NULL lookup when codes are purged.
CREATE INDEX refresh_families_authorization_code_idx ON refresh_token_families (authorization_code_id);
-- Lets cleanup find redeemed codes past their grace period without a full scan.
CREATE INDEX authorization_codes_consumed_idx ON authorization_codes (consumed_at) WHERE consumed_at IS NOT NULL;
