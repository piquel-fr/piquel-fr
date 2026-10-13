-- Links each refresh family to the authorization code it was redeemed from, so
-- redeeming that code again revokes the family (RFC 6749 section 4.1.2).
-- Families created before this migration have no link. Cleanup keeps redeemed
-- codes for a day, then purging one clears the link rather than failing on it.
ALTER TABLE refresh_token_families
    ADD COLUMN authorization_code_id UUID REFERENCES authorization_codes(id) ON DELETE SET NULL;
-- Serves replay revocation and the ON DELETE SET NULL lookup when codes are purged.
CREATE INDEX refresh_families_authorization_code_idx ON refresh_token_families (authorization_code_id);
