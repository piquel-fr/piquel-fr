-- A rotated refresh token names the token it replaced, so a public client that
-- presents that token again moments later, from a second tab or as a retry, is
-- answered with this successor instead of having its family revoked as a
-- replay. A token has at most one successor.
ALTER TABLE refresh_tokens
    ADD COLUMN predecessor_id UUID UNIQUE REFERENCES refresh_tokens(id) ON DELETE SET NULL;
