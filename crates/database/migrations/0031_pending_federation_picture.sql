-- The profile picture URL a provider reported with its evidence, so a social
-- signup can import it once the account exists. Nullable: the previous release
-- inserts evidence without one, and its signups import nothing.
ALTER TABLE pending_federation
    ADD COLUMN picture_url TEXT CHECK (char_length(picture_url) <= 2048);
