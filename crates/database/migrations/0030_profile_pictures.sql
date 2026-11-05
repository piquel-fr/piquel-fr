-- Each account's profile picture: the JPEG auth re-encoded from the upload, never
-- the uploaded bytes. `id` names it in its URL and is new on every upload, so the
-- image at a URL never changes and caches keep it for good; replacing or removing
-- the picture stops that URL at once.
--
-- The account's purge removes it through the cascade, whichever release purges:
-- the previous release's purge does not know this table.
CREATE TABLE profile_pictures (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    id UUID NOT NULL UNIQUE,
    image BYTEA NOT NULL CHECK (octet_length(image) BETWEEN 1 AND 131072),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- JPEG does not compress further: keep images out of line without trying.
ALTER TABLE profile_pictures ALTER COLUMN image SET STORAGE EXTERNAL;
