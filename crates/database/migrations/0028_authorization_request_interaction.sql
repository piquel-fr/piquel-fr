-- An authorization request's `prompt` becomes one value: `prompt=none` excludes
-- `login` and `consent`, which three flags could not say. The old release reads
-- and writes the flags, so its replicas fail authorizations until they are
-- replaced, as after migration 0021; requests live for minutes, so keeping both
-- shapes in sync for a release would buy little.
ALTER TABLE authorization_requests
    ADD COLUMN interaction TEXT NOT NULL DEFAULT 'as_needed'
        CHECK (interaction IN ('as_needed', 'login', 'consent', 'login_consent', 'none'));

UPDATE authorization_requests SET interaction = CASE
    WHEN prompt_none THEN 'none'
    WHEN force_login AND force_consent THEN 'login_consent'
    WHEN force_login THEN 'login'
    WHEN force_consent THEN 'consent'
    ELSE 'as_needed'
END;

ALTER TABLE authorization_requests
    ALTER COLUMN interaction DROP DEFAULT,
    DROP COLUMN force_login,
    DROP COLUMN force_consent,
    DROP COLUMN prompt_none;
