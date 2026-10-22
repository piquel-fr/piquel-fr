-- oidc_consents becomes the one record of "this user uses this app" (#80): every
-- successful authorization writes it, trusted clients included, and the user can
-- revoke it from settings.
--
-- Revocation sets revoked_at and increments generation. Codes and refresh families
-- record the generation they were issued under, and code exchange and refresh
-- rotation accept them only while their grant is unrevoked at that generation. A
-- later authorization clears revoked_at but keeps the new generation, so nothing
-- issued before the revocation works again.
ALTER TABLE oidc_consents
    -- Some scope was granted without the consent screen, to a trusted client. Such
    -- a row never lets an untrusted client skip it.
    ADD COLUMN implicit BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Moved by code exchange and refresh rotation.
    ADD COLUMN last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN revoked_at TIMESTAMPTZ;

-- The previous release inserts codes and families without a generation, and never
-- revokes a grant, so the first generation is right for them.
ALTER TABLE authorization_codes ADD COLUMN grant_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE refresh_token_families ADD COLUMN grant_generation BIGINT NOT NULL DEFAULT 1;

-- Trusted clients never wrote a row, so their live codes and families get an
-- implicit one; existing consent covers the others. A code or family the previous
-- release issues to a trusted client during the deploy still has none, and is
-- rejected: that app signs in again.
INSERT INTO oidc_consents (user_id, client_id, audience, scopes, implicit, granted_at, last_used_at)
SELECT g.user_id, g.client_id, g.audience, jsonb_agg(DISTINCT s.scope), TRUE,
    min(g.created_at), max(g.created_at)
FROM (
    SELECT user_id, client_id, audience, scopes, created_at
    FROM refresh_token_families
    WHERE revoked_at IS NULL
    UNION ALL
    SELECT user_id, client_id, audience, scopes, created_at
    FROM authorization_codes
    WHERE consumed_at IS NULL
    AND expires_at > now()
) g
CROSS JOIN LATERAL jsonb_array_elements(g.scopes) AS s(scope)
GROUP BY g.user_id, g.client_id, g.audience
ON CONFLICT (user_id, client_id, audience) DO NOTHING;
