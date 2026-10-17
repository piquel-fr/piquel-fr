-- Tokens report how and when the session behind a grant authenticated: `acr`,
-- `amr` and `auth_time`, derived from the session. Codes and refresh families
-- keep the values from when the code was issued, so later re-authentication of
-- the session never changes what an existing grant reports (OIDC Core 12.2).

-- The class the client asked for with `acr_values`, if it named a known one.
ALTER TABLE authorization_requests ADD COLUMN target_acr TEXT;

-- `SessionAuthentication` as JSON: `acr`, `auth_time` and `amr`.
ALTER TABLE authorization_codes ADD COLUMN authentication JSONB;
ALTER TABLE refresh_token_families ADD COLUMN authentication JSONB;

-- Existing grants keep reporting their session's sign-in, as they did before: its
-- time and methods. A passkey confirmation may postdate the grant, so it is
-- ignored, and the class follows the sign-in method.
CREATE FUNCTION pg_temp.sign_in_authentication(s sessions) RETURNS JSONB LANGUAGE SQL AS $$
    SELECT jsonb_build_object(
        'acr', CASE WHEN s.authentication_methods ? 'passkey' THEN 'phr' ELSE 'urn:piquel:acr:social' END,
        'auth_time', to_jsonb(s.authenticated_at),
        'amr', (
            SELECT COALESCE(jsonb_agg(DISTINCT amr.value), '[]'::jsonb)
            FROM jsonb_array_elements_text(s.authentication_methods) AS method(name),
            LATERAL jsonb_array_elements_text(
                CASE method.name WHEN 'passkey' THEN '["pop", "mfa", "user"]' ELSE '["fed"]' END::jsonb
            ) AS amr(value)
        )
    )
$$;
UPDATE authorization_codes c
SET authentication = pg_temp.sign_in_authentication(s)
FROM sessions s
WHERE s.id = c.session_id;
UPDATE refresh_token_families f
SET authentication = pg_temp.sign_in_authentication(s)
FROM sessions s
WHERE s.id = f.session_id;

ALTER TABLE authorization_codes ALTER COLUMN authentication SET NOT NULL;
ALTER TABLE refresh_token_families ALTER COLUMN authentication SET NOT NULL;

-- A session is phishing-resistant exactly when it has a passkey confirmation, and
-- then lists passkeys among its methods. Passkey sessions from before 0003 have no
-- confirmation, though their sign-in was one, and confirmations made before this
-- migration did not record the method.
UPDATE sessions
SET passkey_confirmed_at = authenticated_at
WHERE passkey_confirmed_at IS NULL
AND authentication_methods ? 'passkey'
AND revoked_at IS NULL;
UPDATE sessions
SET authentication_methods = authentication_methods || '["passkey"]'
WHERE passkey_confirmed_at IS NOT NULL
AND NOT authentication_methods ? 'passkey';
