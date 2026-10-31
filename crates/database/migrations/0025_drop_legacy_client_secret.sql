-- Contracts what migration 0018 (#187) kept for the release before it, which no
-- environment runs anymore: every deployed release stores client secrets only in
-- oidc_client_secrets, and none reads or writes oidc_clients.client_secret_hash.
ALTER TABLE oidc_clients DROP COLUMN client_secret_hash;
