-- Contracts what earlier migrations kept for the release before them, which no
-- environment runs anymore: staging and production both run releases that
-- include the changes below.

-- Migration 0044 (#491) stopped ordering deliveries, but kept their ordering for
-- the release before it, which still inserted, claimed and listed deliveries by
-- it. Dropping the columns takes their UNIQUE and CHECK constraints with them.
DROP TABLE delivery_orderings;
ALTER TABLE deliveries DROP COLUMN ordering_key, DROP COLUMN ordinal;

-- Migration 0036 (#369) lists an account's history by (txid, sequence) through
-- domain_events_subject_order_idx, but kept the index by sequence alone for the
-- release before it, which still listed history that way.
DROP INDEX domain_events_subject_idx;

-- Migration 0041 (#439) defaulted a dashboard session's expiry for the release
-- before it, which inserted none. Auth now sets it on every sign-in, so a
-- session inserted without one is a bug, not a 12-hour session.
ALTER TABLE dashboard_sessions ALTER COLUMN expires_at DROP DEFAULT;
