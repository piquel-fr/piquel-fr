-- The sealer verifies what it builds on, and the chain can grow new fields (#251).
--
-- Each sealed event records the format of the canonical event its hash covers,
-- so a later format can add fields without breaking the hashes of events sealed
-- before it. Format 1 is the original, untagged one; every event sealed so far
-- is in it. The default keeps the previous release's seals in format 1, which is
-- what it hashes. Only known formats are allowed, so a forged one is reported
-- where it is rather than taken for a newer release's; the release that adds a
-- format widens the check.
ALTER TABLE domain_events
    ADD COLUMN chain_format SMALLINT NOT NULL DEFAULT 1 CHECK (chain_format IN (1, 2));

-- Histories list events in the order they are sealed in, (txid, sequence), which
-- verification checks against the chain, rather than by sequence alone, which the
-- chain does not cover.
--
-- PENDING CONTRACT: domain_events_subject_idx stays while a deployed release
-- still lists an account's history by sequence; drop it once none does.
CREATE INDEX domain_events_subject_order_idx
    ON domain_events (subject_user_id, txid DESC, sequence DESC);
