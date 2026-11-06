-- The audit page shows the newest audit chain verification, in recording order:
-- by `sequence`, since a clock stepped back could date a newer one earlier. The
-- index holds only verifications, so finding the newest reads one entry however
-- long the history, and whether or not there is one.
CREATE INDEX domain_events_audit_verifications_idx ON domain_events (sequence)
WHERE kind = 'audit_chain_verified';
