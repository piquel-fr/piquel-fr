-- The overviews count events of a kind over the last hour and week, across
-- every account: the dashboard's failed and successful sign-ins and code
-- exchanges, against what an hour usually brings.
CREATE INDEX domain_events_kind_time_idx ON domain_events (kind, occurred_at);
