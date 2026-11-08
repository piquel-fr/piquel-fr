-- What administrators post on an alert while they handle it: where its handling
-- stands. The first acknowledges the alert, which then needs no attention while
-- its condition holds as it says. The author is the administrator or operator, as
-- an event's actor. Each update records an `alert_updated` event, `event_id`,
-- whose reason holds its note: the note is personal data, deleted with the
-- event's after 90 days or when its author's account is purged. No foreign key
-- holds `event_id`, since pruning the audit chain deletes events, and the update
-- outlives its event. An update is stamped when it is written, after its alert's
-- row is locked, not when its transaction began: updates sort in the order they
-- were posted even when their transactions overlap.
CREATE TABLE alert_updates (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('investigating', 'fixing', 'monitoring')),
    event_id UUID NOT NULL UNIQUE,
    author JSONB NOT NULL CHECK (author ->> 'type' IN ('admin', 'cli')),
    posted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- An alert's updates, oldest first.
CREATE INDEX alert_updates_alert_idx ON alert_updates (alert_id, posted_at, id);
