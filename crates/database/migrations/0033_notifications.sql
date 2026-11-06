-- What each account's owner is told about their account, in their settings
-- inbox. A notification is written in the transaction of the event it comes
-- from, if any, and holds no personal data: it renders from its payload alone,
-- so it outlives its event's personal data and the event itself, which audit
-- pruning may delete. `event_id` is no foreign key for that reason. Purging the
-- account deletes its notifications with it.
CREATE TABLE notifications (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id UUID,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload -> 'kind') = 'string'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at TIMESTAMPTZ
);

-- The inbox, newest first. Notifications written in one transaction share
-- `now()`, so pages continue after `(created_at, id)`.
CREATE INDEX notifications_inbox_idx ON notifications (user_id, created_at DESC, id DESC);
-- The unread count every settings page shows.
CREATE INDEX notifications_unread_idx ON notifications (user_id) WHERE read_at IS NULL;
