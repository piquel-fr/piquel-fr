-- Announcements administrators send to accounts, such as a security incident or
-- a change to the privacy policy: emailed to each recipient's primary verified
-- address, and written to each recipient's inbox as a notification.
--
-- An announcement is a draft until it is sent, and only a draft changes. Its
-- text is written for everyone it goes to, so it is no one's personal data,
-- except that an announcement to chosen accounts may concern them: a purge
-- deletes it with its last recipient.
CREATE TABLE announcements (
    id UUID PRIMARY KEY,
    subject TEXT NOT NULL CHECK (subject <> ''),
    body TEXT NOT NULL CHECK (body <> ''),
    -- Whether it goes to every account, rather than to the chosen ones.
    everyone BOOLEAN NOT NULL,
    -- Counts the draft's changes. Sending names the revision that was checked,
    -- so a change made meanwhile is checked again before anything is sent.
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    sent_at TIMESTAMPTZ
);
CREATE INDEX announcements_recent_idx ON announcements (created_at DESC, id DESC);

-- What was sent stays as it was sent: the audit history names the announcement,
-- not its text.
CREATE FUNCTION guard_sent_announcement() RETURNS TRIGGER
LANGUAGE plpgsql SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'announcement % was sent, so it can no longer change', OLD.id
        USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER announcements_sent_unchanged
    BEFORE UPDATE ON announcements
    FOR EACH ROW WHEN (OLD.sent_at IS NOT NULL)
    EXECUTE FUNCTION guard_sent_announcement();

-- The accounts an announcement goes to: the chosen ones from the draft on, or
-- every account, added when it is sent. Accounts created later never get it.
-- Deleting an account deletes its rows.
CREATE TABLE announcement_recipients (
    announcement_id UUID NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (announcement_id, user_id)
);
-- A purge finds the announcements an account received, and the cascade its rows.
CREATE INDEX announcement_recipients_user_idx ON announcement_recipients (user_id);

-- The dashboard counts an announcement's emails by status while the queue keeps
-- them: their payload is the announcement's ID. A purge deletes the account's.
CREATE INDEX deliveries_announcement_idx ON deliveries (payload)
    WHERE channel = 'announcement';
CREATE INDEX deliveries_announcement_recipient_idx ON deliveries (recipient)
    WHERE channel = 'announcement';

-- How many of an announcement's recipients read it, which its page shows.
CREATE INDEX notifications_announcement_idx ON notifications ((payload ->> 'announcement_id'))
    WHERE payload ->> 'kind' = 'announcement';
