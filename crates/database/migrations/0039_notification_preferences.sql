-- Whether each account receives a category of notifications by email. Only
-- categories whose email the owner may turn off have rows, and no row means
-- the category's default: everything about the account itself is always
-- emailed. Deleting an account deletes its rows.
CREATE TABLE notification_preferences (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    email BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, category)
);

-- An essential announcement, such as a security incident or a change to the
-- privacy policy or terms, is emailed to every recipient whatever their
-- preference. Its sender chooses so on the draft.
ALTER TABLE announcements ADD COLUMN essential BOOLEAN NOT NULL DEFAULT false;

-- Whether `account` receives announcements that are not essential by email:
-- unless its owner turned them off.
CREATE FUNCTION announcements_emailed(account UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE SET search_path = pg_catalog, public, pg_temp AS $$
    SELECT NOT EXISTS (
        SELECT FROM notification_preferences p
        WHERE p.user_id = account AND p.category = 'announcements' AND NOT p.email
    )
$$;
