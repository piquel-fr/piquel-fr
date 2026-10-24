-- The passkey that last proved possession for each session: the one that signed
-- it in, or confirmed it since; NULL for a social sign-in never confirmed, and for
-- sessions from before this column until their next passkey sign-in or
-- confirmation. Undoing an account recovery needs a session of a passkey enrolled
-- before it, so NULL never counts. Not a foreign key: it is only compared with
-- passkeys, and a purge may delete either row first.
ALTER TABLE sessions ADD COLUMN passkey_id UUID;
