-- The browsers each account has signed in from, so a sign-in from any other
-- one alerts its owner. A browser is known by the digest of its device cookie,
-- a random secret it keeps for 400 days, apart from its session cookie, so
-- signing out does not forget it. Maintenance deletes a device unused for 400
-- days, and deleting the account deletes its devices.
CREATE TABLE known_devices (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_digest BYTEA NOT NULL CHECK (octet_length(device_digest) = 32),
    user_agent_family TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, device_digest)
);

-- Maintenance finds the devices unused for 400 days.
CREATE INDEX known_devices_last_seen_idx ON known_devices (last_seen_at);

-- When the "sign me out everywhere" link of a notification's email was used.
-- The link works once, within 7 days of the notification.
ALTER TABLE notifications ADD COLUMN signed_out_at TIMESTAMPTZ;
