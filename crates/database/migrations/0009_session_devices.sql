-- Where each session signed in from and was last seen, for the account's list of
-- signed-in devices. The IPs live only as long as the session row. The existing
-- user_agent_family column now holds the coarse browser and platform as
-- `browser/platform`, e.g. `firefox/linux`; no release wrote it before.
ALTER TABLE sessions
    ADD COLUMN created_ip INET,
    ADD COLUMN last_seen_ip INET;

-- The platform half of an event's user agent family. user_agent_family keeps only
-- the browser, the one value previous releases read there.
ALTER TABLE event_personal_data ADD COLUMN platform TEXT;
