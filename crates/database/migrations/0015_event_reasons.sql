-- Why an administrator or operator changed someone's account, as they wrote it.
-- Free text may name people, so it is personal data: it lives beside the request
-- origin and is deleted with it.
ALTER TABLE event_personal_data ADD COLUMN reason TEXT;
