-- Keep the requested subject across login, consent, and authorization resumption.
ALTER TABLE authorization_requests ADD COLUMN hinted_user_id UUID;
