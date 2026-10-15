-- Replaces the explicit two-minute management window with the time the session
-- last proved possession of a passkey. Each protected action states the maximum
-- age it accepts. Open windows lasted two minutes, so none are carried over.
ALTER TABLE sessions DROP COLUMN management_expires_at;
ALTER TABLE sessions ADD COLUMN passkey_confirmed_at TIMESTAMPTZ;
-- The audited event is the same passkey proof under its new name.
UPDATE security_audit_log SET action = 'session.passkey_confirmed' WHERE action = 'settings.unlock';
