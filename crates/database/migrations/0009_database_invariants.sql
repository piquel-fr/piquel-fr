-- AFTER triggers see the updated table, including an unchanged verified row.
CREATE OR REPLACE FUNCTION release_active_verified_email() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.verified_at IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM user_emails e JOIN users u ON u.id=e.user_id
        WHERE e.user_id=OLD.user_id AND e.normalized_email=OLD.normalized_email
          AND e.verified_at IS NOT NULL AND u.status='active'
    ) THEN
        DELETE FROM active_verified_email_ownership
        WHERE normalized_email=OLD.normalized_email AND user_id=OLD.user_id;
    END IF;
    RETURN OLD;
END $$;

-- Repair missing/stale ownership atomically. Conflicting active owners require
-- operator resolution; never silently choose one account during migration.
LOCK TABLE users, user_emails, active_verified_email_ownership IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (
        SELECT e.normalized_email FROM user_emails e JOIN users u ON u.id=e.user_id
        WHERE e.verified_at IS NOT NULL AND u.status='active'
        GROUP BY e.normalized_email HAVING count(DISTINCT e.user_id)>1
    ) THEN
        RAISE EXCEPTION 'conflicting active verified emails require resolution before migration'
            USING ERRCODE='unique_violation';
    END IF;
END $$;
DELETE FROM active_verified_email_ownership;
INSERT INTO active_verified_email_ownership(normalized_email,user_id)
SELECT DISTINCT e.normalized_email,e.user_id
FROM user_emails e JOIN users u ON u.id=e.user_id
WHERE e.verified_at IS NOT NULL AND u.status='active';

CREATE INDEX refresh_families_session_idx ON refresh_token_families(session_id);
CREATE INDEX refresh_families_active_user_idx ON refresh_token_families(user_id) WHERE revoked_at IS NULL;
