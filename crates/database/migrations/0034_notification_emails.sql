-- The notices about an account's addresses and recoveries are now emails of its
-- notifications (`{"type": "notification", …}`), and the four kinds of message
-- that carried them before are gone, so a delivery of one would no longer decode.
-- Those still waiting to be sent, or failed, are cancelled rather than
-- translated: there are no real users yet, and a notice that late is stale.
UPDATE deliveries
SET status = 'cancelled', finished_at = now(), claim_token = NULL
WHERE channel = 'email'
    AND status IN ('pending', 'failed')
    AND payload ->> 'type' IN (
        'primary_address_changed', 'address_removed', 'recovery_revoked', 'recovered'
    );
