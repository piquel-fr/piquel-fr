ALTER TABLE webauthn_ceremonies
    DROP CONSTRAINT webauthn_ceremonies_ceremony_kind_check;

ALTER TABLE webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_ceremony_kind_check
    CHECK (ceremony_kind IN ('registration', 'authentication', 'enrollment'));
