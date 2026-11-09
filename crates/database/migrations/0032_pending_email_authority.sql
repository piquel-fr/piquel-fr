-- Whether the provider of a pending sign-in is authoritative for its address, so
-- the address is imported verified. Rows written before this read as not, which
-- only asks their owner to verify the address.
ALTER TABLE pending_federation
    ADD COLUMN email_authoritative BOOLEAN NOT NULL DEFAULT false,
    ADD CHECK (email IS NOT NULL OR NOT email_authoritative);
