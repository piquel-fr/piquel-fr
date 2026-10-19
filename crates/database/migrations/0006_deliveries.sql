-- The outbound delivery queue: messages for other systems, such as back-channel
-- logout tokens or SCIM requests. DatabaseTransaction::record creates them in the
-- transaction of the event that causes them, and workers send them with leases.
-- See docs/architecture/delivery-queue.md.
--
-- event_id has no foreign key, like domain_events.subject_user_id: nothing deletes
-- events, and a delivery must never depend on rows that can change after it is
-- created. destination and recipient copy everything a send needs.
CREATE TABLE deliveries (
    -- Also the delivery's identity for receivers: a jti or Message-ID.
    id UUID PRIMARY KEY,
    -- The event that caused it, when there is one.
    event_id UUID,
    channel TEXT NOT NULL,
    destination TEXT NOT NULL,
    recipient JSONB NOT NULL,
    -- Deliveries sharing a key are sent one at a time, in ordinal order. NULL is unordered.
    ordering_key TEXT,
    ordinal BIGINT,
    -- Never a plaintext secret.
    payload JSONB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'succeeded', 'failed', 'cancelled')),
    attempts INT NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set by the worker sending it. Only the holder of claim_token records the outcome.
    -- Cancelling clears claim_token but keeps leased_until, so an attempt in progress
    -- holds back the deliveries ordered after it until its lease expires.
    claim_token UUID,
    leased_until TIMESTAMPTZ,
    -- A status code or an error kind, never a response body.
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When an operator last retried it; the channel's maximum age counts from here.
    retried_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    UNIQUE (ordering_key, ordinal),
    CHECK ((ordering_key IS NULL) = (ordinal IS NULL))
);
-- Workers poll for due deliveries.
CREATE INDEX deliveries_due_idx ON deliveries (next_attempt_at) WHERE status = 'pending';
-- Cleanup finds finished deliveries past their retention.
CREATE INDEX deliveries_finished_idx ON deliveries (finished_at) WHERE status <> 'pending';

-- The next ordinal of each ordering key. Taking one locks the row until commit, so
-- ordinals follow commit order.
CREATE TABLE delivery_orderings (
    ordering_key TEXT PRIMARY KEY,
    next_ordinal BIGINT NOT NULL
);
