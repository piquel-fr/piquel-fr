-- Replaces the free-form security audit log with typed domain events.
--
-- domain_events holds only non-identifying content: the event kind and payload,
-- its actor, and the subject, client and session it concerns. Anything that
-- identifies a person outside auth (client IP, user agent family, and every
-- Personal value of the payload) lives in event_personal_data, which retention
-- and account purges delete without touching the event.
--
-- subject_user_id has no foreign key: history outlives the account it describes.
CREATE TABLE domain_events (
    id UUID PRIMARY KEY,
    txid XID8 NOT NULL DEFAULT pg_current_xact_id(),
    sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    kind TEXT NOT NULL,
    version SMALLINT NOT NULL,
    payload JSONB NOT NULL,
    actor JSONB NOT NULL,
    subject_user_id UUID,
    client_id TEXT,
    session_id UUID,
    -- Filled once requests carry a trace ID.
    trace_id TEXT
);
CREATE INDEX domain_events_subject_idx ON domain_events (subject_user_id, sequence DESC);
-- Consumers read in (txid, sequence) order; see EventRepository::read_after.
CREATE INDEX domain_events_cursor_idx ON domain_events (txid, sequence);

-- details maps the JSON pointer of each Personal payload value to that value.
CREATE TABLE event_personal_data (
    event_id UUID PRIMARY KEY REFERENCES domain_events(id) ON DELETE CASCADE,
    client_ip INET,
    user_agent_family TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Lets cleanup find personal data past its retention without a full scan.
CREATE INDEX event_personal_data_created_idx ON event_personal_data (created_at);

-- How far each named consumer has read.
CREATE TABLE event_consumers (
    name TEXT PRIMARY KEY,
    txid XID8 NOT NULL,
    sequence BIGINT NOT NULL
);

-- Existing audit rows become imported events with the same IDs, oldest first,
-- keeping their action, outcome and metadata verbatim. The metadata holds only
-- provider names, which are not personal data. The log never recorded who acted.
--
-- security_audit_log stays: the previous release writes to it until this one
-- replaces it. A later release imports the rows written since, by ID, then drops it.
INSERT INTO domain_events (id, occurred_at, kind, version, payload, actor, subject_user_id)
SELECT
    id,
    created_at,
    'imported',
    1,
    jsonb_build_object('action', action, 'outcome', outcome, 'metadata', request_metadata),
    '{"type": "unrecorded"}',
    user_id
FROM security_audit_log
ORDER BY created_at, id;
