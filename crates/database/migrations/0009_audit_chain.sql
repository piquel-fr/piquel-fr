-- Makes the event history tamper-evident: a hash chain over sealed events, and
-- signed checkpoints of its head. See docs/security/audit-history.md.
--
-- The sealer, one replica at a time, gives each event its chain position and hash
-- after its transaction and every older one have finished. Events are inserted
-- unsealed, so the previous release keeps writing them unchanged.
ALTER TABLE domain_events
    ADD COLUMN chain_position BIGINT UNIQUE CHECK (chain_position > 0),
    -- SHA-256(previous chain_hash || SHA-256(canonical event)).
    ADD COLUMN chain_hash BYTEA CHECK (octet_length(chain_hash) = 32),
    ADD CHECK ((chain_position IS NULL) = (chain_hash IS NULL));
-- The sealer reads unsealed events in consumer order, (txid, sequence).
CREATE INDEX domain_events_unsealed_idx ON domain_events (txid, sequence)
    WHERE chain_position IS NULL;

-- Signed checkpoints of the chain head, in the C2SP signed-note format. Never
-- pruned: pruned events stay covered by the checkpoints that signed them.
CREATE TABLE audit_checkpoints (
    position BIGINT PRIMARY KEY CHECK (position > 0),
    head BYTEA NOT NULL CHECK (octet_length(head) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    note TEXT NOT NULL
);

-- The checkpoint the chain was last pruned through, if it ever was. The first
-- remaining event chains from its head instead of from 32 zero bytes.
--
-- Once events are pruned, the pending import of security_audit_log (0005) must
-- take only rows written after 0005 ran: pruned rows are no longer there to skip.
CREATE TABLE audit_anchor (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    position BIGINT NOT NULL REFERENCES audit_checkpoints (position)
);

-- Guards sealed history against bugs: a sealed event is never updated, and only
-- pruning, which sets piquel.audit_prune for its transaction, deletes one.
-- Checkpoints are never updated or deleted, and neither table is truncated. Anyone
-- with enough database rights can drop these triggers; the chain is what detects
-- attackers.
CREATE FUNCTION guard_sealed_events() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.chain_position IS NULL
        OR (TG_OP = 'DELETE' AND current_setting('piquel.audit_prune', true) = 'on') THEN
        RETURN CASE TG_OP WHEN 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    RAISE EXCEPTION 'sealed event at chain position % cannot be changed', OLD.chain_position
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER domain_events_guard_sealed
    BEFORE UPDATE OR DELETE ON domain_events
    FOR EACH ROW EXECUTE FUNCTION guard_sealed_events();

CREATE FUNCTION refuse_audit_history_change() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % would change sealed audit history', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER audit_checkpoints_guard
    BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION refuse_audit_history_change();

-- The anchor moves only forward, and only while pruning, so it cannot hide events
-- left at or before it, and concurrent prunes cannot move it back.
CREATE FUNCTION guard_audit_anchor() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP <> 'DELETE' AND current_setting('piquel.audit_prune', true) = 'on' THEN
        IF TG_OP = 'INSERT' THEN
            RETURN NEW;
        END IF;
        IF NEW.position > OLD.position THEN
            RETURN NEW;
        END IF;
    END IF;
    RAISE EXCEPTION 'the audit anchor only moves forward, by pruning'
        USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER audit_anchor_guard
    BEFORE INSERT OR UPDATE OR DELETE ON audit_anchor
    FOR EACH ROW EXECUTE FUNCTION guard_audit_anchor();

CREATE TRIGGER audit_anchor_guard_truncate
    BEFORE TRUNCATE ON audit_anchor
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_audit_history_change();

CREATE TRIGGER domain_events_guard_truncate
    BEFORE TRUNCATE ON domain_events
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_audit_history_change();

CREATE TRIGGER audit_checkpoints_guard_truncate
    BEFORE TRUNCATE ON audit_checkpoints
    FOR EACH STATEMENT EXECUTE FUNCTION refuse_audit_history_change();
