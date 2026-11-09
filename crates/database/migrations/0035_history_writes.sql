-- Auth's runtime role writes history only the way auth does (#250), so a
-- compromised auth can neither forge history nor plant rows that freeze it. With
-- the column grants of runtime_role.sql, it cannot set an event's transaction,
-- time, sequence or chain columns when inserting it. These guards refuse the
-- rest, for every role: an event auth could not read back, personal data
-- attached to another transaction's event, a seal that skips a position, and a
-- checkpoint for anything but a sealed event's hash, or dated in the future. A
-- huge position, an unreadable event or a future checkpoint would otherwise stop
-- sealing or signing until the schema owner repaired it. SQL cannot check a hash
-- or a checkpoint's signature; the sealer and `audit verify` do, and a seal with
-- a wrong one still stops signing until the owner repairs the chain.
--
-- The previous release keeps working beside this one: it records personal data
-- with its event, seals positions in order and signs the head it just sealed.
--
-- Requests write a passkey, then an event, then its personal data. Changing each
-- table locks it against writes, and adding the check also against reads of
-- domain_events, for a moment, so take the locks up front in that order: locking
-- personal data first would deadlock with a request that already inserted its
-- event. The migration waits for those requests, within its lock limit. An
-- account purge erases personal data before recording its event, so one running
-- then can still deadlock with the migration, which fails and is run again.
LOCK TABLE passkey_credentials IN SHARE ROW EXCLUSIVE MODE;

-- An event the sealer could not read would fail every sealing pass, which loads
-- up to 100 events at once. serde_json refuses numbers beyond a double's range
-- and nesting past 128 levels, and a huge event would exhaust the sealer's memory
-- or time: parsed, JSON can take about 100 times its text. So an event's payload
-- stays under 8 KiB, its actor under 1 KiB and its text columns under 256 bytes,
-- about 95 MB for a batch at worst. Real events are a few hundred bytes, the
-- largest a recovery listing an account's passkeys, which the passkey limit below
-- keeps around 4 KiB, so existing rows are not rechecked. Sealing an event
-- updates it and checks it again, so one recorded before this migration must
-- fit too; real ones do.
CREATE FUNCTION auth_reads_json(value JSONB, bytes INT) RETURNS BOOLEAN
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT octet_length(value::text) <= bytes AND NOT (
        value @? '$.** ? (@.type() == "number" && (@ > 1e308 || @ < -1e308))'
        OR value @? '$.**{64 to last}'
    )
$$;
ALTER TABLE domain_events ADD CONSTRAINT domain_events_readable CHECK (
    auth_reads_json(payload, 8192) AND auth_reads_json(actor, 1024)
    AND octet_length(kind) <= 256 AND octet_length(client_id) <= 256
    AND octet_length(trace_id) <= 256
) NOT VALID;
LOCK TABLE event_personal_data, audit_checkpoints IN SHARE ROW EXCLUSIVE MODE;

-- Personal data is recorded with its event, never attached to an older one: with
-- the deletes retention needs, that would let it be rewritten.
CREATE FUNCTION guard_personal_data_insert() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (
        SELECT FROM domain_events WHERE id = NEW.event_id AND txid = pg_current_xact_id()
    ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'personal data of event % can only be recorded with the event', NEW.event_id
        USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER event_personal_data_guard_insert
    BEFORE INSERT ON event_personal_data
    FOR EACH ROW EXECUTE FUNCTION guard_personal_data_insert();

-- Each sealed position follows a sealed one, or the anchor, or starts the chain,
-- so no seal leaves a gap or jumps ahead. It runs once the statement has sealed
-- its whole batch, whatever order the rows were updated in. A wrong hash is for
-- verification to find: SQL cannot compute one.
--
-- Sealing must read committed data, as the sealer does: an older snapshot could
-- still show events a concurrent prune deleted, and seal behind the anchor. Read
-- committed, the check sees every committed prune, and a prune still deleting the
-- position makes the seal wait for it on the unique index first.
CREATE FUNCTION guard_seal_order() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'events are sealed only in read committed transactions'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.chain_position - 1 = coalesce((SELECT position FROM audit_anchor), 0)
        OR EXISTS (SELECT FROM domain_events WHERE chain_position = NEW.chain_position - 1)
    THEN
        RETURN NULL;
    END IF;
    RAISE EXCEPTION 'event % cannot be sealed at position %: the position before is not sealed',
        NEW.id, NEW.chain_position
        USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER domain_events_guard_seal_order
    AFTER UPDATE OF chain_position ON domain_events
    FOR EACH ROW WHEN (OLD.chain_position IS NULL AND NEW.chain_position IS NOT NULL)
    EXECUTE FUNCTION guard_seal_order();

-- A checkpoint is of a sealed event's chain hash, and dated at a finite time
-- not in the future: auth cannot read an infinite one back. A minute of leeway
-- covers auth's clock running ahead of the database's. Its note, which auth reads
-- and checks a signature line by line, stays under 1 KiB; auth's are about 300
-- bytes.
CREATE FUNCTION guard_new_checkpoint() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF isfinite(NEW.created_at) AND octet_length(NEW.note) <= 1024
        AND NEW.created_at <= clock_timestamp() + INTERVAL '1 minute' AND EXISTS (
        SELECT FROM domain_events WHERE chain_position = NEW.position AND chain_hash = NEW.head
    ) THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'checkpoint at position % is not of the sealed chain as of now',
        NEW.position
        USING ERRCODE = 'integrity_constraint_violation';
END $$;
CREATE TRIGGER audit_checkpoints_guard_insert
    BEFORE INSERT ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION guard_new_checkpoint();

-- An account keeps at most 100 active passkeys, so the recovery event listing
-- them stays well under the payload bound above. Nobody needs more. Concurrent
-- registrations can pass it by a few, which the bound still fits.
CREATE FUNCTION limit_passkeys() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    IF (
        SELECT count(*) FROM passkey_credentials
        WHERE user_id = NEW.user_id AND revoked_at IS NULL
    ) < 100 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'account % already has 100 active passkeys', NEW.user_id
        USING ERRCODE = 'check_violation';
END $$;
CREATE TRIGGER passkey_credentials_limit
    BEFORE INSERT ON passkey_credentials
    FOR EACH ROW EXECUTE FUNCTION limit_passkeys();

-- The functions look tables up in the schema this migration runs in, with
-- pg_temp last: public when deployed, a test's own schema in tests.
DO $$
DECLARE
    guard TEXT;
BEGIN
    FOREACH guard IN ARRAY ARRAY[
        'guard_personal_data_insert', 'guard_seal_order', 'guard_new_checkpoint',
        'limit_passkeys'
    ] LOOP
        EXECUTE format(
            'ALTER FUNCTION %I() SET search_path = pg_catalog, %I, pg_temp',
            guard, current_schema()
        );
    END LOOP;
END $$;
