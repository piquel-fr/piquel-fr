-- A new account may correct the handle it chose at signup at once: the rename
-- cooldown counts only from a change. handle_changed_at is NULL until the
-- handle first changes, and existing accounts that never changed theirs get it
-- back, since migration 0021 copied created_at into it.
ALTER TABLE users ALTER COLUMN handle_changed_at DROP NOT NULL;
ALTER TABLE users ALTER COLUMN handle_changed_at DROP DEFAULT;
UPDATE users SET handle_changed_at = NULL WHERE handle_changed_at = created_at;
