-- Handles administrators reserve, on top of the names the handle rules build in:
-- signup and the settings refuse them and their look-alikes, as they do built-in
-- ones, until an administrator gives one to an account or removes it from the
-- list. The reason says who or what it is kept for. Accounts already holding one
-- keep it, and `handle check` lists them.
CREATE TABLE reserved_handles (
    handle TEXT PRIMARY KEY
        CHECK (length(handle) BETWEEN 3 AND 32 AND handle ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    skeleton TEXT NOT NULL UNIQUE GENERATED ALWAYS AS (handle_skeleton(handle)) STORED,
    reason TEXT NOT NULL CHECK (length(reason) BETWEEN 1 AND 500),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
