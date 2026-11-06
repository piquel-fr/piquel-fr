-- What needs an administrator's attention, such as a broken audit chain: a
-- condition auth found, which concerns no account. An alert is current from when
-- it is raised until its condition clears, and open until then too, unless an
-- administrator acknowledges it first: auth then raises it again only once its
-- condition clears or changes. At most one alert of each kind is current. Like
-- an event's payload, it holds no personal data, and its events tell who
-- acknowledged it.
CREATE TABLE alerts (
    id UUID PRIMARY KEY,
    payload JSONB NOT NULL CHECK (jsonb_typeof(payload -> 'kind') = 'string'),
    -- The payload's version, as an event's: a release reads one it does not
    -- write as an alert it cannot show.
    version SMALLINT NOT NULL,
    raised_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- When auth last found its condition holding.
    seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    cleared_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX alerts_current_idx ON alerts ((payload ->> 'kind')) WHERE cleared_at IS NULL;
