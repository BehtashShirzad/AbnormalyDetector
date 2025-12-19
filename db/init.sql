CREATE TABLE IF NOT EXISTS anormal_events (
    id              BIGSERIAL PRIMARY KEY,
    service_name    VARCHAR(100) NOT NULL,
    ip              INET NOT NULL,
    description     TEXT NOT NULL,
    severity        SMALLINT NOT NULL
        CHECK (severity IN (0,1,2,3)),
    occurred_at     TIMESTAMPTZ NOT NULL,
    request         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anormal_events_ip
    ON anormal_events (ip);

CREATE INDEX IF NOT EXISTS idx_anormal_events_occurred_at
    ON anormal_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_anormal_events_severity
    ON anormal_events (severity);
