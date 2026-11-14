-- Append-only security audit log.
CREATE TABLE audit_events (
    id             UUID PRIMARY KEY,
    ts             TIMESTAMPTZ NOT NULL,
    correlation_id TEXT,
    actor          TEXT,
    type           TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    service        TEXT NOT NULL,
    context        JSONB,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_ts ON audit_events (ts DESC);
CREATE INDEX audit_events_type ON audit_events (type, ts DESC);
CREATE INDEX audit_events_actor ON audit_events (actor, ts DESC);

-- Records are immutable; only the retention job may delete them.
CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit events are append-only';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
