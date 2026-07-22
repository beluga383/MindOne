-- Durable Standard-mode SSE transport. Data events contain model output and therefore
-- must use the same coordinator-held AEAD boundary as Standard request/result bodies.
-- Rows are append-only; settlement remains exclusively owned by the existing final
-- job-result transaction and never occurs while a chunk is appended.

CREATE TABLE job_stream_events (
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    sequence_number INTEGER NOT NULL
        CHECK (sequence_number >= 0 AND sequence_number < 65536),
    idempotency_key TEXT NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 200
    ),
    event_kind TEXT NOT NULL CHECK (event_kind IN ('data', 'upstream_done')),
    event_ciphertext TEXT,
    standard_event_storage_version SMALLINT,
    plaintext_bytes INTEGER NOT NULL CHECK (
        plaintext_bytes >= 0 AND plaintext_bytes <= 65536
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, attempt_number, sequence_number),
    UNIQUE (job_id, idempotency_key),
    CHECK (
        (event_kind = 'data'
            AND event_ciphertext
                ~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$'
            AND standard_event_storage_version = 1
            AND plaintext_bytes > 0)
        OR
        (event_kind = 'upstream_done'
            AND event_ciphertext IS NULL
            AND standard_event_storage_version IS NULL
            AND plaintext_bytes = 0)
    )
);

CREATE INDEX job_stream_events_read_v1
    ON job_stream_events(job_id, attempt_number, sequence_number);

CREATE OR REPLACE FUNCTION mindone_prevent_job_stream_event_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'MindOne job stream events are append-only';
END;
$$;

CREATE TRIGGER job_stream_events_append_only_v1
    BEFORE UPDATE OR DELETE ON job_stream_events
    FOR EACH ROW
    EXECUTE FUNCTION mindone_prevent_job_stream_event_mutation_v1();

-- Migration 0026 gives future tables broad runtime DML by default. This event log
-- only permits the coordinator runtime to append and read encrypted records.
REVOKE ALL PRIVILEGES ON TABLE job_stream_events FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON TABLE job_stream_events FROM mindone_app;
        GRANT SELECT, INSERT ON TABLE job_stream_events TO mindone_app;
    END IF;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION
    mindone_prevent_job_stream_event_mutation_v1()
    FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON FUNCTION
            mindone_prevent_job_stream_event_mutation_v1()
            FROM mindone_app;
    END IF;
END;
$$;
