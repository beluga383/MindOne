-- Audited SLA exclusions are operator decisions, never node/worker self-reports.
-- The event log is append-only and stores only an evidence content commitment;
-- local paths and request/response bodies are deliberately absent.

CREATE TABLE sla_exclusion_events (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
    category TEXT NOT NULL CHECK (
        category IN ('content_policy_refusal', 'force_majeure')
    ),
    operator_id TEXT NOT NULL CHECK (
        octet_length(operator_id) BETWEEN 1 AND 128
        AND operator_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    ),
    reason TEXT NOT NULL CHECK (
        char_length(reason) BETWEEN 8 AND 512
        AND reason = btrim(reason)
        AND reason !~ '[[:cntrl:]]'
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    ),
    evidence_sha256 TEXT NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    request_fingerprint TEXT NOT NULL CHECK (
        request_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sla_exclusion_events_created_category_v1
    ON sla_exclusion_events(created_at, category);

CREATE OR REPLACE FUNCTION mindone_validate_sla_exclusion_insert_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    terminal_status TEXT;
BEGIN
    SELECT status INTO terminal_status
    FROM public.jobs
    WHERE id = NEW.job_id;

    IF terminal_status IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'sla exclusion job does not exist';
    END IF;
    IF terminal_status NOT IN ('failed', 'cancelled') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sla exclusion requires a failed or cancelled job';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mindone_prevent_sla_exclusion_mutation_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'MindOne SLA exclusion events are append-only';
END;
$$;

CREATE TRIGGER sla_exclusion_events_validate_insert_v1
    BEFORE INSERT ON sla_exclusion_events
    FOR EACH ROW
    EXECUTE FUNCTION mindone_validate_sla_exclusion_insert_v1();

CREATE TRIGGER sla_exclusion_events_append_only_rows_v1
    BEFORE UPDATE OR DELETE ON sla_exclusion_events
    FOR EACH ROW
    EXECUTE FUNCTION mindone_prevent_sla_exclusion_mutation_v1();

CREATE TRIGGER sla_exclusion_events_append_only_truncate_v1
    BEFORE TRUNCATE ON sla_exclusion_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION mindone_prevent_sla_exclusion_mutation_v1();

-- The sole runtime-role write boundary. Locks serialize both a global
-- idempotency key and the target job. A different key for the same job therefore
-- receives the same deterministic conflict even under concurrent submissions.
CREATE OR REPLACE FUNCTION mindone_record_sla_exclusion_v1(
    p_event_id UUID,
    p_job_id UUID,
    p_category TEXT,
    p_operator_id TEXT,
    p_reason TEXT,
    p_idempotency_key TEXT,
    p_evidence_sha256 TEXT,
    p_request_fingerprint TEXT
)
RETURNS TABLE (
    out_event_id UUID,
    out_created_at TIMESTAMPTZ,
    out_idempotent_replay BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    existing public.sla_exclusion_events%ROWTYPE;
    terminal_status TEXT;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'mindone:sla-exclusion:idempotency:v1:' || p_idempotency_key,
            0
        )
    );

    SELECT * INTO existing
    FROM public.sla_exclusion_events
    WHERE idempotency_key = p_idempotency_key;

    IF FOUND THEN
        IF existing.job_id IS DISTINCT FROM p_job_id
           OR existing.category IS DISTINCT FROM p_category
           OR existing.operator_id IS DISTINCT FROM p_operator_id
           OR existing.reason IS DISTINCT FROM p_reason
           OR existing.evidence_sha256 IS DISTINCT FROM p_evidence_sha256
           OR existing.request_fingerprint IS DISTINCT FROM p_request_fingerprint
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'sla exclusion idempotency conflict';
        END IF;

        RETURN QUERY SELECT existing.id, existing.created_at, TRUE;
        RETURN;
    END IF;

    SELECT status INTO terminal_status
    FROM public.jobs
    WHERE id = p_job_id
    FOR UPDATE;

    IF terminal_status IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'sla exclusion job does not exist';
    END IF;
    IF terminal_status NOT IN ('failed', 'cancelled') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'sla exclusion requires a failed or cancelled job';
    END IF;
    IF EXISTS (
        SELECT 1 FROM public.sla_exclusion_events WHERE job_id = p_job_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'sla exclusion job conflict';
    END IF;

    INSERT INTO public.sla_exclusion_events (
        id, job_id, category, operator_id, reason, idempotency_key,
        evidence_sha256, request_fingerprint
    ) VALUES (
        p_event_id, p_job_id, p_category, p_operator_id, p_reason,
        p_idempotency_key, p_evidence_sha256, p_request_fingerprint
    )
    RETURNING id, created_at INTO out_event_id, out_created_at;

    out_idempotent_replay := FALSE;
    RETURN NEXT;
END;
$$;

REVOKE ALL PRIVILEGES ON TABLE sla_exclusion_events FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_validate_sla_exclusion_insert_v1()
    FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_prevent_sla_exclusion_mutation_v1()
    FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_record_sla_exclusion_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON TABLE sla_exclusion_events FROM mindone_app;
        GRANT SELECT ON TABLE sla_exclusion_events TO mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION
            mindone_validate_sla_exclusion_insert_v1()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION
            mindone_prevent_sla_exclusion_mutation_v1()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_record_sla_exclusion_v1(
            UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT
        ) FROM mindone_app;
        GRANT EXECUTE ON FUNCTION mindone_record_sla_exclusion_v1(
            UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT
        ) TO mindone_app;
    END IF;
END;
$$;
