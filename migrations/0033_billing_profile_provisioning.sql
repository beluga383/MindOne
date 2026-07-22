-- Server-only provisioning for immutable physical billing profiles.
--
-- This migration deliberately does not tighten the transitional NULL billing
-- snapshots introduced by 0032. Route/job/receipt writers must land first. It
-- only adds the append-only operator audit/idempotency boundary and removes the
-- runtime role's ability to insert an unaudited profile directly.

CREATE TABLE billing_profile_provision_audits (
    id UUID PRIMARY KEY,
    billing_profile_id UUID NOT NULL UNIQUE
        REFERENCES billing_profiles(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    profile_version BIGINT NOT NULL CHECK (profile_version > 0),
    operator_id TEXT NOT NULL CHECK (
        octet_length(operator_id) BETWEEN 1 AND 128
        AND operator_id ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
    ),
    reason TEXT NOT NULL CHECK (
        char_length(reason) BETWEEN 8 AND 512
        AND reason = btrim(reason)
        AND reason !~ '[[:cntrl:]]'
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$'
    ),
    request_fingerprint TEXT NOT NULL
        CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    evidence_sha256 TEXT NOT NULL
        CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    profile_fingerprint TEXT NOT NULL
        CHECK (profile_fingerprint ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT billing_profile_provision_audits_model_version_unique_v1
        UNIQUE (model_id, profile_version)
);

COMMENT ON TABLE billing_profile_provision_audits IS
    'Append-only operator audit for the sole runtime billing-profile provisioning entrypoint.';
COMMENT ON COLUMN billing_profile_provision_audits.evidence_sha256 IS
    'SHA-256 of the bounded local regular evidence file; local paths are never persisted.';
COMMENT ON COLUMN billing_profile_provision_audits.request_fingerprint IS
    'SHA-256 commitment over every semantic operator request field, including evidence content.';

CREATE OR REPLACE FUNCTION mindone_validate_billing_profile_provision_audit_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM billing_profiles AS profile
        WHERE profile.id = NEW.billing_profile_id
          AND profile.model_id = NEW.model_id
          AND profile.profile_version = NEW.profile_version
          AND profile.evidence_hash = NEW.evidence_sha256
          AND profile.profile_fingerprint = NEW.profile_fingerprint
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'billing profile provision audit does not match immutable profile';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_profile_provision_audits_00_validate_v1
    BEFORE INSERT ON billing_profile_provision_audits
    FOR EACH ROW
    EXECUTE FUNCTION mindone_validate_billing_profile_provision_audit_v1();

CREATE TRIGGER billing_profile_provision_audits_append_only_v1
    BEFORE UPDATE OR DELETE ON billing_profile_provision_audits
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_physical_billing_mutation();

-- This is the only runtime-role write capability for billing profiles. The
-- function owns the advisory lock, exact replay comparison, canonical model
-- weights lookup, database fingerprint generation, profile INSERT and audit
-- INSERT, so those writes are one PostgreSQL statement and one transaction.
CREATE OR REPLACE FUNCTION mindone_record_billing_profile_v1(
    p_profile_id UUID,
    p_audit_id UUID,
    p_model_id UUID,
    p_profile_version BIGINT,
    p_reference_hardware_class TEXT,
    p_maximum_input_tokens BIGINT,
    p_maximum_output_tokens BIGINT,
    p_fixed_gpu_time_us BIGINT,
    p_gpu_time_us_per_1k_tokens BIGINT,
    p_reference_vram_mib BIGINT,
    p_token_rate_micro_per_1k BIGINT,
    p_gpu_rate_micro_per_second BIGINT,
    p_vram_rate_micro_per_gib_second BIGINT,
    p_evidence_sha256 TEXT,
    p_valid_from TIMESTAMPTZ,
    p_valid_until TIMESTAMPTZ,
    p_operator_id TEXT,
    p_reason TEXT,
    p_idempotency_key TEXT,
    p_request_fingerprint TEXT
)
RETURNS TABLE (
    out_audit_id UUID,
    out_profile_id UUID,
    out_model_weights_hash TEXT,
    out_profile_fingerprint TEXT,
    out_created_at TIMESTAMPTZ,
    out_idempotent_replay BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
    existing RECORD;
    model_weights_hash_v1 TEXT;
    profile_fingerprint_v1 TEXT;
BEGIN
    PERFORM pg_advisory_xact_lock(
        hashtextextended('mindone:billing-profile:v1:' || p_idempotency_key, 0)
    );

    SELECT
        audit.id AS audit_id,
        audit.operator_id,
        audit.reason,
        audit.idempotency_key,
        audit.request_fingerprint,
        audit.evidence_sha256,
        audit.profile_fingerprint AS audit_profile_fingerprint,
        audit.created_at AS audit_created_at,
        profile.id AS profile_id,
        profile.contract_version,
        profile.profile_version,
        profile.model_id,
        profile.model_weights_hash,
        profile.reference_hardware_class,
        profile.maximum_input_tokens,
        profile.maximum_output_tokens,
        profile.fixed_gpu_time_us,
        profile.gpu_time_us_per_1k_tokens,
        profile.reference_vram_mib,
        profile.token_rate_micro_per_1k,
        profile.gpu_rate_micro_per_second,
        profile.vram_rate_micro_per_gib_second,
        profile.evidence_hash,
        profile.profile_fingerprint,
        profile.valid_from,
        profile.valid_until
    INTO existing
    FROM billing_profile_provision_audits AS audit
    JOIN billing_profiles AS profile ON profile.id = audit.billing_profile_id
    WHERE audit.idempotency_key = p_idempotency_key
    FOR SHARE OF audit, profile;

    IF FOUND THEN
        IF existing.contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
           OR existing.profile_version IS DISTINCT FROM p_profile_version
           OR existing.model_id IS DISTINCT FROM p_model_id
           OR existing.reference_hardware_class
                IS DISTINCT FROM p_reference_hardware_class
           OR existing.maximum_input_tokens IS DISTINCT FROM p_maximum_input_tokens
           OR existing.maximum_output_tokens IS DISTINCT FROM p_maximum_output_tokens
           OR existing.fixed_gpu_time_us IS DISTINCT FROM p_fixed_gpu_time_us
           OR existing.gpu_time_us_per_1k_tokens
                IS DISTINCT FROM p_gpu_time_us_per_1k_tokens
           OR existing.reference_vram_mib IS DISTINCT FROM p_reference_vram_mib
           OR existing.token_rate_micro_per_1k
                IS DISTINCT FROM p_token_rate_micro_per_1k
           OR existing.gpu_rate_micro_per_second
                IS DISTINCT FROM p_gpu_rate_micro_per_second
           OR existing.vram_rate_micro_per_gib_second
                IS DISTINCT FROM p_vram_rate_micro_per_gib_second
           OR existing.evidence_hash IS DISTINCT FROM p_evidence_sha256
           OR existing.evidence_sha256 IS DISTINCT FROM p_evidence_sha256
           OR existing.valid_from IS DISTINCT FROM p_valid_from
           OR existing.valid_until IS DISTINCT FROM p_valid_until
           OR existing.operator_id IS DISTINCT FROM p_operator_id
           OR existing.reason IS DISTINCT FROM p_reason
           OR existing.request_fingerprint IS DISTINCT FROM p_request_fingerprint
           OR existing.audit_profile_fingerprint
                IS DISTINCT FROM existing.profile_fingerprint
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23505',
                MESSAGE = 'billing profile idempotency conflict';
        END IF;

        RETURN QUERY SELECT
            existing.audit_id::UUID,
            existing.profile_id::UUID,
            existing.model_weights_hash::TEXT,
            existing.profile_fingerprint::TEXT,
            existing.audit_created_at::TIMESTAMPTZ,
            TRUE;
        RETURN;
    END IF;

    -- Different idempotency keys targeting the same immutable model/version
    -- must classify deterministically instead of racing on a UNIQUE index.
    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            'mindone:billing-profile-version:v1:'
            || p_model_id::text || ':' || p_profile_version::text,
            0
        )
    );
    IF EXISTS (
        SELECT 1 FROM billing_profiles
        WHERE model_id = p_model_id
          AND profile_version = p_profile_version
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23505',
            MESSAGE = 'billing profile version conflict';
    END IF;

    SELECT weights_hash
    INTO model_weights_hash_v1
    FROM models
    WHERE id = p_model_id
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'billing profile model does not exist';
    END IF;

    profile_fingerprint_v1 := mindone_billing_profile_fingerprint_v1(
        p_profile_id,
        'server_reference_upper_bound_v1',
        p_profile_version,
        p_model_id,
        model_weights_hash_v1,
        p_reference_hardware_class,
        p_maximum_input_tokens,
        p_maximum_output_tokens,
        p_fixed_gpu_time_us,
        p_gpu_time_us_per_1k_tokens,
        p_reference_vram_mib,
        p_token_rate_micro_per_1k,
        p_gpu_rate_micro_per_second,
        p_vram_rate_micro_per_gib_second,
        p_evidence_sha256,
        p_valid_from,
        p_valid_until
    );

    INSERT INTO billing_profiles (
        id,contract_version,profile_version,model_id,model_weights_hash,
        reference_hardware_class,maximum_input_tokens,maximum_output_tokens,
        fixed_gpu_time_us,gpu_time_us_per_1k_tokens,reference_vram_mib,
        token_rate_micro_per_1k,gpu_rate_micro_per_second,
        vram_rate_micro_per_gib_second,evidence_hash,profile_fingerprint,
        valid_from,valid_until
    ) VALUES (
        p_profile_id,'server_reference_upper_bound_v1',p_profile_version,p_model_id,
        model_weights_hash_v1,p_reference_hardware_class,p_maximum_input_tokens,
        p_maximum_output_tokens,p_fixed_gpu_time_us,p_gpu_time_us_per_1k_tokens,
        p_reference_vram_mib,p_token_rate_micro_per_1k,
        p_gpu_rate_micro_per_second,p_vram_rate_micro_per_gib_second,
        p_evidence_sha256,profile_fingerprint_v1,p_valid_from,p_valid_until
    );

    INSERT INTO billing_profile_provision_audits (
        id,billing_profile_id,model_id,profile_version,operator_id,reason,
        idempotency_key,request_fingerprint,evidence_sha256,profile_fingerprint
    ) VALUES (
        p_audit_id,p_profile_id,p_model_id,p_profile_version,p_operator_id,p_reason,
        p_idempotency_key,p_request_fingerprint,p_evidence_sha256,
        profile_fingerprint_v1
    );

    RETURN QUERY
    SELECT
        audit.id,
        profile.id,
        profile.model_weights_hash,
        profile.profile_fingerprint,
        audit.created_at,
        FALSE
    FROM billing_profile_provision_audits AS audit
    JOIN billing_profiles AS profile ON profile.id = audit.billing_profile_id
    WHERE audit.id = p_audit_id;
END;
$$;

-- 0032 temporarily allowed direct profile INSERT while writers were landing.
-- From 0033 onward the runtime role can only execute the atomic, audited entrypoint.
REVOKE ALL PRIVILEGES ON TABLE billing_profile_provision_audits FROM PUBLIC;
REVOKE INSERT ON TABLE billing_profiles FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_validate_billing_profile_provision_audit_v1()
    FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_record_billing_profile_v1(
    UUID,UUID,UUID,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
    BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT
) FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE INSERT ON TABLE billing_profiles FROM mindone_app;
        REVOKE ALL PRIVILEGES ON TABLE billing_profile_provision_audits
            FROM mindone_app;
        GRANT SELECT ON TABLE billing_profile_provision_audits TO mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION
            mindone_validate_billing_profile_provision_audit_v1()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_record_billing_profile_v1(
            UUID,UUID,UUID,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
            BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT
        ) FROM mindone_app;
        GRANT EXECUTE ON FUNCTION mindone_record_billing_profile_v1(
            UUID,UUID,UUID,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
            BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT
        ) TO mindone_app;
    END IF;
END;
$$;
