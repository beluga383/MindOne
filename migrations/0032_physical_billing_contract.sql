-- Physical billing contract v1: coordinator-owned token/GPU-time/VRAM-integral
-- reference upper bounds. Node telemetry is deliberately absent from every money
-- field below. All rates and amounts are integer microquota values.
--
-- This is phase one of a two-phase rollout. Existing rows are frozen as
-- legacy_token_v1 through an immutable allowlist. Until the v1 writers land in
-- the same release, a newly inserted row may only keep the version and every
-- snapshot column NULL. NULL is an explicit transitional state: it is not a
-- billing contract and cannot later be rewritten into legacy or v1. The next
-- migration must reject NULL after all writers atomically persist v1 snapshots.

-- Prevent a writer from slipping between the legacy allowlist snapshot and the
-- metadata-only legacy marker. The final schema has no legacy default.
LOCK TABLE jobs, regulated_routes, receipts IN ACCESS EXCLUSIVE MODE;

CREATE TABLE billing_profiles (
    id UUID PRIMARY KEY,
    contract_version TEXT NOT NULL
        CHECK (contract_version = 'server_reference_upper_bound_v1'),
    profile_version BIGINT NOT NULL CHECK (profile_version > 0),
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_weights_hash TEXT NOT NULL
        CHECK (model_weights_hash ~ '^[0-9a-f]{64}$'),
    reference_hardware_class TEXT NOT NULL CHECK (
        octet_length(reference_hardware_class) BETWEEN 1 AND 128
        AND reference_hardware_class = btrim(reference_hardware_class)
        AND reference_hardware_class !~ '[[:cntrl:]]'
    ),
    maximum_input_tokens BIGINT NOT NULL CHECK (maximum_input_tokens >= 0),
    maximum_output_tokens BIGINT NOT NULL CHECK (maximum_output_tokens > 0),
    fixed_gpu_time_us BIGINT NOT NULL CHECK (fixed_gpu_time_us >= 0),
    gpu_time_us_per_1k_tokens BIGINT NOT NULL
        CHECK (gpu_time_us_per_1k_tokens > 0),
    reference_vram_mib BIGINT NOT NULL CHECK (reference_vram_mib > 0),
    token_rate_micro_per_1k BIGINT NOT NULL
        CHECK (token_rate_micro_per_1k > 0),
    gpu_rate_micro_per_second BIGINT NOT NULL
        CHECK (gpu_rate_micro_per_second > 0),
    vram_rate_micro_per_gib_second BIGINT NOT NULL
        CHECK (vram_rate_micro_per_gib_second > 0),
    evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    profile_fingerprint TEXT NOT NULL UNIQUE
        CHECK (profile_fingerprint ~ '^[0-9a-f]{64}$'),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT billing_profiles_validity_v1 CHECK (valid_until > valid_from),
    CONSTRAINT billing_profiles_model_version_unique_v1
        UNIQUE (model_id, profile_version)
);

CREATE INDEX billing_profiles_model_validity_v1
    ON billing_profiles (model_id, valid_from DESC, valid_until DESC, profile_version DESC);

COMMENT ON TABLE billing_profiles IS
    'Immutable coordinator-owned physical reference profiles; telemetry never changes money.';
COMMENT ON COLUMN billing_profiles.profile_fingerprint IS
    'Database-verified SHA-256 fingerprint over the complete v1 profile identity and rates.';

-- Only migration 0032 may populate this table. Runtime can read it to validate
-- legacy rows but cannot add a newly created ID and thereby forge legacy status.
CREATE TABLE physical_billing_legacy_allowlist (
    entity_kind TEXT NOT NULL
        CHECK (entity_kind IN ('jobs', 'regulated_routes', 'receipts')),
    entity_id UUID NOT NULL,
    migrated_at TIMESTAMPTZ NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (entity_kind, entity_id)
);

COMMENT ON TABLE physical_billing_legacy_allowlist IS
    'Immutable IDs present before migration 0032; the sole authority for legacy_token_v1 markers.';

INSERT INTO physical_billing_legacy_allowlist (entity_kind, entity_id)
SELECT 'jobs', id FROM jobs
UNION ALL
SELECT 'regulated_routes', id FROM regulated_routes
UNION ALL
SELECT 'receipts', id FROM receipts;

-- A constant ADD COLUMN default marks only rows protected by the table lock.
-- Dropping it before the lock is released guarantees no future INSERT can obtain
-- legacy_token_v1 by omission.
ALTER TABLE jobs
    ADD COLUMN billing_contract_version TEXT DEFAULT 'legacy_token_v1',
    ADD COLUMN billing_profile_id UUID REFERENCES billing_profiles(id) ON DELETE RESTRICT,
    ADD COLUMN billing_profile_version BIGINT,
    ADD COLUMN billing_profile_fingerprint TEXT,
    ADD COLUMN billing_model_weights_hash TEXT,
    ADD COLUMN billing_reference_hardware_class TEXT,
    ADD COLUMN billing_profile_evidence_hash TEXT,
    ADD COLUMN billing_profile_valid_from TIMESTAMPTZ,
    ADD COLUMN billing_profile_valid_until TIMESTAMPTZ,
    ADD COLUMN billing_profile_max_input_tokens BIGINT,
    ADD COLUMN billing_profile_max_output_tokens BIGINT,
    ADD COLUMN billing_fixed_gpu_time_us BIGINT,
    ADD COLUMN billing_gpu_time_us_per_1k_tokens BIGINT,
    ADD COLUMN billing_reference_vram_mib BIGINT,
    ADD COLUMN billing_token_rate_micro_per_1k BIGINT,
    ADD COLUMN billing_gpu_rate_micro_per_second BIGINT,
    ADD COLUMN billing_vram_rate_micro_per_gib_second BIGINT,
    ADD COLUMN billing_authorized_input_tokens BIGINT,
    ADD COLUMN billing_authorized_max_output_tokens BIGINT,
    ADD COLUMN billing_billable_tokens BIGINT,
    ADD COLUMN billing_reference_gpu_time_us BIGINT,
    ADD COLUMN billing_reference_vram_mib_microseconds BIGINT,
    ADD COLUMN billing_token_cost_micro BIGINT,
    ADD COLUMN billing_gpu_cost_micro BIGINT,
    ADD COLUMN billing_vram_cost_micro BIGINT,
    ADD COLUMN billing_base_cost_micro BIGINT;
ALTER TABLE jobs ALTER COLUMN billing_contract_version DROP DEFAULT;

ALTER TABLE regulated_routes
    ADD COLUMN billing_contract_version TEXT DEFAULT 'legacy_token_v1',
    ADD COLUMN billing_profile_id UUID REFERENCES billing_profiles(id) ON DELETE RESTRICT,
    ADD COLUMN billing_profile_version BIGINT,
    ADD COLUMN billing_profile_fingerprint TEXT,
    ADD COLUMN billing_model_weights_hash TEXT,
    ADD COLUMN billing_reference_hardware_class TEXT,
    ADD COLUMN billing_profile_evidence_hash TEXT,
    ADD COLUMN billing_profile_valid_from TIMESTAMPTZ,
    ADD COLUMN billing_profile_valid_until TIMESTAMPTZ,
    ADD COLUMN billing_profile_max_input_tokens BIGINT,
    ADD COLUMN billing_profile_max_output_tokens BIGINT,
    ADD COLUMN billing_fixed_gpu_time_us BIGINT,
    ADD COLUMN billing_gpu_time_us_per_1k_tokens BIGINT,
    ADD COLUMN billing_reference_vram_mib BIGINT,
    ADD COLUMN billing_token_rate_micro_per_1k BIGINT,
    ADD COLUMN billing_gpu_rate_micro_per_second BIGINT,
    ADD COLUMN billing_vram_rate_micro_per_gib_second BIGINT,
    ADD COLUMN billing_authorized_input_tokens BIGINT,
    ADD COLUMN billing_authorized_max_output_tokens BIGINT,
    ADD COLUMN billing_billable_tokens BIGINT,
    ADD COLUMN billing_reference_gpu_time_us BIGINT,
    ADD COLUMN billing_reference_vram_mib_microseconds BIGINT,
    ADD COLUMN billing_token_cost_micro BIGINT,
    ADD COLUMN billing_gpu_cost_micro BIGINT,
    ADD COLUMN billing_vram_cost_micro BIGINT,
    ADD COLUMN billing_base_cost_micro BIGINT;
ALTER TABLE regulated_routes ALTER COLUMN billing_contract_version DROP DEFAULT;

ALTER TABLE receipts
    ADD COLUMN billing_contract_version TEXT DEFAULT 'legacy_token_v1',
    ADD COLUMN billing_profile_id UUID REFERENCES billing_profiles(id) ON DELETE RESTRICT,
    ADD COLUMN billing_profile_version BIGINT,
    ADD COLUMN billing_profile_fingerprint TEXT,
    ADD COLUMN billing_model_weights_hash TEXT,
    ADD COLUMN billing_reference_hardware_class TEXT,
    ADD COLUMN billing_profile_evidence_hash TEXT,
    ADD COLUMN billing_profile_valid_from TIMESTAMPTZ,
    ADD COLUMN billing_profile_valid_until TIMESTAMPTZ,
    ADD COLUMN billing_profile_max_input_tokens BIGINT,
    ADD COLUMN billing_profile_max_output_tokens BIGINT,
    ADD COLUMN billing_fixed_gpu_time_us BIGINT,
    ADD COLUMN billing_gpu_time_us_per_1k_tokens BIGINT,
    ADD COLUMN billing_reference_vram_mib BIGINT,
    ADD COLUMN billing_token_rate_micro_per_1k BIGINT,
    ADD COLUMN billing_gpu_rate_micro_per_second BIGINT,
    ADD COLUMN billing_vram_rate_micro_per_gib_second BIGINT,
    ADD COLUMN billing_authorized_input_tokens BIGINT,
    ADD COLUMN billing_authorized_max_output_tokens BIGINT,
    ADD COLUMN billing_billable_tokens BIGINT,
    ADD COLUMN billing_reference_gpu_time_us BIGINT,
    ADD COLUMN billing_reference_vram_mib_microseconds BIGINT,
    ADD COLUMN billing_token_cost_micro BIGINT,
    ADD COLUMN billing_gpu_cost_micro BIGINT,
    ADD COLUMN billing_vram_cost_micro BIGINT,
    ADD COLUMN billing_base_cost_micro BIGINT;
ALTER TABLE receipts ALTER COLUMN billing_contract_version DROP DEFAULT;

CREATE OR REPLACE FUNCTION mindone_billing_profile_fingerprint_v1(
    p_id UUID,
    p_contract_version TEXT,
    p_profile_version BIGINT,
    p_model_id UUID,
    p_model_weights_hash TEXT,
    p_reference_hardware_class TEXT,
    p_maximum_input_tokens BIGINT,
    p_maximum_output_tokens BIGINT,
    p_fixed_gpu_time_us BIGINT,
    p_gpu_time_us_per_1k_tokens BIGINT,
    p_reference_vram_mib BIGINT,
    p_token_rate_micro_per_1k BIGINT,
    p_gpu_rate_micro_per_second BIGINT,
    p_vram_rate_micro_per_gib_second BIGINT,
    p_evidence_hash TEXT,
    p_valid_from TIMESTAMPTZ,
    p_valid_until TIMESTAMPTZ
)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
DECLARE
    canonical TEXT := '';
    field_value TEXT;
BEGIN
    FOREACH field_value IN ARRAY ARRAY[
        'mindone-billing-profile',
        '1',
        p_id::text,
        p_contract_version,
        p_profile_version::text,
        p_model_id::text,
        p_model_weights_hash,
        p_reference_hardware_class,
        p_maximum_input_tokens::text,
        p_maximum_output_tokens::text,
        p_fixed_gpu_time_us::text,
        p_gpu_time_us_per_1k_tokens::text,
        p_reference_vram_mib::text,
        p_token_rate_micro_per_1k::text,
        p_gpu_rate_micro_per_second::text,
        p_vram_rate_micro_per_gib_second::text,
        p_evidence_hash,
        ((extract(epoch FROM p_valid_from) * 1000000)::bigint)::text,
        ((extract(epoch FROM p_valid_until) * 1000000)::bigint)::text
    ]
    LOOP
        canonical := canonical
            || octet_length(field_value)::text || ':' || field_value;
    END LOOP;
    RETURN encode(sha256(convert_to(canonical, 'UTF8')), 'hex');
END;
$$;

CREATE OR REPLACE FUNCTION mindone_validate_billing_profile_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path FROM CURRENT
AS $$
DECLARE
    expected_fingerprint TEXT;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM models
        WHERE id = NEW.model_id
          AND weights_hash = NEW.model_weights_hash
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'billing profile does not match canonical model weights';
    END IF;

    expected_fingerprint := mindone_billing_profile_fingerprint_v1(
        NEW.id,
        NEW.contract_version,
        NEW.profile_version,
        NEW.model_id,
        NEW.model_weights_hash,
        NEW.reference_hardware_class,
        NEW.maximum_input_tokens,
        NEW.maximum_output_tokens,
        NEW.fixed_gpu_time_us,
        NEW.gpu_time_us_per_1k_tokens,
        NEW.reference_vram_mib,
        NEW.token_rate_micro_per_1k,
        NEW.gpu_rate_micro_per_second,
        NEW.vram_rate_micro_per_gib_second,
        NEW.evidence_hash,
        NEW.valid_from,
        NEW.valid_until
    );
    IF NEW.profile_fingerprint IS NULL THEN
        NEW.profile_fingerprint := expected_fingerprint;
    ELSIF NEW.profile_fingerprint IS DISTINCT FROM expected_fingerprint THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'billing profile fingerprint does not match profile content';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_profiles_00_validate_v1
    BEFORE INSERT ON billing_profiles
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_billing_profile_v1();

-- A single immutable predicate is used by all three tables so PostgreSQL and the
-- Rust accounting crate enforce the exact same component-wise ceil contract.
CREATE OR REPLACE FUNCTION mindone_physical_billing_snapshot_is_valid_v1(
    p_contract_version TEXT,
    p_profile_id UUID,
    p_profile_version BIGINT,
    p_profile_fingerprint TEXT,
    p_model_weights_hash TEXT,
    p_reference_hardware_class TEXT,
    p_profile_evidence_hash TEXT,
    p_profile_valid_from TIMESTAMPTZ,
    p_profile_valid_until TIMESTAMPTZ,
    p_profile_max_input_tokens BIGINT,
    p_profile_max_output_tokens BIGINT,
    p_fixed_gpu_time_us BIGINT,
    p_gpu_time_us_per_1k_tokens BIGINT,
    p_reference_vram_mib BIGINT,
    p_token_rate_micro_per_1k BIGINT,
    p_gpu_rate_micro_per_second BIGINT,
    p_vram_rate_micro_per_gib_second BIGINT,
    p_authorized_input_tokens BIGINT,
    p_authorized_max_output_tokens BIGINT,
    p_billable_tokens BIGINT,
    p_reference_gpu_time_us BIGINT,
    p_reference_vram_mib_microseconds BIGINT,
    p_token_cost_micro BIGINT,
    p_gpu_cost_micro BIGINT,
    p_vram_cost_micro BIGINT,
    p_base_cost_micro BIGINT
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN p_contract_version IS NULL THEN
            p_profile_id IS NULL
            AND p_profile_version IS NULL
            AND p_profile_fingerprint IS NULL
            AND p_model_weights_hash IS NULL
            AND p_reference_hardware_class IS NULL
            AND p_profile_evidence_hash IS NULL
            AND p_profile_valid_from IS NULL
            AND p_profile_valid_until IS NULL
            AND p_profile_max_input_tokens IS NULL
            AND p_profile_max_output_tokens IS NULL
            AND p_fixed_gpu_time_us IS NULL
            AND p_gpu_time_us_per_1k_tokens IS NULL
            AND p_reference_vram_mib IS NULL
            AND p_token_rate_micro_per_1k IS NULL
            AND p_gpu_rate_micro_per_second IS NULL
            AND p_vram_rate_micro_per_gib_second IS NULL
            AND p_authorized_input_tokens IS NULL
            AND p_authorized_max_output_tokens IS NULL
            AND p_billable_tokens IS NULL
            AND p_reference_gpu_time_us IS NULL
            AND p_reference_vram_mib_microseconds IS NULL
            AND p_token_cost_micro IS NULL
            AND p_gpu_cost_micro IS NULL
            AND p_vram_cost_micro IS NULL
            AND p_base_cost_micro IS NULL
        WHEN p_contract_version = 'legacy_token_v1' THEN
            p_profile_id IS NULL
            AND p_profile_version IS NULL
            AND p_profile_fingerprint IS NULL
            AND p_model_weights_hash IS NULL
            AND p_reference_hardware_class IS NULL
            AND p_profile_evidence_hash IS NULL
            AND p_profile_valid_from IS NULL
            AND p_profile_valid_until IS NULL
            AND p_profile_max_input_tokens IS NULL
            AND p_profile_max_output_tokens IS NULL
            AND p_fixed_gpu_time_us IS NULL
            AND p_gpu_time_us_per_1k_tokens IS NULL
            AND p_reference_vram_mib IS NULL
            AND p_token_rate_micro_per_1k IS NULL
            AND p_gpu_rate_micro_per_second IS NULL
            AND p_vram_rate_micro_per_gib_second IS NULL
            AND p_authorized_input_tokens IS NULL
            AND p_authorized_max_output_tokens IS NULL
            AND p_billable_tokens IS NULL
            AND p_reference_gpu_time_us IS NULL
            AND p_reference_vram_mib_microseconds IS NULL
            AND p_token_cost_micro IS NULL
            AND p_gpu_cost_micro IS NULL
            AND p_vram_cost_micro IS NULL
            AND p_base_cost_micro IS NULL
        WHEN p_contract_version = 'server_reference_upper_bound_v1' THEN
            p_profile_id IS NOT NULL
            AND p_profile_version > 0
            AND p_profile_fingerprint ~ '^[0-9a-f]{64}$'
            AND p_model_weights_hash ~ '^[0-9a-f]{64}$'
            AND octet_length(p_reference_hardware_class) BETWEEN 1 AND 128
            AND p_reference_hardware_class = btrim(p_reference_hardware_class)
            AND p_reference_hardware_class !~ '[[:cntrl:]]'
            AND p_profile_evidence_hash ~ '^[0-9a-f]{64}$'
            AND p_profile_valid_from IS NOT NULL
            AND p_profile_valid_until > p_profile_valid_from
            AND p_profile_max_input_tokens >= 0
            AND p_profile_max_output_tokens > 0
            AND p_fixed_gpu_time_us >= 0
            AND p_gpu_time_us_per_1k_tokens > 0
            AND p_reference_vram_mib > 0
            AND p_token_rate_micro_per_1k > 0
            AND p_gpu_rate_micro_per_second > 0
            AND p_vram_rate_micro_per_gib_second > 0
            AND p_authorized_input_tokens >= 0
            AND p_authorized_max_output_tokens > 0
            AND p_authorized_input_tokens <= p_profile_max_input_tokens
            AND p_authorized_max_output_tokens <= p_profile_max_output_tokens
            AND p_billable_tokens::numeric =
                p_authorized_input_tokens::numeric
                + p_authorized_max_output_tokens::numeric
            AND p_reference_gpu_time_us::numeric =
                p_fixed_gpu_time_us::numeric
                + ceil(
                    p_billable_tokens::numeric
                    * p_gpu_time_us_per_1k_tokens::numeric
                    / 1000::numeric
                )
            AND p_reference_vram_mib_microseconds::numeric =
                p_reference_gpu_time_us::numeric
                * p_reference_vram_mib::numeric
            AND p_token_cost_micro::numeric = ceil(
                p_billable_tokens::numeric
                * p_token_rate_micro_per_1k::numeric
                / 1000::numeric
            )
            AND p_gpu_cost_micro::numeric = ceil(
                p_reference_gpu_time_us::numeric
                * p_gpu_rate_micro_per_second::numeric
                / 1000000::numeric
            )
            AND p_vram_cost_micro::numeric = ceil(
                p_reference_vram_mib_microseconds::numeric
                * p_vram_rate_micro_per_gib_second::numeric
                / 1024000000::numeric
            )
            AND p_token_cost_micro > 0
            AND p_gpu_cost_micro > 0
            AND p_vram_cost_micro > 0
            AND p_base_cost_micro::numeric =
                p_token_cost_micro::numeric
                + p_gpu_cost_micro::numeric
                + p_vram_cost_micro::numeric
        ELSE FALSE
    END IS TRUE
$$;

ALTER TABLE jobs
    ADD CONSTRAINT jobs_physical_billing_snapshot_shape_v1 CHECK (
        mindone_physical_billing_snapshot_is_valid_v1(
            billing_contract_version,billing_profile_id,billing_profile_version,
            billing_profile_fingerprint,billing_model_weights_hash,
            billing_reference_hardware_class,billing_profile_evidence_hash,
            billing_profile_valid_from,billing_profile_valid_until,
            billing_profile_max_input_tokens,billing_profile_max_output_tokens,
            billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
            billing_reference_vram_mib,billing_token_rate_micro_per_1k,
            billing_gpu_rate_micro_per_second,
            billing_vram_rate_micro_per_gib_second,
            billing_authorized_input_tokens,billing_authorized_max_output_tokens,
            billing_billable_tokens,billing_reference_gpu_time_us,
            billing_reference_vram_mib_microseconds,billing_token_cost_micro,
            billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
        )
    ),
    ADD CONSTRAINT jobs_billing_profile_valid_at_creation_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR (
            created_at >= billing_profile_valid_from
            AND created_at < billing_profile_valid_until
        )
    ),
    ADD CONSTRAINT jobs_billing_authorization_binding_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR (
            estimated_input_tokens::bigint = billing_authorized_input_tokens
            AND max_output_tokens::bigint = billing_authorized_max_output_tokens
        )
    ),
    ADD CONSTRAINT jobs_physical_billing_reservation_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR reserved_cost_micro::numeric = ceil(
            billing_base_cost_micro::numeric * 1500::numeric / 1000::numeric
        )
    );

ALTER TABLE regulated_routes
    ADD CONSTRAINT regulated_routes_billing_snapshot_shape_v1 CHECK (
        mindone_physical_billing_snapshot_is_valid_v1(
            billing_contract_version,billing_profile_id,billing_profile_version,
            billing_profile_fingerprint,billing_model_weights_hash,
            billing_reference_hardware_class,billing_profile_evidence_hash,
            billing_profile_valid_from,billing_profile_valid_until,
            billing_profile_max_input_tokens,billing_profile_max_output_tokens,
            billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
            billing_reference_vram_mib,billing_token_rate_micro_per_1k,
            billing_gpu_rate_micro_per_second,
            billing_vram_rate_micro_per_gib_second,
            billing_authorized_input_tokens,billing_authorized_max_output_tokens,
            billing_billable_tokens,billing_reference_gpu_time_us,
            billing_reference_vram_mib_microseconds,billing_token_cost_micro,
            billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
        )
    ),
    ADD CONSTRAINT regulated_routes_billing_profile_valid_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR (
            prepared_at >= billing_profile_valid_from
            AND prepared_at < billing_profile_valid_until
        )
    ),
    ADD CONSTRAINT regulated_routes_billing_authorization_binding_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR (
            estimated_input_tokens::bigint = billing_authorized_input_tokens
            AND max_output_tokens::bigint = billing_authorized_max_output_tokens
        )
    );

ALTER TABLE receipts
    ADD CONSTRAINT receipts_physical_billing_snapshot_shape_v1 CHECK (
        mindone_physical_billing_snapshot_is_valid_v1(
            billing_contract_version,billing_profile_id,billing_profile_version,
            billing_profile_fingerprint,billing_model_weights_hash,
            billing_reference_hardware_class,billing_profile_evidence_hash,
            billing_profile_valid_from,billing_profile_valid_until,
            billing_profile_max_input_tokens,billing_profile_max_output_tokens,
            billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
            billing_reference_vram_mib,billing_token_rate_micro_per_1k,
            billing_gpu_rate_micro_per_second,
            billing_vram_rate_micro_per_gib_second,
            billing_authorized_input_tokens,billing_authorized_max_output_tokens,
            billing_billable_tokens,billing_reference_gpu_time_us,
            billing_reference_vram_mib_microseconds,billing_token_cost_micro,
            billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
        )
    ),
    ADD CONSTRAINT receipts_billing_base_matches_settlement_v1 CHECK (
        billing_contract_version IS DISTINCT FROM 'server_reference_upper_bound_v1'
        OR base_cost_micro = billing_base_cost_micro
    );

CREATE OR REPLACE FUNCTION mindone_guard_physical_billing_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    snapshot_model_id UUID;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF ROW(
            NEW.billing_contract_version,
            NEW.billing_profile_id,
            NEW.billing_profile_version,
            NEW.billing_profile_fingerprint,
            NEW.billing_model_weights_hash,
            NEW.billing_reference_hardware_class,
            NEW.billing_profile_evidence_hash,
            NEW.billing_profile_valid_from,
            NEW.billing_profile_valid_until,
            NEW.billing_profile_max_input_tokens,
            NEW.billing_profile_max_output_tokens,
            NEW.billing_fixed_gpu_time_us,
            NEW.billing_gpu_time_us_per_1k_tokens,
            NEW.billing_reference_vram_mib,
            NEW.billing_token_rate_micro_per_1k,
            NEW.billing_gpu_rate_micro_per_second,
            NEW.billing_vram_rate_micro_per_gib_second,
            NEW.billing_authorized_input_tokens,
            NEW.billing_authorized_max_output_tokens,
            NEW.billing_billable_tokens,
            NEW.billing_reference_gpu_time_us,
            NEW.billing_reference_vram_mib_microseconds,
            NEW.billing_token_cost_micro,
            NEW.billing_gpu_cost_micro,
            NEW.billing_vram_cost_micro,
            NEW.billing_base_cost_micro
        ) IS DISTINCT FROM ROW(
            OLD.billing_contract_version,
            OLD.billing_profile_id,
            OLD.billing_profile_version,
            OLD.billing_profile_fingerprint,
            OLD.billing_model_weights_hash,
            OLD.billing_reference_hardware_class,
            OLD.billing_profile_evidence_hash,
            OLD.billing_profile_valid_from,
            OLD.billing_profile_valid_until,
            OLD.billing_profile_max_input_tokens,
            OLD.billing_profile_max_output_tokens,
            OLD.billing_fixed_gpu_time_us,
            OLD.billing_gpu_time_us_per_1k_tokens,
            OLD.billing_reference_vram_mib,
            OLD.billing_token_rate_micro_per_1k,
            OLD.billing_gpu_rate_micro_per_second,
            OLD.billing_vram_rate_micro_per_gib_second,
            OLD.billing_authorized_input_tokens,
            OLD.billing_authorized_max_output_tokens,
            OLD.billing_billable_tokens,
            OLD.billing_reference_gpu_time_us,
            OLD.billing_reference_vram_mib_microseconds,
            OLD.billing_token_cost_micro,
            OLD.billing_gpu_cost_micro,
            OLD.billing_vram_cost_micro,
            OLD.billing_base_cost_micro
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'physical billing snapshot is immutable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.billing_contract_version IS NULL THEN
        RETURN NEW;
    END IF;

    IF NEW.billing_contract_version = 'legacy_token_v1' THEN
        IF NOT EXISTS (
            SELECT 1 FROM physical_billing_legacy_allowlist
            WHERE entity_kind = TG_TABLE_NAME
              AND entity_id = NEW.id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'new rows cannot claim legacy_token_v1';
        END IF;
        RETURN NEW;
    END IF;

    IF TG_TABLE_NAME = 'receipts' THEN
        SELECT job.model_id INTO snapshot_model_id
        FROM jobs AS job
        WHERE job.id = NEW.job_id
          AND job.billing_contract_version = 'server_reference_upper_bound_v1'
          AND job.billing_profile_id = NEW.billing_profile_id
          AND job.billing_authorized_input_tokens
                = NEW.billing_authorized_input_tokens
          AND job.billing_authorized_max_output_tokens
                = NEW.billing_authorized_max_output_tokens
          AND job.billing_billable_tokens = NEW.billing_billable_tokens
          AND job.billing_reference_gpu_time_us
                = NEW.billing_reference_gpu_time_us
          AND job.billing_reference_vram_mib_microseconds
                = NEW.billing_reference_vram_mib_microseconds
          AND job.billing_token_cost_micro = NEW.billing_token_cost_micro
          AND job.billing_gpu_cost_micro = NEW.billing_gpu_cost_micro
          AND job.billing_vram_cost_micro = NEW.billing_vram_cost_micro
          AND job.billing_base_cost_micro = NEW.billing_base_cost_micro;
        IF snapshot_model_id IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'receipt billing snapshot does not match its job';
        END IF;
    ELSE
        snapshot_model_id := NEW.model_id;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM billing_profiles AS profile
        JOIN models AS canonical_model ON canonical_model.id = profile.model_id
        WHERE profile.id = NEW.billing_profile_id
          AND profile.contract_version = NEW.billing_contract_version
          AND profile.profile_version = NEW.billing_profile_version
          AND profile.model_id = snapshot_model_id
          AND profile.model_weights_hash = NEW.billing_model_weights_hash
          AND canonical_model.weights_hash = profile.model_weights_hash
          AND profile.reference_hardware_class
                = NEW.billing_reference_hardware_class
          AND profile.evidence_hash = NEW.billing_profile_evidence_hash
          AND profile.valid_from = NEW.billing_profile_valid_from
          AND profile.valid_until = NEW.billing_profile_valid_until
          AND profile.maximum_input_tokens = NEW.billing_profile_max_input_tokens
          AND profile.maximum_output_tokens = NEW.billing_profile_max_output_tokens
          AND profile.fixed_gpu_time_us = NEW.billing_fixed_gpu_time_us
          AND profile.gpu_time_us_per_1k_tokens
                = NEW.billing_gpu_time_us_per_1k_tokens
          AND profile.reference_vram_mib = NEW.billing_reference_vram_mib
          AND profile.token_rate_micro_per_1k
                = NEW.billing_token_rate_micro_per_1k
          AND profile.gpu_rate_micro_per_second
                = NEW.billing_gpu_rate_micro_per_second
          AND profile.vram_rate_micro_per_gib_second
                = NEW.billing_vram_rate_micro_per_gib_second
          AND profile.profile_fingerprint = NEW.billing_profile_fingerprint
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'billing snapshot does not match immutable profile';
    END IF;

    -- NEW is a dynamically typed trigger record.  Keep the jobs-only field
    -- access in a nested branch: referencing NEW.regulated_route_id in a
    -- boolean expression for a receipts trigger is still resolved by
    -- PostgreSQL and fails before ordinary short-circuiting can help.
    IF TG_TABLE_NAME = 'jobs' THEN
        IF NEW.regulated_route_id IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1 FROM regulated_routes AS route
                WHERE route.id = NEW.regulated_route_id
                  AND route.billing_contract_version
                        = 'server_reference_upper_bound_v1'
                  AND route.billing_profile_id = NEW.billing_profile_id
                  AND route.billing_authorized_input_tokens
                        = NEW.billing_authorized_input_tokens
                  AND route.billing_authorized_max_output_tokens
                        = NEW.billing_authorized_max_output_tokens
                  AND route.billing_billable_tokens = NEW.billing_billable_tokens
                  AND route.billing_reference_gpu_time_us
                        = NEW.billing_reference_gpu_time_us
                  AND route.billing_reference_vram_mib_microseconds
                        = NEW.billing_reference_vram_mib_microseconds
                  AND route.billing_token_cost_micro = NEW.billing_token_cost_micro
                  AND route.billing_gpu_cost_micro = NEW.billing_gpu_cost_micro
                  AND route.billing_vram_cost_micro = NEW.billing_vram_cost_micro
                  AND route.billing_base_cost_micro = NEW.billing_base_cost_micro
            ) THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    MESSAGE = 'regulated job billing snapshot does not match prepared route';
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER jobs_physical_billing_snapshot_guard_v1
    BEFORE INSERT OR UPDATE OF
        billing_contract_version,billing_profile_id,billing_profile_version,
        billing_profile_fingerprint,billing_model_weights_hash,
        billing_reference_hardware_class,billing_profile_evidence_hash,
        billing_profile_valid_from,billing_profile_valid_until,
        billing_profile_max_input_tokens,billing_profile_max_output_tokens,
        billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
        billing_reference_vram_mib,billing_token_rate_micro_per_1k,
        billing_gpu_rate_micro_per_second,
        billing_vram_rate_micro_per_gib_second,
        billing_authorized_input_tokens,billing_authorized_max_output_tokens,
        billing_billable_tokens,billing_reference_gpu_time_us,
        billing_reference_vram_mib_microseconds,billing_token_cost_micro,
        billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
    ON jobs
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_physical_billing_snapshot_v1();

CREATE TRIGGER regulated_routes_billing_snapshot_guard_v1
    BEFORE INSERT OR UPDATE OF
        billing_contract_version,billing_profile_id,billing_profile_version,
        billing_profile_fingerprint,billing_model_weights_hash,
        billing_reference_hardware_class,billing_profile_evidence_hash,
        billing_profile_valid_from,billing_profile_valid_until,
        billing_profile_max_input_tokens,billing_profile_max_output_tokens,
        billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
        billing_reference_vram_mib,billing_token_rate_micro_per_1k,
        billing_gpu_rate_micro_per_second,
        billing_vram_rate_micro_per_gib_second,
        billing_authorized_input_tokens,billing_authorized_max_output_tokens,
        billing_billable_tokens,billing_reference_gpu_time_us,
        billing_reference_vram_mib_microseconds,billing_token_cost_micro,
        billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
    ON regulated_routes
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_physical_billing_snapshot_v1();

CREATE TRIGGER receipts_physical_billing_snapshot_guard_v1
    BEFORE INSERT ON receipts
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_physical_billing_snapshot_v1();

CREATE OR REPLACE FUNCTION mindone_prevent_physical_billing_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        MESSAGE = 'MindOne physical billing records are append-only';
END;
$$;

CREATE OR REPLACE FUNCTION mindone_guard_legacy_billing_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.billing_contract_version = 'legacy_token_v1' THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'legacy physical billing identity cannot be deleted';
        END IF;
        RETURN OLD;
    END IF;
    IF OLD.billing_contract_version = 'legacy_token_v1'
       AND NEW.id IS DISTINCT FROM OLD.id THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'legacy physical billing identity cannot be rebound';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER billing_profiles_append_only_v1
    BEFORE UPDATE OR DELETE ON billing_profiles
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_physical_billing_mutation();
CREATE TRIGGER physical_billing_legacy_allowlist_append_only_v1
    BEFORE INSERT OR UPDATE OR DELETE ON physical_billing_legacy_allowlist
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_physical_billing_mutation();
CREATE TRIGGER receipts_append_only_v1
    BEFORE UPDATE OR DELETE ON receipts
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_physical_billing_mutation();
CREATE TRIGGER jobs_legacy_billing_identity_guard_v1
    BEFORE UPDATE OF id OR DELETE ON jobs
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_legacy_billing_identity_v1();
CREATE TRIGGER regulated_routes_legacy_identity_guard_v1
    BEFORE UPDATE OF id OR DELETE ON regulated_routes
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_legacy_billing_identity_v1();

-- Migration 0026 grants future tables broad runtime DML by default. Narrow the
-- immutable/audit surfaces explicitly: profiles are insert-and-read, the legacy
-- allowlist is read-only, and receipts are append-and-read.
REVOKE ALL PRIVILEGES ON TABLE billing_profiles FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE physical_billing_legacy_allowlist FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLE receipts FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON TABLE billing_profiles FROM mindone_app;
        GRANT SELECT, INSERT ON TABLE billing_profiles TO mindone_app;
        REVOKE ALL PRIVILEGES ON TABLE physical_billing_legacy_allowlist FROM mindone_app;
        GRANT SELECT ON TABLE physical_billing_legacy_allowlist TO mindone_app;
        REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
            ON TABLE receipts FROM mindone_app;
        GRANT SELECT, INSERT ON TABLE receipts TO mindone_app;
    END IF;
END;
$$;

REVOKE ALL PRIVILEGES ON FUNCTION mindone_billing_profile_fingerprint_v1(
    UUID,TEXT,BIGINT,UUID,TEXT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
    BIGINT,BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_validate_billing_profile_v1() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_physical_billing_snapshot_is_valid_v1(
    TEXT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,
    BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
    BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT
) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_guard_physical_billing_snapshot_v1() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_prevent_physical_billing_mutation() FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_guard_legacy_billing_identity_v1() FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_billing_profile_fingerprint_v1(
            UUID,TEXT,BIGINT,UUID,TEXT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
            BIGINT,BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ
        ) FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_validate_billing_profile_v1()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_physical_billing_snapshot_is_valid_v1(
            TEXT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,
            BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
            BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT
        ) FROM mindone_app;
        GRANT EXECUTE ON FUNCTION mindone_physical_billing_snapshot_is_valid_v1(
            TEXT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,
            BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
            BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT
        ) TO mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_guard_physical_billing_snapshot_v1()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_prevent_physical_billing_mutation()
            FROM mindone_app;
        REVOKE ALL PRIVILEGES ON FUNCTION mindone_guard_legacy_billing_identity_v1()
            FROM mindone_app;
    END IF;
END;
$$;
