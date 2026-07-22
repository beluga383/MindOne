-- MindOne 协调服务器 v1 初始结构。
-- 金额字段全部使用整数 microquota；账本表通过触发器强制只追加。

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    username TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_subject)
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash TEXT NOT NULL UNIQUE,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS sessions_user_active_idx
    ON sessions (user_id, access_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_device_flows (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL,
    provider_device_code TEXT NOT NULL,
    user_code TEXT NOT NULL,
    verification_uri TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL CHECK (interval_seconds > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'authorized', 'denied', 'expired')),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_polled_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS auth_device_flows_expiry_idx
    ON auth_device_flows (expires_at) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS device_keys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS quota_accounts (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    spendable_micro BIGINT NOT NULL DEFAULT 0 CHECK (spendable_micro >= 0),
    reserved_micro BIGINT NOT NULL DEFAULT 0 CHECK (reserved_micro >= 0),
    contribution_micro BIGINT NOT NULL DEFAULT 0 CHECK (contribution_micro >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (reserved_micro <= spendable_micro)
);

CREATE TABLE IF NOT EXISTS nodes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'unverified'
        CHECK (trust_level IN ('enhanced', 'standard', 'standard-limited', 'unverified', 'experimental')),
    status TEXT NOT NULL DEFAULT 'offline'
        CHECK (status IN ('online', 'paused', 'draining', 'offline')),
    pause_reason TEXT,
    hardware_profile JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    UNIQUE (user_id, alias)
);

CREATE INDEX IF NOT EXISTS nodes_status_last_seen_idx ON nodes (status, last_seen_at);

CREATE TABLE IF NOT EXISTS node_policies (
    node_id UUID PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
    reject_tags TEXT[] NOT NULL DEFAULT '{}',
    max_concurrent INTEGER NOT NULL DEFAULT 1 CHECK (max_concurrent > 0 AND max_concurrent <= 1024),
    gpu_temp_limit_c INTEGER NOT NULL DEFAULT 85 CHECK (gpu_temp_limit_c BETWEEN 30 AND 120),
    vram_reserve_mib BIGINT NOT NULL DEFAULT 0 CHECK (vram_reserve_mib >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS node_metrics (
    id UUID PRIMARY KEY,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    tps_milli BIGINT NOT NULL DEFAULT 0 CHECK (tps_milli >= 0),
    ttft_ms BIGINT NOT NULL DEFAULT 0 CHECK (ttft_ms >= 0),
    current_concurrent INTEGER NOT NULL DEFAULT 0 CHECK (current_concurrent >= 0),
    gpu_temp_c INTEGER,
    vram_used_mib BIGINT,
    vram_total_mib BIGINT,
    error_rate_ppm INTEGER NOT NULL DEFAULT 0 CHECK (error_rate_ppm BETWEEN 0 AND 1000000),
    measured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS node_metrics_node_time_idx
    ON node_metrics (node_id, measured_at DESC);

CREATE TABLE IF NOT EXISTS heartbeats (
    id UUID PRIMARY KEY,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    status TEXT NOT NULL,
    accepting_jobs BOOLEAN NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS heartbeats_node_time_idx
    ON heartbeats (node_id, received_at DESC);

CREATE TABLE IF NOT EXISTS models (
    id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('gguf', 'safetensors')),
    weights_hash TEXT NOT NULL CHECK (weights_hash ~ '^[0-9a-f]{64}$'),
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    context_length INTEGER NOT NULL CHECK (context_length > 0),
    benchmark_normalized INTEGER NOT NULL DEFAULT 0
        CHECK (benchmark_normalized BETWEEN 0 AND 1000000),
    glicko_normalized INTEGER NOT NULL DEFAULT 0
        CHECK (glicko_normalized BETWEEN 0 AND 1000000),
    evaluation_samples INTEGER NOT NULL DEFAULT 0 CHECK (evaluation_samples >= 0),
    tier TEXT NOT NULL DEFAULT 'medium' CHECK (tier IN ('high', 'medium', 'low')),
    base_cost_per_1k_micro BIGINT NOT NULL CHECK (base_cost_per_1k_micro > 0),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (owner_user_id, name, weights_hash)
);

CREATE INDEX IF NOT EXISTS models_name_enabled_idx ON models (name, enabled);

CREATE TABLE IF NOT EXISTS model_instances (
    id UUID PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    tags TEXT[] NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'published'
        CHECK (status IN ('published', 'draining', 'unpublished')),
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    unpublished_at TIMESTAMPTZ,
    UNIQUE (node_id, alias)
);

CREATE INDEX IF NOT EXISTS model_instances_routing_idx
    ON model_instances (model_id, status, node_id);

CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_instance_id UUID REFERENCES model_instances(id) ON DELETE SET NULL,
    idempotency_key TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'leased', 'retry', 'succeeded', 'failed', 'cancelled')),
    encrypted_payload TEXT NOT NULL,
    payload_encoding TEXT NOT NULL DEFAULT 'base64',
    tags TEXT[] NOT NULL DEFAULT '{}',
    estimated_input_tokens INTEGER NOT NULL CHECK (estimated_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens > 0),
    reserved_cost_micro BIGINT NOT NULL CHECK (reserved_cost_micro > 0),
    priority INTEGER NOT NULL DEFAULT 0,
    leased_to_node_id UUID REFERENCES nodes(id) ON DELETE SET NULL,
    lease_expires_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts > 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    result_ciphertext TEXT,
    result_idempotency_key TEXT,
    actual_input_tokens INTEGER,
    actual_output_tokens INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE (user_id, idempotency_key)
);

CREATE UNIQUE INDEX IF NOT EXISTS jobs_result_idempotency_idx
    ON jobs (id, result_idempotency_key) WHERE result_idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS jobs_claim_idx
    ON jobs (status, available_at, priority DESC, created_at)
    WHERE status IN ('queued', 'retry', 'leased');

CREATE TABLE IF NOT EXISTS job_attempts (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    status TEXT NOT NULL CHECK (status IN ('leased', 'succeeded', 'failed', 'expired')),
    lease_started_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    error_class TEXT,
    error_message TEXT,
    result_idempotency_key TEXT,
    UNIQUE (job_id, attempt_number),
    UNIQUE (job_id, result_idempotency_key)
);

CREATE INDEX IF NOT EXISTS job_attempts_node_idx ON job_attempts (node_id, status);

CREATE TABLE IF NOT EXISTS quota_ledger (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id UUID REFERENCES jobs(id) ON DELETE RESTRICT,
    entry_type TEXT NOT NULL,
    delta_micro BIGINT NOT NULL,
    balance_before_micro BIGINT NOT NULL CHECK (balance_before_micro >= 0),
    balance_after_micro BIGINT NOT NULL CHECK (balance_after_micro >= 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS quota_ledger_user_time_idx
    ON quota_ledger (user_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS contribution_ledger (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    request_id UUID REFERENCES jobs(id) ON DELETE RESTRICT,
    entry_type TEXT NOT NULL,
    delta_micro BIGINT NOT NULL CHECK (delta_micro >= 0),
    balance_before_micro BIGINT NOT NULL CHECK (balance_before_micro >= 0),
    balance_after_micro BIGINT NOT NULL CHECK (balance_after_micro >= 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS contribution_ledger_user_time_idx
    ON contribution_ledger (user_id, created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS reserve_accounts (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    balance_micro BIGINT NOT NULL DEFAULT 0 CHECK (balance_micro >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO reserve_accounts (id, balance_micro)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS reserve_ledger (
    id UUID PRIMARY KEY,
    request_id UUID REFERENCES jobs(id) ON DELETE RESTRICT,
    entry_type TEXT NOT NULL CHECK (entry_type IN ('settlement_inflow', 'verification', 'retry', 'bandwidth', 'peak_capacity')),
    delta_micro BIGINT NOT NULL,
    balance_before_micro BIGINT NOT NULL CHECK (balance_before_micro >= 0),
    balance_after_micro BIGINT NOT NULL CHECK (balance_after_micro >= 0),
    idempotency_key TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS reserve_ledger_time_idx
    ON reserve_ledger (created_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS receipts (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
    consumer_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    node_user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    model_name TEXT NOT NULL,
    tier TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    base_cost_micro BIGINT NOT NULL CHECK (base_cost_micro >= 0),
    user_deduction_micro BIGINT NOT NULL CHECK (user_deduction_micro >= 0),
    node_quota_micro BIGINT NOT NULL CHECK (node_quota_micro >= 0),
    contribution_micro BIGINT NOT NULL CHECK (contribution_micro >= 0),
    reserve_micro BIGINT NOT NULL CHECK (reserve_micro >= 0),
    settlement_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attestation_reports (
    id UUID PRIMARY KEY,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    runtime_hash TEXT NOT NULL,
    model_hash TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'rejected', 'expired')),
    UNIQUE (node_id, nonce_hash)
);

CREATE OR REPLACE FUNCTION mindone_prevent_ledger_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MindOne ledger rows are append-only';
END;
$$;

DROP TRIGGER IF EXISTS quota_ledger_append_only ON quota_ledger;
CREATE TRIGGER quota_ledger_append_only
    BEFORE UPDATE OR DELETE ON quota_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();

DROP TRIGGER IF EXISTS contribution_ledger_append_only ON contribution_ledger;
CREATE TRIGGER contribution_ledger_append_only
    BEFORE UPDATE OR DELETE ON contribution_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();

DROP TRIGGER IF EXISTS reserve_ledger_append_only ON reserve_ledger;
CREATE TRIGGER reserve_ledger_append_only
    BEFORE UPDATE OR DELETE ON reserve_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();
