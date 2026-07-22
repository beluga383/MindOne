-- 每个已结算任务的延迟/显存风险指纹，以及服务端生成的只追加异常账本。
-- 节点上报值只能作为风险信号；是否产生告警及基线全部由协调服务器计算。

ALTER TABLE jobs
    ADD COLUMN result_telemetry_fingerprint TEXT
        CHECK (result_telemetry_fingerprint IS NULL
            OR result_telemetry_fingerprint ~ '^[0-9a-f]{64}$');

CREATE TABLE job_execution_telemetry (
    id UUID PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_instance_id UUID REFERENCES model_instances(id) ON DELETE SET NULL,
    attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
    result_idempotency_key TEXT NOT NULL,
    evidence_kind TEXT NOT NULL CHECK (evidence_kind IN (
        'standard_self_reported_risk_signal',
        'enhanced_node_reported_risk_signal'
    )),
    ttft_ms BIGINT,
    tps_milli BIGINT,
    peak_vram_mib BIGINT,
    vram_sample_count INTEGER NOT NULL CHECK (vram_sample_count >= 0),
    declared_vram_total_mib BIGINT,
    model_size_bytes BIGINT NOT NULL CHECK (model_size_bytes > 0),
    model_soft_min_peak_mib BIGINT NOT NULL CHECK (model_soft_min_peak_mib > 0),
    model_critical_min_peak_mib BIGINT NOT NULL CHECK (model_critical_min_peak_mib > 0),
    historical_ttft_median_ms BIGINT,
    historical_tps_median_milli BIGINT,
    historical_sample_count BIGINT NOT NULL CHECK (historical_sample_count >= 0),
    hardware_cohort_key TEXT NOT NULL CHECK (hardware_cohort_key ~ '^[0-9a-f]{64}$'),
    verdict TEXT NOT NULL CHECK (verdict IN (
        'insufficient_evidence', 'no_anomaly_observed', 'warning', 'critical'
    )),
    assessment_version TEXT NOT NULL,
    telemetry_fingerprint TEXT NOT NULL CHECK (telemetry_fingerprint ~ '^[0-9a-f]{64}$'),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (job_id, result_idempotency_key)
);

CREATE INDEX job_execution_telemetry_node_time_idx
    ON job_execution_telemetry (node_id, recorded_at DESC, id DESC);
CREATE INDEX job_execution_telemetry_model_time_idx
    ON job_execution_telemetry (model_id, recorded_at DESC, id DESC);

CREATE TABLE execution_anomaly_ledger (
    id UUID PRIMARY KEY,
    telemetry_id UUID NOT NULL REFERENCES job_execution_telemetry(id) ON DELETE RESTRICT,
    job_id UUID NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    severity TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    code TEXT NOT NULL,
    explanation TEXT NOT NULL,
    observed JSONB NOT NULL,
    expected JSONB NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (telemetry_id, code)
);

CREATE INDEX execution_anomaly_ledger_node_time_idx
    ON execution_anomaly_ledger (node_id, created_at DESC, id DESC);

DROP TRIGGER IF EXISTS job_execution_telemetry_append_only ON job_execution_telemetry;
CREATE TRIGGER job_execution_telemetry_append_only
    BEFORE UPDATE OR DELETE ON job_execution_telemetry
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();

DROP TRIGGER IF EXISTS execution_anomaly_ledger_append_only ON execution_anomaly_ledger;
CREATE TRIGGER execution_anomaly_ledger_append_only
    BEFORE UPDATE OR DELETE ON execution_anomaly_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();
