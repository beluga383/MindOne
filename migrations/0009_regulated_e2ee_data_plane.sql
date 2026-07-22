-- Regulated/Enhanced E2EE 数据面。
-- Standard 任务仍是明确的 base64 JSON；只有绑定硬件报告的一次性 route 可创建
-- regulated 任务。协调器只持久化不透明 AEAD envelope，不解密 Prompt/Response。

ALTER TABLE attestation_challenges
    ADD COLUMN IF NOT EXISTS key_origin TEXT NOT NULL DEFAULT 'control_software'
        CHECK (key_origin IN ('control_software', 'tee_runtime'));

ALTER TABLE attestation_reports
    ADD COLUMN IF NOT EXISTS key_origin TEXT NOT NULL DEFAULT 'control_software'
        CHECK (key_origin IN ('control_software', 'tee_runtime')),
    ADD COLUMN IF NOT EXISTS evidence_base64 TEXT;

ALTER TABLE attestation_reports
    ADD CONSTRAINT attestation_reports_evidence_base64_v1 CHECK (
        evidence_base64 IS NULL
        OR (length(evidence_base64) BETWEEN 4 AND 786432)
    );

CREATE TABLE regulated_routes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_instance_id UUID NOT NULL REFERENCES model_instances(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    attestation_report_id UUID NOT NULL REFERENCES attestation_reports(id) ON DELETE RESTRICT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    estimated_input_tokens INTEGER NOT NULL CHECK (estimated_input_tokens >= 0),
    max_output_tokens INTEGER NOT NULL CHECK (max_output_tokens > 0),
    priority INTEGER NOT NULL DEFAULT 0 CHECK (priority BETWEEN -100 AND 100),
    status TEXT NOT NULL DEFAULT 'prepared'
        CHECK (status IN ('prepared', 'consumed', 'expired')),
    prepared_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    job_id UUID UNIQUE,
    UNIQUE (user_id, idempotency_key),
    CHECK (expires_at > prepared_at),
    CHECK (
        (status = 'prepared' AND consumed_at IS NULL AND job_id IS NULL)
        OR (status = 'consumed' AND consumed_at IS NOT NULL AND job_id IS NOT NULL)
        OR (status = 'expired' AND consumed_at IS NOT NULL AND job_id IS NULL)
    )
);

CREATE INDEX regulated_routes_ready_idx
    ON regulated_routes (user_id, expires_at)
    WHERE status = 'prepared';

ALTER TABLE jobs
    ADD COLUMN IF NOT EXISTS confidentiality_mode TEXT NOT NULL DEFAULT 'standard'
        CHECK (confidentiality_mode IN ('standard', 'regulated')),
    ADD COLUMN IF NOT EXISTS regulated_route_id UUID UNIQUE
        REFERENCES regulated_routes(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS regulated_node_id UUID
        REFERENCES nodes(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS attestation_report_id UUID
        REFERENCES attestation_reports(id) ON DELETE RESTRICT;

ALTER TABLE jobs
    ADD CONSTRAINT jobs_regulated_binding_v1 CHECK (
        (confidentiality_mode = 'standard'
            AND regulated_route_id IS NULL
            AND regulated_node_id IS NULL
            AND attestation_report_id IS NULL)
        OR
        (confidentiality_mode = 'regulated'
            AND regulated_route_id IS NOT NULL
            AND regulated_node_id IS NOT NULL
            AND attestation_report_id IS NOT NULL
            AND model_instance_id IS NOT NULL)
    );

ALTER TABLE regulated_routes
    ADD CONSTRAINT regulated_routes_job_fk_v1
    FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE RESTRICT;

CREATE INDEX jobs_regulated_claim_idx
    ON jobs (regulated_node_id, status, available_at, priority DESC, created_at)
    WHERE confidentiality_mode = 'regulated'
      AND status IN ('queued', 'retry', 'leased');
