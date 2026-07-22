-- 一次性硬件远程证明挑战与可审计验证结论。
-- 原始 quote 不入库；只保存不可逆摘要和 verifier 的逐项结论。

CREATE TABLE IF NOT EXISTS attestation_challenges (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    model_instance_id UUID NOT NULL REFERENCES model_instances(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (provider IN ('amd_sev_snp', 'intel_tdx')),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    nonce_hash TEXT NOT NULL UNIQUE CHECK (length(nonce_hash) = 64),
    sandbox_policy_hash TEXT NOT NULL CHECK (length(sandbox_policy_hash) = 64),
    runtime_binary_hash TEXT NOT NULL CHECK (length(runtime_binary_hash) = 64),
    model_weights_hash TEXT NOT NULL CHECK (length(model_weights_hash) = 64),
    ephemeral_public_key TEXT NOT NULL CHECK (length(ephemeral_public_key) = 64),
    report_data TEXT NOT NULL CHECK (length(report_data) = 128),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'rejected', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK ((status = 'pending') = (consumed_at IS NULL))
);

CREATE INDEX IF NOT EXISTS attestation_challenges_owner_idx
    ON attestation_challenges (user_id, node_id, model_instance_id, created_at DESC);
CREATE INDEX IF NOT EXISTS attestation_challenges_expiry_idx
    ON attestation_challenges (expires_at) WHERE status = 'pending';

ALTER TABLE attestation_reports
    ADD COLUMN IF NOT EXISTS challenge_id UUID REFERENCES attestation_challenges(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS model_instance_id UUID REFERENCES model_instances(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS evidence_kind TEXT,
    ADD COLUMN IF NOT EXISTS evidence_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS report_data TEXT,
    ADD COLUMN IF NOT EXISTS tee_measurement TEXT,
    ADD COLUMN IF NOT EXISTS ephemeral_public_key TEXT,
    ADD COLUMN IF NOT EXISTS verifier_name TEXT NOT NULL DEFAULT 'legacy-unverified',
    ADD COLUMN IF NOT EXISTS signature_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS certificate_chain_verified BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS tcb_current BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS collateral_current BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS collateral_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS verdict_reason TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS attestation_reports_challenge_idx
    ON attestation_reports (challenge_id) WHERE challenge_id IS NOT NULL;

ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS attestation_report_id UUID REFERENCES attestation_reports(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS trust_expires_at TIMESTAMPTZ;

ALTER TABLE attestation_reports
    ADD CONSTRAINT attestation_reports_verified_fields_v1 CHECK (
        status <> 'verified'
        OR (
            challenge_id IS NOT NULL
            AND model_instance_id IS NOT NULL
            AND evidence_sha256 IS NOT NULL
            AND report_data IS NOT NULL
            AND tee_measurement IS NOT NULL
            AND ephemeral_public_key IS NOT NULL
            AND signature_verified
            AND certificate_chain_verified
            AND tcb_current
            AND collateral_current
            AND collateral_expires_at IS NOT NULL
            AND verified_at IS NOT NULL
        )
    );

-- 旧部署可能已有实验性 provider 行，因此不回溯验证旧数据；新写入仍受约束。
ALTER TABLE attestation_reports
    ADD CONSTRAINT attestation_reports_provider_v1
    CHECK (provider IN ('amd_sev_snp', 'intel_tdx')) NOT VALID;
