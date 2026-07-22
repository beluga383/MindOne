-- 真正的 hidden benchmark 内容来自仓库外、受信 evaluator 签名的私有 catalog。
-- 数据库只保存一次性条目、模型/实例/nonce/时效绑定和行为 commitment；不得保存
-- Prompt、预期响应或实际响应明文。
ALTER TABLE model_evaluation_challenges
    ADD COLUMN IF NOT EXISTS model_weights_hash TEXT,
    ADD COLUMN IF NOT EXISTS challenge_nonce_hash TEXT,
    ADD COLUMN IF NOT EXISTS challenge_binding_hash TEXT,
    ADD COLUMN IF NOT EXISTS challenge_issued_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS authorized_input_tokens INTEGER,
    ADD COLUMN IF NOT EXISTS authorized_max_output_tokens INTEGER,
    ADD COLUMN IF NOT EXISTS inference_seed BIGINT,
    ADD COLUMN IF NOT EXISTS private_catalog_id TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_entry_id TEXT,
    ADD COLUMN IF NOT EXISTS private_case_family TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_id TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_key_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_valid_until TIMESTAMPTZ;

ALTER TABLE model_evaluation_challenges
    ADD CONSTRAINT model_evaluation_execution_binding_v1 CHECK (
        (model_weights_hash IS NULL
            AND challenge_nonce_hash IS NULL
            AND challenge_binding_hash IS NULL
            AND challenge_issued_expires_at IS NULL
            AND authorized_input_tokens IS NULL
            AND authorized_max_output_tokens IS NULL
            AND inference_seed IS NULL)
        OR
        (model_weights_hash ~ '^[0-9a-f]{64}$'
            AND challenge_nonce_hash ~ '^[0-9a-f]{64}$'
            AND challenge_binding_hash ~ '^[0-9a-f]{64}$'
            AND challenge_issued_expires_at IS NOT NULL
            AND authorized_input_tokens > 0
            AND authorized_max_output_tokens > 0
            AND inference_seed BETWEEN 0 AND 4294967295)
    ),
    ADD CONSTRAINT model_evaluation_private_catalog_v1 CHECK (
        (private_catalog_id IS NULL
            AND private_catalog_entry_id IS NULL
            AND private_case_family IS NULL
            AND private_catalog_commitment IS NULL
            AND private_evaluator_id IS NULL
            AND private_evaluator_key_fingerprint IS NULL
            AND private_catalog_valid_until IS NULL)
        OR
        (challenge_kind = 'hidden_benchmark'
            AND private_catalog_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_catalog_entry_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_case_family ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_catalog_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_evaluator_key_fingerprint ~ '^[0-9a-f]{64}$'
            AND private_catalog_valid_until IS NOT NULL
            AND model_weights_hash IS NOT NULL
            AND challenge_nonce_hash IS NOT NULL
            AND challenge_binding_hash IS NOT NULL)
    );

-- catalog 条目全网只消费一次；补充题库必须由 evaluator 签发新 statement/entry。
CREATE UNIQUE INDEX model_evaluation_private_entry_once_v1
    ON model_evaluation_challenges
       (private_catalog_commitment, private_catalog_entry_id)
    WHERE private_catalog_commitment IS NOT NULL;

-- catalog 轮换不能让已暴露的 Prompt 或已观察到的模型输出重新变成有效挑战。
-- evaluator 必须为每次签发提供全新的 Prompt 与行为指纹；ON CONFLICT 的领取路径会
-- 跳过旧条目并最终安全降级为公开 canary。
CREATE UNIQUE INDEX model_evaluation_private_prompt_once_v1
    ON model_evaluation_challenges (prompt_hash)
    WHERE private_catalog_commitment IS NOT NULL;
CREATE UNIQUE INDEX model_evaluation_private_behavior_once_v1
    ON model_evaluation_challenges (expected_hash)
    WHERE private_catalog_commitment IS NOT NULL;

-- 每个私有结果写一条只追加跨实例仲裁快照。仲裁按目标权重与 case family 聚合，
-- 只有至少两个不同实例才能得到 corroborated/disputed；单实例永远是 pending。
CREATE TABLE model_authenticity_arbitration_events (
    id UUID PRIMARY KEY,
    challenge_id UUID NOT NULL UNIQUE
        REFERENCES model_evaluation_challenges(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_instance_id UUID NOT NULL
        REFERENCES model_instances(id) ON DELETE RESTRICT,
    model_weights_hash TEXT NOT NULL CHECK (model_weights_hash ~ '^[0-9a-f]{64}$'),
    private_evaluator_key_fingerprint TEXT NOT NULL
        CHECK (private_evaluator_key_fingerprint ~ '^[0-9a-f]{64}$'),
    private_catalog_commitment TEXT NOT NULL
        CHECK (private_catalog_commitment ~ '^[0-9a-f]{64}$'),
    private_case_family TEXT NOT NULL
        CHECK (private_case_family ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    passed BOOLEAN NOT NULL,
    observed_distinct_instances INTEGER NOT NULL CHECK (observed_distinct_instances > 0),
    passed_distinct_instances INTEGER NOT NULL CHECK (passed_distinct_instances >= 0),
    failed_distinct_instances INTEGER NOT NULL CHECK (failed_distinct_instances >= 0),
    verdict TEXT NOT NULL CHECK (verdict IN ('pending','corroborated','disputed')),
    challenge_binding_hash TEXT NOT NULL
        CHECK (challenge_binding_hash ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT model_authenticity_arbitration_counts_v1 CHECK (
        observed_distinct_instances
            = passed_distinct_instances + failed_distinct_instances
        AND (
            (verdict = 'pending' AND observed_distinct_instances < 2)
            OR
            (verdict = 'corroborated'
                AND observed_distinct_instances >= 2
                AND passed_distinct_instances >= 2
                AND failed_distinct_instances = 0)
            OR
            (verdict = 'disputed'
                AND observed_distinct_instances >= 2
                AND failed_distinct_instances > 0)
        )
    )
);

CREATE INDEX model_authenticity_arbitration_family_time_v1
    ON model_authenticity_arbitration_events
       (model_weights_hash,private_evaluator_key_fingerprint,
        private_case_family,created_at DESC,id DESC);

DROP TRIGGER IF EXISTS model_authenticity_arbitration_events_append_only
    ON model_authenticity_arbitration_events;
CREATE TRIGGER model_authenticity_arbitration_events_append_only
    BEFORE UPDATE OR DELETE ON model_authenticity_arbitration_events
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
