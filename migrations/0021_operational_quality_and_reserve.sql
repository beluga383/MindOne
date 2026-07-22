-- 服务器侧受控质量评价与准备金释放入口。公网 HTTP 不暴露写接口；
-- 两类操作都必须绑定 operator、幂等指纹和只追加审计。

CREATE TABLE quality_evidence_audits (
    id UUID PRIMARY KEY,
    quality_event_id UUID NOT NULL UNIQUE
        REFERENCES model_quality_events(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    evaluator_id TEXT NOT NULL CHECK (
        octet_length(evaluator_id) BETWEEN 1 AND 128
        AND evaluator_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
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
    event_kind TEXT NOT NULL CHECK (
        event_kind IN ('hidden_benchmark', 'canary', 'blind_evaluation')
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    request_fingerprint TEXT NOT NULL UNIQUE CHECK (
        request_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    evidence_schema TEXT NOT NULL CHECK (
        evidence_schema = 'mindone-quality-evidence-v1'
    ),
    statement_json TEXT NOT NULL CHECK (
        octet_length(statement_json) BETWEEN 2 AND 65536
    ),
    statement_sha256 TEXT NOT NULL UNIQUE CHECK (
        statement_sha256 ~ '^[0-9a-f]{64}$'
    ),
    artifact_sha256 TEXT NOT NULL CHECK (
        artifact_sha256 ~ '^[0-9a-f]{64}$'
    ),
    evaluator_key_fingerprint TEXT NOT NULL CHECK (
        evaluator_key_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    signature_hex TEXT NOT NULL CHECK (
        signature_hex ~ '^[0-9a-f]{128}$'
    ),
    observed_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL CHECK (valid_until > observed_at),
    verified_at TIMESTAMPTZ NOT NULL CHECK (verified_at <= valid_until),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX quality_evidence_audits_model_time_idx
    ON quality_evidence_audits (model_id, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION mindone_validate_quality_evidence_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM model_quality_events event
        WHERE event.id = NEW.quality_event_id
          AND event.model_id = NEW.model_id
          AND event.event_kind = NEW.event_kind
          AND event.idempotency_key = NEW.idempotency_key
          AND event.evidence_hash = NEW.artifact_sha256
    ) THEN
        RAISE EXCEPTION 'quality evidence audit does not match its quality event';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quality_evidence_audits_validate_event
    BEFORE INSERT ON quality_evidence_audits
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_quality_evidence_audit();

CREATE TRIGGER quality_evidence_audits_append_only
    BEFORE UPDATE OR DELETE ON quality_evidence_audits
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();

CREATE TABLE operator_reserve_releases (
    id UUID PRIMARY KEY,
    reserve_ledger_id UUID NOT NULL UNIQUE
        REFERENCES reserve_ledger(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (
        purpose IN ('verification', 'retry', 'bandwidth', 'peak_capacity')
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
    amount_micro BIGINT NOT NULL CHECK (
        amount_micro > 0 AND amount_micro <= 1000000000000
    ),
    reference_id TEXT NOT NULL CHECK (
        octet_length(reference_id) BETWEEN 1 AND 255
        AND reference_id = btrim(reference_id)
        AND reference_id !~ '[[:cntrl:]]'
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    ),
    request_fingerprint TEXT NOT NULL UNIQUE CHECK (
        request_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    reserve_ledger_entry_hash TEXT NOT NULL CHECK (
        reserve_ledger_entry_hash ~ '^[0-9a-f]{64}$'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX operator_reserve_releases_time_idx
    ON operator_reserve_releases (created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION mindone_validate_operator_reserve_release()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM reserve_ledger ledger
        WHERE ledger.id = NEW.reserve_ledger_id
          AND ledger.request_id IS NULL
          AND ledger.entry_type = NEW.purpose
          AND ledger.delta_micro = -NEW.amount_micro
          AND ledger.balance_after_micro = ledger.balance_before_micro - NEW.amount_micro
          AND ledger.idempotency_key = NEW.idempotency_key
          AND ledger.audit_reference = NEW.reference_id
          AND ledger.entry_hash = NEW.reserve_ledger_entry_hash
          AND EXISTS (
              SELECT 1 FROM reserve_accounts account
              WHERE account.id = 1
                AND account.balance_micro = ledger.balance_after_micro
          )
    ) THEN
        RAISE EXCEPTION 'operator reserve release does not match its reserve ledger entry';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER operator_reserve_releases_validate_ledger
    BEFORE INSERT ON operator_reserve_releases
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_operator_reserve_release();

CREATE TRIGGER operator_reserve_releases_append_only
    BEFORE UPDATE OR DELETE ON operator_reserve_releases
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();
