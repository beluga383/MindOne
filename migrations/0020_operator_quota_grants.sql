-- 生产初始额度的受控运维入口。赠额审计和 quota 账本都只追加，
-- 且数据库在插入时验证两者的用户、金额、幂等键和哈希引用一致。

CREATE TABLE operator_quota_grants (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
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
    idempotency_key TEXT NOT NULL UNIQUE CHECK (
        octet_length(idempotency_key) BETWEEN 1 AND 128
        AND idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9._:@/-]*$'
    ),
    request_fingerprint TEXT NOT NULL CHECK (
        request_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    quota_ledger_id UUID NOT NULL UNIQUE REFERENCES quota_ledger(id) ON DELETE RESTRICT,
    quota_ledger_entry_hash TEXT NOT NULL CHECK (
        quota_ledger_entry_hash ~ '^[0-9a-f]{64}$'
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX operator_quota_grants_user_time_idx
    ON operator_quota_grants (user_id, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION mindone_validate_operator_quota_grant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM quota_ledger q
        WHERE q.id = NEW.quota_ledger_id
          AND q.user_id = NEW.user_id
          AND q.request_id IS NULL
          AND q.entry_type = 'operator_grant'
          AND q.delta_micro = NEW.amount_micro
          AND q.balance_after_micro = q.balance_before_micro + NEW.amount_micro
          AND q.idempotency_key = 'operator-grant:' || NEW.idempotency_key
          AND q.entry_hash = NEW.quota_ledger_entry_hash
          AND EXISTS (
              SELECT 1 FROM quota_accounts a
              WHERE a.user_id = NEW.user_id
                AND a.spendable_micro = q.balance_after_micro
          )
    ) THEN
        RAISE EXCEPTION 'operator quota grant does not match its quota ledger entry';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS operator_quota_grants_validate_ledger ON operator_quota_grants;
CREATE TRIGGER operator_quota_grants_validate_ledger
    BEFORE INSERT ON operator_quota_grants
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_operator_quota_grant();

DROP TRIGGER IF EXISTS operator_quota_grants_append_only ON operator_quota_grants;
CREATE TRIGGER operator_quota_grants_append_only
    BEFORE UPDATE OR DELETE ON operator_quota_grants
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();
