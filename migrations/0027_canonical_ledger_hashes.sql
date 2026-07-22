-- 0024 建立了权威链头，但历史 writer 使用过多套哈希算法，数据库只校验了
-- 64hex 外形，且没有持久化 metadata，因而无法从数据库行重算 entry_hash。
-- 本迁移不改写既有链：旧行冻结为 legacy v1；此后所有新行必须使用统一的
-- length-prefixed UTF-8 v2 schema，并由 BEFORE INSERT trigger 在数据库内重算。

LOCK TABLE quota_ledger, contribution_ledger, reserve_ledger
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE quota_ledger
    ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE contribution_ledger
    ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE reserve_ledger
    ADD COLUMN hash_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

-- 迁移前的 entry_hash 可能来自旧 LedgerEntry JSON 或早期 writer 的拼接格式；
-- 在缺失 metadata 的前提下不能诚实重算。ADD COLUMN 的常量 DEFAULT 只为历史行
-- 建立 v1 标记，不触发 UPDATE，也不会绕过或触发只追加保护；原 hash/prev/head 与
-- 审计外键保持逐字不变。下面立即把未来 INSERT 的默认版本切换为 v2。

ALTER TABLE quota_ledger
    ALTER COLUMN hash_version SET DEFAULT 2,
    ALTER COLUMN hash_version SET NOT NULL,
    ALTER COLUMN metadata SET DEFAULT '{}'::jsonb,
    ALTER COLUMN metadata SET NOT NULL,
    ADD CONSTRAINT quota_ledger_hash_version CHECK (hash_version IN (1,2)),
    ADD CONSTRAINT quota_ledger_metadata_object CHECK (jsonb_typeof(metadata)='object'),
    ADD CONSTRAINT quota_ledger_legacy_metadata CHECK (
        hash_version=2 OR metadata='{}'::jsonb
    );
ALTER TABLE contribution_ledger
    ALTER COLUMN hash_version SET DEFAULT 2,
    ALTER COLUMN hash_version SET NOT NULL,
    ALTER COLUMN metadata SET DEFAULT '{}'::jsonb,
    ALTER COLUMN metadata SET NOT NULL,
    ADD CONSTRAINT contribution_ledger_hash_version CHECK (hash_version IN (1,2)),
    ADD CONSTRAINT contribution_ledger_metadata_object CHECK (jsonb_typeof(metadata)='object'),
    ADD CONSTRAINT contribution_ledger_legacy_metadata CHECK (
        hash_version=2 OR metadata='{}'::jsonb
    );
ALTER TABLE reserve_ledger
    ALTER COLUMN hash_version SET DEFAULT 2,
    ALTER COLUMN hash_version SET NOT NULL,
    ALTER COLUMN metadata SET DEFAULT '{}'::jsonb,
    ALTER COLUMN metadata SET NOT NULL,
    ADD CONSTRAINT reserve_ledger_hash_version CHECK (hash_version IN (1,2)),
    ADD CONSTRAINT reserve_ledger_metadata_object CHECK (jsonb_typeof(metadata)='object'),
    ADD CONSTRAINT reserve_ledger_legacy_metadata CHECK (
        hash_version=2 OR metadata='{}'::jsonb
    );

-- v2 canonical byte stream is the concatenation of these UTF-8 fields, each
-- encoded as decimal-octet-length ":" raw-value:
-- domain, version, scope, id, account_id, request_id-or-empty, idempotency_key,
-- entry_type, delta, before, after, unix-microseconds, prev_hash,
-- metadata-entry-count, then each metadata key/value sorted by UTF-8 bytes.
CREATE OR REPLACE FUNCTION mindone_ledger_hash_v2(
    p_scope TEXT,
    p_id UUID,
    p_account_id UUID,
    p_request_id UUID,
    p_idempotency_key TEXT,
    p_entry_type TEXT,
    p_delta_micro BIGINT,
    p_balance_before_micro BIGINT,
    p_balance_after_micro BIGINT,
    p_created_at TIMESTAMPTZ,
    p_prev_hash TEXT,
    p_metadata JSONB
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
    metadata_row RECORD;
    metadata_value TEXT;
    metadata_count BIGINT;
    created_at_unix_micros BIGINT;
BEGIN
    IF p_scope NOT IN ('quota','contribution','reserve') THEN
        RAISE EXCEPTION 'invalid canonical ledger scope'
            USING ERRCODE='invalid_parameter_value';
    END IF;
    IF jsonb_typeof(p_metadata) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'canonical ledger metadata must be an object'
            USING ERRCODE='invalid_parameter_value';
    END IF;

    created_at_unix_micros :=
        (extract(epoch FROM p_created_at) * 1000000)::bigint;
    SELECT count(*) INTO metadata_count FROM jsonb_each(p_metadata);
    FOREACH field_value IN ARRAY ARRAY[
        'mindone-ledger',
        '2',
        p_scope,
        p_id::text,
        p_account_id::text,
        COALESCE(p_request_id::text,''),
        p_idempotency_key,
        p_entry_type,
        p_delta_micro::text,
        p_balance_before_micro::text,
        p_balance_after_micro::text,
        created_at_unix_micros::text,
        p_prev_hash,
        metadata_count::text
    ]
    LOOP
        canonical := canonical || octet_length(field_value)::text || ':' || field_value;
    END LOOP;

    FOR metadata_row IN
        SELECT entry.key,entry.value
        FROM jsonb_each(p_metadata) AS entry
        ORDER BY convert_to(entry.key,'UTF8')
    LOOP
        IF jsonb_typeof(metadata_row.value) IS DISTINCT FROM 'string' THEN
            RAISE EXCEPTION 'canonical ledger metadata values must be strings'
                USING ERRCODE='invalid_parameter_value';
        END IF;
        metadata_value := metadata_row.value #>> '{}';
        canonical := canonical
            || octet_length(metadata_row.key)::text || ':' || metadata_row.key
            || octet_length(metadata_value)::text || ':' || metadata_value;
    END LOOP;

    RETURN encode(sha256(convert_to(canonical,'UTF8')),'hex');
END;
$$;

CREATE OR REPLACE FUNCTION mindone_validate_canonical_ledger_hash()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    ledger_scope TEXT;
    ledger_account_id UUID;
    ledger_schema NAME;
    expected_hash TEXT;
    metadata_row RECORD;
BEGIN
    IF NEW.hash_version IS DISTINCT FROM 2 THEN
        RAISE EXCEPTION 'new ledger rows must use canonical hash version 2'
            USING ERRCODE='check_violation';
    END IF;
    IF jsonb_typeof(NEW.metadata) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'ledger metadata must be a JSON object'
            USING ERRCODE='check_violation';
    END IF;
    IF octet_length(NEW.idempotency_key) NOT BETWEEN 1 AND 255
       OR NEW.idempotency_key ~ '[[:cntrl:]]' THEN
        RAISE EXCEPTION 'ledger idempotency_key is invalid'
            USING ERRCODE='check_violation';
    END IF;
    FOR metadata_row IN SELECT entry.key,entry.value FROM jsonb_each(NEW.metadata) AS entry
    LOOP
        IF jsonb_typeof(metadata_row.value) IS DISTINCT FROM 'string'
           OR octet_length(metadata_row.key) NOT BETWEEN 1 AND 128
           OR octet_length(metadata_row.value #>> '{}') > 2048
           OR metadata_row.key ~ '[[:cntrl:]]'
           OR (metadata_row.value #>> '{}') ~ '[[:cntrl:]]' THEN
            RAISE EXCEPTION 'ledger metadata must contain bounded string pairs'
                USING ERRCODE='check_violation';
        END IF;
    END LOOP;

    CASE TG_TABLE_NAME
        WHEN 'quota_ledger' THEN
            ledger_scope := 'quota';
            ledger_account_id := NEW.user_id;
            IF NEW.entry_type NOT IN (
                'consumer_deduction','node_reward','bootstrap_grant','operator_grant'
            ) OR (NEW.entry_type='consumer_deduction' AND NEW.delta_micro >= 0)
              OR (NEW.entry_type<>'consumer_deduction' AND NEW.delta_micro <= 0) THEN
                RAISE EXCEPTION 'invalid canonical quota ledger type or direction'
                    USING ERRCODE='check_violation';
            END IF;
        WHEN 'contribution_ledger' THEN
            ledger_scope := 'contribution';
            ledger_account_id := NEW.user_id;
            IF NEW.entry_type <> 'node_contribution' OR NEW.delta_micro < 0 THEN
                RAISE EXCEPTION 'invalid canonical contribution ledger type or direction'
                    USING ERRCODE='check_violation';
            END IF;
        WHEN 'reserve_ledger' THEN
            ledger_scope := 'reserve';
            ledger_account_id := '00000000-0000-0000-0000-000000000001'::uuid;
            IF (NEW.entry_type='settlement_inflow' AND NEW.delta_micro <= 0)
               OR (NEW.entry_type<>'settlement_inflow' AND NEW.delta_micro >= 0) THEN
                RAISE EXCEPTION 'invalid canonical reserve ledger direction'
                    USING ERRCODE='check_violation';
            END IF;
        ELSE
            RAISE EXCEPTION 'canonical hash trigger attached to unexpected table'
                USING ERRCODE='internal_error';
    END CASE;

    SELECT namespace_row.nspname INTO STRICT ledger_schema
    FROM pg_class AS table_row
    JOIN pg_namespace AS namespace_row ON namespace_row.oid=table_row.relnamespace
    WHERE table_row.oid=TG_RELID;
    -- schema 名直接由触发器所属 relation OID 取得并用 %I 引用，不能由 INSERT
    -- 调用者控制；这样真实 public 与隔离 schema 的迁移测试使用同一实现。
    EXECUTE format(
        'SELECT %I.mindone_ledger_hash_v2($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)',
        ledger_schema
    )
    INTO expected_hash
    USING ledger_scope,NEW.id,ledger_account_id,NEW.request_id,NEW.idempotency_key,
          NEW.entry_type,NEW.delta_micro,NEW.balance_before_micro,
          NEW.balance_after_micro,NEW.created_at,NEW.prev_hash,NEW.metadata;
    IF NEW.entry_hash IS NULL THEN
        NEW.entry_hash := expected_hash;
    ELSIF NEW.entry_hash IS DISTINCT FROM expected_hash THEN
        RAISE EXCEPTION 'ledger entry_hash does not match canonical row content'
            USING ERRCODE='check_violation';
    END IF;
    RETURN NEW;
END;
$$;

-- 名称中的 00 保证 canonical 校验先于 0024 的 advance-head trigger；即使后续
-- trigger 失败，PostgreSQL 仍会回滚同一语句中的账户余额/head/count 更新。
CREATE TRIGGER quota_ledger_00_validate_canonical_hash
    BEFORE INSERT ON quota_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_canonical_ledger_hash();
CREATE TRIGGER contribution_ledger_00_validate_canonical_hash
    BEFORE INSERT ON contribution_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_canonical_ledger_hash();
CREATE TRIGGER reserve_ledger_00_validate_canonical_hash
    BEFORE INSERT ON reserve_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_canonical_ledger_hash();

-- 0026 已撤销 PUBLIC/runtime 的函数 EXECUTE；显式重复可防止数据库采用了不同
-- default ACL 时，mindone_app 直接调用 SECURITY DEFINER trigger function。
REVOKE ALL PRIVILEGES ON FUNCTION mindone_ledger_hash_v2(
    TEXT,UUID,UUID,UUID,TEXT,TEXT,BIGINT,BIGINT,BIGINT,TIMESTAMPTZ,TEXT,JSONB
) FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION mindone_validate_canonical_ledger_hash()
    FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='mindone_app') THEN
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON FUNCTION %I.mindone_ledger_hash_v2(text,uuid,uuid,uuid,text,text,bigint,bigint,bigint,timestamptz,text,jsonb) FROM mindone_app',
            current_schema()
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON FUNCTION %I.mindone_validate_canonical_ledger_hash() FROM mindone_app',
            current_schema()
        );
    END IF;
END;
$$;
