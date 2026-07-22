-- 账本链头不能通过 transaction timestamp 推断。长事务的 now() 早于后来先提交的
-- 事务时，按 created_at 排序会把真正的后继误判为旧记录并产生分叉。
-- 本迁移先从 genesis 逐条回放现有链并核对余额，再把唯一权威链头存到账户行。

-- SQLx 会在单一事务中执行本迁移。先阻断旧进程和直接 SQL 的全部相关写入，
-- 避免回放 COUNT 之后又出现未计入的新 ledger 行。
LOCK TABLE quota_accounts, quota_ledger, contribution_ledger,
    reserve_accounts, reserve_ledger IN ACCESS EXCLUSIVE MODE;

ALTER TABLE quota_accounts
    ADD COLUMN quota_ledger_head_hash TEXT,
    ADD COLUMN quota_ledger_entry_count BIGINT,
    ADD COLUMN contribution_ledger_head_hash TEXT,
    ADD COLUMN contribution_ledger_entry_count BIGINT;

ALTER TABLE reserve_accounts
    ADD COLUMN ledger_head_hash TEXT,
    ADD COLUMN ledger_entry_count BIGINT;

-- 在回放前先安装单后继索引和账户外键：既为逐 head 查找提供索引，也让 fork
-- 或没有账户的旧 ledger 行在写入任何 head 状态前 fail-closed。
ALTER TABLE quota_ledger
    ADD CONSTRAINT quota_ledger_account_fk
        FOREIGN KEY (user_id) REFERENCES quota_accounts(user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT quota_ledger_hash_shape CHECK (
        prev_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash <>
            '0000000000000000000000000000000000000000000000000000000000000000'
    ),
    ADD CONSTRAINT quota_ledger_balance_arithmetic CHECK (
        balance_after_micro = balance_before_micro + delta_micro
    ),
    ADD CONSTRAINT quota_ledger_single_successor UNIQUE (user_id,prev_hash);

ALTER TABLE contribution_ledger
    ADD CONSTRAINT contribution_ledger_account_fk
        FOREIGN KEY (user_id) REFERENCES quota_accounts(user_id) ON DELETE RESTRICT,
    ADD CONSTRAINT contribution_ledger_hash_shape CHECK (
        prev_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash <>
            '0000000000000000000000000000000000000000000000000000000000000000'
    ),
    ADD CONSTRAINT contribution_ledger_balance_arithmetic CHECK (
        balance_after_micro = balance_before_micro + delta_micro
    ),
    ADD CONSTRAINT contribution_ledger_single_successor UNIQUE (user_id,prev_hash);

ALTER TABLE reserve_ledger
    ADD CONSTRAINT reserve_ledger_hash_shape CHECK (
        prev_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash ~ '^[0-9a-f]{64}$'
        AND entry_hash <>
            '0000000000000000000000000000000000000000000000000000000000000000'
    ),
    ADD CONSTRAINT reserve_ledger_balance_arithmetic CHECK (
        balance_after_micro = balance_before_micro + delta_micro
    ),
    ADD CONSTRAINT reserve_ledger_single_successor UNIQUE (prev_hash);

DO $$
DECLARE
    account_row RECORD;
    next_row RECORD;
    current_hash TEXT;
    current_balance BIGINT;
    successor_count BIGINT;
    total_count BIGINT;
    visited_count BIGINT;
BEGIN
    FOR account_row IN
        SELECT user_id,spendable_micro FROM quota_accounts ORDER BY user_id
    LOOP
        current_hash := repeat('0',64);
        current_balance := 0;
        visited_count := 0;
        SELECT COUNT(*)::bigint INTO total_count
        FROM quota_ledger WHERE user_id=account_row.user_id;
        LOOP
            SELECT COUNT(*)::bigint INTO successor_count
            FROM quota_ledger
            WHERE user_id=account_row.user_id AND prev_hash=current_hash;
            IF successor_count > 1 THEN
                RAISE EXCEPTION 'quota ledger fork for account %', account_row.user_id;
            END IF;
            EXIT WHEN successor_count = 0;
            SELECT entry_hash,balance_before_micro,balance_after_micro,delta_micro
            INTO STRICT next_row
            FROM quota_ledger
            WHERE user_id=account_row.user_id AND prev_hash=current_hash;
            IF next_row.balance_before_micro IS DISTINCT FROM current_balance
               OR next_row.balance_after_micro IS DISTINCT FROM
                    next_row.balance_before_micro + next_row.delta_micro THEN
                RAISE EXCEPTION 'quota ledger balance discontinuity for account %',
                    account_row.user_id;
            END IF;
            current_balance := next_row.balance_after_micro;
            current_hash := next_row.entry_hash;
            visited_count := visited_count + 1;
            IF visited_count > total_count THEN
                RAISE EXCEPTION 'quota ledger cycle for account %', account_row.user_id;
            END IF;
        END LOOP;
        IF visited_count IS DISTINCT FROM total_count
           OR current_balance IS DISTINCT FROM account_row.spendable_micro THEN
            RAISE EXCEPTION 'quota ledger is disconnected or does not match account %',
                account_row.user_id;
        END IF;
        UPDATE quota_accounts
        SET quota_ledger_head_hash=current_hash,
            quota_ledger_entry_count=visited_count
        WHERE user_id=account_row.user_id;
    END LOOP;
END;
$$;

DO $$
DECLARE
    account_row RECORD;
    next_row RECORD;
    current_hash TEXT;
    current_balance BIGINT;
    successor_count BIGINT;
    total_count BIGINT;
    visited_count BIGINT;
BEGIN
    FOR account_row IN
        SELECT user_id,contribution_micro FROM quota_accounts ORDER BY user_id
    LOOP
        current_hash := repeat('0',64);
        current_balance := 0;
        visited_count := 0;
        SELECT COUNT(*)::bigint INTO total_count
        FROM contribution_ledger WHERE user_id=account_row.user_id;
        LOOP
            SELECT COUNT(*)::bigint INTO successor_count
            FROM contribution_ledger
            WHERE user_id=account_row.user_id AND prev_hash=current_hash;
            IF successor_count > 1 THEN
                RAISE EXCEPTION 'contribution ledger fork for account %', account_row.user_id;
            END IF;
            EXIT WHEN successor_count = 0;
            SELECT entry_hash,balance_before_micro,balance_after_micro,delta_micro
            INTO STRICT next_row
            FROM contribution_ledger
            WHERE user_id=account_row.user_id AND prev_hash=current_hash;
            IF next_row.balance_before_micro IS DISTINCT FROM current_balance
               OR next_row.balance_after_micro IS DISTINCT FROM
                    next_row.balance_before_micro + next_row.delta_micro THEN
                RAISE EXCEPTION 'contribution ledger balance discontinuity for account %',
                    account_row.user_id;
            END IF;
            current_balance := next_row.balance_after_micro;
            current_hash := next_row.entry_hash;
            visited_count := visited_count + 1;
            IF visited_count > total_count THEN
                RAISE EXCEPTION 'contribution ledger cycle for account %', account_row.user_id;
            END IF;
        END LOOP;
        IF visited_count IS DISTINCT FROM total_count
           OR current_balance IS DISTINCT FROM account_row.contribution_micro THEN
            RAISE EXCEPTION 'contribution ledger is disconnected or does not match account %',
                account_row.user_id;
        END IF;
        UPDATE quota_accounts
        SET contribution_ledger_head_hash=current_hash,
            contribution_ledger_entry_count=visited_count
        WHERE user_id=account_row.user_id;
    END LOOP;
END;
$$;

DO $$
DECLARE
    next_row RECORD;
    current_hash TEXT := repeat('0',64);
    current_balance BIGINT := 0;
    successor_count BIGINT;
    total_count BIGINT;
    visited_count BIGINT := 0;
    account_balance BIGINT;
BEGIN
    SELECT balance_micro INTO STRICT account_balance
    FROM reserve_accounts WHERE id=1;
    SELECT COUNT(*)::bigint INTO total_count FROM reserve_ledger;
    LOOP
        SELECT COUNT(*)::bigint INTO successor_count
        FROM reserve_ledger WHERE prev_hash=current_hash;
        IF successor_count > 1 THEN
            RAISE EXCEPTION 'reserve ledger fork';
        END IF;
        EXIT WHEN successor_count = 0;
        SELECT entry_hash,balance_before_micro,balance_after_micro,delta_micro
        INTO STRICT next_row
        FROM reserve_ledger WHERE prev_hash=current_hash;
        IF next_row.balance_before_micro IS DISTINCT FROM current_balance
           OR next_row.balance_after_micro IS DISTINCT FROM
                next_row.balance_before_micro + next_row.delta_micro THEN
            RAISE EXCEPTION 'reserve ledger balance discontinuity';
        END IF;
        current_balance := next_row.balance_after_micro;
        current_hash := next_row.entry_hash;
        visited_count := visited_count + 1;
        IF visited_count > total_count THEN
            RAISE EXCEPTION 'reserve ledger cycle';
        END IF;
    END LOOP;
    IF visited_count IS DISTINCT FROM total_count
       OR current_balance IS DISTINCT FROM account_balance THEN
        RAISE EXCEPTION 'reserve ledger is disconnected or does not match account';
    END IF;
    UPDATE reserve_accounts
    SET ledger_head_hash=current_hash,ledger_entry_count=visited_count
    WHERE id=1;
END;
$$;

ALTER TABLE quota_accounts
    ALTER COLUMN quota_ledger_head_hash SET DEFAULT
        '0000000000000000000000000000000000000000000000000000000000000000',
    ALTER COLUMN quota_ledger_head_hash SET NOT NULL,
    ALTER COLUMN quota_ledger_entry_count SET DEFAULT 0,
    ALTER COLUMN quota_ledger_entry_count SET NOT NULL,
    ALTER COLUMN contribution_ledger_head_hash SET DEFAULT
        '0000000000000000000000000000000000000000000000000000000000000000',
    ALTER COLUMN contribution_ledger_head_hash SET NOT NULL,
    ALTER COLUMN contribution_ledger_entry_count SET DEFAULT 0,
    ALTER COLUMN contribution_ledger_entry_count SET NOT NULL,
    ADD CONSTRAINT quota_accounts_quota_ledger_head_shape CHECK (
        quota_ledger_head_hash ~ '^[0-9a-f]{64}$'
        AND quota_ledger_entry_count >= 0
        AND (
            (quota_ledger_entry_count = 0 AND quota_ledger_head_hash =
                '0000000000000000000000000000000000000000000000000000000000000000')
            OR (quota_ledger_entry_count > 0 AND quota_ledger_head_hash <>
                '0000000000000000000000000000000000000000000000000000000000000000')
        )
    ),
    ADD CONSTRAINT quota_accounts_contribution_ledger_head_shape CHECK (
        contribution_ledger_head_hash ~ '^[0-9a-f]{64}$'
        AND contribution_ledger_entry_count >= 0
        AND (
            (contribution_ledger_entry_count = 0 AND contribution_ledger_head_hash =
                '0000000000000000000000000000000000000000000000000000000000000000')
            OR (contribution_ledger_entry_count > 0 AND contribution_ledger_head_hash <>
                '0000000000000000000000000000000000000000000000000000000000000000')
        )
    );

ALTER TABLE reserve_accounts
    ALTER COLUMN ledger_head_hash SET DEFAULT
        '0000000000000000000000000000000000000000000000000000000000000000',
    ALTER COLUMN ledger_head_hash SET NOT NULL,
    ALTER COLUMN ledger_entry_count SET DEFAULT 0,
    ALTER COLUMN ledger_entry_count SET NOT NULL,
    ADD CONSTRAINT reserve_accounts_ledger_head_shape CHECK (
        ledger_head_hash ~ '^[0-9a-f]{64}$'
        AND ledger_entry_count >= 0
        AND (
            (ledger_entry_count = 0 AND ledger_head_hash =
                '0000000000000000000000000000000000000000000000000000000000000000')
            OR (ledger_entry_count > 0 AND ledger_head_hash <>
                '0000000000000000000000000000000000000000000000000000000000000000')
        )
    );

-- 账户 tracked 字段只能由下面的 ledger INSERT trigger 在嵌套 trigger 深度内修改。
-- reserved_micro 不属于结算账本余额，普通任务预留/释放仍可直接更新它。
CREATE OR REPLACE FUNCTION mindone_guard_quota_account_ledger_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.spendable_micro IS DISTINCT FROM 0
           OR NEW.reserved_micro IS DISTINCT FROM 0
           OR NEW.contribution_micro IS DISTINCT FROM 0
           OR NEW.quota_ledger_head_hash IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR NEW.quota_ledger_entry_count IS DISTINCT FROM 0
           OR NEW.contribution_ledger_head_hash IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR NEW.contribution_ledger_entry_count IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'new quota account must start from zero ledger genesis'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'quota account rows cannot be deleted'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'quota account identity cannot be changed'
            USING ERRCODE = 'check_violation';
    END IF;
    -- ledger BEFORE INSERT trigger 调用账户 UPDATE 时，本 guard 的精确深度为 2。
    -- 顶层直接 SQL（深度 1）或其它意外嵌套深度都 fail-closed。
    IF pg_trigger_depth() <> 2
       AND (NEW.spendable_micro IS DISTINCT FROM OLD.spendable_micro
            OR NEW.contribution_micro IS DISTINCT FROM OLD.contribution_micro
            OR NEW.quota_ledger_head_hash IS DISTINCT FROM OLD.quota_ledger_head_hash
            OR NEW.quota_ledger_entry_count IS DISTINCT FROM OLD.quota_ledger_entry_count
            OR NEW.contribution_ledger_head_hash IS DISTINCT FROM
                OLD.contribution_ledger_head_hash
            OR NEW.contribution_ledger_entry_count IS DISTINCT FROM
                OLD.contribution_ledger_entry_count) THEN
        RAISE EXCEPTION 'quota account ledger state can only be advanced by ledger insert'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mindone_guard_reserve_account_ledger_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.id IS DISTINCT FROM 1
           OR NEW.balance_micro IS DISTINCT FROM 0
           OR NEW.ledger_head_hash IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR NEW.ledger_entry_count IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'reserve account must start from zero ledger genesis'
                USING ERRCODE = 'check_violation';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'reserve account row cannot be deleted'
            USING ERRCODE = 'check_violation';
    END IF;
    IF pg_trigger_depth() <> 2
       AND (NEW.balance_micro IS DISTINCT FROM OLD.balance_micro
            OR NEW.ledger_head_hash IS DISTINCT FROM OLD.ledger_head_hash
            OR NEW.ledger_entry_count IS DISTINCT FROM OLD.ledger_entry_count) THEN
        RAISE EXCEPTION 'reserve account ledger state can only be advanced by ledger insert'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quota_accounts_guard_ledger_state
    BEFORE INSERT OR UPDATE OR DELETE ON quota_accounts
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_quota_account_ledger_state();

CREATE TRIGGER reserve_accounts_guard_ledger_state
    BEFORE INSERT OR UPDATE OR DELETE ON reserve_accounts
    FOR EACH ROW EXECUTE FUNCTION mindone_guard_reserve_account_ledger_state();

CREATE OR REPLACE FUNCTION mindone_advance_quota_ledger_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_head TEXT;
    current_count BIGINT;
    current_balance BIGINT;
    head_balance BIGINT;
BEGIN
    SELECT quota_ledger_head_hash,quota_ledger_entry_count,spendable_micro
    INTO STRICT current_head,current_count,current_balance
    FROM quota_accounts WHERE user_id=NEW.user_id FOR UPDATE;
    IF current_count = 0 THEN
        IF current_head IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR current_balance IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'empty quota ledger account state is inconsistent';
        END IF;
    ELSE
        SELECT balance_after_micro INTO STRICT head_balance
        FROM quota_ledger
        WHERE user_id=NEW.user_id AND entry_hash=current_head;
        IF head_balance IS DISTINCT FROM current_balance THEN
            RAISE EXCEPTION 'quota ledger head balance does not match account';
        END IF;
    END IF;
    IF NEW.entry_hash =
            '0000000000000000000000000000000000000000000000000000000000000000'
       OR NEW.prev_hash IS DISTINCT FROM current_head
       OR NEW.balance_before_micro IS DISTINCT FROM current_balance
       OR NEW.balance_after_micro IS DISTINCT FROM
            NEW.balance_before_micro + NEW.delta_micro THEN
        RAISE EXCEPTION 'quota ledger entry does not extend authoritative account state';
    END IF;
    UPDATE quota_accounts
    SET spendable_micro=NEW.balance_after_micro,
        quota_ledger_head_hash=NEW.entry_hash,
        quota_ledger_entry_count=current_count+1,
        updated_at=now()
    WHERE user_id=NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mindone_advance_contribution_ledger_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_head TEXT;
    current_count BIGINT;
    current_balance BIGINT;
    head_balance BIGINT;
BEGIN
    SELECT contribution_ledger_head_hash,contribution_ledger_entry_count,
           contribution_micro
    INTO STRICT current_head,current_count,current_balance
    FROM quota_accounts WHERE user_id=NEW.user_id FOR UPDATE;
    IF current_count = 0 THEN
        IF current_head IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR current_balance IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'empty contribution ledger account state is inconsistent';
        END IF;
    ELSE
        SELECT balance_after_micro INTO STRICT head_balance
        FROM contribution_ledger
        WHERE user_id=NEW.user_id AND entry_hash=current_head;
        IF head_balance IS DISTINCT FROM current_balance THEN
            RAISE EXCEPTION 'contribution ledger head balance does not match account';
        END IF;
    END IF;
    IF NEW.entry_hash =
            '0000000000000000000000000000000000000000000000000000000000000000'
       OR NEW.prev_hash IS DISTINCT FROM current_head
       OR NEW.balance_before_micro IS DISTINCT FROM current_balance
       OR NEW.balance_after_micro IS DISTINCT FROM
            NEW.balance_before_micro + NEW.delta_micro THEN
        RAISE EXCEPTION 'contribution ledger entry does not extend authoritative account state';
    END IF;
    UPDATE quota_accounts
    SET contribution_micro=NEW.balance_after_micro,
        contribution_ledger_head_hash=NEW.entry_hash,
        contribution_ledger_entry_count=current_count+1,
        updated_at=now()
    WHERE user_id=NEW.user_id;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mindone_advance_reserve_ledger_head()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_head TEXT;
    current_count BIGINT;
    current_balance BIGINT;
    head_balance BIGINT;
BEGIN
    SELECT ledger_head_hash,ledger_entry_count,balance_micro
    INTO STRICT current_head,current_count,current_balance
    FROM reserve_accounts WHERE id=1 FOR UPDATE;
    IF current_count = 0 THEN
        IF current_head IS DISTINCT FROM
                '0000000000000000000000000000000000000000000000000000000000000000'
           OR current_balance IS DISTINCT FROM 0 THEN
            RAISE EXCEPTION 'empty reserve ledger account state is inconsistent';
        END IF;
    ELSE
        SELECT balance_after_micro INTO STRICT head_balance
        FROM reserve_ledger WHERE entry_hash=current_head;
        IF head_balance IS DISTINCT FROM current_balance THEN
            RAISE EXCEPTION 'reserve ledger head balance does not match account';
        END IF;
    END IF;
    IF NEW.entry_hash =
            '0000000000000000000000000000000000000000000000000000000000000000'
       OR NEW.prev_hash IS DISTINCT FROM current_head
       OR NEW.balance_before_micro IS DISTINCT FROM current_balance
       OR NEW.balance_after_micro IS DISTINCT FROM
            NEW.balance_before_micro + NEW.delta_micro THEN
        RAISE EXCEPTION 'reserve ledger entry does not extend authoritative account state';
    END IF;
    UPDATE reserve_accounts
    SET balance_micro=NEW.balance_after_micro,
        ledger_head_hash=NEW.entry_hash,
        ledger_entry_count=current_count+1,
        updated_at=now()
    WHERE id=1;
    RETURN NEW;
END;
$$;

CREATE TRIGGER quota_ledger_advance_head
    BEFORE INSERT ON quota_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_advance_quota_ledger_head();

CREATE TRIGGER contribution_ledger_advance_head
    BEFORE INSERT ON contribution_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_advance_contribution_ledger_head();

CREATE TRIGGER reserve_ledger_advance_head
    BEFORE INSERT ON reserve_ledger
    FOR EACH ROW EXECUTE FUNCTION mindone_advance_reserve_ledger_head();
