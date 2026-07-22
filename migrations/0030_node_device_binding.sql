-- Worker 节点、普通租约和隐藏挑战必须绑定到发起认证的精确设备密钥。
--
-- 迁移必须在没有存量活动租约的维护窗口执行。真实 claim 先锁 nodes，
-- 再写 jobs/job_attempts 或 model_evaluation_challenges；迁移必须使用同一
-- 顺序，先阻断 node-first claim，以免“迁移持有 jobs 等 nodes，claim 持有
-- nodes 等 jobs”的锁升级死锁。LOCK 不写数据；检查仍处于任何 DDL/DML
-- 之前，sqlx 也会在同一事务内执行整份 migration。
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE jobs, job_attempts, model_evaluation_challenges
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM jobs
        WHERE status = 'leased'
    ) OR EXISTS (
        SELECT 1 FROM job_attempts
        WHERE status = 'leased'
    ) OR EXISTS (
        SELECT 1 FROM model_evaluation_challenges
        WHERE status = 'leased'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0030 requires zero active worker leases';
    END IF;
END
$$;

-- 复合外键同时证明设备密钥属于节点账号；单独的 device_keys(id) 主键不足以表达
-- 这个跨列不变量。
ALTER TABLE device_keys
    ADD CONSTRAINT device_keys_user_id_id_unique_v1 UNIQUE (user_id,id);

ALTER TABLE nodes
    ADD COLUMN device_key_id UUID,
    ADD CONSTRAINT nodes_user_device_key_v1
        FOREIGN KEY (user_id,device_key_id)
        REFERENCES device_keys(user_id,id) ON DELETE RESTRICT;

-- 租约表用 (node_id,device_key_id) 复合外键证明领取设备正是该节点的设备，
-- 不能只证明“系统中存在这个 device key”。
ALTER TABLE nodes
    ADD CONSTRAINT nodes_id_device_key_unique_v1 UNIQUE (id,device_key_id);

-- 旧节点不能在未显式重新注册绑定前恢复接单。NOT VALID 只豁免当前旧行的扫描，
-- 之后的新行和任何 UPDATE 仍必须携带非空 device_key_id。
UPDATE nodes
SET status = 'offline',
    pause_reason = 'device_rebind_required',
    last_seen_at = NULL,
    updated_at = now()
WHERE device_key_id IS NULL;

ALTER TABLE nodes
    ADD CONSTRAINT nodes_device_key_required_v1
        CHECK (device_key_id IS NOT NULL) NOT VALID;

CREATE OR REPLACE FUNCTION mindone_prevent_node_device_rebinding()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id
       OR (OLD.device_key_id IS NOT NULL
           AND NEW.device_key_id IS DISTINCT FROM OLD.device_key_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'node owner and established device binding are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS nodes_device_binding_immutable ON nodes;
CREATE TRIGGER nodes_device_binding_immutable
    BEFORE UPDATE OF user_id,device_key_id ON nodes
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_node_device_rebinding();

ALTER TABLE job_attempts
    ADD COLUMN claim_device_binding_version INTEGER,
    ADD COLUMN claim_device_key_id UUID
        REFERENCES device_keys(id) ON DELETE RESTRICT,
    ADD CONSTRAINT job_attempts_node_claim_device_v1
        FOREIGN KEY (node_id,claim_device_key_id)
        REFERENCES nodes(id,device_key_id) ON DELETE RESTRICT;

-- NOT VALID 保留迁移前已存在的历史终态 NULL 行，但 PostgreSQL 仍会对
-- 0030 之后的每个 INSERT/UPDATE 执行严格检查。因此新行无论 leased 还是
-- terminal 都必须固化完整设备身份，不能在 v31 伪造新的“legacy”行。
ALTER TABLE job_attempts
    ADD CONSTRAINT job_attempts_claim_device_binding_v1 CHECK ((
        claim_device_binding_version = 1
        AND claim_device_key_id IS NOT NULL
    ) IS TRUE) NOT VALID;

CREATE OR REPLACE FUNCTION mindone_prevent_job_attempt_claim_rebinding()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.claim_device_binding_version IS DISTINCT FROM OLD.claim_device_binding_version
       OR NEW.claim_device_key_id IS DISTINCT FROM OLD.claim_device_key_id THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'job attempt claim device binding is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS job_attempts_claim_device_binding_immutable ON job_attempts;
CREATE TRIGGER job_attempts_claim_device_binding_immutable
    BEFORE UPDATE OF node_id,claim_device_binding_version,claim_device_key_id ON job_attempts
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_job_attempt_claim_rebinding();

ALTER TABLE model_evaluation_challenges
    ADD COLUMN claimed_user_id UUID,
    ADD COLUMN claimed_device_key_id UUID,
    ADD COLUMN claim_device_binding_version INTEGER,
    ADD CONSTRAINT model_evaluation_claim_device_key_v1
        FOREIGN KEY (claimed_user_id,claimed_device_key_id)
        REFERENCES device_keys(user_id,id) ON DELETE RESTRICT,
    ADD CONSTRAINT model_evaluation_node_claim_device_v1
        FOREIGN KEY (node_id,claimed_device_key_id)
        REFERENCES nodes(id,device_key_id) ON DELETE RESTRICT;

-- 与普通 attempt 相同：NOT VALID 只保留迁移前已存在的历史终态
-- NULL 行；0030 之后的任何新行或更新都必须完整绑定账号、设备和版本。
ALTER TABLE model_evaluation_challenges
    ADD CONSTRAINT model_evaluation_claim_device_binding_v1 CHECK ((
        claimed_user_id IS NOT NULL
        AND claimed_device_key_id IS NOT NULL
        AND claim_device_binding_version = 1
    ) IS TRUE) NOT VALID;

CREATE OR REPLACE FUNCTION mindone_prevent_evaluation_claim_rebinding()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.node_id IS DISTINCT FROM OLD.node_id
       OR NEW.claimed_user_id IS DISTINCT FROM OLD.claimed_user_id
       OR NEW.claimed_device_key_id IS DISTINCT FROM OLD.claimed_device_key_id
       OR NEW.claim_device_binding_version IS DISTINCT FROM OLD.claim_device_binding_version
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'evaluation claim device binding is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS model_evaluation_claim_device_binding_immutable
    ON model_evaluation_challenges;
CREATE TRIGGER model_evaluation_claim_device_binding_immutable
    BEFORE UPDATE OF node_id,claimed_user_id,claimed_device_key_id,claim_device_binding_version
    ON model_evaluation_challenges
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_evaluation_claim_rebinding();
