-- 将 OpenAI model 末尾速度后缀固化为服务端字段，避免 worker 或客户端自行解释。
-- standard 保持历史路由合同；slow 只有在节点真实发布多个可用 slot 后才可打包，
-- 当前单 slot 节点仍会排队，不能用虚报并发伪装容量。

ALTER TABLE jobs
    ADD COLUMN speed_class TEXT NOT NULL DEFAULT 'standard'
        CHECK (speed_class IN ('fast', 'standard', 'slow'));

CREATE INDEX jobs_ready_speed_queue_idx
    ON jobs (speed_class, priority DESC, created_at ASC)
    WHERE status IN ('queued', 'retry');
