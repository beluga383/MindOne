-- 白皮书第 9 节公开聚合报表所需的只读查询索引。
-- 报表实时读取权威账本与状态表，不维护可漂移的影子余额或状态文件。

CREATE INDEX IF NOT EXISTS receipts_transparency_time_node_idx
    ON receipts (created_at, node_user_id);

CREATE INDEX IF NOT EXISTS abuse_decisions_transparency_time_block_idx
    ON abuse_decisions (created_at)
    WHERE decision = 'block';

CREATE INDEX IF NOT EXISTS jobs_transparency_time_status_idx
    ON jobs (created_at, status);

CREATE INDEX IF NOT EXISTS reserve_ledger_transparency_time_delta_idx
    ON reserve_ledger (created_at, delta_micro);
