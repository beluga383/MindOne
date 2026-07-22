-- Refresh token 只能与绑定设备私钥共同使用；成功轮换时 challenge 也必须轮换。
-- 旧会话没有 challenge，应用层会 fail closed 并要求重新登录。
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS refresh_challenge TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'sessions_refresh_challenge_v1'
          AND conrelid = 'sessions'::regclass
    ) THEN
        ALTER TABLE sessions
            ADD CONSTRAINT sessions_refresh_challenge_v1 CHECK (
                refresh_challenge IS NULL
                OR refresh_challenge ~ '^[0-9a-f]{64}$'
            );
    END IF;
END
$$;

-- v1 基础费率由协调器独占拥有。清除旧版由发布请求写入的任意值，并让数据库
-- 约束阻止应用回归到“发布者自选价格”。
UPDATE models SET base_cost_per_1k_micro = 1000000
WHERE base_cost_per_1k_micro <> 1000000;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'models_server_owned_base_cost_v1'
          AND conrelid = 'models'::regclass
    ) THEN
        ALTER TABLE models
            ADD CONSTRAINT models_server_owned_base_cost_v1
            CHECK (base_cost_per_1k_micro = 1000000);
    END IF;
END
$$;

-- uptime 只累计两次相邻、由协调器接收且间隔不超过失联阈值（90 秒）的心跳。
-- 不把注册时间或最后一次心跳之后的墙钟时间计入，因此节点离线后数值不会增长。
ALTER TABLE nodes
    ADD COLUMN IF NOT EXISTS verified_uptime_seconds BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS verified_heartbeat_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_verified_heartbeat_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'nodes_verified_uptime_nonnegative_v1'
          AND conrelid = 'nodes'::regclass
    ) THEN
        ALTER TABLE nodes
            ADD CONSTRAINT nodes_verified_uptime_nonnegative_v1 CHECK (
                verified_uptime_seconds >= 0
                AND verified_heartbeat_count >= 0
            );
    END IF;
END
$$;

-- 既有部署从权威 heartbeats 表确定性回填；超过 90 秒的空档视为离线，不计时。
WITH ordered AS (
    SELECT node_id, received_at,
           lead(received_at) OVER (
               PARTITION BY node_id ORDER BY received_at, id
           ) AS next_received_at
    FROM heartbeats
), aggregate AS (
    SELECT node_id,
           COUNT(*)::bigint AS heartbeat_count,
           MAX(received_at) AS last_heartbeat_at,
           COALESCE(SUM(
               CASE
                   WHEN next_received_at IS NOT NULL
                    AND next_received_at <= received_at + interval '90 seconds'
                   THEN GREATEST(
                       EXTRACT(EPOCH FROM (next_received_at - received_at))::bigint,
                       0
                   )
                   ELSE 0
               END
           ),0)::bigint AS uptime_seconds
    FROM ordered
    GROUP BY node_id
)
UPDATE nodes AS node
SET verified_uptime_seconds = aggregate.uptime_seconds,
    verified_heartbeat_count = aggregate.heartbeat_count,
    last_verified_heartbeat_at = aggregate.last_heartbeat_at
FROM aggregate
WHERE aggregate.node_id = node.id;
