-- 客户端测得的协调服务器往返时延。旧节点没有该指标，因此保持可空且不回填；
-- 服务端只接受有意义的正值，并限制异常/恶意上报的范围。
ALTER TABLE node_metrics
    ADD COLUMN coordinator_rtt_ms BIGINT;

ALTER TABLE node_metrics
    ADD CONSTRAINT node_metrics_coordinator_rtt_ms_range_v1 CHECK (
        coordinator_rtt_ms IS NULL
        OR coordinator_rtt_ms BETWEEN 1 AND 60000
    );

COMMENT ON COLUMN node_metrics.coordinator_rtt_ms IS
    'Client-observed coordinator heartbeat round-trip time in milliseconds; nullable for legacy nodes.';
