-- 部分平台（例如未暴露 GPU 温度传感器的 macOS）无法提供温度指标。
-- NULL 表示节点未配置温度策略；配置了阈值时仍按 5°C 滞回执行。
ALTER TABLE node_policies
    ALTER COLUMN gpu_temp_limit_c DROP NOT NULL,
    ALTER COLUMN gpu_temp_limit_c DROP DEFAULT;
