-- Device Flow 必须绑定真实 Ed25519 密钥，并在轮询时证明私钥持有权。
-- 既有已完成 flow 可能没有 challenge，因此 flow 列保持可空；应用层会拒绝
-- 任何缺少新字段的 pending flow，要求客户端重新发起登录。
ALTER TABLE auth_device_flows
    ADD COLUMN IF NOT EXISTS device_key_algorithm TEXT,
    ADD COLUMN IF NOT EXISTS device_key_challenge TEXT;

ALTER TABLE device_keys
    ADD COLUMN IF NOT EXISTS algorithm TEXT NOT NULL DEFAULT 'ed25519';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'auth_device_flows_device_key_algorithm_v1'
          AND conrelid = 'auth_device_flows'::regclass
    ) THEN
        ALTER TABLE auth_device_flows
            ADD CONSTRAINT auth_device_flows_device_key_algorithm_v1
            CHECK (device_key_algorithm IS NULL OR device_key_algorithm = 'ed25519');
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'auth_device_flows_device_key_challenge_v1'
          AND conrelid = 'auth_device_flows'::regclass
    ) THEN
        ALTER TABLE auth_device_flows
            ADD CONSTRAINT auth_device_flows_device_key_challenge_v1
            CHECK (
                device_key_challenge IS NULL
                OR device_key_challenge ~ '^[0-9a-f]{64}$'
            );
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'device_keys_algorithm_v1'
          AND conrelid = 'device_keys'::regclass
    ) THEN
        ALTER TABLE device_keys
            ADD CONSTRAINT device_keys_algorithm_v1
            CHECK (algorithm = 'ed25519');
    END IF;
END
$$;
