-- Regulated prepare/create 的幂等键必须同时绑定完整请求内容。
-- 旧 route 无法从选路结果反推原始 virtual_model，因此历史行保留 NULL；
-- 新请求遇到 NULL 时 fail closed，而不是把旧响应冒充成同一请求。

ALTER TABLE regulated_routes
    ADD COLUMN IF NOT EXISTS prepare_request_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS create_request_fingerprint TEXT;

ALTER TABLE regulated_routes
    ADD CONSTRAINT regulated_routes_prepare_fingerprint_v1 CHECK (
        prepare_request_fingerprint IS NULL
        OR prepare_request_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT regulated_routes_create_fingerprint_v1 CHECK (
        create_request_fingerprint IS NULL
        OR create_request_fingerprint ~ '^[0-9a-f]{64}$'
    );
