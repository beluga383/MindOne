-- OpenAI 兼容推理 API Key。只保存 HMAC hash 与不可逆前缀提示，Secret 仅创建时返回。
-- Key 绑定创建它的 session/device；注销或撤销设备会立即关闭推理访问。

CREATE TABLE inference_api_keys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_by_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE RESTRICT,
    device_key_id UUID NOT NULL REFERENCES device_keys(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (
        char_length(name) BETWEEN 1 AND 64
        AND name = btrim(name)
        AND name !~ '[[:cntrl:]]'
    ),
    key_prefix TEXT NOT NULL CHECK (key_prefix ~ '^mok_[A-Za-z0-9_-]{8}$'),
    key_hash TEXT NOT NULL UNIQUE CHECK (key_hash ~ '^[A-Za-z0-9_-]{43}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    UNIQUE (user_id, name)
);

CREATE INDEX inference_api_keys_user_active_idx
    ON inference_api_keys (user_id, created_at DESC)
    WHERE revoked_at IS NULL;

CREATE TABLE inference_api_key_events (
    id UUID PRIMARY KEY,
    api_key_id UUID NOT NULL REFERENCES inference_api_keys(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (event_type IN ('created', 'revoked')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (api_key_id, event_type)
);

CREATE FUNCTION reject_inference_api_key_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'inference_api_key_events is append-only' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER inference_api_key_events_no_update
BEFORE UPDATE ON inference_api_key_events
FOR EACH ROW EXECUTE FUNCTION reject_inference_api_key_event_mutation();

CREATE TRIGGER inference_api_key_events_no_delete
BEFORE DELETE ON inference_api_key_events
FOR EACH ROW EXECUTE FUNCTION reject_inference_api_key_event_mutation();

REVOKE ALL PRIVILEGES ON TABLE
    inference_api_keys,
    inference_api_key_events
FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON TABLE
            inference_api_keys,
            inference_api_key_events
        FROM mindone_app;
        GRANT SELECT, INSERT, UPDATE ON TABLE inference_api_keys TO mindone_app;
        GRANT SELECT, INSERT ON TABLE inference_api_key_events TO mindone_app;
    END IF;
END;
$$;
