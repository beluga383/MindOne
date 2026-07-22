ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS device_key_id UUID REFERENCES device_keys(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS sessions_device_key_active_idx
    ON sessions (device_key_id)
    WHERE revoked_at IS NULL AND device_key_id IS NOT NULL;
