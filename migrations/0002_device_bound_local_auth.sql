ALTER TABLE auth_device_flows
    ADD COLUMN IF NOT EXISTS device_public_key TEXT,
    ADD COLUMN IF NOT EXISTS device_key_fingerprint TEXT;

CREATE INDEX IF NOT EXISTS auth_device_flows_device_fingerprint_idx
    ON auth_device_flows (device_key_fingerprint)
    WHERE device_key_fingerprint IS NOT NULL;
