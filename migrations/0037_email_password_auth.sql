-- Email/password verifies a browser identity, then authorizes an existing Ed25519-bound
-- Device Flow. Raw verification codes and bearer tokens are never persisted.

ALTER TABLE users
    ADD COLUMN email TEXT,
    ADD COLUMN password_hash TEXT,
    ADD COLUMN email_verified_at TIMESTAMPTZ,
    ADD CONSTRAINT users_email_normalized_v1 CHECK (
        email IS NULL OR (
            octet_length(email) BETWEEN 3 AND 254
            AND email = btrim(email)
            AND email = lower(email)
            AND email ~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+\.[^@[:space:][:cntrl:]]+$'
        )
    ),
    ADD CONSTRAINT users_email_password_provider_v1 CHECK (
        provider <> 'email' OR (email IS NOT NULL AND password_hash IS NOT NULL)
    );

CREATE UNIQUE INDEX users_email_unique_idx
    ON users (email)
    WHERE email IS NOT NULL;

-- The application stores only HMAC-SHA256(token, server pepper). The raw value exists only
-- in the outbound verification email and the user's browser request.
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[A-Za-z0-9_-]{43}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at TIMESTAMPTZ,
    CHECK (expires_at > created_at),
    CHECK (used_at IS NULL OR used_at >= created_at)
);

CREATE INDEX email_verification_tokens_user_idx
    ON email_verification_tokens (user_id);
CREATE INDEX email_verification_tokens_expires_idx
    ON email_verification_tokens (expires_at)
    WHERE used_at IS NULL;

-- Browser login can only mark a pending email Device Flow as authorized. Token issuance
-- remains in /v1/auth/device/poll after the CLI proves possession of its Ed25519 key.
ALTER TABLE auth_device_flows
    ADD COLUMN email_authorized_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN email_authorized_at TIMESTAMPTZ,
    ADD CONSTRAINT auth_device_flows_email_authorization_pair_v1 CHECK (
        (email_authorized_user_id IS NULL) = (email_authorized_at IS NULL)
    ),
    ADD CONSTRAINT auth_device_flows_email_authorization_provider_v1 CHECK (
        email_authorized_user_id IS NULL OR provider = 'email'
    ),
    ADD CONSTRAINT auth_device_flows_email_code_format_v1 CHECK (
        provider <> 'email' OR (
            provider_device_code ~ '^[A-Za-z0-9_-]{43}$'
            AND user_code ~ '^[0-9A-F]{12}$'
            AND verification_uri ~ '^https?://[^/?#]+/auth/login$'
        )
    );

CREATE UNIQUE INDEX auth_device_flows_email_code_v1
    ON auth_device_flows (provider_device_code)
    WHERE provider = 'email';
CREATE UNIQUE INDEX auth_device_flows_email_user_code_v1
    ON auth_device_flows (user_code)
    WHERE provider = 'email' AND status = 'pending';
CREATE INDEX auth_device_flows_email_authorized_user_v1
    ON auth_device_flows (email_authorized_user_id)
    WHERE email_authorized_user_id IS NOT NULL;

REVOKE ALL PRIVILEGES ON TABLE email_verification_tokens FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON TABLE email_verification_tokens FROM mindone_app;
        GRANT SELECT, INSERT, UPDATE ON TABLE email_verification_tokens TO mindone_app;
    END IF;
END;
$$;
