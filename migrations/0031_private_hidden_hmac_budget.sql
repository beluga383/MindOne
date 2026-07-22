-- Migration 0031 also requires a quiescent worker plane. Real claims lock nodes
-- before writing either ordinary or hidden leases, so take the same node-first
-- lock as 0030 before the lease tables. This both closes the predicate/write race
-- and avoids a lock-upgrade cycle with a concurrent claim. LOCK performs no write.
LOCK TABLE nodes IN ACCESS EXCLUSIVE MODE;
LOCK TABLE jobs, job_attempts, model_evaluation_challenges
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM jobs
        WHERE status = 'leased'
    ) OR EXISTS (
        SELECT 1 FROM job_attempts
        WHERE status = 'leased'
    ) OR EXISTS (
        SELECT 1 FROM model_evaluation_challenges
        WHERE status = 'leased'
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'migration 0031 requires zero active worker leases';
    END IF;
END
$$;

-- Private hidden benchmark v2 only persists keyed commitments. The HMAC key is
-- provisioned outside PostgreSQL and must never be stored in this database.
-- This singleton records only the commitment of key version 1 so every writer
-- can fail closed when it is configured with a different key.
CREATE TABLE IF NOT EXISTS private_evaluation_hmac_key_state (
    version INTEGER PRIMARY KEY CHECK (version = 1),
    key_commitment TEXT NOT NULL CHECK (key_commitment ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE private_evaluation_hmac_key_state IS
    'Append-only singleton for HMAC key version 1 commitment; the HMAC key itself must never enter PostgreSQL.';
COMMENT ON COLUMN private_evaluation_hmac_key_state.key_commitment IS
    'Domain-separated SHA-256 of mindone:private-hidden:hmac-key-state:v1 NUL, u64_be(32), and the external 32-byte key; never the raw key or bare SHA-256(key).';

DROP TRIGGER IF EXISTS private_evaluation_hmac_key_state_append_only
    ON private_evaluation_hmac_key_state;
CREATE TRIGGER private_evaluation_hmac_key_state_append_only
    BEFORE UPDATE OR DELETE ON private_evaluation_hmac_key_state
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();

-- Version NULL is the existing public/canary/private-v1 representation. Version
-- 2 is a keyed-commitment-only private challenge. No legacy row is backfilled:
-- old rows retain prompt_hash/expected_hash and every new column remains NULL.
ALTER TABLE model_evaluation_challenges
    ADD COLUMN IF NOT EXISTS private_commitment_version INTEGER,
    ADD COLUMN IF NOT EXISTS private_catalog_statement_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_entry_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_case_family_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_key_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_prompt_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_expected_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_account_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_device_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_node_commitment TEXT;

ALTER TABLE model_evaluation_challenges
    ALTER COLUMN prompt_hash DROP NOT NULL,
    ALTER COLUMN expected_hash DROP NOT NULL;

-- 0028 的 v1 约束把 private_catalog_valid_until 与 raw catalog 标识符视为同一组。
-- v2 必须隐藏那些标识符，但仍需保留绝对有效期供 renew/expiry 安全边界使用。
ALTER TABLE model_evaluation_challenges
    DROP CONSTRAINT IF EXISTS model_evaluation_private_catalog_v1;
ALTER TABLE model_evaluation_challenges
    ADD CONSTRAINT model_evaluation_private_catalog_v1_v2 CHECK ((
        (
            private_commitment_version IS NULL
            AND private_catalog_id IS NULL
            AND private_catalog_entry_id IS NULL
            AND private_case_family IS NULL
            AND private_catalog_commitment IS NULL
            AND private_evaluator_id IS NULL
            AND private_evaluator_key_fingerprint IS NULL
            AND private_catalog_valid_until IS NULL
        )
        OR
        (
            private_commitment_version IS NULL
            AND challenge_kind = 'hidden_benchmark'
            AND private_catalog_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_catalog_entry_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_case_family ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_catalog_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_evaluator_key_fingerprint ~ '^[0-9a-f]{64}$'
            AND private_catalog_valid_until IS NOT NULL
            AND model_weights_hash IS NOT NULL
            AND challenge_nonce_hash IS NOT NULL
            AND challenge_binding_hash IS NOT NULL
        )
        OR
        (
            private_commitment_version = 2
            AND private_catalog_id IS NULL
            AND private_catalog_entry_id IS NULL
            AND private_case_family IS NULL
            AND private_catalog_commitment IS NULL
            AND private_evaluator_id IS NULL
            AND private_evaluator_key_fingerprint IS NULL
            AND private_catalog_valid_until IS NOT NULL
        )
    ) IS TRUE);

ALTER TABLE model_evaluation_challenges
    DROP CONSTRAINT IF EXISTS model_evaluation_private_commitment_shape_v2;
ALTER TABLE model_evaluation_challenges
    ADD CONSTRAINT model_evaluation_private_commitment_shape_v2 CHECK ((
        (
            private_commitment_version IS NULL
            AND private_catalog_statement_commitment IS NULL
            AND private_catalog_id_commitment IS NULL
            AND private_catalog_entry_commitment IS NULL
            AND private_case_family_commitment IS NULL
            AND private_evaluator_id_commitment IS NULL
            AND private_evaluator_key_commitment IS NULL
            AND private_prompt_commitment IS NULL
            AND private_expected_commitment IS NULL
            AND private_account_commitment IS NULL
            AND private_device_commitment IS NULL
            AND private_node_commitment IS NULL
            AND prompt_hash ~ '^[0-9a-f]{64}$'
            AND expected_hash ~ '^[0-9a-f]{64}$'
        )
        OR
        (
            private_commitment_version = 2
            AND challenge_kind = 'hidden_benchmark'
            AND private_catalog_statement_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_entry_commitment ~ '^[0-9a-f]{64}$'
            AND private_case_family_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_key_commitment ~ '^[0-9a-f]{64}$'
            AND private_prompt_commitment ~ '^[0-9a-f]{64}$'
            AND private_expected_commitment ~ '^[0-9a-f]{64}$'
            AND private_account_commitment ~ '^[0-9a-f]{64}$'
            AND private_device_commitment ~ '^[0-9a-f]{64}$'
            AND private_node_commitment ~ '^[0-9a-f]{64}$'
            AND claimed_user_id IS NOT NULL
            AND claimed_device_key_id IS NOT NULL
            AND claim_device_binding_version = 1
            AND prompt_hash IS NULL
            AND expected_hash IS NULL
            AND private_catalog_id IS NULL
            AND private_catalog_entry_id IS NULL
            AND private_case_family IS NULL
            AND private_catalog_commitment IS NULL
            AND private_evaluator_id IS NULL
            AND private_evaluator_key_fingerprint IS NULL
            -- 绝对有效期不是 catalog 标识符，且续租/过期路径必须保留它以阻止
            -- challenge 被延长到 evaluator 授权窗口之外。
            AND private_catalog_valid_until IS NOT NULL
            AND model_weights_hash IS NOT NULL
            AND challenge_nonce_hash IS NOT NULL
            AND challenge_binding_hash IS NOT NULL
            AND challenge_issued_expires_at IS NOT NULL
            AND authorized_input_tokens IS NOT NULL
            AND authorized_max_output_tokens IS NOT NULL
            AND inference_seed IS NOT NULL
        )
    ) IS TRUE);

-- A catalog entry is consumed once across statement rotation. Prompt and
-- behavior commitments stay globally unique, preserving the v1 anti-replay
-- contract without publishing dictionary-attackable hashes.
CREATE UNIQUE INDEX IF NOT EXISTS model_evaluation_private_entry_once_v2
    ON model_evaluation_challenges
       (private_catalog_id_commitment, private_catalog_entry_commitment)
    WHERE private_commitment_version = 2;
CREATE UNIQUE INDEX IF NOT EXISTS model_evaluation_private_prompt_once_v2
    ON model_evaluation_challenges (private_prompt_commitment)
    WHERE private_commitment_version = 2;
CREATE UNIQUE INDEX IF NOT EXISTS model_evaluation_private_behavior_once_v2
    ON model_evaluation_challenges (private_expected_commitment)
    WHERE private_commitment_version = 2;

-- A v2 challenge is an audit identity, not a mutable cache. Lease status,
-- lease_expires_at, challenge_seed and terminal result fields may follow their
-- existing lifecycle, but the target, issued binding, absolute validity and every
-- keyed commitment are frozen. The version itself is always immutable, which also
-- prevents converting a legacy v1 row into a fabricated v2 row after migration.
CREATE OR REPLACE FUNCTION mindone_prevent_private_evaluation_v2_rebinding()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.private_commitment_version IS DISTINCT FROM OLD.private_commitment_version
       OR (
            OLD.private_commitment_version = 2
            AND (
                NEW.model_id IS DISTINCT FROM OLD.model_id
                OR NEW.model_instance_id IS DISTINCT FROM OLD.model_instance_id
                OR NEW.node_id IS DISTINCT FROM OLD.node_id
                OR NEW.challenge_kind IS DISTINCT FROM OLD.challenge_kind
                OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
                OR NEW.prompt_hash IS DISTINCT FROM OLD.prompt_hash
                OR NEW.expected_hash IS DISTINCT FROM OLD.expected_hash
                OR NEW.model_weights_hash IS DISTINCT FROM OLD.model_weights_hash
                OR NEW.challenge_nonce_hash IS DISTINCT FROM OLD.challenge_nonce_hash
                OR NEW.challenge_binding_hash IS DISTINCT FROM OLD.challenge_binding_hash
                OR NEW.challenge_issued_expires_at
                    IS DISTINCT FROM OLD.challenge_issued_expires_at
                OR NEW.authorized_input_tokens IS DISTINCT FROM OLD.authorized_input_tokens
                OR NEW.authorized_max_output_tokens
                    IS DISTINCT FROM OLD.authorized_max_output_tokens
                OR NEW.inference_seed IS DISTINCT FROM OLD.inference_seed
                OR NEW.private_catalog_id IS DISTINCT FROM OLD.private_catalog_id
                OR NEW.private_catalog_entry_id IS DISTINCT FROM OLD.private_catalog_entry_id
                OR NEW.private_case_family IS DISTINCT FROM OLD.private_case_family
                OR NEW.private_catalog_commitment IS DISTINCT FROM OLD.private_catalog_commitment
                OR NEW.private_evaluator_id IS DISTINCT FROM OLD.private_evaluator_id
                OR NEW.private_evaluator_key_fingerprint
                    IS DISTINCT FROM OLD.private_evaluator_key_fingerprint
                OR NEW.private_catalog_valid_until
                    IS DISTINCT FROM OLD.private_catalog_valid_until
                OR NEW.claimed_user_id IS DISTINCT FROM OLD.claimed_user_id
                OR NEW.claimed_device_key_id IS DISTINCT FROM OLD.claimed_device_key_id
                OR NEW.claim_device_binding_version
                    IS DISTINCT FROM OLD.claim_device_binding_version
                OR NEW.private_catalog_statement_commitment
                    IS DISTINCT FROM OLD.private_catalog_statement_commitment
                OR NEW.private_catalog_id_commitment
                    IS DISTINCT FROM OLD.private_catalog_id_commitment
                OR NEW.private_catalog_entry_commitment
                    IS DISTINCT FROM OLD.private_catalog_entry_commitment
                OR NEW.private_case_family_commitment
                    IS DISTINCT FROM OLD.private_case_family_commitment
                OR NEW.private_evaluator_id_commitment
                    IS DISTINCT FROM OLD.private_evaluator_id_commitment
                OR NEW.private_evaluator_key_commitment
                    IS DISTINCT FROM OLD.private_evaluator_key_commitment
                OR NEW.private_prompt_commitment
                    IS DISTINCT FROM OLD.private_prompt_commitment
                OR NEW.private_expected_commitment
                    IS DISTINCT FROM OLD.private_expected_commitment
                OR NEW.private_account_commitment
                    IS DISTINCT FROM OLD.private_account_commitment
                OR NEW.private_device_commitment
                    IS DISTINCT FROM OLD.private_device_commitment
                OR NEW.private_node_commitment
                    IS DISTINCT FROM OLD.private_node_commitment
            )
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'private evaluation v2 identity and commitments are immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS model_evaluation_private_v2_binding_immutable
    ON model_evaluation_challenges;
CREATE TRIGGER model_evaluation_private_v2_binding_immutable
    BEFORE UPDATE OF
        model_id,model_instance_id,node_id,challenge_kind,issued_at,
        prompt_hash,expected_hash,model_weights_hash,challenge_nonce_hash,
        challenge_binding_hash,challenge_issued_expires_at,
        authorized_input_tokens,authorized_max_output_tokens,inference_seed,
        private_catalog_id,private_catalog_entry_id,private_case_family,
        private_catalog_commitment,private_evaluator_id,
        private_evaluator_key_fingerprint,private_catalog_valid_until,
        claimed_user_id,claimed_device_key_id,claim_device_binding_version,
        private_commitment_version,private_catalog_statement_commitment,
        private_catalog_id_commitment,private_catalog_entry_commitment,
        private_case_family_commitment,private_evaluator_id_commitment,
        private_evaluator_key_commitment,private_prompt_commitment,
        private_expected_commitment,private_account_commitment,
        private_device_commitment,private_node_commitment
    ON model_evaluation_challenges
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_private_evaluation_v2_rebinding();

-- Challenge lifecycle events are the authoritative source for private-budget
-- counts. Every v2 lifecycle event snapshots the same complete commitment set;
-- the old prompt_hash representation and the v2 representation cannot mix.
ALTER TABLE model_evaluation_challenge_events
    ADD COLUMN IF NOT EXISTS private_commitment_version INTEGER,
    ADD COLUMN IF NOT EXISTS private_catalog_statement_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_entry_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_case_family_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_key_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_prompt_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_expected_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_account_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_device_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_node_commitment TEXT;

ALTER TABLE model_evaluation_challenge_events
    ALTER COLUMN prompt_hash DROP NOT NULL;

ALTER TABLE model_evaluation_challenge_events
    DROP CONSTRAINT IF EXISTS model_evaluation_challenge_event_private_commitment_shape_v2;
ALTER TABLE model_evaluation_challenge_events
    ADD CONSTRAINT model_evaluation_challenge_event_private_commitment_shape_v2 CHECK ((
        (
            private_commitment_version IS NULL
            AND private_catalog_statement_commitment IS NULL
            AND private_catalog_id_commitment IS NULL
            AND private_catalog_entry_commitment IS NULL
            AND private_case_family_commitment IS NULL
            AND private_evaluator_id_commitment IS NULL
            AND private_evaluator_key_commitment IS NULL
            AND private_prompt_commitment IS NULL
            AND private_expected_commitment IS NULL
            AND private_account_commitment IS NULL
            AND private_device_commitment IS NULL
            AND private_node_commitment IS NULL
            AND prompt_hash ~ '^[0-9a-f]{64}$'
        )
        OR
        (
            private_commitment_version = 2
            AND private_catalog_statement_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_entry_commitment ~ '^[0-9a-f]{64}$'
            AND private_case_family_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_key_commitment ~ '^[0-9a-f]{64}$'
            AND private_prompt_commitment ~ '^[0-9a-f]{64}$'
            AND private_expected_commitment ~ '^[0-9a-f]{64}$'
            AND private_account_commitment ~ '^[0-9a-f]{64}$'
            AND private_device_commitment ~ '^[0-9a-f]{64}$'
            AND private_node_commitment ~ '^[0-9a-f]{64}$'
            AND prompt_hash IS NULL
        )
    ) IS TRUE);

-- The append-only event stream is the authority for cross-instance budgets.
-- A syntactically valid but differently scoped event would permanently poison or
-- evade those counts, so every INSERT must match the referenced challenge version
-- and its complete public-v1 or private-v2 commitment identity.
CREATE OR REPLACE FUNCTION mindone_validate_evaluation_event_binding()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM 1
    FROM model_evaluation_challenges challenge
    WHERE challenge.id = NEW.challenge_id
      AND challenge.private_commitment_version
            IS NOT DISTINCT FROM NEW.private_commitment_version
      AND (
          (
              NEW.private_commitment_version IS NULL
              AND challenge.prompt_hash IS NOT DISTINCT FROM NEW.prompt_hash
          )
          OR
          (
              NEW.private_commitment_version = 2
              AND challenge.private_catalog_statement_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_statement_commitment
              AND challenge.private_catalog_id_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_id_commitment
              AND challenge.private_catalog_entry_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_entry_commitment
              AND challenge.private_case_family_commitment
                    IS NOT DISTINCT FROM NEW.private_case_family_commitment
              AND challenge.private_evaluator_id_commitment
                    IS NOT DISTINCT FROM NEW.private_evaluator_id_commitment
              AND challenge.private_evaluator_key_commitment
                    IS NOT DISTINCT FROM NEW.private_evaluator_key_commitment
              AND challenge.private_prompt_commitment
                    IS NOT DISTINCT FROM NEW.private_prompt_commitment
              AND challenge.private_expected_commitment
                    IS NOT DISTINCT FROM NEW.private_expected_commitment
              AND challenge.private_account_commitment
                    IS NOT DISTINCT FROM NEW.private_account_commitment
              AND challenge.private_device_commitment
                    IS NOT DISTINCT FROM NEW.private_device_commitment
              AND challenge.private_node_commitment
                    IS NOT DISTINCT FROM NEW.private_node_commitment
          )
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'evaluation lifecycle event does not match challenge identity';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS model_evaluation_challenge_event_binding_guard
    ON model_evaluation_challenge_events;
CREATE TRIGGER model_evaluation_challenge_event_binding_guard
    BEFORE INSERT ON model_evaluation_challenge_events
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_evaluation_event_binding();

-- Budget readers lock scopes first, then count only authoritative challenge
-- events (normally event_kind = 'issued'). Time indexes keep each HMAC scope
-- bounded without exposing raw catalog/account/device/node identifiers.
CREATE INDEX IF NOT EXISTS model_evaluation_private_catalog_time_v2
    ON model_evaluation_challenge_events
       (private_catalog_id_commitment, created_at DESC, id DESC)
    WHERE private_commitment_version = 2 AND event_kind = 'issued';
CREATE INDEX IF NOT EXISTS model_evaluation_private_account_time_v2
    ON model_evaluation_challenge_events
       (private_account_commitment, created_at DESC, id DESC)
    WHERE private_commitment_version = 2 AND event_kind = 'issued';
CREATE INDEX IF NOT EXISTS model_evaluation_private_device_time_v2
    ON model_evaluation_challenge_events
       (private_device_commitment, created_at DESC, id DESC)
    WHERE private_commitment_version = 2 AND event_kind = 'issued';
CREATE INDEX IF NOT EXISTS model_evaluation_private_node_time_v2
    ON model_evaluation_challenge_events
       (private_node_commitment, created_at DESC, id DESC)
    WHERE private_commitment_version = 2 AND event_kind = 'issued';

-- Arbitration v1 keeps the raw evaluator/catalog/family fields introduced by
-- 0028. Arbitration v2 keeps only keyed commitments. The row shape makes the
-- two versions mutually exclusive; aggregation must include version and the
-- matching version-specific evaluator/case scope so v1 and v2 cannot mix.
ALTER TABLE model_authenticity_arbitration_events
    ADD COLUMN IF NOT EXISTS private_commitment_version INTEGER,
    ADD COLUMN IF NOT EXISTS private_catalog_statement_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_catalog_entry_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_case_family_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_id_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_evaluator_key_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_prompt_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_expected_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_account_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_device_commitment TEXT,
    ADD COLUMN IF NOT EXISTS private_node_commitment TEXT;

ALTER TABLE model_authenticity_arbitration_events
    ALTER COLUMN private_evaluator_key_fingerprint DROP NOT NULL,
    ALTER COLUMN private_catalog_commitment DROP NOT NULL,
    ALTER COLUMN private_case_family DROP NOT NULL;

ALTER TABLE model_authenticity_arbitration_events
    DROP CONSTRAINT IF EXISTS model_authenticity_arbitration_private_commitment_shape_v2;
ALTER TABLE model_authenticity_arbitration_events
    ADD CONSTRAINT model_authenticity_arbitration_private_commitment_shape_v2 CHECK ((
        (
            private_commitment_version IS NULL
            AND private_evaluator_key_fingerprint ~ '^[0-9a-f]{64}$'
            AND private_catalog_commitment ~ '^[0-9a-f]{64}$'
            AND private_case_family ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND private_catalog_statement_commitment IS NULL
            AND private_catalog_id_commitment IS NULL
            AND private_catalog_entry_commitment IS NULL
            AND private_case_family_commitment IS NULL
            AND private_evaluator_id_commitment IS NULL
            AND private_evaluator_key_commitment IS NULL
            AND private_prompt_commitment IS NULL
            AND private_expected_commitment IS NULL
            AND private_account_commitment IS NULL
            AND private_device_commitment IS NULL
            AND private_node_commitment IS NULL
        )
        OR
        (
            private_commitment_version = 2
            AND private_evaluator_key_fingerprint IS NULL
            AND private_catalog_commitment IS NULL
            AND private_case_family IS NULL
            AND private_catalog_statement_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_catalog_entry_commitment ~ '^[0-9a-f]{64}$'
            AND private_case_family_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_id_commitment ~ '^[0-9a-f]{64}$'
            AND private_evaluator_key_commitment ~ '^[0-9a-f]{64}$'
            AND private_prompt_commitment ~ '^[0-9a-f]{64}$'
            AND private_expected_commitment ~ '^[0-9a-f]{64}$'
            AND private_account_commitment ~ '^[0-9a-f]{64}$'
            AND private_device_commitment ~ '^[0-9a-f]{64}$'
            AND private_node_commitment ~ '^[0-9a-f]{64}$'
        )
    ) IS TRUE);

-- Arbitration is another append-only projection of the same challenge identity.
-- Bind every new row back to the exact target, execution binding and matching
-- version-specific evaluator/catalog scope before it can enter aggregation.
CREATE OR REPLACE FUNCTION mindone_validate_authenticity_arbitration_binding()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM 1
    FROM model_evaluation_challenges challenge
    WHERE challenge.id = NEW.challenge_id
      AND challenge.model_id = NEW.model_id
      AND challenge.model_instance_id = NEW.model_instance_id
      AND challenge.model_weights_hash IS NOT DISTINCT FROM NEW.model_weights_hash
      AND challenge.challenge_binding_hash
            IS NOT DISTINCT FROM NEW.challenge_binding_hash
      AND challenge.private_commitment_version
            IS NOT DISTINCT FROM NEW.private_commitment_version
      AND (
          (
              NEW.private_commitment_version IS NULL
              AND challenge.private_evaluator_key_fingerprint
                    IS NOT DISTINCT FROM NEW.private_evaluator_key_fingerprint
              AND challenge.private_catalog_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_commitment
              AND challenge.private_case_family
                    IS NOT DISTINCT FROM NEW.private_case_family
          )
          OR
          (
              NEW.private_commitment_version = 2
              AND challenge.private_catalog_statement_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_statement_commitment
              AND challenge.private_catalog_id_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_id_commitment
              AND challenge.private_catalog_entry_commitment
                    IS NOT DISTINCT FROM NEW.private_catalog_entry_commitment
              AND challenge.private_case_family_commitment
                    IS NOT DISTINCT FROM NEW.private_case_family_commitment
              AND challenge.private_evaluator_id_commitment
                    IS NOT DISTINCT FROM NEW.private_evaluator_id_commitment
              AND challenge.private_evaluator_key_commitment
                    IS NOT DISTINCT FROM NEW.private_evaluator_key_commitment
              AND challenge.private_prompt_commitment
                    IS NOT DISTINCT FROM NEW.private_prompt_commitment
              AND challenge.private_expected_commitment
                    IS NOT DISTINCT FROM NEW.private_expected_commitment
              AND challenge.private_account_commitment
                    IS NOT DISTINCT FROM NEW.private_account_commitment
              AND challenge.private_device_commitment
                    IS NOT DISTINCT FROM NEW.private_device_commitment
              AND challenge.private_node_commitment
                    IS NOT DISTINCT FROM NEW.private_node_commitment
          )
      );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'authenticity arbitration does not match challenge identity';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS model_authenticity_arbitration_binding_guard
    ON model_authenticity_arbitration_events;
CREATE TRIGGER model_authenticity_arbitration_binding_guard
    BEFORE INSERT ON model_authenticity_arbitration_events
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_authenticity_arbitration_binding();

CREATE INDEX IF NOT EXISTS model_authenticity_arbitration_family_time_v2
    ON model_authenticity_arbitration_events
       (private_commitment_version, model_weights_hash,
        private_evaluator_key_commitment, private_case_family_commitment,
        created_at DESC, id DESC)
    WHERE private_commitment_version = 2;

-- One append-only row exists per v2 HMAC budget scope and is inserted lazily.
-- Rust must acquire these rows in strict catalog/account/device/node order before
-- counting authoritative challenge events and issuing a new challenge. The rows
-- contain no counters; event history remains the source of truth.
CREATE TABLE IF NOT EXISTS private_evaluation_budget_scopes (
    version INTEGER NOT NULL CHECK (version = 2),
    scope_kind TEXT NOT NULL
        CHECK (scope_kind IN ('catalog', 'account', 'device', 'node')),
    scope_commitment TEXT NOT NULL
        CHECK (scope_commitment ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (version, scope_kind, scope_commitment)
);

COMMENT ON TABLE private_evaluation_budget_scopes IS
    'Append-only lock rows; Rust locks catalog/account/device/node in strict order and derives counts from authoritative challenge events.';

DROP TRIGGER IF EXISTS private_evaluation_budget_scopes_append_only
    ON private_evaluation_budget_scopes;
CREATE TRIGGER private_evaluation_budget_scopes_append_only
    BEFORE UPDATE OR DELETE ON private_evaluation_budget_scopes
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
