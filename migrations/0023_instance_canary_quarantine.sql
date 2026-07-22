-- A small public-template canary is a risk signal, not cryptographic execution proof.
-- Keep its mutable exact-instance routing state separate from canonical model quality,
-- and retain every signal/transition in an append-only audit trail.
CREATE TABLE IF NOT EXISTS model_instance_canary_state (
    model_instance_id UUID PRIMARY KEY
        REFERENCES model_instances(id) ON DELETE CASCADE,
    consecutive_failures INTEGER NOT NULL DEFAULT 0
        CHECK (consecutive_failures BETWEEN 0 AND 1000000),
    recovery_passes INTEGER NOT NULL DEFAULT 0
        CHECK (recovery_passes BETWEEN 0 AND 1000000),
    quarantined BOOLEAN NOT NULL DEFAULT FALSE,
    last_challenge_id UUID
        REFERENCES model_evaluation_challenges(id) ON DELETE RESTRICT,
    quarantined_at TIMESTAMPTZ,
    recovered_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT model_instance_canary_state_shape CHECK (
        (quarantined = FALSE AND recovery_passes = 0)
        OR quarantined = TRUE
    )
);

CREATE INDEX IF NOT EXISTS model_instance_canary_quarantined_idx
    ON model_instance_canary_state (model_instance_id)
    WHERE quarantined = TRUE;

CREATE TABLE IF NOT EXISTS model_instance_canary_events (
    id UUID PRIMARY KEY,
    model_instance_id UUID NOT NULL
        REFERENCES model_instances(id) ON DELETE RESTRICT,
    challenge_id UUID NOT NULL
        REFERENCES model_evaluation_challenges(id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK (
        event_kind IN ('signal_passed','signal_failed','quarantined','recovered')
    ),
    reason_code TEXT NOT NULL CHECK (
        reason_code IN ('answer_match','answer_mismatch','worker_failed','lease_expired')
    ),
    consecutive_failures INTEGER NOT NULL
        CHECK (consecutive_failures BETWEEN 0 AND 1000000),
    recovery_passes INTEGER NOT NULL
        CHECK (recovery_passes BETWEEN 0 AND 1000000),
    quarantined BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (challenge_id,event_kind)
);

CREATE INDEX IF NOT EXISTS model_instance_canary_events_instance_time_idx
    ON model_instance_canary_events (model_instance_id,created_at DESC,id DESC);

DROP TRIGGER IF EXISTS model_instance_canary_events_append_only
    ON model_instance_canary_events;
CREATE TRIGGER model_instance_canary_events_append_only
    BEFORE UPDATE OR DELETE ON model_instance_canary_events
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
