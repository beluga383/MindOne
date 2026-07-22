CREATE TABLE IF NOT EXISTS model_evaluation_challenges (
    id UUID PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    model_instance_id UUID NOT NULL REFERENCES model_instances(id) ON DELETE RESTRICT,
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT,
    challenge_kind TEXT NOT NULL CHECK (challenge_kind IN ('hidden_benchmark', 'canary')),
    challenge_seed BYTEA CHECK (challenge_seed IS NULL OR octet_length(challenge_seed) = 32),
    prompt_hash TEXT NOT NULL CHECK (prompt_hash ~ '^[0-9a-f]{64}$'),
    expected_hash TEXT NOT NULL CHECK (expected_hash ~ '^[0-9a-f]{64}$'),
    lease_token_hash TEXT NOT NULL CHECK (lease_token_hash ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('leased', 'succeeded', 'failed', 'expired')),
    result_hash TEXT CHECK (result_hash ~ '^[0-9a-f]{64}$'),
    score_normalized INTEGER CHECK (score_normalized BETWEEN 0 AND 1000000),
    resulting_tier TEXT CHECK (resulting_tier IN ('high', 'medium', 'low')),
    resulting_evaluation_samples INTEGER CHECK (resulting_evaluation_samples >= 0),
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CONSTRAINT model_evaluation_challenge_state CHECK (
        (status = 'leased'
            AND challenge_seed IS NOT NULL
            AND result_hash IS NULL
            AND score_normalized IS NULL
            AND resulting_tier IS NULL
            AND resulting_evaluation_samples IS NULL
            AND completed_at IS NULL)
        OR
        (status IN ('succeeded', 'failed')
            AND challenge_seed IS NULL
            AND result_hash IS NOT NULL
            AND score_normalized IS NOT NULL
            AND resulting_tier IS NOT NULL
            AND resulting_evaluation_samples IS NOT NULL
            AND completed_at IS NOT NULL)
        OR
        (status = 'expired'
            AND challenge_seed IS NULL
            AND result_hash IS NULL
            AND score_normalized IS NULL
            AND resulting_tier IS NULL
            AND resulting_evaluation_samples IS NULL
            AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS model_evaluation_one_live_instance_idx
    ON model_evaluation_challenges (model_instance_id)
    WHERE status = 'leased';

CREATE INDEX IF NOT EXISTS model_evaluation_model_time_idx
    ON model_evaluation_challenges (model_id, issued_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS model_evaluation_challenge_events (
    id UUID PRIMARY KEY,
    challenge_id UUID NOT NULL REFERENCES model_evaluation_challenges(id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('issued', 'completed', 'expired')),
    prompt_hash TEXT NOT NULL CHECK (prompt_hash ~ '^[0-9a-f]{64}$'),
    result_hash TEXT CHECK (result_hash ~ '^[0-9a-f]{64}$'),
    score_normalized INTEGER CHECK (score_normalized BETWEEN 0 AND 1000000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT model_evaluation_lifecycle_shape CHECK (
        (event_kind = 'issued' AND result_hash IS NULL AND score_normalized IS NULL)
        OR
        (event_kind = 'completed' AND result_hash IS NOT NULL AND score_normalized IS NOT NULL)
        OR
        (event_kind = 'expired' AND result_hash IS NULL AND score_normalized IS NULL)
    ),
    UNIQUE (challenge_id, event_kind)
);

CREATE INDEX IF NOT EXISTS model_evaluation_challenge_events_time_idx
    ON model_evaluation_challenge_events (created_at DESC, id DESC);

DROP TRIGGER IF EXISTS model_evaluation_challenge_events_append_only
    ON model_evaluation_challenge_events;
CREATE TRIGGER model_evaluation_challenge_events_append_only
    BEFORE UPDATE OR DELETE ON model_evaluation_challenge_events
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
