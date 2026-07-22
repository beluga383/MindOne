-- Public model publishers may no longer author quality or Tier state. These columns are
-- mutated only by the coordinator's trusted evaluation transaction.
ALTER TABLE models
    ADD COLUMN IF NOT EXISTS benchmark_samples INTEGER NOT NULL DEFAULT 0
        CHECK (benchmark_samples >= 0),
    ADD COLUMN IF NOT EXISTS glicko_rating_milli BIGINT NOT NULL DEFAULT 1500000
        CHECK (glicko_rating_milli BETWEEN 0 AND 4000000),
    ADD COLUMN IF NOT EXISTS glicko_deviation_milli BIGINT NOT NULL DEFAULT 350000
        CHECK (glicko_deviation_milli BETWEEN 1 AND 350000),
    ADD COLUMN IF NOT EXISTS glicko_volatility_nano BIGINT NOT NULL DEFAULT 60000000
        CHECK (glicko_volatility_nano BETWEEN 1000 AND 1000000000),
    ADD COLUMN IF NOT EXISTS quality_fusion_normalized INTEGER NOT NULL DEFAULT 0
        CHECK (quality_fusion_normalized BETWEEN 0 AND 1000000),
    ADD COLUMN IF NOT EXISTS quality_policy_version INTEGER NOT NULL DEFAULT 1
        CHECK (quality_policy_version > 0),
    ADD COLUMN IF NOT EXISTS quality_updated_at TIMESTAMPTZ;

ALTER TABLE models
    ALTER COLUMN glicko_normalized SET DEFAULT 500000;

-- Values written before this migration came from the public publish request and therefore
-- have no trusted provenance. Reset them to a neutral cold-start state instead of silently
-- grandfathering a self-awarded Tier.
UPDATE models
SET benchmark_normalized = 0,
    benchmark_samples = 0,
    glicko_normalized = 500000,
    glicko_rating_milli = 1500000,
    glicko_deviation_milli = 350000,
    glicko_volatility_nano = 60000000,
    evaluation_samples = 0,
    quality_fusion_normalized = 0,
    tier = 'medium',
    quality_policy_version = 1,
    quality_updated_at = NULL;

CREATE TABLE IF NOT EXISTS model_quality_events (
    id UUID PRIMARY KEY,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL
        CHECK (event_kind IN ('hidden_benchmark', 'canary', 'blind_evaluation')),
    idempotency_key TEXT NOT NULL UNIQUE
        CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    request_hash TEXT NOT NULL UNIQUE CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    evidence_hash TEXT NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    score_normalized INTEGER CHECK (score_normalized BETWEEN 0 AND 1000000),
    sample_count INTEGER NOT NULL CHECK (sample_count BETWEEN 1 AND 10000),
    opponent_rating_milli BIGINT CHECK (opponent_rating_milli BETWEEN 0 AND 4000000),
    opponent_deviation_milli BIGINT
        CHECK (opponent_deviation_milli BETWEEN 1 AND 350000),
    outcome_millionths INTEGER CHECK (outcome_millionths IN (0, 500000, 1000000)),
    old_benchmark_normalized INTEGER NOT NULL
        CHECK (old_benchmark_normalized BETWEEN 0 AND 1000000),
    new_benchmark_normalized INTEGER NOT NULL
        CHECK (new_benchmark_normalized BETWEEN 0 AND 1000000),
    old_benchmark_samples INTEGER NOT NULL CHECK (old_benchmark_samples >= 0),
    new_benchmark_samples INTEGER NOT NULL CHECK (new_benchmark_samples >= 0),
    old_glicko_normalized INTEGER NOT NULL
        CHECK (old_glicko_normalized BETWEEN 0 AND 1000000),
    new_glicko_normalized INTEGER NOT NULL
        CHECK (new_glicko_normalized BETWEEN 0 AND 1000000),
    old_glicko_rating_milli BIGINT NOT NULL
        CHECK (old_glicko_rating_milli BETWEEN 0 AND 4000000),
    new_glicko_rating_milli BIGINT NOT NULL
        CHECK (new_glicko_rating_milli BETWEEN 0 AND 4000000),
    old_glicko_deviation_milli BIGINT NOT NULL
        CHECK (old_glicko_deviation_milli BETWEEN 1 AND 350000),
    new_glicko_deviation_milli BIGINT NOT NULL
        CHECK (new_glicko_deviation_milli BETWEEN 1 AND 350000),
    old_glicko_volatility_nano BIGINT NOT NULL
        CHECK (old_glicko_volatility_nano BETWEEN 1000 AND 1000000000),
    new_glicko_volatility_nano BIGINT NOT NULL
        CHECK (new_glicko_volatility_nano BETWEEN 1000 AND 1000000000),
    old_evaluation_samples INTEGER NOT NULL CHECK (old_evaluation_samples >= 0),
    new_evaluation_samples INTEGER NOT NULL CHECK (new_evaluation_samples >= 0),
    old_fusion_normalized INTEGER NOT NULL
        CHECK (old_fusion_normalized BETWEEN 0 AND 1000000),
    new_fusion_normalized INTEGER NOT NULL
        CHECK (new_fusion_normalized BETWEEN 0 AND 1000000),
    old_tier TEXT NOT NULL CHECK (old_tier IN ('high', 'medium', 'low')),
    new_tier TEXT NOT NULL CHECK (new_tier IN ('high', 'medium', 'low')),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT model_quality_event_shape CHECK (
        (event_kind IN ('hidden_benchmark', 'canary')
            AND score_normalized IS NOT NULL
            AND opponent_rating_milli IS NULL
            AND opponent_deviation_milli IS NULL
            AND outcome_millionths IS NULL)
        OR
        (event_kind = 'blind_evaluation'
            AND score_normalized IS NULL
            AND sample_count = 1
            AND opponent_rating_milli IS NOT NULL
            AND opponent_deviation_milli IS NOT NULL
            AND outcome_millionths IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS model_quality_events_model_time_idx
    ON model_quality_events (model_id, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION mindone_prevent_quality_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MindOne model quality events are append-only';
END;
$$;

DROP TRIGGER IF EXISTS model_quality_events_append_only ON model_quality_events;
CREATE TRIGGER model_quality_events_append_only
    BEFORE UPDATE OR DELETE ON model_quality_events
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
