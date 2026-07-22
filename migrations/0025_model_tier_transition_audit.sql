-- 同名、已启用模型的相对 percentile 会使一次可信质量事件改变其他 cohort 成员的
-- Tier。派生转换必须绑定源质量事件并只追加，避免只在 models 当前状态中静默改写。

CREATE TABLE model_tier_transition_events (
    id UUID PRIMARY KEY,
    source_quality_event_id UUID NOT NULL
        REFERENCES model_quality_events(id) ON DELETE RESTRICT,
    model_id UUID NOT NULL REFERENCES models(id) ON DELETE RESTRICT,
    cohort_name TEXT NOT NULL CHECK (
        octet_length(cohort_name) BETWEEN 1 AND 512
        AND cohort_name = btrim(cohort_name)
        AND cohort_name !~ '[[:cntrl:]]'
    ),
    cohort_size INTEGER NOT NULL CHECK (cohort_size > 0),
    cohort_commitment TEXT NOT NULL CHECK (
        cohort_commitment ~ '^[0-9a-f]{64}$'
    ),
    old_tier TEXT NOT NULL CHECK (old_tier IN ('high', 'medium', 'low')),
    new_tier TEXT NOT NULL CHECK (new_tier IN ('high', 'medium', 'low')),
    fusion_normalized INTEGER NOT NULL CHECK (
        fusion_normalized BETWEEN 0 AND 1000000
    ),
    percentile_millionths INTEGER NOT NULL CHECK (
        percentile_millionths BETWEEN 0 AND 1000000
    ),
    evaluation_samples INTEGER NOT NULL CHECK (evaluation_samples >= 0),
    policy_version INTEGER NOT NULL CHECK (policy_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT model_tier_transition_changed CHECK (old_tier <> new_tier),
    CONSTRAINT model_tier_transition_source_model_unique
        UNIQUE (source_quality_event_id, model_id)
);

CREATE INDEX model_tier_transition_events_model_time_idx
    ON model_tier_transition_events (model_id, created_at DESC, id DESC);

CREATE INDEX model_tier_transition_events_source_idx
    ON model_tier_transition_events (source_quality_event_id, model_id);

CREATE OR REPLACE FUNCTION mindone_validate_model_tier_transition_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM model_quality_events source_event
        JOIN models source_model ON source_model.id = source_event.model_id
        JOIN models model ON model.id = NEW.model_id
        WHERE source_event.id = NEW.source_quality_event_id
          AND source_model.enabled = TRUE
          AND source_model.name = NEW.cohort_name
          AND model.enabled = TRUE
          AND model.name = NEW.cohort_name
          AND model.tier = NEW.new_tier
          AND model.quality_fusion_normalized = NEW.fusion_normalized
          AND model.evaluation_samples = NEW.evaluation_samples
          AND model.quality_policy_version = NEW.policy_version
          AND (
              SELECT COUNT(*) FROM models cohort_model
              WHERE cohort_model.enabled = TRUE
                AND cohort_model.name = NEW.cohort_name
          ) = NEW.cohort_size
    ) THEN
        RAISE EXCEPTION 'model tier transition does not match source event and current model state';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER model_tier_transition_events_validate
    BEFORE INSERT ON model_tier_transition_events
    FOR EACH ROW EXECUTE FUNCTION mindone_validate_model_tier_transition_event();

CREATE TRIGGER model_tier_transition_events_append_only
    BEFORE UPDATE OR DELETE ON model_tier_transition_events
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_quality_event_mutation();
