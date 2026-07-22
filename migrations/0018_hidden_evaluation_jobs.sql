-- Hidden benchmark/canary submissions travel through the ordinary job endpoints.
-- These columns bind the ordinary result/fail idempotency key to an exact request
-- without retaining worker output or failure plaintext.
ALTER TABLE model_evaluation_challenges
    ADD COLUMN IF NOT EXISTS worker_submission_kind TEXT,
    ADD COLUMN IF NOT EXISTS worker_idempotency_key TEXT,
    ADD COLUMN IF NOT EXISTS worker_request_hash TEXT;

ALTER TABLE model_evaluation_challenges
    DROP CONSTRAINT IF EXISTS model_evaluation_worker_submission_shape;
ALTER TABLE model_evaluation_challenges
    ADD CONSTRAINT model_evaluation_worker_submission_shape CHECK (
        (worker_submission_kind IS NULL
            AND worker_idempotency_key IS NULL
            AND worker_request_hash IS NULL)
        OR
        (worker_submission_kind IN ('result', 'fail')
            AND worker_idempotency_key IS NOT NULL
            AND length(worker_idempotency_key) BETWEEN 1 AND 200
            AND worker_request_hash ~ '^[0-9a-f]{64}$')
    );

-- A worker-side execution failure is also append-only audited. The event stores
-- only a salted commitment, never the worker's failure message.
ALTER TABLE model_evaluation_challenge_events
    DROP CONSTRAINT IF EXISTS model_evaluation_challenge_events_event_kind_check;
ALTER TABLE model_evaluation_challenge_events
    ADD CONSTRAINT model_evaluation_challenge_events_event_kind_check
        CHECK (event_kind IN ('issued', 'completed', 'expired', 'worker_failed'));

ALTER TABLE model_evaluation_challenge_events
    DROP CONSTRAINT IF EXISTS model_evaluation_lifecycle_shape;
ALTER TABLE model_evaluation_challenge_events
    ADD CONSTRAINT model_evaluation_lifecycle_shape CHECK (
        (event_kind = 'issued' AND result_hash IS NULL AND score_normalized IS NULL)
        OR
        (event_kind = 'completed' AND result_hash IS NOT NULL AND score_normalized IS NOT NULL)
        OR
        (event_kind = 'expired' AND result_hash IS NULL AND score_normalized IS NULL)
        OR
        (event_kind = 'worker_failed' AND result_hash IS NOT NULL AND score_normalized IS NULL)
    );
