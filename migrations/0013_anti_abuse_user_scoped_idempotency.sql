-- 反滥用幂等键与任务幂等键一样只在账户内唯一，避免其他账户预占同名键造成拒绝服务。
ALTER TABLE abuse_decisions
    DROP CONSTRAINT IF EXISTS abuse_decisions_assessment_key_key;

ALTER TABLE abuse_decisions
    ADD CONSTRAINT abuse_decisions_user_assessment_key_key
    UNIQUE (user_id, assessment_key);
