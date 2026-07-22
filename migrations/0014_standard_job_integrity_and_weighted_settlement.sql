-- Standard 数据面完整性、失败回放绑定与贡献权重审计。

ALTER TABLE jobs
    ADD COLUMN standard_request_fingerprint TEXT
        CHECK (standard_request_fingerprint IS NULL
            OR standard_request_fingerprint ~ '^[0-9a-f]{64}$');

ALTER TABLE job_attempts
    ADD COLUMN retryable_requested BOOLEAN;

ALTER TABLE receipts
    ADD COLUMN contribution_weight_ppm INTEGER NOT NULL DEFAULT 1000000
        CHECK (contribution_weight_ppm BETWEEN 0 AND 1000000);
