-- Standard 模式数据库静态数据保护。线协议继续使用 Base64/Base64URL；
-- 旧行由协调器在开始接流量前、持有密钥的事务中完成原地回填。

CREATE TABLE standard_data_key_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    envelope_version SMALLINT NOT NULL CHECK (envelope_version = 1),
    key_commitment TEXT NOT NULL CHECK (key_commitment ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TRIGGER standard_data_key_state_immutable
    BEFORE UPDATE OR DELETE ON standard_data_key_state
    FOR EACH ROW EXECUTE FUNCTION mindone_prevent_ledger_mutation();

ALTER TABLE jobs
    DROP CONSTRAINT IF EXISTS jobs_standard_request_fingerprint_check;

ALTER TABLE jobs
    ADD COLUMN standard_payload_storage_version SMALLINT,
    ADD COLUMN standard_result_storage_version SMALLINT;

UPDATE jobs
SET standard_payload_storage_version = 0,
    standard_result_storage_version = CASE
        WHEN result_ciphertext IS NULL THEN NULL ELSE 0
    END
WHERE confidentiality_mode = 'standard';

ALTER TABLE jobs
    ADD CONSTRAINT jobs_standard_payload_storage_shape CHECK (
        (confidentiality_mode = 'standard'
            AND standard_payload_storage_version IN (0, 1))
        OR (confidentiality_mode <> 'standard'
            AND standard_payload_storage_version IS NULL)
    ),
    ADD CONSTRAINT jobs_standard_result_storage_shape CHECK (
        (confidentiality_mode = 'standard' AND (
            (result_ciphertext IS NULL AND standard_result_storage_version IS NULL)
            OR (result_ciphertext IS NOT NULL
                AND standard_result_storage_version IN (0, 1))
        ))
        OR (confidentiality_mode <> 'standard'
            AND standard_result_storage_version IS NULL)
    ),
    ADD CONSTRAINT jobs_standard_request_fingerprint_shape CHECK (
        standard_request_fingerprint IS NULL
        OR standard_request_fingerprint ~ '^[0-9a-f]{64}$'
        OR standard_request_fingerprint
            ~ '^mindone-standard-hmac-v1:[0-9a-f]{64}$'
    );

CREATE OR REPLACE FUNCTION mindone_enforce_standard_data_at_rest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.confidentiality_mode = 'standard' THEN
        IF NEW.standard_payload_storage_version IS DISTINCT FROM 1
           OR NEW.encrypted_payload
                !~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$' THEN
            RAISE EXCEPTION 'Standard payload must use storage envelope v1'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.standard_request_fingerprint IS NULL
           OR NEW.standard_request_fingerprint
                !~ '^mindone-standard-hmac-v1:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION 'Standard request fingerprint must use keyed format v1'
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.result_ciphertext IS NULL THEN
            IF NEW.standard_result_storage_version IS NOT NULL THEN
                RAISE EXCEPTION 'empty Standard result cannot have a storage version'
                    USING ERRCODE = 'check_violation';
            END IF;
        ELSIF NEW.standard_result_storage_version IS DISTINCT FROM 1
              OR NEW.result_ciphertext
                    !~ '^mindone-standard-aead-v1:[A-Za-z0-9_-]+$' THEN
            RAISE EXCEPTION 'Standard result must use storage envelope v1'
                USING ERRCODE = 'check_violation';
        END IF;
    ELSIF NEW.standard_payload_storage_version IS NOT NULL
          OR NEW.standard_result_storage_version IS NOT NULL THEN
        RAISE EXCEPTION 'non-Standard job cannot use Standard storage versions'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER jobs_enforce_standard_data_at_rest
    BEFORE INSERT OR UPDATE ON jobs
    FOR EACH ROW EXECUTE FUNCTION mindone_enforce_standard_data_at_rest();
