-- Finalize the physical billing cutover without rewriting historical rows.
--
-- The migration must run with coordinators stopped. It rejects active ordinary
-- work that cannot settle under v1 and still-consumable prepared regulated
-- routes. Terminal legacy history remains readable. A transaction-scoped table
-- lock closes the race between the preflight and installation of INSERT guards.

LOCK TABLE jobs, regulated_routes, receipts IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE
    unsettled_job_count BIGINT;
    consumable_route_count BIGINT;
BEGIN
    SELECT COUNT(*)::bigint
    INTO unsettled_job_count
    FROM jobs
    WHERE status IN ('queued', 'leased', 'retry')
      AND billing_contract_version IS DISTINCT FROM
            'server_reference_upper_bound_v1';

    SELECT COUNT(*)::bigint
    INTO consumable_route_count
    FROM regulated_routes
    WHERE status = 'prepared'
      AND expires_at > transaction_timestamp()
      AND billing_contract_version IS DISTINCT FROM
            'server_reference_upper_bound_v1';

    IF unsettled_job_count > 0 OR consumable_route_count > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = format(
                'MindOne 0034 升级被拒绝：存在 %s 个无法按 v1 结算的非终态任务和 %s 个仍可消费的旧 Regulated route。请先停止协调服务器，排空或取消任务并按账本流程释放准备金，等待或作废 prepared route 后再迁移。',
                unsettled_job_count,
                consumable_route_count
            ),
            DETAIL = format(
                'unsettled_jobs=%s consumable_prepared_routes=%s',
                unsettled_job_count,
                consumable_route_count
            ),
            HINT = '停止所有 coordinator writer；确认 queued/leased/retry 已结算或取消释放，且旧 prepared route 已消费、作废或过期。';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION mindone_require_current_physical_billing_insert_v1()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.billing_contract_version IS DISTINCT FROM
            'server_reference_upper_bound_v1'
       OR mindone_physical_billing_snapshot_is_valid_v1(
            NEW.billing_contract_version,
            NEW.billing_profile_id,
            NEW.billing_profile_version,
            NEW.billing_profile_fingerprint,
            NEW.billing_model_weights_hash,
            NEW.billing_reference_hardware_class,
            NEW.billing_profile_evidence_hash,
            NEW.billing_profile_valid_from,
            NEW.billing_profile_valid_until,
            NEW.billing_profile_max_input_tokens,
            NEW.billing_profile_max_output_tokens,
            NEW.billing_fixed_gpu_time_us,
            NEW.billing_gpu_time_us_per_1k_tokens,
            NEW.billing_reference_vram_mib,
            NEW.billing_token_rate_micro_per_1k,
            NEW.billing_gpu_rate_micro_per_second,
            NEW.billing_vram_rate_micro_per_gib_second,
            NEW.billing_authorized_input_tokens,
            NEW.billing_authorized_max_output_tokens,
            NEW.billing_billable_tokens,
            NEW.billing_reference_gpu_time_us,
            NEW.billing_reference_vram_mib_microseconds,
            NEW.billing_token_cost_micro,
            NEW.billing_gpu_cost_micro,
            NEW.billing_vram_cost_micro,
            NEW.billing_base_cost_micro
       ) IS NOT TRUE
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'new rows require a complete server_reference_upper_bound_v1 billing snapshot';
    END IF;

    -- jobs and regulated_routes share the same protocol token authorization
    -- fields. Keep this in a nested branch because receipts do not have them.
    IF TG_TABLE_NAME IN ('jobs', 'regulated_routes') THEN
        IF NEW.estimated_input_tokens::bigint
                IS DISTINCT FROM NEW.billing_authorized_input_tokens
           OR NEW.max_output_tokens::bigint
                IS DISTINCT FROM NEW.billing_authorized_max_output_tokens
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'protocol token authorization does not match billing authorization';
        END IF;
    END IF;

    -- The settlement amount is frozen twice intentionally: the 0032 CHECK
    -- protects all rows, while this INSERT guard fails before a new receipt can
    -- enter an append-only table with a divergent top-level base amount.
    IF TG_TABLE_NAME = 'receipts' THEN
        IF NEW.base_cost_micro IS DISTINCT FROM NEW.billing_base_cost_micro THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'receipt base_cost_micro does not match billing_base_cost_micro';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER jobs_00_require_current_physical_billing_v1
    BEFORE INSERT ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION mindone_require_current_physical_billing_insert_v1();

CREATE TRIGGER regulated_routes_00_require_current_physical_billing_v1
    BEFORE INSERT ON regulated_routes
    FOR EACH ROW
    EXECUTE FUNCTION mindone_require_current_physical_billing_insert_v1();

CREATE TRIGGER receipts_00_require_current_physical_billing_v1
    BEFORE INSERT ON receipts
    FOR EACH ROW
    EXECUTE FUNCTION mindone_require_current_physical_billing_insert_v1();

-- Trigger execution does not require callers to hold EXECUTE on the trigger
-- function. Keep the runtime function allowlist unchanged: only the immutable
-- snapshot validator and audited provisioning definer remain callable.
REVOKE ALL PRIVILEGES ON FUNCTION
    mindone_require_current_physical_billing_insert_v1()
    FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        REVOKE ALL PRIVILEGES ON FUNCTION
            mindone_require_current_physical_billing_insert_v1()
            FROM mindone_app;
    END IF;
END;
$$;
