use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

use mindone_accounting::{
    maximum_reservation_quote, LedgerEntry, LedgerKind, MicroQuota, PerformanceTier,
    ReservePurpose, ReserveState, ServerReferenceBillingProfile, Settlement, TrustClass,
    SERVER_REFERENCE_UPPER_BOUND_V1,
};
use mindone_protocol::{
    EnvelopeDirection, ExecutionTelemetryVerdict, JobExecutionTelemetry, RegulatedEnvelope,
    Validate,
};

use crate::anti_abuse::{
    job_assessment_key, record_settled_edge, settlement_contribution_weight, AntiAbuseError,
    TrafficClass,
};
use crate::device_binding::DEVICE_BINDING_VERSION;
use crate::error::ApiError;
use crate::execution_fingerprint::{
    append_execution_fingerprint, telemetry_fingerprint, FingerprintContext,
};
use crate::routes::evaluations::instance_canary_quarantined;
use crate::standard_data::{
    decrypt_from_storage, encrypt_for_storage, StorageDirection, STORAGE_VERSION,
};

pub struct CompleteJob {
    pub job_id: Uuid,
    pub node_id: Uuid,
    pub worker_user_id: Uuid,
    pub claim_device_key_id: Uuid,
    pub idempotency_key: String,
    pub result_ciphertext: Zeroizing<String>,
    pub actual_input_tokens: i32,
    pub actual_output_tokens: i32,
    pub execution_telemetry: JobExecutionTelemetry,
}

/// 任务创建时由协调器冻结的物理计费快照。节点提交的实际 Token 或遥测从不写入
/// 这个结构，也绝不能参与金额计算。
#[derive(Clone, Debug, Serialize)]
struct JobBillingSnapshot {
    contract_version: String,
    profile_id: Uuid,
    profile_version: i64,
    profile_fingerprint: String,
    model_weights_hash: String,
    reference_hardware_class: String,
    profile_evidence_hash: String,
    profile_valid_from: time::OffsetDateTime,
    profile_valid_until: time::OffsetDateTime,
    profile_max_input_tokens: i64,
    profile_max_output_tokens: i64,
    fixed_gpu_time_us: i64,
    gpu_time_us_per_1k_tokens: i64,
    reference_vram_mib: i64,
    token_rate_micro_per_1k: i64,
    gpu_rate_micro_per_second: i64,
    vram_rate_micro_per_gib_second: i64,
    authorized_input_tokens: i64,
    authorized_max_output_tokens: i64,
    billable_tokens: i64,
    reference_gpu_time_us: i64,
    reference_vram_mib_microseconds: i64,
    token_cost_micro: i64,
    gpu_cost_micro: i64,
    vram_cost_micro: i64,
    base_cost_micro: i64,
}

impl JobBillingSnapshot {
    fn from_job_row(row: &PgRow) -> Result<Self, ApiError> {
        let contract_version: Option<String> = row.try_get("billing_contract_version")?;
        if contract_version.as_deref() != Some(SERVER_REFERENCE_UPPER_BOUND_V1) {
            return Err(ApiError::conflict(
                "billing_contract_unavailable",
                "任务没有冻结可结算的服务器参考上界计费合同",
            ));
        }
        let required = || ApiError::internal();
        let snapshot = Self {
            contract_version: contract_version.ok_or_else(required)?,
            profile_id: row
                .try_get::<Option<Uuid>, _>("billing_profile_id")?
                .ok_or_else(required)?,
            profile_version: row
                .try_get::<Option<i64>, _>("billing_profile_version")?
                .ok_or_else(required)?,
            profile_fingerprint: row
                .try_get::<Option<String>, _>("billing_profile_fingerprint")?
                .ok_or_else(required)?,
            model_weights_hash: row
                .try_get::<Option<String>, _>("billing_model_weights_hash")?
                .ok_or_else(required)?,
            reference_hardware_class: row
                .try_get::<Option<String>, _>("billing_reference_hardware_class")?
                .ok_or_else(required)?,
            profile_evidence_hash: row
                .try_get::<Option<String>, _>("billing_profile_evidence_hash")?
                .ok_or_else(required)?,
            profile_valid_from: row
                .try_get::<Option<time::OffsetDateTime>, _>("billing_profile_valid_from")?
                .ok_or_else(required)?,
            profile_valid_until: row
                .try_get::<Option<time::OffsetDateTime>, _>("billing_profile_valid_until")?
                .ok_or_else(required)?,
            profile_max_input_tokens: row
                .try_get::<Option<i64>, _>("billing_profile_max_input_tokens")?
                .ok_or_else(required)?,
            profile_max_output_tokens: row
                .try_get::<Option<i64>, _>("billing_profile_max_output_tokens")?
                .ok_or_else(required)?,
            fixed_gpu_time_us: row
                .try_get::<Option<i64>, _>("billing_fixed_gpu_time_us")?
                .ok_or_else(required)?,
            gpu_time_us_per_1k_tokens: row
                .try_get::<Option<i64>, _>("billing_gpu_time_us_per_1k_tokens")?
                .ok_or_else(required)?,
            reference_vram_mib: row
                .try_get::<Option<i64>, _>("billing_reference_vram_mib")?
                .ok_or_else(required)?,
            token_rate_micro_per_1k: row
                .try_get::<Option<i64>, _>("billing_token_rate_micro_per_1k")?
                .ok_or_else(required)?,
            gpu_rate_micro_per_second: row
                .try_get::<Option<i64>, _>("billing_gpu_rate_micro_per_second")?
                .ok_or_else(required)?,
            vram_rate_micro_per_gib_second: row
                .try_get::<Option<i64>, _>("billing_vram_rate_micro_per_gib_second")?
                .ok_or_else(required)?,
            authorized_input_tokens: row
                .try_get::<Option<i64>, _>("billing_authorized_input_tokens")?
                .ok_or_else(required)?,
            authorized_max_output_tokens: row
                .try_get::<Option<i64>, _>("billing_authorized_max_output_tokens")?
                .ok_or_else(required)?,
            billable_tokens: row
                .try_get::<Option<i64>, _>("billing_billable_tokens")?
                .ok_or_else(required)?,
            reference_gpu_time_us: row
                .try_get::<Option<i64>, _>("billing_reference_gpu_time_us")?
                .ok_or_else(required)?,
            reference_vram_mib_microseconds: row
                .try_get::<Option<i64>, _>("billing_reference_vram_mib_microseconds")?
                .ok_or_else(required)?,
            token_cost_micro: row
                .try_get::<Option<i64>, _>("billing_token_cost_micro")?
                .ok_or_else(required)?,
            gpu_cost_micro: row
                .try_get::<Option<i64>, _>("billing_gpu_cost_micro")?
                .ok_or_else(required)?,
            vram_cost_micro: row
                .try_get::<Option<i64>, _>("billing_vram_cost_micro")?
                .ok_or_else(required)?,
            base_cost_micro: row
                .try_get::<Option<i64>, _>("billing_base_cost_micro")?
                .ok_or_else(required)?,
        };
        if snapshot.authorized_input_tokens
            != i64::from(row.try_get::<i32, _>("estimated_input_tokens")?)
            || snapshot.authorized_max_output_tokens
                != i64::from(row.try_get::<i32, _>("max_output_tokens")?)
        {
            tracing::error!(
                profile_id = %snapshot.profile_id,
                "任务协议授权上限与冻结物理计费授权不一致"
            );
            return Err(ApiError::internal());
        }
        snapshot.validate_frozen_quote()?;
        Ok(snapshot)
    }

    fn validate_frozen_quote(&self) -> Result<(), ApiError> {
        let quote = maximum_reservation_quote(
            ServerReferenceBillingProfile {
                maximum_input_tokens: self.profile_max_input_tokens,
                maximum_output_tokens: self.profile_max_output_tokens,
                fixed_gpu_time_us: self.fixed_gpu_time_us,
                gpu_time_us_per_1k_tokens: self.gpu_time_us_per_1k_tokens,
                reference_vram_mib: self.reference_vram_mib,
                token_rate_micro_per_1k: self.token_rate_micro_per_1k,
                gpu_rate_micro_per_second: self.gpu_rate_micro_per_second,
                vram_rate_micro_per_gib_second: self.vram_rate_micro_per_gib_second,
            },
            self.authorized_input_tokens,
            self.authorized_max_output_tokens,
        )
        .map_err(map_accounting_error)?;
        if quote.billable_tokens != self.billable_tokens
            || quote.reference_gpu_time_us != self.reference_gpu_time_us
            || quote.reference_vram_mib_microseconds != self.reference_vram_mib_microseconds
            || quote.token_cost.as_i64() != self.token_cost_micro
            || quote.gpu_cost.as_i64() != self.gpu_cost_micro
            || quote.vram_cost.as_i64() != self.vram_cost_micro
            || quote.base_cost.as_i64() != self.base_cost_micro
        {
            tracing::error!(
                profile_id = %self.profile_id,
                profile_version = self.profile_version,
                "任务冻结的物理计费快照与合同公式不一致"
            );
            return Err(ApiError::internal());
        }
        Ok(())
    }

    fn canonical_hash(&self) -> Result<String, ApiError> {
        let canonical = serde_json::to_string(self).map_err(|_| ApiError::internal())?;
        Ok(sha256_hex(canonical))
    }
}

fn frozen_base_for_authorized_usage(
    billing: &JobBillingSnapshot,
    actual_input_tokens: i32,
    actual_output_tokens: i32,
) -> Result<i64, ApiError> {
    if i64::from(actual_input_tokens) > billing.authorized_input_tokens
        || i64::from(actual_output_tokens) > billing.authorized_max_output_tokens
    {
        return Err(ApiError::bad_request(
            "usage_exceeds_authorized_limit",
            "节点上报的 Token 使用量超过任务授权上限",
        ));
    }
    Ok(billing.base_cost_micro)
}

#[derive(Clone, Debug, Serialize)]
pub struct SettlementOutcome {
    pub receipt_id: Uuid,
    pub job_id: Uuid,
    pub base_cost_micro: i64,
    pub user_deduction_micro: i64,
    pub node_quota_micro: i64,
    pub contribution_micro: i64,
    pub contribution_weight_ppm: i32,
    pub reserve_micro: i64,
    pub settlement_hash: String,
    pub telemetry_verdict: ExecutionTelemetryVerdict,
    pub telemetry_alert_count: u32,
    pub telemetry_evidence_kind: String,
    pub idempotent_replay: bool,
}

#[derive(Clone, Debug)]
pub struct ReserveReleaseCommand {
    pub purpose: ReservePurpose,
    pub amount_micro: i64,
    pub reference_id: String,
    pub idempotency_key: String,
    pub operator_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReserveReleaseOutcome {
    pub operator_audit_id: Uuid,
    pub release_id: Uuid,
    pub purpose: ReservePurpose,
    pub amount_micro: i64,
    pub balance_before_micro: i64,
    pub balance_after_micro: i64,
    pub reference_id: String,
    pub entry_hash: String,
    pub idempotent_replay: bool,
}

pub fn maximum_reservation_micro(
    estimated_input_tokens: i32,
    max_output_tokens: i32,
    base_cost_per_1k_micro: i64,
) -> Result<i64, ApiError> {
    if estimated_input_tokens < 0 || max_output_tokens <= 0 || base_cost_per_1k_micro <= 0 {
        return Err(ApiError::bad_request(
            "invalid_usage_limits",
            "Token 上限或模型计价无效",
        ));
    }
    let tokens = i128::from(estimated_input_tokens) + i128::from(max_output_tokens);
    let base = checked_i64(ceil_div(
        tokens * i128::from(base_cost_per_1k_micro),
        1_000,
    )?)?;
    let settlement = Settlement::calculate(
        MicroQuota::new(base).map_err(map_accounting_error)?,
        PerformanceTier::High,
        TrustClass::Enhanced,
    )
    .map_err(map_accounting_error)?;
    Ok(settlement.user_deduction.as_i64())
}

pub async fn complete_job(
    pool: &PgPool,
    standard_data_key: &[u8; 32],
    command: CompleteJob,
) -> Result<SettlementOutcome, ApiError> {
    if command.actual_input_tokens < 0
        || command.actual_output_tokens < 0
        || (command.actual_input_tokens == 0 && command.actual_output_tokens == 0)
    {
        return Err(ApiError::bad_request(
            "invalid_usage",
            "Token 使用量不能为负数或全部为零",
        ));
    }
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT
            j.user_id AS consumer_user_id,
            j.status,
            j.leased_to_node_id,
            j.model_instance_id,
            j.confidentiality_mode,
            j.regulated_route_id,
            j.attestation_report_id,
            j.lease_expires_at,
            j.result_idempotency_key,
            j.result_ciphertext,
            j.standard_result_storage_version,
            j.result_telemetry_fingerprint,
            j.actual_input_tokens,
            j.actual_output_tokens,
            j.idempotency_key,
            j.estimated_input_tokens,
            j.max_output_tokens,
            j.reserved_cost_micro,
            j.billing_contract_version,
            j.billing_profile_id,
            j.billing_profile_version,
            j.billing_profile_fingerprint,
            j.billing_model_weights_hash,
            j.billing_reference_hardware_class,
            j.billing_profile_evidence_hash,
            j.billing_profile_valid_from,
            j.billing_profile_valid_until,
            j.billing_profile_max_input_tokens,
            j.billing_profile_max_output_tokens,
            j.billing_fixed_gpu_time_us,
            j.billing_gpu_time_us_per_1k_tokens,
            j.billing_reference_vram_mib,
            j.billing_token_rate_micro_per_1k,
            j.billing_gpu_rate_micro_per_second,
            j.billing_vram_rate_micro_per_gib_second,
            j.billing_authorized_input_tokens,
            j.billing_authorized_max_output_tokens,
            j.billing_billable_tokens,
            j.billing_reference_gpu_time_us,
            j.billing_reference_vram_mib_microseconds,
            j.billing_token_cost_micro,
            j.billing_gpu_cost_micro,
            j.billing_vram_cost_micro,
            j.billing_base_cost_micro,
            j.attempt_count,
            n.user_id AS node_user_id,
            n.device_key_id AS node_device_key_id,
            ja.claim_device_binding_version,
            ja.claim_device_key_id,
            n.trust_level,
            n.hardware_profile,
            ar.ephemeral_public_key AS tee_public_key,
            m.name AS model_name,
            m.id AS model_id,
            m.size_bytes AS model_size_bytes,
            m.tier,
            m.base_cost_per_1k_micro
        FROM jobs j
        JOIN nodes n ON n.id = j.leased_to_node_id
        LEFT JOIN job_attempts ja
          ON ja.job_id = j.id AND ja.attempt_number = j.attempt_count
        JOIN models m ON m.id = j.model_id
        LEFT JOIN attestation_reports ar ON ar.id = j.attestation_report_id
        WHERE j.id = $1
        FOR UPDATE OF j
        "#,
    )
    .bind(command.job_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;

    let status: String = row.try_get("status")?;
    let leased_to_node_id: Option<Uuid> = row.try_get("leased_to_node_id")?;
    if leased_to_node_id != Some(command.node_id) {
        return Err(ApiError::forbidden("任务租约不属于当前节点"));
    }
    if row.try_get::<Uuid, _>("node_user_id")? != command.worker_user_id
        || row.try_get::<Option<Uuid>, _>("node_device_key_id")?
            != Some(command.claim_device_key_id)
        || row.try_get::<Option<Uuid>, _>("claim_device_key_id")?
            != Some(command.claim_device_key_id)
        || row.try_get::<Option<i32>, _>("claim_device_binding_version")?
            != Some(DEVICE_BINDING_VERSION)
    {
        return Err(ApiError::forbidden("任务租约不属于当前设备"));
    }
    let previous_key: Option<String> = row.try_get("result_idempotency_key")?;
    let confidentiality: String = row.try_get("confidentiality_mode")?;
    let fingerprint_context = FingerprintContext {
        job_id: command.job_id,
        node_id: command.node_id,
        model_id: row.try_get("model_id")?,
        model_instance_id: row.try_get("model_instance_id")?,
        attempt_number: row.try_get("attempt_count")?,
        result_idempotency_key: command.idempotency_key.clone(),
        confidentiality: confidentiality.clone(),
        trust_level: row.try_get("trust_level")?,
        model_size_bytes: row.try_get("model_size_bytes")?,
        hardware_profile: row.try_get("hardware_profile")?,
    };
    let submitted_telemetry_fingerprint =
        telemetry_fingerprint(&fingerprint_context, &command.execution_telemetry)?;
    if status == "succeeded" {
        let stored_result: Option<String> = row.try_get("result_ciphertext")?;
        let result_matches = if confidentiality == "standard" {
            match stored_result {
                Some(stored)
                    if row.try_get::<Option<i16>, _>("standard_result_storage_version")?
                        == Some(STORAGE_VERSION) =>
                {
                    decrypt_from_storage(
                        standard_data_key,
                        command.job_id,
                        StorageDirection::Result,
                        &stored,
                    )
                    .map_err(|error| {
                        tracing::error!(error = %error, job_id = %command.job_id, field = "result", "Standard 数据静态保护校验失败");
                        ApiError::internal()
                    })?
                    .as_slice()
                        == command.result_ciphertext.as_bytes()
                }
                _ => false,
            }
        } else if confidentiality == "regulated" {
            stored_result.as_deref() == Some(command.result_ciphertext.as_str())
        } else {
            return Err(ApiError::internal());
        };
        if previous_key.as_deref() != Some(command.idempotency_key.as_str())
            || !result_matches
            || row.try_get::<Option<i32>, _>("actual_input_tokens")?
                != Some(command.actual_input_tokens)
            || row.try_get::<Option<i32>, _>("actual_output_tokens")?
                != Some(command.actual_output_tokens)
            || row
                .try_get::<Option<String>, _>("result_telemetry_fingerprint")?
                .as_deref()
                != Some(submitted_telemetry_fingerprint.as_str())
        {
            return Err(ApiError::conflict(
                "idempotency_binding_mismatch",
                "结果幂等键已绑定到不同节点、密文、Token 使用量或任务遥测",
            ));
        }
        let mut outcome = load_outcome(&mut tx, command.job_id).await?;
        outcome.idempotent_replay = true;
        tx.commit().await?;
        return Ok(outcome);
    }
    if status != "leased" {
        return Err(ApiError::conflict(
            "job_not_leased",
            "任务当前不处于可提交结果的租约状态",
        ));
    }
    if confidentiality == "regulated" {
        if !regulated_lease_binding_valid(&mut tx, command.job_id, command.node_id).await? {
            fail_regulated_lease_attestation(
                &mut tx,
                command.job_id,
                "Regulated 租约的硬件报告、固定节点或模型绑定已失效",
            )
            .await?;
            tx.commit().await?;
            return Err(ApiError::attestation_failed(
                "Regulated 租约的硬件报告、固定节点或模型绑定已失效；任务已终止且未计费",
            ));
        }
        validate_regulated_result_binding(&row, &command)?;
    }
    let lease_is_valid: bool =
        sqlx::query_scalar("SELECT COALESCE($1::timestamptz > now(), FALSE)")
            .bind(row.try_get::<Option<time::OffsetDateTime>, _>("lease_expires_at")?)
            .fetch_one(&mut *tx)
            .await?;
    if !lease_is_valid {
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }

    let billing = JobBillingSnapshot::from_job_row(&row)?;
    let frozen_base_cost_micro = frozen_base_for_authorized_usage(
        &billing,
        command.actual_input_tokens,
        command.actual_output_tokens,
    )?;

    let consumer_user_id: Uuid = row.try_get("consumer_user_id")?;
    let node_user_id: Uuid = row.try_get("node_user_id")?;
    lock_accounts(&mut tx, consumer_user_id, node_user_id).await?;

    let tier: String = row.try_get("tier")?;
    let performance_tier = match tier.as_str() {
        "high" => PerformanceTier::High,
        "medium" => PerformanceTier::Medium,
        "low" => PerformanceTier::Low,
        _ => return Err(ApiError::internal()),
    };
    let trust_level: String = row.try_get("trust_level")?;
    let trust_class = match trust_level.as_str() {
        "enhanced" => TrustClass::Enhanced,
        "standard" | "standard-limited" => TrustClass::Standard,
        "unverified" | "experimental" => TrustClass::Unverified,
        _ => return Err(ApiError::internal()),
    };
    // 金额只来自任务创建时冻结并经数据库约束验证的服务器参考上界。实际 Token、
    // TTFT、TPS 和峰值显存仍用于授权/风险验证，但不会重新计算或降低金额。
    let base_cost_micro = frozen_base_cost_micro;
    let calculated = Settlement::calculate(
        MicroQuota::new(base_cost_micro).map_err(map_accounting_error)?,
        performance_tier,
        trust_class,
    )
    .map_err(map_accounting_error)?;
    let user_deduction_micro = calculated.user_deduction.as_i64();
    let node_quota_micro = calculated.node_spendable_quota.as_i64();
    let assessment_key = job_assessment_key(
        consumer_user_id,
        &row.try_get::<String, _>("idempotency_key")?,
    )
    .map_err(map_anti_abuse_error)?;
    let precreate_weight: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT contribution_weight_ppm FROM abuse_decisions
        WHERE user_id=$1 AND assessment_key=$2 AND decision='allow'
        "#,
    )
    .bind(consumer_user_id)
    .bind(&assessment_key)
    .fetch_optional(&mut *tx)
    .await?;
    let graph_weight = settlement_contribution_weight(
        &mut tx,
        consumer_user_id,
        node_user_id,
        TrafficClass::Normal,
    )
    .await
    .map_err(map_anti_abuse_error)?;
    // 缺失创建阶段决定时只把贡献奖励归零；消费者扣费、节点可消费额度与准备金
    // 仍按真实工作结算，既不凭空奖励，也不扣留已完成工作的经济结算。
    let contribution_weight_ppm = precreate_weight.unwrap_or(0).min(graph_weight);
    let contribution_micro = checked_i64(
        i128::from(calculated.node_contribution_points.as_i64())
            .checked_mul(i128::from(contribution_weight_ppm))
            .ok_or_else(ApiError::internal)?
            / 1_000_000,
    )?;
    let reserve_micro = calculated.reserve_inflow.as_i64();
    let reserved_cost_micro: i64 = row.try_get("reserved_cost_micro")?;
    if user_deduction_micro > reserved_cost_micro {
        return Err(ApiError::internal());
    }

    let consumer_before = account_spendable(&mut tx, consumer_user_id).await?;
    if consumer_before < user_deduction_micro {
        return Err(ApiError::insufficient_quota());
    }
    let consumer_after = consumer_before - user_deduction_micro;
    // reserved_micro 不是 ledger tracked balance，可以直接更新
    let updated = sqlx::query(
        r#"
        UPDATE quota_accounts
        SET reserved_micro = reserved_micro - $2,
            updated_at = now()
        WHERE user_id = $1 AND reserved_micro >= $2
        "#,
    )
    .bind(consumer_user_id)
    .bind(reserved_cost_micro)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::internal());
    }
    // ledger insert trigger 会原子更新 spendable_micro, quota_ledger_head_hash 和 count
    let consumer_hash = append_quota(
        &mut tx,
        consumer_user_id,
        command.job_id,
        "consumer_deduction",
        -user_deduction_micro,
        consumer_before,
        consumer_after,
        format!("job:{}:consumer", command.job_id),
    )
    .await?;

    let node_before = account_spendable(&mut tx, node_user_id).await?;
    let node_after = node_before
        .checked_add(node_quota_micro)
        .ok_or_else(ApiError::internal)?;
    // ledger insert trigger 会原子更新 spendable_micro
    let node_quota_hash = append_quota(
        &mut tx,
        node_user_id,
        command.job_id,
        "node_reward",
        node_quota_micro,
        node_before,
        node_after,
        format!("job:{}:node-quota", command.job_id),
    )
    .await?;

    let contribution_before: i64 =
        sqlx::query_scalar("SELECT contribution_micro FROM quota_accounts WHERE user_id = $1")
            .bind(node_user_id)
            .fetch_one(&mut *tx)
            .await?;
    let contribution_after = contribution_before
        .checked_add(contribution_micro)
        .ok_or_else(ApiError::internal)?;
    // ledger insert trigger 会原子更新 contribution_micro
    let contribution_hash = append_contribution(
        &mut tx,
        node_user_id,
        command.job_id,
        contribution_micro,
        contribution_before,
        contribution_after,
        format!("job:{}:contribution", command.job_id),
    )
    .await?;

    let reserve_before: i64 =
        sqlx::query_scalar("SELECT balance_micro FROM reserve_accounts WHERE id = 1 FOR UPDATE")
            .fetch_one(&mut *tx)
            .await?;
    let reserve_after = reserve_before
        .checked_add(reserve_micro)
        .ok_or_else(ApiError::internal)?;
    // ledger insert trigger 会原子更新 balance_micro
    let reserve_hash = append_reserve(
        &mut tx,
        command.job_id,
        reserve_micro,
        reserve_before,
        reserve_after,
        format!("job:{}:reserve", command.job_id),
    )
    .await?;

    let receipt_id = Uuid::now_v7();
    let billing_snapshot_hash = billing.canonical_hash()?;
    let settlement_hash = sha256_hex(format!(
        "receipt-v2|{receipt_id}|{}|{consumer_hash}|{node_quota_hash}|{contribution_hash}|{reserve_hash}|{user_deduction_micro}|{node_quota_micro}|{contribution_micro}|{contribution_weight_ppm}|{billing_snapshot_hash}",
        command.job_id
    ));
    sqlx::query(
        r#"
        INSERT INTO receipts (
            id, job_id, consumer_user_id, node_user_id, model_name, tier, trust_level,
            base_cost_micro, user_deduction_micro, node_quota_micro, contribution_micro,
            contribution_weight_ppm,reserve_micro,settlement_hash,
            billing_contract_version,billing_profile_id,billing_profile_version,
            billing_profile_fingerprint,billing_model_weights_hash,
            billing_reference_hardware_class,billing_profile_evidence_hash,
            billing_profile_valid_from,billing_profile_valid_until,
            billing_profile_max_input_tokens,billing_profile_max_output_tokens,
            billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
            billing_reference_vram_mib,billing_token_rate_micro_per_1k,
            billing_gpu_rate_micro_per_second,billing_vram_rate_micro_per_gib_second,
            billing_authorized_input_tokens,billing_authorized_max_output_tokens,
            billing_billable_tokens,billing_reference_gpu_time_us,
            billing_reference_vram_mib_microseconds,billing_token_cost_micro,
            billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
        ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
            $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,
            $30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40
        )
        "#,
    )
    .bind(receipt_id)
    .bind(command.job_id)
    .bind(consumer_user_id)
    .bind(node_user_id)
    .bind(row.try_get::<String, _>("model_name")?)
    .bind(&tier)
    .bind(&trust_level)
    .bind(base_cost_micro)
    .bind(user_deduction_micro)
    .bind(node_quota_micro)
    .bind(contribution_micro)
    .bind(contribution_weight_ppm)
    .bind(reserve_micro)
    .bind(&settlement_hash)
    .bind(&billing.contract_version)
    .bind(billing.profile_id)
    .bind(billing.profile_version)
    .bind(&billing.profile_fingerprint)
    .bind(&billing.model_weights_hash)
    .bind(&billing.reference_hardware_class)
    .bind(&billing.profile_evidence_hash)
    .bind(billing.profile_valid_from)
    .bind(billing.profile_valid_until)
    .bind(billing.profile_max_input_tokens)
    .bind(billing.profile_max_output_tokens)
    .bind(billing.fixed_gpu_time_us)
    .bind(billing.gpu_time_us_per_1k_tokens)
    .bind(billing.reference_vram_mib)
    .bind(billing.token_rate_micro_per_1k)
    .bind(billing.gpu_rate_micro_per_second)
    .bind(billing.vram_rate_micro_per_gib_second)
    .bind(billing.authorized_input_tokens)
    .bind(billing.authorized_max_output_tokens)
    .bind(billing.billable_tokens)
    .bind(billing.reference_gpu_time_us)
    .bind(billing.reference_vram_mib_microseconds)
    .bind(billing.token_cost_micro)
    .bind(billing.gpu_cost_micro)
    .bind(billing.vram_cost_micro)
    .bind(billing.base_cost_micro)
    .execute(&mut *tx)
    .await?;

    // 风险指纹与结算共享事务，但绝不参与 Tier、扣费或奖励计算。verdict、基线和
    // evidence_kind 全由服务端派生，节点只能提交原始观测值。
    let fingerprint_outcome = append_execution_fingerprint(
        &mut tx,
        fingerprint_context,
        &command.execution_telemetry,
        &submitted_telemetry_fingerprint,
    )
    .await?;

    let (stored_result_ciphertext, standard_result_storage_version) = if confidentiality
        == "standard"
    {
        (
                encrypt_for_storage(
                    standard_data_key,
                    command.job_id,
                    StorageDirection::Result,
                    command.result_ciphertext.as_bytes(),
                )
                .map_err(|error| {
                    tracing::error!(error = %error, job_id = %command.job_id, field = "result", "Standard 数据静态保护失败");
                    ApiError::internal()
                })?,
                Some(STORAGE_VERSION),
            )
    } else if confidentiality == "regulated" {
        (command.result_ciphertext.to_string(), None)
    } else {
        return Err(ApiError::internal());
    };
    sqlx::query(
        r#"
        UPDATE jobs
        SET status = 'succeeded', result_ciphertext = $2, result_idempotency_key = $3,
            actual_input_tokens = $4, actual_output_tokens = $5,
            result_telemetry_fingerprint = $6,standard_result_storage_version = $7,
            completed_at = now(), updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(command.job_id)
    .bind(stored_result_ciphertext)
    .bind(&command.idempotency_key)
    .bind(command.actual_input_tokens)
    .bind(command.actual_output_tokens)
    .bind(&submitted_telemetry_fingerprint)
    .bind(standard_result_storage_version)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        UPDATE job_attempts
        SET status = 'succeeded', finished_at = now(), result_idempotency_key = $3
        WHERE job_id = $1 AND attempt_number = $2
        "#,
    )
    .bind(command.job_id)
    .bind(row.try_get::<i32, _>("attempt_count")?)
    .bind(&command.idempotency_key)
    .execute(&mut *tx)
    .await?;
    finalize_draining_instance(
        &mut tx,
        row.try_get::<Option<Uuid>, _>("model_instance_id")?,
    )
    .await?;
    record_settled_edge(
        &mut tx,
        consumer_user_id,
        node_user_id,
        TrafficClass::Normal,
    )
    .await
    .map_err(map_anti_abuse_error)?;

    tx.commit().await?;
    Ok(SettlementOutcome {
        receipt_id,
        job_id: command.job_id,
        base_cost_micro,
        user_deduction_micro,
        node_quota_micro,
        contribution_micro,
        contribution_weight_ppm,
        reserve_micro,
        settlement_hash,
        telemetry_verdict: fingerprint_outcome.verdict,
        telemetry_alert_count: fingerprint_outcome.alert_count,
        telemetry_evidence_kind: fingerprint_outcome.evidence_kind,
        idempotent_replay: false,
    })
}

/// 仅供服务器侧 `reserve-release` 受控运维命令调用的准备金释放事务。
/// HTTP Router 故意不公开此函数；每次释放与 operator 审计在同一事务提交。
pub async fn release_reserve(
    pool: &PgPool,
    command: ReserveReleaseCommand,
) -> Result<ReserveReleaseOutcome, ApiError> {
    validate_reserve_release_command(&command)?;
    let request_fingerprint = reserve_release_request_fingerprint(&command)?;
    let amount = MicroQuota::new(command.amount_micro).map_err(map_accounting_error)?;
    let mut tx = pool.begin().await?;
    // 先锁单例准备金账户，再检查幂等键；这样并发的同键释放会串行观察到
    // 已提交账本，而不会在唯一约束处退化为内部错误。
    let reserve_account = sqlx::query(
        "SELECT balance_micro,ledger_head_hash FROM reserve_accounts WHERE id = 1 FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await?;
    let balance_before: i64 = reserve_account.try_get("balance_micro")?;
    let previous_hash: String = reserve_account.try_get("ledger_head_hash")?;
    if let Some(row) = sqlx::query(
        r#"
        SELECT ledger.id,ledger.entry_type,ledger.delta_micro,
               ledger.balance_before_micro,ledger.balance_after_micro,
               ledger.audit_reference,ledger.entry_hash,
               audit.id AS operator_audit_id,audit.request_fingerprint
        FROM reserve_ledger ledger
        LEFT JOIN operator_reserve_releases audit ON audit.reserve_ledger_id=ledger.id
        WHERE ledger.idempotency_key = $1
        "#,
    )
    .bind(&command.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let stored_delta: i64 = row.try_get("delta_micro")?;
        let stored_reference: Option<String> = row.try_get("audit_reference")?;
        let stored_type: String = row.try_get("entry_type")?;
        let stored_fingerprint: Option<String> = row.try_get("request_fingerprint")?;
        let operator_audit_id: Option<Uuid> = row.try_get("operator_audit_id")?;
        if stored_delta != -command.amount_micro
            || stored_reference.as_deref() != Some(command.reference_id.as_str())
            || stored_type != reserve_entry_type(command.purpose)
            || stored_fingerprint.as_deref() != Some(request_fingerprint.as_str())
            || operator_audit_id.is_none()
        {
            return Err(ApiError::conflict(
                "idempotency_key_reused",
                "准备金幂等键已经用于不同释放请求",
            ));
        }
        let outcome = ReserveReleaseOutcome {
            operator_audit_id: operator_audit_id.ok_or_else(ApiError::internal)?,
            release_id: row.try_get("id")?,
            purpose: command.purpose,
            amount_micro: command.amount_micro,
            balance_before_micro: row.try_get("balance_before_micro")?,
            balance_after_micro: row.try_get("balance_after_micro")?,
            reference_id: command.reference_id,
            entry_hash: row.try_get("entry_hash")?,
            idempotent_replay: true,
        };
        tx.commit().await?;
        return Ok(outcome);
    }

    let total_inflow: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(delta_micro) FILTER (WHERE delta_micro > 0),0)::bigint FROM reserve_ledger",
    )
    .fetch_one(&mut *tx)
    .await?;
    let total_outflow: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(-delta_micro) FILTER (WHERE delta_micro < 0),0)::bigint FROM reserve_ledger",
    )
    .fetch_one(&mut *tx)
    .await?;
    let mut reserve_state = ReserveState {
        balance: MicroQuota::new(balance_before).map_err(map_accounting_error)?,
        total_inflow: MicroQuota::new(total_inflow).map_err(map_accounting_error)?,
        total_outflow: MicroQuota::new(total_outflow).map_err(map_accounting_error)?,
    };
    let release_id = Uuid::now_v7();
    let created_at = time::OffsetDateTime::now_utc();
    let release = reserve_state
        .release(
            release_id,
            command.purpose,
            amount,
            &command.reference_id,
            created_at,
        )
        .map_err(|error| match error {
            mindone_accounting::AccountingError::InsufficientBalance { .. } => {
                ApiError::conflict("reserve_insufficient", "网络准备金余额不足")
            }
            other => map_accounting_error(other),
        })?;
    let balance_after = release.balance_after.as_i64();
    let metadata = BTreeMap::from([
        (
            "purpose".to_owned(),
            reserve_entry_type(command.purpose).to_owned(),
        ),
        ("reference_id".to_owned(), command.reference_id.clone()),
        ("operator_id".to_owned(), command.operator_id.clone()),
        ("reason".to_owned(), command.reason.clone()),
    ]);
    let ledger = LedgerEntry::new(
        release_id,
        Uuid::from_u128(1),
        None,
        &command.idempotency_key,
        LedgerKind::ReserveRelease,
        -command.amount_micro,
        balance_before,
        balance_after,
        created_at,
        previous_hash,
        metadata,
    )
    .map_err(map_accounting_error)?;
    let ledger_metadata = ledger_metadata_json(&ledger.metadata);
    // ledger insert trigger 会原子更新 balance_micro, ledger_head_hash 和 count
    sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,
             hash_version,metadata,audit_reference,created_at)
        VALUES ($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
        "#,
    )
    .bind(release_id)
    .bind(reserve_entry_type(command.purpose))
    .bind(-command.amount_micro)
    .bind(balance_before)
    .bind(balance_after)
    .bind(&command.idempotency_key)
    .bind(&ledger.previous_hash)
    .bind(&ledger.hash)
    .bind(ledger.hash_version)
    .bind(ledger_metadata)
    .bind(&command.reference_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    let operator_audit_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO operator_reserve_releases
            (id,reserve_ledger_id,purpose,operator_id,reason,amount_micro,
             reference_id,idempotency_key,request_fingerprint,reserve_ledger_entry_hash,
             created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(operator_audit_id)
    .bind(release_id)
    .bind(reserve_entry_type(command.purpose))
    .bind(&command.operator_id)
    .bind(&command.reason)
    .bind(command.amount_micro)
    .bind(&command.reference_id)
    .bind(&command.idempotency_key)
    .bind(&request_fingerprint)
    .bind(&ledger.hash)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ReserveReleaseOutcome {
        operator_audit_id,
        release_id,
        purpose: command.purpose,
        amount_micro: command.amount_micro,
        balance_before_micro: balance_before,
        balance_after_micro: balance_after,
        reference_id: command.reference_id,
        entry_hash: ledger.hash,
        idempotent_replay: false,
    })
}

/// 在持有任务行锁的事务内重验 Regulated 租约的全部硬件与固定路由绑定。
///
/// `FOR SHARE` 阻止节点、模型、实例或报告在结算/续租提交前被并发修改；PostgreSQL
/// 的 `now()` 在事务内稳定，因此过期边界也与最终提交属于同一个判定时点。
pub(crate) async fn regulated_lease_binding_valid(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
    node_id: Uuid,
) -> Result<bool, ApiError> {
    let binding = sqlx::query(
        r#"
        SELECT j.model_instance_id,COALESCE((
            j.confidentiality_mode='regulated'
            AND j.status='leased'
            AND j.leased_to_node_id=$2
            AND j.regulated_node_id=$2
            AND n.status IN ('online','paused','draining')
            AND n.last_seen_at > now() - interval '90 seconds'
            AND n.trust_level='enhanced'
            AND n.trust_expires_at > now()
            AND n.attestation_report_id=j.attestation_report_id
            AND mi.node_id=$2
            AND mi.model_id=j.model_id
            AND mi.status IN ('published','draining')
            AND NOT EXISTS (
                SELECT 1 FROM model_instance_canary_state canary_risk
                WHERE canary_risk.model_instance_id=mi.id
                  AND canary_risk.quarantined=TRUE
            )
            AND m.enabled=TRUE
            AND ar.node_id=$2
            AND ar.model_instance_id=j.model_instance_id
            AND ar.model_hash=m.weights_hash
            AND ar.status='verified'
            AND ar.key_origin='tee_runtime'
            AND ar.expires_at > now()
            AND ar.collateral_current=TRUE
            AND ar.collateral_expires_at > now()
            AND ar.signature_verified=TRUE
            AND ar.certificate_chain_verified=TRUE
            AND ar.tcb_current=TRUE
        ),FALSE) AS valid
        FROM jobs j
        JOIN nodes n ON n.id=j.regulated_node_id
        JOIN model_instances mi ON mi.id=j.model_instance_id
        JOIN models m ON m.id=j.model_id
        JOIN attestation_reports ar ON ar.id=j.attestation_report_id
        WHERE j.id=$1
        FOR SHARE OF n,mi,m,ar
        "#,
    )
    .bind(job_id)
    .bind(node_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(binding) = binding else {
        return Ok(false);
    };
    if !binding.try_get::<bool, _>("valid")? {
        return Ok(false);
    }
    let model_instance_id: Uuid = binding.try_get("model_instance_id")?;
    // 先取得 node/model/report 行锁，再按全局顺序取得 canary 锁并复核，既关闭
    // 查询到提交的隔离窗口，也避免与 ordinary claim 形成 canary->node 反向锁。
    Ok(!instance_canary_quarantined(tx, model_instance_id).await?)
}

/// 原子终止已失去硬件信任的 Regulated 租约并完整释放消费者 reservation。
pub(crate) async fn fail_regulated_lease_attestation(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
    message: &str,
) -> Result<(), ApiError> {
    let row = sqlx::query(
        r#"
        SELECT user_id,reserved_cost_micro,model_instance_id,attempt_count,
               confidentiality_mode,status
        FROM jobs WHERE id=$1 FOR UPDATE
        "#,
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    if row.try_get::<String, _>("confidentiality_mode")? != "regulated"
        || row.try_get::<String, _>("status")? != "leased"
    {
        return Err(ApiError::internal());
    }
    let user_id: Uuid = row.try_get("user_id")?;
    let reservation: i64 = row.try_get("reserved_cost_micro")?;
    let released = sqlx::query(
        r#"
        UPDATE quota_accounts
        SET reserved_micro=reserved_micro-$2,updated_at=now()
        WHERE user_id=$1 AND reserved_micro >= $2
        "#,
    )
    .bind(user_id)
    .bind(reservation)
    .execute(&mut **tx)
    .await?;
    if released.rows_affected() != 1 {
        return Err(ApiError::internal());
    }
    let attempt = row.try_get::<i32, _>("attempt_count")?;
    let failed_attempt = sqlx::query(
        r#"
        UPDATE job_attempts
        SET status='failed',finished_at=now(),error_class='attestation',
            error_message=$3,retryable_requested=FALSE
        WHERE job_id=$1 AND attempt_number=$2 AND status='leased'
        "#,
    )
    .bind(job_id)
    .bind(attempt)
    .bind(message)
    .execute(&mut **tx)
    .await?;
    if failed_attempt.rows_affected() != 1 {
        return Err(ApiError::internal());
    }
    sqlx::query(
        r#"
        UPDATE jobs
        SET status='failed',completed_at=now(),updated_at=now()
        WHERE id=$1 AND status='leased'
        "#,
    )
    .bind(job_id)
    .execute(&mut **tx)
    .await?;
    finalize_draining_instance(tx, row.try_get::<Option<Uuid>, _>("model_instance_id")?).await
}

fn validate_regulated_result_binding(
    row: &sqlx::postgres::PgRow,
    command: &CompleteJob,
) -> Result<(), ApiError> {
    let envelope: RegulatedEnvelope = serde_json::from_str(&command.result_ciphertext)
        .map_err(|_| ApiError::attestation_failed("TEE 返回的结果不是严格 Regulated envelope"))?;
    envelope
        .validate()
        .map_err(|error| ApiError::attestation_failed(error.to_string()))?;
    if envelope.direction != EnvelopeDirection::Result
        || Some(envelope.route_id) != row.try_get::<Option<Uuid>, _>("regulated_route_id")?
        || Some(envelope.report_id) != row.try_get::<Option<Uuid>, _>("attestation_report_id")?
        || Some(envelope.model_instance_id)
            != row.try_get::<Option<Uuid>, _>("model_instance_id")?
        || Some(envelope.sender_public_key.as_str())
            != row
                .try_get::<Option<String>, _>("tee_public_key")?
                .as_deref()
    {
        return Err(ApiError::attestation_failed(
            "TEE 结果 envelope 与任务 route/report/model/public-key 绑定不一致",
        ));
    }
    Ok(())
}

fn reserve_entry_type(purpose: ReservePurpose) -> &'static str {
    match purpose {
        ReservePurpose::ResultValidation => "verification",
        ReservePurpose::FailedRetry => "retry",
        ReservePurpose::BandwidthSubsidy => "bandwidth",
        ReservePurpose::PeakGuarantee => "peak_capacity",
    }
}

const MAX_OPERATOR_RESERVE_RELEASE_MICRO: i64 = 1_000_000_000_000;

fn validate_reserve_release_command(command: &ReserveReleaseCommand) -> Result<(), ApiError> {
    if !(1..=MAX_OPERATOR_RESERVE_RELEASE_MICRO).contains(&command.amount_micro) {
        return Err(ApiError::bad_request(
            "invalid_reserve_amount",
            format!("准备金释放 amount_micro 必须在 1..={MAX_OPERATOR_RESERVE_RELEASE_MICRO}"),
        ));
    }
    if !valid_operator_identifier(&command.idempotency_key) {
        return Err(ApiError::bad_request(
            "invalid_idempotency_key",
            "准备金释放 idempotency_key 必须是 1 到 128 字节的安全 ASCII 标识符",
        ));
    }
    if !valid_operator_identifier(&command.operator_id) {
        return Err(ApiError::bad_request(
            "invalid_operator",
            "operator 必须是 1 到 128 字节的安全 ASCII 标识符",
        ));
    }
    if command.reference_id.is_empty()
        || command.reference_id.len() > 255
        || command.reference_id.trim() != command.reference_id
        || command.reference_id.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "invalid_reserve_reference",
            "reference 必须是 1 到 255 字节、无首尾空白或控制字符的审计引用",
        ));
    }
    let reason_chars = command.reason.chars().count();
    if !(8..=512).contains(&reason_chars)
        || command.reason.trim() != command.reason
        || command.reason.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "invalid_operator_reason",
            "reason 必须是 8 到 512 个字符、无首尾空白或控制字符",
        ));
    }
    Ok(())
}

fn valid_operator_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        })
}

fn reserve_release_request_fingerprint(
    command: &ReserveReleaseCommand,
) -> Result<String, ApiError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        purpose: &'a str,
        amount_micro: i64,
        reference_id: &'a str,
        idempotency_key: &'a str,
        operator_id: &'a str,
        reason: &'a str,
    }
    let payload = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        purpose: reserve_entry_type(command.purpose),
        amount_micro: command.amount_micro,
        reference_id: &command.reference_id,
        idempotency_key: &command.idempotency_key,
        operator_id: &command.operator_id,
        reason: &command.reason,
    })
    .map_err(|_| ApiError::internal())?;
    Ok(hex::encode(Sha256::digest(payload)))
}

pub(crate) async fn finalize_draining_instance(
    tx: &mut Transaction<'_, Postgres>,
    model_instance_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(model_instance_id) = model_instance_id else {
        return Ok(());
    };
    sqlx::query(
        r#"
        UPDATE model_instances mi
        SET status = 'unpublished',unpublished_at = now()
        WHERE mi.id = $1 AND mi.status = 'draining'
          AND NOT EXISTS (
              SELECT 1 FROM jobs j
              WHERE j.model_instance_id = mi.id AND j.status = 'leased'
          )
          AND NOT EXISTS (
              SELECT 1 FROM model_evaluation_challenges hidden_work
              WHERE hidden_work.model_instance_id = mi.id
                AND hidden_work.status = 'leased'
          )
        "#,
    )
    .bind(model_instance_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn load_outcome(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
) -> Result<SettlementOutcome, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT r.id, r.base_cost_micro, r.user_deduction_micro, r.node_quota_micro,
               r.contribution_micro, r.contribution_weight_ppm, r.reserve_micro,
               r.settlement_hash, t.verdict, t.evidence_kind,
               (SELECT COUNT(*)::bigint FROM execution_anomaly_ledger a
                WHERE a.telemetry_id=t.id) AS telemetry_alert_count
        FROM receipts r
        JOIN job_execution_telemetry t ON t.job_id=r.job_id
        WHERE r.job_id = $1
        "#,
    )
    .bind(job_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(SettlementOutcome {
        receipt_id: row.try_get("id")?,
        job_id,
        base_cost_micro: row.try_get("base_cost_micro")?,
        user_deduction_micro: row.try_get("user_deduction_micro")?,
        node_quota_micro: row.try_get("node_quota_micro")?,
        contribution_micro: row.try_get("contribution_micro")?,
        contribution_weight_ppm: row.try_get("contribution_weight_ppm")?,
        reserve_micro: row.try_get("reserve_micro")?,
        settlement_hash: row.try_get("settlement_hash")?,
        telemetry_verdict: parse_telemetry_verdict(row.try_get::<String, _>("verdict")?.as_str())?,
        telemetry_alert_count: u32::try_from(row.try_get::<i64, _>("telemetry_alert_count")?)
            .map_err(|_| ApiError::internal())?,
        telemetry_evidence_kind: row.try_get("evidence_kind")?,
        idempotent_replay: false,
    })
}

fn parse_telemetry_verdict(value: &str) -> Result<ExecutionTelemetryVerdict, ApiError> {
    match value {
        "insufficient_evidence" => Ok(ExecutionTelemetryVerdict::InsufficientEvidence),
        "no_anomaly_observed" => Ok(ExecutionTelemetryVerdict::NoAnomalyObserved),
        "warning" => Ok(ExecutionTelemetryVerdict::Warning),
        "critical" => Ok(ExecutionTelemetryVerdict::Critical),
        _ => Err(ApiError::internal()),
    }
}

async fn lock_accounts(
    tx: &mut Transaction<'_, Postgres>,
    first: Uuid,
    second: Uuid,
) -> Result<(), ApiError> {
    let ids = if first == second {
        vec![first]
    } else {
        vec![first, second]
    };
    let rows = sqlx::query(
        "SELECT user_id FROM quota_accounts WHERE user_id = ANY($1) ORDER BY user_id FOR UPDATE",
    )
    .bind(&ids)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() != ids.len() {
        return Err(ApiError::internal());
    }
    Ok(())
}

async fn account_spendable(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<i64, ApiError> {
    Ok(
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut **tx)
            .await?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn append_quota(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    job_id: Uuid,
    entry_type: &str,
    delta: i64,
    before: i64,
    after: i64,
    idempotency_key: String,
) -> Result<String, ApiError> {
    let prev_hash: String = sqlx::query_scalar(
        "SELECT quota_ledger_head_hash FROM quota_accounts WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let id = Uuid::now_v7();
    let created_at = time::OffsetDateTime::now_utc();
    let kind = match entry_type {
        "consumer_deduction" => LedgerKind::ConsumerDeduction,
        "node_reward" => LedgerKind::NodeQuotaCredit,
        _ => return Err(ApiError::internal()),
    };
    let ledger = LedgerEntry::new(
        id,
        user_id,
        Some(job_id),
        &idempotency_key,
        kind,
        delta,
        before,
        after,
        created_at,
        prev_hash,
        BTreeMap::new(),
    )
    .map_err(map_accounting_error)?;
    sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        "#,
    )
    .bind(ledger.id)
    .bind(user_id)
    .bind(job_id)
    .bind(entry_type)
    .bind(delta)
    .bind(before)
    .bind(after)
    .bind(idempotency_key)
    .bind(&ledger.previous_hash)
    .bind(&ledger.hash)
    .bind(ledger.hash_version)
    .bind(ledger_metadata_json(&ledger.metadata))
    .bind(created_at)
    .execute(&mut **tx)
    .await?;
    Ok(ledger.hash)
}

#[allow(clippy::too_many_arguments)]
async fn append_contribution(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    job_id: Uuid,
    delta: i64,
    before: i64,
    after: i64,
    idempotency_key: String,
) -> Result<String, ApiError> {
    let prev_hash: String = sqlx::query_scalar(
        "SELECT contribution_ledger_head_hash FROM quota_accounts WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let id = Uuid::now_v7();
    let created_at = time::OffsetDateTime::now_utc();
    let ledger = LedgerEntry::new(
        id,
        user_id,
        Some(job_id),
        &idempotency_key,
        LedgerKind::ContributionCredit,
        delta,
        before,
        after,
        created_at,
        prev_hash,
        BTreeMap::new(),
    )
    .map_err(map_accounting_error)?;
    sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,$3,'node_contribution',$4,$5,$6,$7,$8,$9,$10,$11,$12)
        "#,
    )
    .bind(ledger.id)
    .bind(user_id)
    .bind(job_id)
    .bind(delta)
    .bind(before)
    .bind(after)
    .bind(idempotency_key)
    .bind(&ledger.previous_hash)
    .bind(&ledger.hash)
    .bind(ledger.hash_version)
    .bind(ledger_metadata_json(&ledger.metadata))
    .bind(created_at)
    .execute(&mut **tx)
    .await?;
    Ok(ledger.hash)
}

#[allow(clippy::too_many_arguments)]
async fn append_reserve(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
    delta: i64,
    before: i64,
    after: i64,
    idempotency_key: String,
) -> Result<String, ApiError> {
    let prev_hash: String =
        sqlx::query_scalar("SELECT ledger_head_hash FROM reserve_accounts WHERE id=1 FOR UPDATE")
            .fetch_one(&mut **tx)
            .await?;
    let id = Uuid::now_v7();
    let created_at = time::OffsetDateTime::now_utc();
    let ledger = LedgerEntry::new(
        id,
        Uuid::from_u128(1),
        Some(job_id),
        &idempotency_key,
        LedgerKind::ReserveInflow,
        delta,
        before,
        after,
        created_at,
        prev_hash,
        BTreeMap::new(),
    )
    .map_err(map_accounting_error)?;
    sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,'settlement_inflow',$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(ledger.id)
    .bind(job_id)
    .bind(delta)
    .bind(before)
    .bind(after)
    .bind(idempotency_key)
    .bind(&ledger.previous_hash)
    .bind(&ledger.hash)
    .bind(ledger.hash_version)
    .bind(ledger_metadata_json(&ledger.metadata))
    .bind(created_at)
    .execute(&mut **tx)
    .await?;
    Ok(ledger.hash)
}

fn ledger_metadata_json(metadata: &BTreeMap<String, String>) -> serde_json::Value {
    serde_json::Value::Object(
        metadata
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    )
}

fn ceil_div(numerator: i128, denominator: i128) -> Result<i128, ApiError> {
    if numerator < 0 || denominator <= 0 {
        return Err(ApiError::internal());
    }
    numerator
        .checked_add(denominator - 1)
        .map(|value| value / denominator)
        .ok_or_else(ApiError::internal)
}

fn checked_i64(value: i128) -> Result<i64, ApiError> {
    i64::try_from(value).map_err(|_| ApiError::internal())
}

fn map_accounting_error(error: mindone_accounting::AccountingError) -> ApiError {
    tracing::error!(error = %error, "确定性结算计算失败");
    ApiError::internal()
}

fn map_anti_abuse_error(error: AntiAbuseError) -> ApiError {
    tracing::error!(error = %error, "结算反滥用状态无效");
    ApiError::internal()
}

fn sha256_hex(value: String) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{frozen_base_for_authorized_usage, maximum_reservation_micro, JobBillingSnapshot};

    #[test]
    fn reservation_uses_high_tier_upper_bound() {
        let value = maximum_reservation_micro(500, 500, 1_000);
        assert_eq!(value.ok(), Some(1_500));
    }

    #[test]
    fn frozen_physical_base_does_not_change_with_actual_usage() {
        let billing = JobBillingSnapshot {
            contract_version: "server_reference_upper_bound_v1".to_owned(),
            profile_id: Uuid::from_u128(1),
            profile_version: 1,
            profile_fingerprint: "1".repeat(64),
            model_weights_hash: "2".repeat(64),
            reference_hardware_class: "nvidia-l4".to_owned(),
            profile_evidence_hash: "3".repeat(64),
            profile_valid_from: OffsetDateTime::UNIX_EPOCH,
            profile_valid_until: OffsetDateTime::UNIX_EPOCH + Duration::days(1),
            profile_max_input_tokens: 4_096,
            profile_max_output_tokens: 1_024,
            fixed_gpu_time_us: 100_000,
            gpu_time_us_per_1k_tokens: 2_000_000,
            reference_vram_mib: 8_192,
            token_rate_micro_per_1k: 1_000_000,
            gpu_rate_micro_per_second: 2_000,
            vram_rate_micro_per_gib_second: 3_000,
            authorized_input_tokens: 40,
            authorized_max_output_tokens: 10,
            billable_tokens: 50,
            reference_gpu_time_us: 200_000,
            reference_vram_mib_microseconds: 1_638_400_000,
            token_cost_micro: 50_000,
            gpu_cost_micro: 400,
            vram_cost_micro: 4_800,
            base_cost_micro: 55_200,
        };
        billing
            .validate_frozen_quote()
            .expect("测试快照应满足 v1 物理计费公式");

        let small = frozen_base_for_authorized_usage(&billing, 1, 1);
        let full = frozen_base_for_authorized_usage(&billing, 40, 10);
        assert_eq!(small.ok(), Some(55_200));
        assert_eq!(full.ok(), Some(55_200));
        assert!(frozen_base_for_authorized_usage(&billing, 41, 1).is_err());
        assert!(frozen_base_for_authorized_usage(&billing, 1, 11).is_err());

        let canonical_hash = billing.canonical_hash().expect("计费快照应可规范哈希");
        let mut changed_contract = billing.clone();
        changed_contract.contract_version = "server_reference_upper_bound_v2".to_owned();
        assert_ne!(
            canonical_hash,
            changed_contract.canonical_hash().expect("合同变更应可哈希")
        );
        let mut changed_profile = billing.clone();
        changed_profile.profile_version = 2;
        assert_ne!(
            canonical_hash,
            changed_profile
                .canonical_hash()
                .expect("profile 变更应可哈希")
        );
        let mut changed_component = billing.clone();
        changed_component.gpu_cost_micro += 1;
        assert_ne!(
            canonical_hash,
            changed_component
                .canonical_hash()
                .expect("分项变更应可哈希")
        );
    }
}
