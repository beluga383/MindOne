use std::collections::BTreeMap;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use mindone_accounting::LEDGER_HASH_VERSION;
use mindone_protocol::{
    LedgerEntryResponse, LedgerNamespace, LedgerRecomputationStatus, PhysicalBillingReceipt,
    QuotaHistoryResponse, TrustLevel,
};
use serde::Deserialize;
use sqlx::Row;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::{db::authenticate, error::ApiError, AppState};

pub async fn quota_balance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let account = sqlx::query(
        r#"
        SELECT spendable_micro,reserved_micro,contribution_micro,updated_at
        FROM quota_accounts WHERE user_id = $1
        "#,
    )
    .bind(principal.user_id)
    .fetch_one(&state.pool)
    .await?;
    let reserve_balance: i64 =
        sqlx::query_scalar("SELECT balance_micro FROM reserve_accounts WHERE id = 1")
            .fetch_one(&state.pool)
            .await?;
    let best_tier: Option<String> = sqlx::query_scalar(
        r#"
        SELECT m.tier FROM models m
        JOIN model_instances mi ON mi.model_id = m.id
        JOIN nodes n ON n.id = mi.node_id
        WHERE n.user_id = $1 AND mi.status = 'published'
          AND NOT EXISTS (
              SELECT 1 FROM model_instance_canary_state canary_risk
              WHERE canary_risk.model_instance_id=mi.id
                AND canary_risk.quarantined=TRUE
          )
        ORDER BY CASE m.tier WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC
        LIMIT 1
        "#,
    )
    .bind(principal.user_id)
    .fetch_optional(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({
        "user_id": principal.user_id,
        "spendable_micro": account.try_get::<i64, _>("spendable_micro")?,
        "reserved_micro": account.try_get::<i64, _>("reserved_micro")?,
        "available_micro": account.try_get::<i64, _>("spendable_micro")?
            .saturating_sub(account.try_get::<i64, _>("reserved_micro")?),
        "contribution_micro": account.try_get::<i64, _>("contribution_micro")?,
        "node_tier": best_tier,
        "network_reserve_micro": reserve_balance,
        "updated_at": account.try_get::<OffsetDateTime, _>("updated_at")?
    })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    limit: Option<i64>,
    cursor: Option<Uuid>,
    after: Option<String>,
    before: Option<String>,
}

pub async fn quota_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<QuotaHistoryResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let after = parse_time(query.after.as_deref())?;
    let before = parse_time(query.before.as_deref())?;
    if after
        .zip(before)
        .is_some_and(|(after, before)| after >= before)
    {
        return Err(ApiError::bad_request(
            "invalid_time_range",
            "after 必须早于 before",
        ));
    }
    let rows = sqlx::query(
        r#"
        SELECT entries.*,r.id AS receipt_id FROM (
            SELECT id,'quota'::text AS ledger,user_id AS account_id,request_id,
                   idempotency_key,entry_type,delta_micro,balance_before_micro,
                   balance_after_micro,created_at,prev_hash,hash_version,metadata,entry_hash
            FROM quota_ledger WHERE user_id = $1
            UNION ALL
            SELECT id,'contribution'::text AS ledger,user_id AS account_id,request_id,
                   idempotency_key,entry_type,delta_micro,balance_before_micro,
                   balance_after_micro,created_at,prev_hash,hash_version,metadata,entry_hash
            FROM contribution_ledger WHERE user_id = $1
        ) entries
        LEFT JOIN receipts r ON r.job_id = entries.request_id
        WHERE ($2::uuid IS NULL OR entries.id < $2)
          AND ($3::timestamptz IS NULL OR entries.created_at >= $3)
          AND ($4::timestamptz IS NULL OR entries.created_at < $4)
        ORDER BY entries.created_at DESC,entries.id DESC
        LIMIT $5
        "#,
    )
    .bind(principal.user_id)
    .bind(query.cursor)
    .bind(after)
    .bind(before)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    let next_cursor = rows
        .last()
        .map(|row| row.try_get::<Uuid, _>("id"))
        .transpose()?;
    let entries = rows
        .into_iter()
        .map(|row| -> Result<LedgerEntryResponse, ApiError> {
            let ledger = match row.try_get::<String, _>("ledger")?.as_str() {
                "quota" => LedgerNamespace::Quota,
                "contribution" => LedgerNamespace::Contribution,
                _ => return Err(ApiError::internal()),
            };
            let hash_version: i16 = row.try_get("hash_version")?;
            let Some(recomputation_status) = recomputation_status(hash_version) else {
                tracing::error!(hash_version, "账本出现不受支持的 hash_version");
                return Err(ApiError::internal());
            };
            let metadata_value: serde_json::Value = row.try_get("metadata")?;
            let metadata = serde_json::from_value::<BTreeMap<String, String>>(metadata_value)
                .map_err(|error| {
                    tracing::error!(%error, "账本 metadata 不是受限字符串对象");
                    ApiError::internal()
                })?;
            if recomputation_status == LedgerRecomputationStatus::LegacyV1Unverifiable
                && !metadata.is_empty()
            {
                tracing::error!(hash_version, "legacy v1 账本包含不可解释的 metadata");
                return Err(ApiError::internal());
            }
            Ok(LedgerEntryResponse {
                ledger,
                account_id: row.try_get("account_id")?,
                id: row.try_get("id")?,
                request_id: row.try_get("request_id")?,
                receipt_id: row.try_get("receipt_id")?,
                idempotency_key: row.try_get("idempotency_key")?,
                entry_type: row.try_get("entry_type")?,
                delta_micro: row.try_get("delta_micro")?,
                balance_before_micro: row.try_get("balance_before_micro")?,
                balance_after_micro: row.try_get("balance_after_micro")?,
                created_at: row.try_get("created_at")?,
                prev_hash: row.try_get("prev_hash")?,
                hash_version,
                metadata,
                recomputation_status,
                entry_hash: row.try_get("entry_hash")?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(QuotaHistoryResponse {
        entries,
        next_cursor,
    }))
}

fn recomputation_status(hash_version: i16) -> Option<LedgerRecomputationStatus> {
    match hash_version {
        1 => Some(LedgerRecomputationStatus::LegacyV1Unverifiable),
        LEDGER_HASH_VERSION => Some(LedgerRecomputationStatus::CanonicalV2Recomputable),
        _ => None,
    }
}

pub async fn quota_receipt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(receipt_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let row = sqlx::query(
        r#"
        SELECT id,job_id,consumer_user_id,node_user_id,model_name,tier,trust_level,
               base_cost_micro,user_deduction_micro,node_quota_micro,
               contribution_micro,contribution_weight_ppm,reserve_micro,
               settlement_hash,created_at,
               billing_contract_version,billing_profile_id,billing_profile_version,
               billing_profile_fingerprint,billing_model_weights_hash,
               billing_reference_hardware_class,billing_profile_evidence_hash,
               billing_profile_valid_from,billing_profile_valid_until,
               billing_profile_max_input_tokens,billing_profile_max_output_tokens,
               billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
               billing_reference_vram_mib,billing_token_rate_micro_per_1k,
               billing_gpu_rate_micro_per_second,
               billing_vram_rate_micro_per_gib_second,
               billing_authorized_input_tokens,billing_authorized_max_output_tokens,
               billing_billable_tokens,billing_reference_gpu_time_us,
               billing_reference_vram_mib_microseconds,billing_token_cost_micro,
               billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro
        FROM receipts WHERE id = $1
        "#,
    )
    .bind(receipt_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("荣誉账单"))?;
    let consumer_id: Uuid = row.try_get("consumer_user_id")?;
    let node_user_id: Uuid = row.try_get("node_user_id")?;
    if principal.user_id != consumer_id && principal.user_id != node_user_id {
        return Err(ApiError::forbidden("无权查看此荣誉账单"));
    }
    let trust_level = match row.try_get::<String, _>("trust_level")?.as_str() {
        "enhanced" => TrustLevel::Enhanced,
        "standard" => TrustLevel::Standard,
        "standard-limited" => TrustLevel::StandardLimited,
        "experimental" => TrustLevel::Experimental,
        "unverified" => TrustLevel::Unverified,
        _ => return Err(ApiError::internal()),
    };
    let billing_contract_version: Option<String> = row.try_get("billing_contract_version")?;
    let billing = match billing_contract_version.as_deref() {
        Some("server_reference_upper_bound_v1") => {
            let required = || ApiError::internal();
            Some(PhysicalBillingReceipt {
                contract_version: billing_contract_version.ok_or_else(required)?,
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
                    .try_get::<Option<OffsetDateTime>, _>("billing_profile_valid_from")?
                    .ok_or_else(required)?,
                profile_valid_until: row
                    .try_get::<Option<OffsetDateTime>, _>("billing_profile_valid_until")?
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
            })
        }
        Some("legacy_token_v1") | None => None,
        Some(_) => return Err(ApiError::internal()),
    };
    let base_cost_micro: i64 = row.try_get("base_cost_micro")?;
    if billing
        .as_ref()
        .is_some_and(|snapshot| snapshot.base_cost_micro != base_cost_micro)
    {
        tracing::error!(
            receipt_id = %receipt_id,
            "荣誉账单总基础成本与冻结物理计费快照不一致"
        );
        return Err(ApiError::internal());
    }
    Ok(Json(serde_json::json!({
        "receipt_id": receipt_id,
        "job_id": row.try_get::<Uuid, _>("job_id")?,
        "consumer_user_id": consumer_id,
        "node_user_id": node_user_id,
        "model": row.try_get::<String, _>("model_name")?,
        "tier": row.try_get::<String, _>("tier")?,
        // 数据库内部使用连字符；协议枚举稳定序列化为 standard_limited。
        "trust_level": trust_level,
        "billing": billing,
        "base_cost_micro": base_cost_micro,
        "user_deduction_micro": row.try_get::<i64, _>("user_deduction_micro")?,
        "node_quota_micro": row.try_get::<i64, _>("node_quota_micro")?,
        "contribution_micro": row.try_get::<i64, _>("contribution_micro")?,
        "contribution_weight_ppm": row.try_get::<i32, _>("contribution_weight_ppm")?,
        "reserve_micro": row.try_get::<i64, _>("reserve_micro")?,
        "settlement_hash": row.try_get::<String, _>("settlement_hash")?,
        "created_at": row.try_get::<OffsetDateTime, _>("created_at")?
    })))
}

pub async fn reserve_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let row = sqlx::query(
        r#"
        SELECT ra.balance_micro,
               COALESCE(SUM(CASE WHEN rl.delta_micro > 0 THEN rl.delta_micro ELSE 0 END),0)::bigint AS total_inflow_micro,
               COALESCE(SUM(CASE WHEN rl.delta_micro < 0 THEN -rl.delta_micro ELSE 0 END),0)::bigint AS total_outflow_micro,
               COUNT(rl.id)::bigint AS ledger_entries,
               ra.updated_at
        FROM reserve_accounts ra
        LEFT JOIN reserve_ledger rl ON TRUE
        WHERE ra.id = 1
        GROUP BY ra.id
        "#,
    )
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(serde_json::json!({
        "balance_micro": row.try_get::<i64, _>("balance_micro")?,
        "total_inflow_micro": row.try_get::<i64, _>("total_inflow_micro")?,
        "total_outflow_micro": row.try_get::<i64, _>("total_outflow_micro")?,
        "ledger_entries": row.try_get::<i64, _>("ledger_entries")?,
        "allowed_uses": ["verification", "retry", "bandwidth", "peak_capacity"],
        "updated_at": row.try_get::<OffsetDateTime, _>("updated_at")?
    })))
}

fn parse_time(value: Option<&str>) -> Result<Option<OffsetDateTime>, ApiError> {
    value
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                ApiError::bad_request("invalid_timestamp", "时间必须使用 RFC 3339 格式")
            })
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_marks_only_v2_recomputable_and_legacy_v1_unverifiable() {
        assert_eq!(
            recomputation_status(LEDGER_HASH_VERSION),
            Some(LedgerRecomputationStatus::CanonicalV2Recomputable)
        );
        assert_eq!(
            recomputation_status(1),
            Some(LedgerRecomputationStatus::LegacyV1Unverifiable)
        );
        assert_eq!(recomputation_status(0), None);
        assert_eq!(recomputation_status(3), None);
    }
}
