use std::collections::{BTreeMap, BTreeSet};

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use mindone_accounting::SERVER_REFERENCE_UPPER_BOUND_V1;
use mindone_protocol::{
    approved_base_cost_per_1k_micro, HardwareProfile, HeartbeatRequest, InstanceCanaryRisk,
    NetworkHonorLabel, NetworkHonorLeaderboard, NetworkHonorLeaderboardEntry,
    NetworkHonorTiePolicy, NodeHonorStats, NodePolicyDto, NodeStatus, RegisterNodeRequest,
    RegisterNodeResponse, SandboxMechanism, TrustLevel, Validate, V1_BASE_COST_PER_1K_MICRO,
};

use crate::{
    config::RuntimeEnvironment,
    db::{authenticate, authenticate_inference},
    device_binding::require_node_device_binding,
    error::ApiError,
    AppState,
};

const CONTRIBUTION_RANK_PRIVACY_THRESHOLD: i64 = 5;
const NETWORK_HONOR_COUNT_GRANULARITY: i64 = 5;
const CONTRIBUTION_MILESTONE_BASE_MICRO: i64 = 1_000_000;
const HONOR_AGGREGATION_VERSION: &str = "node-honor-v2";
const NETWORK_HONOR_AGGREGATION_VERSION: &str = "network-honor-v1";
const TEST_BILLING_PROFILE_VERSION: i64 = 1;
const TEST_BILLING_MAXIMUM_INPUT_TOKENS: i64 = 1_000_000;
const TEST_BILLING_MAXIMUM_OUTPUT_TOKENS: i64 = 1_000_000;
const TEST_BILLING_FIXED_GPU_TIME_US: i64 = 0;
const TEST_BILLING_GPU_TIME_US_PER_1K_TOKENS: i64 = 1_000;
const TEST_BILLING_REFERENCE_VRAM_MIB: i64 = 1_024;
const TEST_BILLING_TOKEN_RATE_MICRO_PER_1K: i64 = 1_000;
const TEST_BILLING_GPU_RATE_MICRO_PER_SECOND: i64 = 1_000;
const TEST_BILLING_VRAM_RATE_MICRO_PER_GIB_SECOND: i64 = 1_000;
const TEST_BILLING_VALID_FROM_UNIX_SECONDS: i64 = 1_577_836_800;
const TEST_BILLING_VALID_UNTIL_UNIX_SECONDS: i64 = 4_102_444_800;
const TEST_BILLING_REFERENCE_HARDWARE_CLASS: &str = "test-only-reference-v1";
const TEST_BILLING_OPERATOR_ID: &str = "mindone-test-fixture";
const TEST_BILLING_REASON: &str = "RuntimeEnvironment::Test 的确定性物理计费夹具";

pub async fn register_node(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegisterNodeRequest>,
) -> Result<Json<RegisterNodeResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request.validate().map_err(protocol_validation_error)?;
    let max_concurrent = i32::try_from(request.max_concurrent)
        .map_err(|_| ApiError::bad_request("invalid_node_policy", "节点并发超出数据库范围"))?;
    let gpu_temp_limit_c = request.gpu_temp_limit_c.map(i32::from);
    let vram_reserve_mib = i64::try_from(request.vram_reserve_mib)
        .map_err(|_| ApiError::bad_request("invalid_node_policy", "显存保留阈值超出数据库范围"))?;
    let software_trust = software_trust_level(&request.hardware_profile);
    let hardware_profile = serde_json::to_value(&request.hardware_profile).map_err(|error| {
        tracing::error!(error = %error, "硬件信息序列化失败");
        ApiError::internal()
    })?;
    let mut tx = state.pool.begin().await?;
    let node = sqlx::query(
        r#"
        INSERT INTO nodes AS existing
            (id,user_id,alias,trust_level,status,pause_reason,hardware_profile,last_seen_at,
             device_key_id)
        VALUES ($1,$2,$3,$5,'offline','awaiting_first_heartbeat',$4,NULL,$6)
        ON CONFLICT (user_id,alias) DO UPDATE
        SET hardware_profile = EXCLUDED.hardware_profile,
            device_key_id = CASE
                WHEN existing.device_key_id IS NULL THEN EXCLUDED.device_key_id
                ELSE existing.device_key_id END,
            trust_level = CASE
                WHEN existing.trust_level = 'enhanced'
                  AND existing.trust_expires_at > now()
                  AND EXISTS (
                      SELECT 1 FROM attestation_reports report
                      WHERE report.id = existing.attestation_report_id
                        AND report.node_id = existing.id
                        AND report.status = 'verified'
                        AND report.expires_at > now()
                        AND report.collateral_expires_at > now()
                        AND report.signature_verified
                        AND report.certificate_chain_verified
                        AND report.tcb_current
                        AND report.collateral_current
                  )
                THEN existing.trust_level ELSE EXCLUDED.trust_level END,
            attestation_report_id = CASE
                WHEN existing.trust_level = 'enhanced'
                  AND existing.trust_expires_at > now()
                  AND EXISTS (
                      SELECT 1 FROM attestation_reports report
                      WHERE report.id = existing.attestation_report_id
                        AND report.node_id = existing.id
                        AND report.status = 'verified'
                        AND report.expires_at > now()
                        AND report.collateral_expires_at > now()
                        AND report.signature_verified
                        AND report.certificate_chain_verified
                        AND report.tcb_current
                        AND report.collateral_current
                  )
                THEN existing.attestation_report_id ELSE NULL END,
            trust_expires_at = CASE
                WHEN existing.trust_level = 'enhanced'
                  AND existing.trust_expires_at > now()
                  AND EXISTS (
                      SELECT 1 FROM attestation_reports report
                      WHERE report.id = existing.attestation_report_id
                        AND report.node_id = existing.id
                        AND report.status = 'verified'
                        AND report.expires_at > now()
                        AND report.collateral_expires_at > now()
                        AND report.signature_verified
                        AND report.certificate_chain_verified
                        AND report.tcb_current
                        AND report.collateral_current
                  )
                THEN existing.trust_expires_at ELSE NULL END,
            status = 'offline', pause_reason = 'awaiting_first_heartbeat',
            last_seen_at = NULL, updated_at = now()
        WHERE existing.device_key_id IS NULL
           OR existing.device_key_id = EXCLUDED.device_key_id
        RETURNING id,trust_level
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(principal.user_id)
    .bind(request.alias.trim())
    .bind(hardware_profile)
    .bind(trust_level_db(software_trust))
    .bind(principal.device_key_id)
    .fetch_optional(&mut *tx)
    .await?;
    let node = node.ok_or_else(|| {
        ApiError::conflict(
            "node_device_binding_mismatch",
            "节点已经绑定到另一设备，不能更换设备密钥",
        )
    })?;
    let node_id: Uuid = node.try_get("id")?;
    let stored_trust = parse_db_trust_level(node.try_get::<String, _>("trust_level")?.as_str())?;
    sqlx::query(
        r#"
        INSERT INTO node_policies
            (node_id,reject_tags,max_concurrent,gpu_temp_limit_c,vram_reserve_mib)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (node_id) DO UPDATE
        SET reject_tags = EXCLUDED.reject_tags,
            max_concurrent = EXCLUDED.max_concurrent,
            gpu_temp_limit_c = EXCLUDED.gpu_temp_limit_c,
            vram_reserve_mib = EXCLUDED.vram_reserve_mib,
            updated_at = now()
        "#,
    )
    .bind(node_id)
    .bind(&request.reject_tags)
    .bind(max_concurrent)
    .bind(gpu_temp_limit_c)
    .bind(vram_reserve_mib)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(RegisterNodeResponse {
        node_id,
        status: NodeStatus::Offline,
        trust_level: stored_trust,
    }))
}

fn software_trust_level(profile: &HardwareProfile) -> TrustLevel {
    let mechanisms = profile
        .sandbox_mechanisms
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let has = |mechanism| mechanisms.contains(&mechanism);
    match profile
        .operating_system
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "macos" => {
            if has(SandboxMechanism::Seatbelt) || has(SandboxMechanism::AppSandbox) {
                TrustLevel::StandardLimited
            } else {
                TrustLevel::Unverified
            }
        }
        "linux" => {
            if has(SandboxMechanism::Namespaces)
                && has(SandboxMechanism::SeccompBpf)
                && has(SandboxMechanism::Landlock)
            {
                TrustLevel::Standard
            } else if has(SandboxMechanism::Namespaces) && has(SandboxMechanism::SeccompBpf) {
                TrustLevel::StandardLimited
            } else {
                TrustLevel::Unverified
            }
        }
        "windows" => {
            if has(SandboxMechanism::JobObjects)
                || has(SandboxMechanism::AppContainer)
                || has(SandboxMechanism::HyperV)
            {
                TrustLevel::Experimental
            } else {
                TrustLevel::Unverified
            }
        }
        _ => TrustLevel::Unverified,
    }
}

const fn trust_level_db(trust: TrustLevel) -> &'static str {
    match trust {
        TrustLevel::Enhanced => "enhanced",
        TrustLevel::Standard => "standard",
        TrustLevel::StandardLimited => "standard-limited",
        TrustLevel::Experimental => "experimental",
        TrustLevel::Unverified => "unverified",
    }
}

fn parse_db_trust_level(value: &str) -> Result<TrustLevel, ApiError> {
    match value {
        "enhanced" => Ok(TrustLevel::Enhanced),
        "standard" => Ok(TrustLevel::Standard),
        "standard-limited" => Ok(TrustLevel::StandardLimited),
        "experimental" => Ok(TrustLevel::Experimental),
        "unverified" => Ok(TrustLevel::Unverified),
        other => {
            tracing::error!(trust_level = other, "数据库包含未知节点信任等级");
            Err(ApiError::internal())
        }
    }
}

pub async fn node_heartbeat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<Uuid>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request.validate().map_err(protocol_validation_error)?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,n.status,n.pause_reason,
               p.max_concurrent,p.gpu_temp_limit_c,p.vram_reserve_mib
        FROM nodes n JOIN node_policies p ON p.node_id = n.id
        WHERE n.id = $1 FOR UPDATE OF n,p
        "#,
    )
    .bind(node_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("节点"))?;
    require_node_device_binding(
        &principal,
        row.try_get("user_id")?,
        row.try_get("device_key_id")?,
    )?;
    let (max_concurrent, gpu_limit, vram_reserve) = if let Some(policy) = request.policy.as_ref() {
        let (max_concurrent, gpu_temp_limit_c, vram_reserve_mib) = sql_policy_values(policy)?;
        sqlx::query(
            r#"
                UPDATE node_policies
                SET reject_tags = $2,max_concurrent = $3,gpu_temp_limit_c = $4,
                    vram_reserve_mib = $5,updated_at = now()
                WHERE node_id = $1
                "#,
        )
        .bind(node_id)
        .bind(&policy.reject_tags)
        .bind(max_concurrent)
        .bind(gpu_temp_limit_c)
        .bind(vram_reserve_mib)
        .execute(&mut *tx)
        .await?;
        (max_concurrent, gpu_temp_limit_c, vram_reserve_mib)
    } else {
        (
            row.try_get("max_concurrent")?,
            row.try_get("gpu_temp_limit_c")?,
            row.try_get("vram_reserve_mib")?,
        )
    };
    let mut pause_reason = None;
    let was_temperature_paused = row.try_get::<String, _>("status")? == "paused"
        && row.try_get::<Option<String>, _>("pause_reason")?.as_deref()
            == Some("gpu_temperature_limit");
    let temperature_requires_pause = if let Some(gpu_limit) = gpu_limit {
        let resume_temperature = gpu_limit.saturating_sub(5);
        if was_temperature_paused {
            request
                .gpu_temp_c
                .is_none_or(|temperature| temperature > resume_temperature)
        } else {
            request
                .gpu_temp_c
                .is_none_or(|temperature| temperature >= gpu_limit)
        }
    } else {
        false
    };
    if temperature_requires_pause {
        pause_reason = Some("gpu_temperature_limit");
    }
    if let (Some(used), Some(total)) = (request.vram_used_mib, request.vram_total_mib) {
        if total.saturating_sub(used) < vram_reserve {
            pause_reason = Some("vram_reserve");
        }
    }
    if request.current_concurrent >= max_concurrent {
        pause_reason = Some("max_concurrent");
    }
    let status = if request.draining {
        "draining"
    } else if pause_reason.is_some() {
        "paused"
    } else {
        "online"
    };
    let accepting_jobs = status == "online";
    sqlx::query(
        r#"
        INSERT INTO node_metrics
            (id,node_id,tps_milli,ttft_ms,current_concurrent,gpu_temp_c,
             vram_used_mib,vram_total_mib,error_rate_ppm,coordinator_rtt_ms)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(node_id)
    .bind(request.tps_milli)
    .bind(request.ttft_ms)
    .bind(request.current_concurrent)
    .bind(request.gpu_temp_c)
    .bind(request.vram_used_mib)
    .bind(request.vram_total_mib)
    .bind(request.error_rate_ppm)
    .bind(request.coordinator_rtt_ms)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO heartbeats (id,node_id,status,accepting_jobs) VALUES ($1,$2,$3,$4)")
        .bind(Uuid::now_v7())
        .bind(node_id)
        .bind(status)
        .bind(accepting_jobs)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        UPDATE nodes SET status = $2, pause_reason = $3,
            verified_uptime_seconds = verified_uptime_seconds + CASE
                WHEN last_verified_heartbeat_at IS NOT NULL
                 AND last_verified_heartbeat_at <= now()
                 AND last_verified_heartbeat_at >= now() - interval '90 seconds'
                THEN GREATEST(
                    EXTRACT(EPOCH FROM (now() - last_verified_heartbeat_at))::bigint,
                    0
                )
                ELSE 0
            END,
            verified_heartbeat_count = verified_heartbeat_count + 1,
            last_verified_heartbeat_at = now(),
            last_seen_at = now(), updated_at = now() WHERE id = $1
        "#,
    )
    .bind(node_id)
    .bind(status)
    .bind(pause_reason)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "node_id": node_id,
        "status": status,
        "accepting_jobs": accepting_jobs,
        "pause_reason": pause_reason,
        "policy_updated": request.policy.is_some()
    })))
}

pub async fn node_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(node_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let row = sqlx::query(
        r#"
        SELECT n.user_id, n.alias, n.status, n.trust_level, n.created_at, n.last_seen_at,
               CASE WHEN n.verified_heartbeat_count > 0
                    THEN n.verified_uptime_seconds ELSE NULL END AS uptime_seconds,
               (SELECT COUNT(DISTINCT ja.job_id)::bigint FROM job_attempts ja
                WHERE ja.node_id = n.id
                  AND ja.status IN ('succeeded','failed','expired')) AS requests,
               (SELECT COUNT(*)::bigint FROM job_attempts ja
                WHERE ja.node_id = n.id AND ja.status = 'succeeded') AS succeeded,
               (SELECT COUNT(*)::bigint FROM job_attempts ja
                WHERE ja.node_id = n.id AND ja.status IN ('failed','expired')) AS failed,
               (SELECT m.tier FROM model_instances mi
                JOIN models m ON m.id = mi.model_id
                WHERE mi.node_id = n.id AND mi.status = 'published'
                  AND NOT EXISTS (
                      SELECT 1 FROM model_instance_canary_state risk
                      WHERE risk.model_instance_id = mi.id AND risk.quarantined = TRUE
                  )
                ORDER BY CASE m.tier WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END DESC,
                         mi.published_at DESC LIMIT 1) AS tier,
               (SELECT COALESCE(SUM(r.node_quota_micro),0)::bigint
                FROM receipts r JOIN jobs j ON j.id = r.job_id
                WHERE j.leased_to_node_id = n.id) AS spendable_earned_micro,
               (SELECT COALESCE(SUM(r.contribution_micro),0)::bigint
                FROM receipts r JOIN jobs j ON j.id = r.job_id
                WHERE j.leased_to_node_id = n.id) AS contribution_earned_micro
        FROM nodes n
        WHERE n.id = $1
        "#,
    )
    .bind(node_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("节点"))?;
    if row.try_get::<Uuid, _>("user_id")? != principal.user_id {
        return Err(ApiError::forbidden("无权查看此节点"));
    }
    let metrics = sqlx::query(
        r#"
        SELECT tps_milli, ttft_ms, current_concurrent, gpu_temp_c,
               vram_used_mib, vram_total_mib, error_rate_ppm,
               coordinator_rtt_ms, measured_at
        FROM node_metrics WHERE node_id = $1
        ORDER BY measured_at DESC, id DESC LIMIT 1
        "#,
    )
    .bind(node_id)
    .fetch_optional(&state.pool)
    .await?;
    let contribution_earned_micro: i64 = row.try_get("contribution_earned_micro")?;
    let honor = node_honor_stats(&state.pool, node_id, contribution_earned_micro).await?;
    let risk_rows = sqlx::query(
        r#"
        SELECT mi.id AS model_instance_id,mi.alias,
               COALESCE(risk.quarantined,FALSE) AS quarantined,
               COALESCE(risk.consecutive_failures,0) AS consecutive_failures,
               COALESCE(risk.recovery_passes,0) AS recovery_passes,
               risk.quarantined_at,risk.recovered_at,
               COALESCE(risk.updated_at,mi.published_at) AS risk_updated_at
        FROM model_instances mi
        LEFT JOIN model_instance_canary_state risk ON risk.model_instance_id=mi.id
        WHERE mi.node_id=$1 AND mi.status <> 'unpublished'
        ORDER BY mi.published_at,mi.id
        "#,
    )
    .bind(node_id)
    .fetch_all(&state.pool)
    .await?;
    let instance_canary_risk = risk_rows
        .into_iter()
        .map(|risk| {
            Ok(InstanceCanaryRisk {
                model_instance_id: risk.try_get("model_instance_id")?,
                alias: risk.try_get("alias")?,
                quarantined: risk.try_get("quarantined")?,
                consecutive_failures: u32::try_from(
                    risk.try_get::<i32, _>("consecutive_failures")?,
                )
                .map_err(|_| ApiError::internal())?,
                recovery_passes: u32::try_from(risk.try_get::<i32, _>("recovery_passes")?)
                    .map_err(|_| ApiError::internal())?,
                quarantine_failure_threshold: 3,
                recovery_pass_threshold: 2,
                quarantined_at: risk.try_get("quarantined_at")?,
                recovered_at: risk.try_get("recovered_at")?,
                updated_at: risk.try_get("risk_updated_at")?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    let latest_metrics = metrics.map(|metric| {
        let mut value = serde_json::json!({
            "tps_milli": metric.try_get::<i64, _>("tps_milli").ok(),
            "ttft_ms": metric.try_get::<i64, _>("ttft_ms").ok(),
            "current_concurrent": metric.try_get::<i32, _>("current_concurrent").ok(),
            "gpu_temp_c": metric.try_get::<Option<i32>, _>("gpu_temp_c").ok().flatten(),
            "vram_used_mib": metric.try_get::<Option<i64>, _>("vram_used_mib").ok().flatten(),
            "vram_total_mib": metric.try_get::<Option<i64>, _>("vram_total_mib").ok().flatten(),
            "error_rate_ppm": metric.try_get::<i32, _>("error_rate_ppm").ok(),
            "measured_at": metric.try_get::<time::OffsetDateTime, _>("measured_at").ok()
        });
        if let (Some(coordinator_rtt_ms), Some(object)) = (
            metric
                .try_get::<Option<i64>, _>("coordinator_rtt_ms")
                .ok()
                .flatten(),
            value.as_object_mut(),
        ) {
            object.insert(
                "coordinator_rtt_ms".to_owned(),
                serde_json::json!(coordinator_rtt_ms),
            );
        }
        value
    });
    let trust_level = parse_db_trust_level(row.try_get::<String, _>("trust_level")?.as_str())?;
    Ok(Json(serde_json::json!({
        "node_id": node_id,
        "alias": row.try_get::<String, _>("alias")?,
        "status": row.try_get::<String, _>("status")?,
        "trust_level": trust_level,
        "requests": row.try_get::<i64, _>("requests")?,
        "succeeded": row.try_get::<i64, _>("succeeded")?,
        "failed": row.try_get::<i64, _>("failed")?,
        "uptime_seconds": row.try_get::<Option<i64>, _>("uptime_seconds")?,
        "tier": row.try_get::<Option<String>, _>("tier")?,
        "spendable_earned_micro": row.try_get::<i64, _>("spendable_earned_micro")?,
        "contribution_earned_micro": contribution_earned_micro,
        "created_at": row.try_get::<time::OffsetDateTime, _>("created_at")?,
        "last_seen_at": row.try_get::<Option<time::OffsetDateTime>, _>("last_seen_at")?,
        "metrics": latest_metrics,
        "honor": honor,
        "instance_canary_risk": instance_canary_risk
    })))
}

async fn node_honor_stats(
    pool: &sqlx::PgPool,
    node_id: Uuid,
    contribution_earned_micro: i64,
) -> Result<NodeHonorStats, ApiError> {
    if contribution_earned_micro < 0 {
        tracing::error!(node_id = %node_id, "节点贡献聚合出现负数");
        return Err(ApiError::internal());
    }
    let rank = sqlx::query(
        r#"
        WITH per_node AS (
            SELECT j.leased_to_node_id AS node_id,
                   SUM(r.contribution_micro)::bigint AS contribution_micro
            FROM receipts r
            JOIN jobs j ON j.id = r.job_id
            WHERE j.leased_to_node_id IS NOT NULL
            GROUP BY j.leased_to_node_id
            HAVING SUM(r.contribution_micro) > 0
        )
        SELECT COUNT(*)::bigint AS cohort_nodes,
               COUNT(*) FILTER (WHERE contribution_micro < $2)::bigint AS lower_nodes,
               COUNT(*) FILTER (WHERE contribution_micro = $2)::bigint AS tied_nodes,
               COALESCE(bool_or(node_id = $1),FALSE) AS target_present
        FROM per_node
        "#,
    )
    .bind(node_id)
    .bind(contribution_earned_micro)
    .fetch_one(pool)
    .await?;
    let cohort_nodes: i64 = rank.try_get("cohort_nodes")?;
    let lower_nodes: i64 = rank.try_get("lower_nodes")?;
    let tied_nodes: i64 = rank.try_get("tied_nodes")?;
    let target_present: bool = rank.try_get("target_present")?;
    let contribution_rank_percentile =
        contribution_midrank_percentile(cohort_nodes, lower_nodes, tied_nodes, target_present)?;

    let tie_rows = sqlx::query(
        r#"
        WITH per_node AS (
            SELECT j.leased_to_node_id AS node_id,
                   SUM(r.contribution_micro)::bigint AS contribution_micro
            FROM receipts r
            JOIN jobs j ON j.id = r.job_id
            WHERE j.leased_to_node_id IS NOT NULL
            GROUP BY j.leased_to_node_id
            HAVING SUM(r.contribution_micro) > 0
        )
        SELECT COUNT(*)::bigint AS tied_nodes
        FROM per_node
        GROUP BY contribution_micro
        ORDER BY contribution_micro
        "#,
    )
    .fetch_all(pool)
    .await?;
    let contribution_tie_groups = tie_rows
        .into_iter()
        .map(|row| row.try_get::<i64, _>("tied_nodes"))
        .collect::<Result<Vec<_>, _>>()?;

    let daily_rows = sqlx::query(
        r#"
        SELECT (
                   (now() AT TIME ZONE 'UTC')::date
                   - (finished_at AT TIME ZONE 'UTC')::date
               )::integer AS days_ago,
               COUNT(*) FILTER (
                   WHERE status IN ('failed','expired')
               )::bigint AS failures
        FROM job_attempts
        WHERE node_id = $1 AND finished_at IS NOT NULL AND finished_at <= now()
        GROUP BY (finished_at AT TIME ZONE 'UTC')::date
        ORDER BY days_ago
        "#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;
    let mut daily_failures = BTreeMap::new();
    for daily in daily_rows {
        let days_ago: i32 = daily.try_get("days_ago")?;
        let failures: i64 = daily.try_get("failures")?;
        if days_ago >= 0 && failures >= 0 {
            daily_failures.insert(days_ago, failures);
        }
    }
    let zero_failure_100_days_nodes = if cohort_nodes >= CONTRIBUTION_RANK_PRIVACY_THRESHOLD {
        network_zero_failure_100_days_nodes(pool).await?
    } else {
        0
    };
    let network_leaderboard = network_honor_leaderboard(
        cohort_nodes,
        &contribution_tie_groups,
        zero_failure_100_days_nodes,
    )?;
    let published_cohort_nodes = if cohort_nodes >= CONTRIBUTION_RANK_PRIVACY_THRESHOLD {
        cohort_nodes
    } else {
        0
    };
    let cohort_nodes_u64 =
        u64::try_from(published_cohort_nodes).map_err(|_| ApiError::internal())?;
    let privacy_threshold =
        u64::try_from(CONTRIBUTION_RANK_PRIVACY_THRESHOLD).map_err(|_| ApiError::internal())?;
    let (previous_contribution_milestone_micro, next_contribution_milestone_micro) =
        contribution_milestones(contribution_earned_micro)
            .map_or((None, None), |(previous, next)| {
                (Some(previous), Some(next))
            });
    Ok(NodeHonorStats {
        aggregation_version: HONOR_AGGREGATION_VERSION.to_owned(),
        contribution_rank_percentile,
        contribution_rank_cohort_nodes: cohort_nodes_u64,
        contribution_rank_privacy_threshold: privacy_threshold,
        previous_contribution_milestone_micro,
        next_contribution_milestone_micro,
        zero_failure_streak_days: zero_failure_streak(&daily_failures),
        network_leaderboard,
    })
}

async fn network_zero_failure_100_days_nodes(pool: &sqlx::PgPool) -> Result<i64, ApiError> {
    let rows = sqlx::query(
        r#"
        WITH contributing_nodes AS (
            SELECT DISTINCT j.leased_to_node_id AS node_id
            FROM receipts r
            JOIN jobs j ON j.id = r.job_id
            WHERE j.leased_to_node_id IS NOT NULL
              AND r.contribution_micro > 0
        )
        SELECT ja.node_id,
               (
                   (now() AT TIME ZONE 'UTC')::date
                   - (ja.finished_at AT TIME ZONE 'UTC')::date
               )::integer AS days_ago,
               COUNT(*) FILTER (
                   WHERE ja.status IN ('failed','expired')
               )::bigint AS failures
        FROM job_attempts ja
        JOIN contributing_nodes cohort ON cohort.node_id = ja.node_id
        WHERE ja.finished_at IS NOT NULL
          AND ja.finished_at <= now()
          AND ja.finished_at >= now() - interval '101 days'
        GROUP BY ja.node_id,(ja.finished_at AT TIME ZONE 'UTC')::date
        ORDER BY ja.node_id,days_ago
        "#,
    )
    .fetch_all(pool)
    .await?;
    let mut per_node = BTreeMap::<Uuid, BTreeMap<i32, i64>>::new();
    for row in rows {
        let node_id: Uuid = row.try_get("node_id")?;
        let days_ago: i32 = row.try_get("days_ago")?;
        let failures: i64 = row.try_get("failures")?;
        if days_ago >= 0 && failures >= 0 {
            per_node
                .entry(node_id)
                .or_default()
                .insert(days_ago, failures);
        }
    }
    i64::try_from(
        per_node
            .values()
            .filter(|daily| zero_failure_streak(daily).is_some_and(|days| days >= 100))
            .count(),
    )
    .map_err(|_| ApiError::internal())
}

fn network_honor_leaderboard(
    cohort_nodes: i64,
    contribution_tie_groups: &[i64],
    zero_failure_100_days_nodes: i64,
) -> Result<NetworkHonorLeaderboard, ApiError> {
    if cohort_nodes < 0
        || zero_failure_100_days_nodes < 0
        || zero_failure_100_days_nodes > cohort_nodes
        || contribution_tie_groups.iter().any(|count| *count <= 0)
        || contribution_tie_groups
            .iter()
            .try_fold(0_i64, |total, count| total.checked_add(*count))
            != Some(cohort_nodes)
    {
        return Err(ApiError::internal());
    }
    let privacy_threshold =
        u64::try_from(CONTRIBUTION_RANK_PRIVACY_THRESHOLD).map_err(|_| ApiError::internal())?;
    let count_granularity =
        u64::try_from(NETWORK_HONOR_COUNT_GRANULARITY).map_err(|_| ApiError::internal())?;
    if cohort_nodes < CONTRIBUTION_RANK_PRIVACY_THRESHOLD {
        return Ok(NetworkHonorLeaderboard {
            aggregation_version: NETWORK_HONOR_AGGREGATION_VERSION.to_owned(),
            privacy_threshold,
            cohort_nodes: 0,
            count_granularity,
            suppressed: true,
            tie_policy: NetworkHonorTiePolicy::MidrankSharedBand,
            entries: Vec::new(),
        });
    }

    let mut entries = Vec::new();
    for (label, top_percent) in [
        (NetworkHonorLabel::Top1Percent, 1_i64),
        (NetworkHonorLabel::Top5Percent, 5_i64),
        (NetworkHonorLabel::Top10Percent, 10_i64),
        (NetworkHonorLabel::Top25Percent, 25_i64),
        (NetworkHonorLabel::Top50Percent, 50_i64),
    ] {
        let qualifying = top_ranked_nodes(cohort_nodes, contribution_tie_groups, top_percent)?;
        push_quantized_honor_entry(&mut entries, label, qualifying)?;
    }
    push_quantized_honor_entry(&mut entries, NetworkHonorLabel::Contributor, cohort_nodes)?;
    push_quantized_honor_entry(
        &mut entries,
        NetworkHonorLabel::ZeroFailure100Days,
        zero_failure_100_days_nodes,
    )?;

    Ok(NetworkHonorLeaderboard {
        aggregation_version: NETWORK_HONOR_AGGREGATION_VERSION.to_owned(),
        privacy_threshold,
        cohort_nodes: u64::try_from(cohort_nodes).map_err(|_| ApiError::internal())?,
        count_granularity,
        suppressed: false,
        tie_policy: NetworkHonorTiePolicy::MidrankSharedBand,
        entries,
    })
}

fn top_ranked_nodes(
    cohort_nodes: i64,
    contribution_tie_groups: &[i64],
    top_percent: i64,
) -> Result<i64, ApiError> {
    if cohort_nodes < CONTRIBUTION_RANK_PRIVACY_THRESHOLD || !(1..=100).contains(&top_percent) {
        return Err(ApiError::internal());
    }
    let mut lower_nodes = 0_i64;
    let mut qualifying_nodes = 0_i64;
    for tied_nodes in contribution_tie_groups {
        if *tied_nodes <= 0 || lower_nodes.saturating_add(*tied_nodes) > cohort_nodes {
            return Err(ApiError::internal());
        }
        let twice_midrank_numerator = i128::from(
            lower_nodes
                .checked_mul(2)
                .and_then(|value| value.checked_add(*tied_nodes))
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(ApiError::internal)?,
        );
        let twice_midrank_denominator = i128::from(
            cohort_nodes
                .checked_sub(1)
                .and_then(|value| value.checked_mul(2))
                .ok_or_else(ApiError::internal)?,
        );
        if twice_midrank_numerator * 100
            >= twice_midrank_denominator * i128::from(100 - top_percent)
        {
            qualifying_nodes = qualifying_nodes
                .checked_add(*tied_nodes)
                .ok_or_else(ApiError::internal)?;
        }
        lower_nodes = lower_nodes
            .checked_add(*tied_nodes)
            .ok_or_else(ApiError::internal)?;
    }
    if lower_nodes != cohort_nodes {
        return Err(ApiError::internal());
    }
    Ok(qualifying_nodes)
}

fn push_quantized_honor_entry(
    entries: &mut Vec<NetworkHonorLeaderboardEntry>,
    label: NetworkHonorLabel,
    exact_nodes: i64,
) -> Result<(), ApiError> {
    if exact_nodes < 0 {
        return Err(ApiError::internal());
    }
    let lower_bound =
        exact_nodes / NETWORK_HONOR_COUNT_GRANULARITY * NETWORK_HONOR_COUNT_GRANULARITY;
    if lower_bound >= CONTRIBUTION_RANK_PRIVACY_THRESHOLD {
        entries.push(NetworkHonorLeaderboardEntry {
            label,
            qualifying_nodes_lower_bound: u64::try_from(lower_bound)
                .map_err(|_| ApiError::internal())?,
        });
    }
    Ok(())
}

fn contribution_midrank_percentile(
    cohort_nodes: i64,
    lower_nodes: i64,
    tied_nodes: i64,
    target_present: bool,
) -> Result<Option<f64>, ApiError> {
    if cohort_nodes < 0 || lower_nodes < 0 || tied_nodes < 0 {
        return Err(ApiError::internal());
    }
    if !target_present || cohort_nodes < CONTRIBUTION_RANK_PRIVACY_THRESHOLD {
        return Ok(None);
    }
    if tied_nodes == 0 || lower_nodes.saturating_add(tied_nodes) > cohort_nodes {
        return Err(ApiError::internal());
    }
    if cohort_nodes == 1 {
        return Ok(Some(0.5));
    }
    let numerator = lower_nodes as f64 + (tied_nodes.saturating_sub(1)) as f64 / 2.0;
    Ok(Some(numerator / (cohort_nodes.saturating_sub(1)) as f64))
}

fn contribution_milestones(contribution_micro: i64) -> Option<(i64, i64)> {
    if contribution_micro < 0 {
        return None;
    }
    let mut previous = 0_i64;
    let mut milestone = CONTRIBUTION_MILESTONE_BASE_MICRO;
    while milestone <= contribution_micro {
        previous = milestone;
        milestone = milestone.checked_mul(10)?;
    }
    Some((previous, milestone))
}

fn zero_failure_streak(daily_failures: &BTreeMap<i32, i64>) -> Option<u64> {
    if daily_failures.is_empty() {
        return None;
    }
    let mut days_ago = if daily_failures.contains_key(&0) {
        0
    } else {
        1
    };
    let mut streak = 0_u64;
    while daily_failures
        .get(&days_ago)
        .is_some_and(|failures| *failures == 0)
    {
        streak = streak.saturating_add(1);
        days_ago = days_ago.saturating_add(1);
    }
    Some(streak)
}

#[derive(Deserialize)]
pub struct PublishModelRequest {
    node_id: Uuid,
    name: String,
    alias: String,
    format: String,
    weights_hash: String,
    size_bytes: i64,
    context_length: i32,
    #[serde(default)]
    benchmark_normalized: i32,
    #[serde(default)]
    glicko_normalized: i32,
    #[serde(default)]
    evaluation_samples: i32,
    base_cost_per_1k_micro: i64,
    #[serde(default)]
    tags: Vec<String>,
}

/// PostgreSQL 集成测试必须显式拥有一个确定性的计费 profile，才能覆盖真实 writer。
/// 该夹具只在 `RuntimeEnvironment::Test` 调用；开发和生产环境绝不隐式生成费率。
async fn seed_test_billing_profile(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model_id: Uuid,
) -> Result<(), ApiError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        contract_version: &'static str,
        model_id: Uuid,
        profile_version: i64,
        reference_hardware_class: &'a str,
        maximum_input_tokens: i64,
        maximum_output_tokens: i64,
        fixed_gpu_time_us: i64,
        gpu_time_us_per_1k_tokens: i64,
        reference_vram_mib: i64,
        token_rate_micro_per_1k: i64,
        gpu_rate_micro_per_second: i64,
        vram_rate_micro_per_gib_second: i64,
        evidence_sha256: &'a str,
        valid_from_unix_us: i64,
        valid_until_unix_us: i64,
        operator_id: &'a str,
        reason: &'a str,
        idempotency_key: &'a str,
    }

    let evidence_sha256 = "7e".repeat(32);
    let idempotency_key = format!("test-billing-profile-v1:{model_id}");
    let valid_from = OffsetDateTime::from_unix_timestamp(TEST_BILLING_VALID_FROM_UNIX_SECONDS)
        .map_err(|error| {
            tracing::error!(error = %error, "测试计费 profile 起始时间无效");
            ApiError::internal()
        })?;
    let valid_until = OffsetDateTime::from_unix_timestamp(TEST_BILLING_VALID_UNTIL_UNIX_SECONDS)
        .map_err(|error| {
            tracing::error!(error = %error, "测试计费 profile 截止时间无效");
            ApiError::internal()
        })?;
    let fingerprint = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        contract_version: SERVER_REFERENCE_UPPER_BOUND_V1,
        model_id,
        profile_version: TEST_BILLING_PROFILE_VERSION,
        reference_hardware_class: TEST_BILLING_REFERENCE_HARDWARE_CLASS,
        maximum_input_tokens: TEST_BILLING_MAXIMUM_INPUT_TOKENS,
        maximum_output_tokens: TEST_BILLING_MAXIMUM_OUTPUT_TOKENS,
        fixed_gpu_time_us: TEST_BILLING_FIXED_GPU_TIME_US,
        gpu_time_us_per_1k_tokens: TEST_BILLING_GPU_TIME_US_PER_1K_TOKENS,
        reference_vram_mib: TEST_BILLING_REFERENCE_VRAM_MIB,
        token_rate_micro_per_1k: TEST_BILLING_TOKEN_RATE_MICRO_PER_1K,
        gpu_rate_micro_per_second: TEST_BILLING_GPU_RATE_MICRO_PER_SECOND,
        vram_rate_micro_per_gib_second: TEST_BILLING_VRAM_RATE_MICRO_PER_GIB_SECOND,
        evidence_sha256: &evidence_sha256,
        valid_from_unix_us: TEST_BILLING_VALID_FROM_UNIX_SECONDS * 1_000_000,
        valid_until_unix_us: TEST_BILLING_VALID_UNTIL_UNIX_SECONDS * 1_000_000,
        operator_id: TEST_BILLING_OPERATOR_ID,
        reason: TEST_BILLING_REASON,
        idempotency_key: &idempotency_key,
    })
    .map_err(|error| {
        tracing::error!(error = %error, model_id = %model_id, "测试计费 profile 请求无法规范化");
        ApiError::internal()
    })?;
    let request_fingerprint = hex::encode(Sha256::digest(fingerprint));
    let stored_profile_id: Uuid = sqlx::query_scalar(
        r#"
        SELECT out_profile_id
        FROM mindone_record_billing_profile_v1(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            $11,$12,$13,$14,$15,$16,$17,$18,$19,$20
        )
        "#,
    )
    .bind(model_id)
    .bind(Uuid::now_v7())
    .bind(model_id)
    .bind(TEST_BILLING_PROFILE_VERSION)
    .bind(TEST_BILLING_REFERENCE_HARDWARE_CLASS)
    .bind(TEST_BILLING_MAXIMUM_INPUT_TOKENS)
    .bind(TEST_BILLING_MAXIMUM_OUTPUT_TOKENS)
    .bind(TEST_BILLING_FIXED_GPU_TIME_US)
    .bind(TEST_BILLING_GPU_TIME_US_PER_1K_TOKENS)
    .bind(TEST_BILLING_REFERENCE_VRAM_MIB)
    .bind(TEST_BILLING_TOKEN_RATE_MICRO_PER_1K)
    .bind(TEST_BILLING_GPU_RATE_MICRO_PER_SECOND)
    .bind(TEST_BILLING_VRAM_RATE_MICRO_PER_GIB_SECOND)
    .bind(&evidence_sha256)
    .bind(valid_from)
    .bind(valid_until)
    .bind(TEST_BILLING_OPERATOR_ID)
    .bind(TEST_BILLING_REASON)
    .bind(&idempotency_key)
    .bind(request_fingerprint)
    .fetch_one(&mut **tx)
    .await?;
    if stored_profile_id != model_id {
        tracing::error!(model_id = %model_id, profile_id = %stored_profile_id, "测试计费 profile 幂等结果绑定错误");
        return Err(ApiError::internal());
    }
    Ok(())
}

pub async fn publish_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PublishModelRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    validate_publish(&request)?;
    let node = sqlx::query("SELECT user_id,device_key_id FROM nodes WHERE id = $1")
        .bind(request.node_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("节点"))?;
    require_node_device_binding(
        &principal,
        node.try_get("user_id")?,
        node.try_get("device_key_id")?,
    )?;
    let model_id = Uuid::now_v7();
    let instance_id = Uuid::now_v7();
    let mut tx = state.pool.begin().await?;
    let stored_model = sqlx::query(
        r#"
        INSERT INTO models
            (id,owner_user_id,name,format,weights_hash,size_bytes,context_length,
             base_cost_per_1k_micro)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (name,weights_hash)
        DO UPDATE SET
            enabled = CASE WHEN models.owner_user_id = EXCLUDED.owner_user_id
                THEN TRUE ELSE models.enabled END,
            updated_at = CASE WHEN models.owner_user_id = EXCLUDED.owner_user_id
                THEN now() ELSE models.updated_at END
        RETURNING id,tier,base_cost_per_1k_micro
        "#,
    )
    .bind(model_id)
    .bind(principal.user_id)
    .bind(request.name.trim())
    .bind(request.format.to_ascii_lowercase())
    .bind(request.weights_hash.to_ascii_lowercase())
    .bind(request.size_bytes)
    .bind(request.context_length)
    .bind(V1_BASE_COST_PER_1K_MICRO)
    .fetch_one(&mut *tx)
    .await?;
    let stored_model_id: Uuid = stored_model.try_get("id")?;
    let tier: String = stored_model.try_get("tier")?;
    let stored_base_cost: i64 = stored_model.try_get("base_cost_per_1k_micro")?;
    if stored_base_cost != V1_BASE_COST_PER_1K_MICRO {
        tracing::error!(
            model_id = %stored_model_id,
            stored_base_cost,
            "canonical 模型费率违反 v1 服务端固定基准"
        );
        return Err(ApiError::internal());
    }
    if state.config.environment == RuntimeEnvironment::Test {
        seed_test_billing_profile(&mut tx, stored_model_id).await?;
    }
    let stored_instance_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO model_instances (id,model_id,node_id,alias,tags)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (node_id,alias) DO UPDATE
        SET tags = EXCLUDED.tags, status = 'published',
            published_at = now(), unpublished_at = NULL
        WHERE model_instances.model_id = EXCLUDED.model_id
        RETURNING id
        "#,
    )
    .bind(instance_id)
    .bind(stored_model_id)
    .bind(request.node_id)
    .bind(request.alias.trim())
    .bind(&request.tags)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(stored_instance_id) = stored_instance_id else {
        return Err(ApiError::conflict(
            "model_alias_exists",
            "此节点的模型别名已经绑定到另一模型",
        ));
    };
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "model_id": stored_model_id,
        "model_instance_id": stored_instance_id,
        "tier": tier,
        "status": "published"
    })))
}

pub async fn unpublish_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(instance_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,mi.status
        FROM model_instances mi JOIN nodes n ON n.id = mi.node_id
        WHERE mi.id = $1 FOR UPDATE OF mi
        "#,
    )
    .bind(instance_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("模型实例"))?;
    require_node_device_binding(
        &principal,
        row.try_get("user_id")?,
        row.try_get("device_key_id")?,
    )?;
    let active_jobs: i64 = sqlx::query_scalar(
        r#"
        SELECT (
            SELECT COUNT(*)::bigint FROM jobs
            WHERE model_instance_id = $1 AND status = 'leased'
        ) + (
            SELECT COUNT(*)::bigint FROM model_evaluation_challenges
            WHERE model_instance_id = $1 AND status = 'leased'
        )
        "#,
    )
    .bind(instance_id)
    .fetch_one(&mut *tx)
    .await?;
    let status = if active_jobs == 0 {
        "unpublished"
    } else {
        "draining"
    };
    sqlx::query(
        r#"
        UPDATE model_instances SET status = $2,
            unpublished_at = CASE WHEN $2 = 'unpublished' THEN now() ELSE NULL END
        WHERE id = $1
        "#,
    )
    .bind(instance_id)
    .bind(status)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "model_instance_id": instance_id,
        "status": status,
        "active_jobs": active_jobs
    })))
}

#[derive(Deserialize)]
pub struct ModelListQuery {
    name: Option<String>,
    limit: Option<i64>,
}

pub async fn list_models(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ModelListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _principal = authenticate_inference(&state.pool, &state.tokens, &headers).await?;
    let limit = query.limit.unwrap_or(100).clamp(1, 200);
    let rows = sqlx::query(
        r#"
        SELECT mi.id AS model_instance_id, mi.alias, mi.tags, mi.status,
               m.id AS model_id, m.name, m.format, m.weights_hash, m.size_bytes,
               m.context_length, m.tier, m.base_cost_per_1k_micro, mi.published_at,
               n.id AS node_id, n.trust_level, n.status AS node_status
        FROM model_instances mi
        JOIN models m ON m.id = mi.model_id
        JOIN nodes n ON n.id = mi.node_id
        WHERE mi.status = 'published' AND m.enabled = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM model_instance_canary_state canary_risk
              WHERE canary_risk.model_instance_id=mi.id
                AND canary_risk.quarantined=TRUE
          )
          AND ($1::text IS NULL OR m.name = $1)
        ORDER BY m.name, mi.published_at
        LIMIT $2
        "#,
    )
    .bind(query.name)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    let models = rows
        .into_iter()
        .map(|row| -> Result<serde_json::Value, ApiError> {
            let trust_level =
                parse_db_trust_level(row.try_get::<String, _>("trust_level")?.as_str())?;
            Ok(serde_json::json!({
                "model_instance_id": row.try_get::<Uuid, _>("model_instance_id").ok(),
                "model_id": row.try_get::<Uuid, _>("model_id").ok(),
                "name": row.try_get::<String, _>("name").ok(),
                "alias": row.try_get::<String, _>("alias").ok(),
                "format": row.try_get::<String, _>("format").ok(),
                "weights_hash": row.try_get::<String, _>("weights_hash").ok(),
                "size_bytes": row.try_get::<i64, _>("size_bytes").ok(),
                "context_length": row.try_get::<i32, _>("context_length").ok(),
                "tier": row.try_get::<String, _>("tier").ok(),
                "base_cost_per_1k_micro": row.try_get::<i64, _>("base_cost_per_1k_micro").ok(),
                "tags": row.try_get::<Vec<String>, _>("tags").ok(),
                "node_id": row.try_get::<Uuid, _>("node_id").ok(),
                "node_status": row.try_get::<String, _>("node_status").ok(),
                "trust_level": trust_level,
                "published_at": row.try_get::<time::OffsetDateTime, _>("published_at").ok()
            }))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let names = models
        .iter()
        .filter_map(|model| model.get("name").and_then(serde_json::Value::as_str))
        .collect::<BTreeSet<_>>();
    let openai_models = names
        .into_iter()
        .flat_map(|name| {
            [
                (format!("{name}-fast"), "fast"),
                (name.to_owned(), "standard"),
                (format!("{name}-slow"), "slow"),
            ]
        })
        .map(|(id, speed_class)| {
            serde_json::json!({
                "id": id,
                "object": "model",
                "created": 0,
                "owned_by": "mindone",
                "speed_class": speed_class,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "object": "list",
        "data": openai_models,
        "models": models,
    })))
}

fn validate_alias(alias: &str) -> Result<(), ApiError> {
    let length = alias.trim().chars().count();
    if !(1..=64).contains(&length) {
        return Err(ApiError::bad_request(
            "invalid_alias",
            "别名长度必须为 1 到 64 个字符",
        ));
    }
    Ok(())
}

fn validate_tags(tags: &[String]) -> Result<(), ApiError> {
    if tags.len() > 32
        || tags
            .iter()
            .any(|tag| tag.is_empty() || tag.len() > 64 || !tag.is_ascii())
    {
        return Err(ApiError::bad_request(
            "invalid_tags",
            "标签必须是最多 32 个、每个不超过 64 字节的 ASCII 字符串",
        ));
    }
    Ok(())
}

fn sql_policy_values(policy: &NodePolicyDto) -> Result<(i32, Option<i32>, i64), ApiError> {
    let max_concurrent = i32::try_from(policy.max_concurrent)
        .map_err(|_| ApiError::bad_request("invalid_node_policy", "节点并发超出数据库范围"))?;
    let gpu_temp_limit_c = policy.gpu_temp_limit_c.map(i32::from);
    let vram_reserve_mib = i64::try_from(policy.vram_reserve_mib)
        .map_err(|_| ApiError::bad_request("invalid_node_policy", "显存保留阈值超出数据库范围"))?;
    Ok((max_concurrent, gpu_temp_limit_c, vram_reserve_mib))
}

fn protocol_validation_error(error: mindone_protocol::ProtocolValidationError) -> ApiError {
    ApiError::bad_request("invalid_protocol_payload", error.to_string())
}

fn validate_publish(request: &PublishModelRequest) -> Result<(), ApiError> {
    validate_alias(&request.name)?;
    validate_alias(&request.alias)?;
    validate_tags(&request.tags)?;
    if !matches!(
        request.format.to_ascii_lowercase().as_str(),
        "gguf" | "safetensors"
    ) {
        return Err(ApiError::bad_request(
            "unsafe_model_format",
            "只允许 GGUF 或 safetensors 模型",
        ));
    }
    let hash = request.weights_hash.as_bytes();
    if hash.len() != 64 || !hash.iter().all(u8::is_ascii_hexdigit) {
        return Err(ApiError::bad_request(
            "invalid_model_hash",
            "model_weights_hash 必须是 64 位 SHA-256 十六进制值",
        ));
    }
    if request.size_bytes <= 0 || request.context_length <= 0 {
        return Err(ApiError::bad_request(
            "invalid_model_metadata",
            "模型元数据超出允许范围",
        ));
    }
    if request.benchmark_normalized != 0
        || request.glicko_normalized != 0
        || request.evaluation_samples != 0
    {
        return Err(ApiError::bad_request(
            "client_quality_forbidden",
            "公开发布不得自报 benchmark、Glicko 或评价样本；这些字段必须为 0",
        ));
    }
    if !approved_base_cost_per_1k_micro(request.base_cost_per_1k_micro) {
        return Err(ApiError::bad_request(
            "client_base_cost_forbidden",
            "base_cost_per_1k_micro 必须等于协调器 v1 唯一受控基准，发布者不能选择费率",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn profile(operating_system: &str, mechanisms: Vec<SandboxMechanism>) -> HardwareProfile {
        HardwareProfile {
            operating_system: operating_system.to_owned(),
            operating_system_version: "test".to_owned(),
            architecture: "test".to_owned(),
            cpu_model: "test".to_owned(),
            cpu_logical_cores: 1,
            ram_total_mib: 1,
            gpus: Vec::new(),
            cuda_available: false,
            metal_available: false,
            sandbox_mechanisms: mechanisms,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn software_trust_matrix_is_strict_and_deterministic() {
        assert_eq!(
            software_trust_level(&profile("macOS", vec![SandboxMechanism::Seatbelt])),
            TrustLevel::StandardLimited
        );
        assert_eq!(
            software_trust_level(&profile("macos", Vec::new())),
            TrustLevel::Unverified
        );
        assert_eq!(
            software_trust_level(&profile(
                "linux",
                vec![
                    SandboxMechanism::Namespaces,
                    SandboxMechanism::SeccompBpf,
                    SandboxMechanism::Landlock,
                ],
            )),
            TrustLevel::Standard
        );
        assert_eq!(
            software_trust_level(&profile(
                "linux",
                vec![SandboxMechanism::Namespaces, SandboxMechanism::SeccompBpf],
            )),
            TrustLevel::StandardLimited
        );
        assert_eq!(
            software_trust_level(&profile("linux", vec![SandboxMechanism::AppArmor])),
            TrustLevel::Unverified
        );
        assert_eq!(
            software_trust_level(&profile("windows", vec![SandboxMechanism::JobObjects],)),
            TrustLevel::Experimental
        );
        assert_eq!(
            software_trust_level(&profile("windows", Vec::new())),
            TrustLevel::Unverified
        );
        assert_eq!(
            software_trust_level(&profile(
                "unknown-os",
                vec![
                    SandboxMechanism::Namespaces,
                    SandboxMechanism::SeccompBpf,
                    SandboxMechanism::Landlock,
                    SandboxMechanism::HyperV,
                ],
            )),
            TrustLevel::Unverified
        );
    }

    #[test]
    fn model_publish_rejects_arbitrary_or_over_cap_base_cost() {
        let request = |base_cost_per_1k_micro| PublishModelRequest {
            node_id: Uuid::nil(),
            name: "model".to_owned(),
            alias: "instance".to_owned(),
            format: "gguf".to_owned(),
            weights_hash: "ab".repeat(32),
            size_bytes: 1,
            context_length: 1,
            benchmark_normalized: 0,
            glicko_normalized: 0,
            evaluation_samples: 0,
            base_cost_per_1k_micro,
            tags: Vec::new(),
        };
        assert!(validate_publish(&request(1_000_000)).is_ok());
        assert!(validate_publish(&request(1_000)).is_err());
        assert!(validate_publish(&request(9_999)).is_err());
        assert!(validate_publish(&request(1_000_001)).is_err());
    }

    #[test]
    fn contribution_percentile_is_midrank_and_privacy_suppressed() {
        assert_eq!(
            contribution_midrank_percentile(4, 3, 1, true).expect("有效小 cohort"),
            None
        );
        assert_eq!(
            contribution_midrank_percentile(5, 0, 1, false).expect("目标缺失"),
            None
        );
        assert_eq!(
            contribution_midrank_percentile(5, 0, 1, true).expect("最低贡献"),
            Some(0.0)
        );
        assert_eq!(
            contribution_midrank_percentile(5, 4, 1, true).expect("最高贡献"),
            Some(1.0)
        );
        assert_eq!(
            contribution_midrank_percentile(5, 1, 2, true).expect("并列 midrank"),
            Some(0.375)
        );
        assert!(contribution_midrank_percentile(5, 5, 1, true).is_err());
    }

    #[test]
    fn milestones_and_zero_failure_streak_use_deterministic_server_rules() {
        assert_eq!(contribution_milestones(0), Some((0, 1_000_000)));
        assert_eq!(contribution_milestones(999_999), Some((0, 1_000_000)));
        assert_eq!(
            contribution_milestones(1_000_000),
            Some((1_000_000, 10_000_000))
        );
        assert_eq!(contribution_milestones(-1), None);

        assert_eq!(zero_failure_streak(&BTreeMap::new()), None);
        assert_eq!(
            zero_failure_streak(&BTreeMap::from([(0, 0), (1, 0), (2, 1)])),
            Some(2)
        );
        assert_eq!(
            zero_failure_streak(&BTreeMap::from([(1, 0), (2, 0), (3, 0)])),
            Some(3)
        );
        assert_eq!(
            zero_failure_streak(&BTreeMap::from([(0, 0), (2, 0)])),
            Some(1),
            "缺失日必须打断连续区间"
        );
        assert_eq!(zero_failure_streak(&BTreeMap::from([(0, 1)])), Some(0));
    }

    #[test]
    fn network_leaderboard_suppresses_small_cohorts_and_quantizes_counts() {
        let suppressed =
            network_honor_leaderboard(4, &[1, 1, 2], 0).expect("有效小 cohort 应返回抑制榜");
        assert!(suppressed.suppressed);
        assert_eq!(suppressed.cohort_nodes, 0);
        assert!(suppressed.entries.is_empty());

        let published = network_honor_leaderboard(10, &[1, 1, 1, 1, 1, 1, 1, 1, 1, 1], 7)
            .expect("十节点 cohort 应发布匿名榜");
        assert!(!published.suppressed);
        assert_eq!(published.cohort_nodes, 10);
        assert_eq!(published.count_granularity, 5);
        assert_eq!(
            published.entries,
            vec![
                NetworkHonorLeaderboardEntry {
                    label: NetworkHonorLabel::Top50Percent,
                    qualifying_nodes_lower_bound: 5,
                },
                NetworkHonorLeaderboardEntry {
                    label: NetworkHonorLabel::Contributor,
                    qualifying_nodes_lower_bound: 10,
                },
                NetworkHonorLeaderboardEntry {
                    label: NetworkHonorLabel::ZeroFailure100Days,
                    qualifying_nodes_lower_bound: 5,
                },
            ]
        );
    }

    #[test]
    fn network_leaderboard_gives_ties_one_shared_midrank_band() {
        assert_eq!(
            top_ranked_nodes(10, &[2, 3, 5], 25).expect("有效并列分组应可排名"),
            5,
            "最高五个并列节点必须整组进入 Top 25% 档"
        );
        assert_eq!(
            top_ranked_nodes(5, &[5], 50).expect("全员并列应可排名"),
            5,
            "全员并列的 midrank 为 50%，不得人为拆散"
        );
        assert!(network_honor_leaderboard(5, &[2, 2], 0).is_err());
    }
}
