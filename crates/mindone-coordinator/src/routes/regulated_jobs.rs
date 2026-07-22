use std::net::SocketAddr;

use axum::{
    extract::{rejection::ExtensionRejection, ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use mindone_accounting::{
    CONTRIBUTION_ROUTING_MIN_COHORT, CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR,
    CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR, CONTRIBUTION_ROUTING_PERCENTILE_SCALE,
    CONTRIBUTION_ROUTING_WINDOW_DAYS,
};
use mindone_protocol::{
    AttestationEvidenceKind, AttestationProvider, CreateJobResponse, CreateRegulatedJobRequest,
    JobStatus, PrepareRegulatedJobRequest, PrepareRegulatedJobResponse, RegulatedRouteAttestation,
    Validate,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Row};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    db::authenticate,
    error::ApiError,
    routes::{
        evaluations::instance_canary_quarantined,
        jobs::{billing_profile_unavailable, load_billing_snapshot, BillingSnapshot},
    },
    AppState,
};

const PREPARED_ROUTE_TTL: Duration = Duration::minutes(2);
const MIN_REPORT_REMAINING: Duration = Duration::seconds(30);

pub async fn prepare_regulated_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PrepareRegulatedJobRequest>,
) -> Result<Json<PrepareRegulatedJobResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_regulated_prepare", error.to_string()))?;
    let request_fingerprint = regulated_request_fingerprint(b"prepare-v1", &request)?;
    let now = OffsetDateTime::now_utc();
    let mut tx = state.pool.begin().await?;
    let lock_domain = format!(
        "regulated-prepare:{}:{}",
        principal.user_id, request.idempotency_key
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 672002))")
        .bind(lock_domain)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        r#"
        UPDATE regulated_routes
        SET status = 'expired', consumed_at = now()
        WHERE user_id = $1 AND status = 'prepared' AND expires_at <= now()
        "#,
    )
    .bind(principal.user_id)
    .execute(&mut *tx)
    .await?;
    if let Some(existing) = sqlx::query(
        "SELECT id,status,prepare_request_fingerprint FROM regulated_routes WHERE user_id = $1 AND idempotency_key = $2",
    )
    .bind(principal.user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let route_id: Uuid = existing.try_get("id")?;
        if existing.try_get::<Option<String>, _>("prepare_request_fingerprint")?
            != Some(request_fingerprint.clone())
        {
            return Err(ApiError::conflict(
                "idempotency_binding_mismatch",
                "Regulated prepare 幂等键已绑定到不同请求内容",
            ));
        }
        if existing.try_get::<String, _>("status")? != "prepared" {
            return Err(ApiError::conflict(
                "regulated_route_replay",
                "该 Regulated prepare 幂等键已消费或过期，不能生成第二个 envelope",
            ));
        }
        let response = load_route_response(&mut tx, route_id, true).await?;
        tx.commit().await?;
        return Ok(Json(response));
    }

    let required_context = request
        .estimated_input_tokens
        .saturating_add(request.max_output_tokens);
    let candidates = sqlx::query(
        r#"
        WITH recent_node_contributions AS (
            SELECT settled_job.leased_to_node_id AS node_id,
                   SUM(receipt.contribution_micro)::numeric AS contribution_micro
            FROM receipts receipt
            JOIN jobs settled_job ON settled_job.id = receipt.job_id
            WHERE settled_job.leased_to_node_id IS NOT NULL
              AND receipt.created_at >= now() - ($4::bigint * interval '1 day')
            GROUP BY settled_job.leased_to_node_id
        ), eligible AS (
        SELECT m.id AS model_id,mi.id AS model_instance_id,n.id AS node_id,
               ar.id AS report_id,ar.challenge_id,ar.provider,ar.evidence_kind,
               ar.evidence_base64,ar.evidence_sha256,ar.report_data,
               ar.tee_measurement,ar.policy_hash,ar.runtime_hash,ar.model_hash,
               ar.ephemeral_public_key,ar.issued_at,ar.verified_at,
               ar.expires_at AS report_expires_at,
               ar.collateral_expires_at,ac.nonce,m.base_cost_per_1k_micro,
               load.reserved_count,
               (m.benchmark_normalized::bigint
                   + m.glicko_normalized::bigint) AS model_quality_score,
               (
                   1000000::bigint * 25
                   + GREATEST(
                         0::bigint,
                         1000000::bigint - LEAST(
                             1000000::bigint,
                             (EXTRACT(EPOCH FROM (now() - n.last_seen_at))
                                 * 1000000 / 90)::bigint
                         )
                     ) * 20
                   + (CASE WHEN metrics.coordinator_rtt_ms IS NULL THEN 0::bigint
                         ELSE 1000000::bigint
                              - metrics.coordinator_rtt_ms * 1000::bigint
                      END) * 15
                   + (LEAST(COALESCE(metrics.tps_milli,0::bigint),100000::bigint) * 10) * 15
                   + GREATEST(0::bigint,1000000::bigint - (
                         load.reserved_count * 1000000::bigint
                         / GREATEST(p.max_concurrent,1)::bigint
                     )) * 15
                   + GREATEST(0::bigint,1000000::bigint
                         - COALESCE(metrics.error_rate_ppm,500000)::bigint) * 10
               ) AS node_routing_score,
               GREATEST(
                   p.max_concurrent::bigint - load.reserved_count,
                   0::bigint
               ) AS server_free_slots,
               COALESCE(
                   recent_contribution.contribution_micro,
                   0::numeric
               ) AS contribution_micro
        FROM models m
        JOIN model_instances mi ON mi.model_id = m.id AND mi.status = 'published'
        JOIN nodes n ON n.id = mi.node_id
        JOIN node_policies p ON p.node_id = n.id
        JOIN LATERAL (
            SELECT profile.maximum_input_tokens,profile.maximum_output_tokens
            FROM billing_profiles profile
            WHERE profile.contract_version = $9
              AND profile.model_id = m.id
              AND profile.model_weights_hash = m.weights_hash
              AND profile.valid_from <= now()
              AND profile.valid_until > now()
            ORDER BY profile.profile_version DESC,profile.valid_from DESC,profile.id
            LIMIT 1
        ) current_billing_profile
          ON current_billing_profile.maximum_input_tokens >= $10
         AND current_billing_profile.maximum_output_tokens >= $11
        JOIN attestation_reports ar
          ON ar.id = n.attestation_report_id
         AND ar.node_id = n.id
         AND ar.model_instance_id = mi.id
         AND ar.model_hash = m.weights_hash
        JOIN attestation_challenges ac ON ac.id = ar.challenge_id
        LEFT JOIN LATERAL (
            SELECT nm.tps_milli,nm.coordinator_rtt_ms,nm.gpu_temp_c,
                   nm.vram_used_mib,nm.vram_total_mib,nm.error_rate_ppm
            FROM node_metrics nm
            WHERE nm.node_id = n.id
            ORDER BY nm.measured_at DESC,nm.id DESC
            LIMIT 1
        ) metrics ON TRUE
        LEFT JOIN recent_node_contributions recent_contribution
          ON recent_contribution.node_id = n.id
        CROSS JOIN LATERAL (
            SELECT
                (
                    SELECT COUNT(*)::bigint FROM jobs active_job
                    WHERE (
                        active_job.status = 'leased'
                        AND active_job.leased_to_node_id = n.id
                        AND active_job.lease_expires_at > now()
                    ) OR (
                        active_job.confidentiality_mode = 'regulated'
                        AND active_job.regulated_node_id = n.id
                        AND active_job.status IN ('queued','retry')
                    )
                ) + (
                    SELECT COUNT(*)::bigint FROM regulated_routes pending_route
                    WHERE pending_route.node_id = n.id
                      AND pending_route.status = 'prepared'
                      AND pending_route.expires_at > now()
                ) + (
                    SELECT COUNT(*)::bigint
                    FROM model_evaluation_challenges hidden_work
                    WHERE hidden_work.node_id = n.id
                      AND hidden_work.status = 'leased'
                      AND hidden_work.lease_expires_at > now()
                ) AS reserved_count
        ) load
        WHERE m.enabled = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM model_instance_canary_state canary_risk
              WHERE canary_risk.model_instance_id=mi.id
                AND canary_risk.quarantined=TRUE
          )
          AND m.context_length >= $3
          AND ($1 = 'auto' OR m.name = $1)
          AND n.status = 'online'
          AND n.trust_level = 'enhanced'
          AND n.last_seen_at > now() - interval '90 seconds'
          AND (
              metrics.coordinator_rtt_ms IS NULL
              OR metrics.coordinator_rtt_ms BETWEEN 1 AND 1000
          )
          AND n.trust_expires_at > now() + interval '30 seconds'
          AND ar.status = 'verified'
          AND ar.key_origin = 'tee_runtime'
          AND ar.expires_at > now() + interval '30 seconds'
          AND ar.collateral_current = TRUE
          AND ar.collateral_expires_at > now() + interval '30 seconds'
          AND ar.signature_verified = TRUE
          AND ar.certificate_chain_verified = TRUE
          AND ar.tcb_current = TRUE
          AND ar.evidence_base64 IS NOT NULL
          AND load.reserved_count < p.max_concurrent::bigint
          AND (
              p.gpu_temp_limit_c IS NULL
              OR (metrics.gpu_temp_c IS NOT NULL
                  AND metrics.gpu_temp_c < p.gpu_temp_limit_c)
          )
          AND (
              p.vram_reserve_mib = 0
              OR (metrics.vram_used_mib IS NOT NULL
                  AND metrics.vram_total_mib IS NOT NULL
                  AND metrics.vram_total_mib - metrics.vram_used_mib
                      >= p.vram_reserve_mib)
          )
          AND NOT EXISTS (
              SELECT 1
              FROM unnest($2::text[]) AS requested(tag)
              JOIN unnest(p.reject_tags) AS rejected(tag)
                ON lower(requested.tag) = lower(rejected.tag)
          )
        ), node_cohort AS (
            SELECT DISTINCT ON (eligible.node_id)
                   eligible.node_id,eligible.model_instance_id,
                   eligible.server_free_slots,eligible.contribution_micro
            FROM eligible
            ORDER BY eligible.node_id,eligible.model_instance_id
        ), node_priorities AS (
            SELECT node_cohort.*,
                   COUNT(*) OVER () AS cohort_size,
                   SUM(node_cohort.server_free_slots) OVER () AS server_free_slots_total,
                   FLOOR(
                       (
                           2::numeric * (
                               RANK() OVER (
                                   ORDER BY node_cohort.contribution_micro
                               ) - 1
                           )::numeric
                           + (
                               COUNT(*) OVER (
                                   PARTITION BY node_cohort.contribution_micro
                               ) - 1
                           )::numeric
                       ) * $5::numeric
                       / NULLIF(
                           2::numeric * (COUNT(*) OVER () - 1)::numeric,
                           0::numeric
                       )
                   )::bigint AS contribution_percentile_ppm
            FROM node_cohort
        ), prioritized AS (
            SELECT eligible.*,
                   MAX(eligible.node_routing_score) OVER (
                       PARTITION BY eligible.model_id
                   ) AS best_node_routing_score
            FROM eligible
        ), ready_demand AS (
            SELECT COUNT(*)::bigint AS ready_count
            FROM jobs ready_job
            WHERE ready_job.model_id IN (
                  SELECT DISTINCT eligible.model_id FROM eligible
              )
              AND ARRAY(
                    SELECT DISTINCT lower(tag)
                    FROM unnest(ready_job.tags) AS demand_tag(tag)
                    ORDER BY lower(tag)
                  ) = ARRAY(
                    SELECT DISTINCT lower(tag)
                    FROM unnest($2::text[]) AS request_tag(tag)
                    ORDER BY lower(tag)
                  )
              AND (
                    ready_job.status IN ('queued','retry')
                    OR (
                        ready_job.status = 'leased'
                        AND ready_job.lease_expires_at <= now()
                    )
                  )
              AND ready_job.available_at <= now()
              AND ready_job.attempt_count < ready_job.max_attempts
        )
        SELECT prioritized.*
        FROM prioritized
        JOIN node_priorities ON node_priorities.node_id = prioritized.node_id
        CROSS JOIN ready_demand
        -- 模型质量/成本为第一阶段；同一模型内按信任、健康、协调器 RTT、
        -- 容量、可用负载和可靠性执行与 Standard 相同权重的第二阶段。贡献
        -- percentile 仅在服务端 DB 证明拥堵且节点位于最佳分 2% 内时破近同分。
        ORDER BY
          prioritized.model_quality_score DESC,
          prioritized.base_cost_per_1k_micro ASC,
          CASE
              WHEN node_priorities.cohort_size >= $6::bigint
               AND ready_demand.ready_count > node_priorities.server_free_slots_total
               AND prioritized.node_routing_score * $7::bigint
                   >= prioritized.best_node_routing_score * $8::bigint
              THEN node_priorities.contribution_percentile_ppm
              ELSE NULL
          END DESC NULLS LAST,
          prioritized.node_routing_score DESC,
          prioritized.node_id,
          prioritized.model_instance_id
        LIMIT 64
        "#,
    )
    .bind(&request.virtual_model)
    .bind(&request.tags)
    .bind(required_context)
    .bind(CONTRIBUTION_ROUTING_WINDOW_DAYS)
    .bind(i64::from(CONTRIBUTION_ROUTING_PERCENTILE_SCALE))
    .bind(CONTRIBUTION_ROUTING_MIN_COHORT as i64)
    .bind(CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR)
    .bind(CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR)
    .bind(mindone_accounting::SERVER_REFERENCE_UPPER_BOUND_V1)
    .bind(i64::from(request.estimated_input_tokens))
    .bind(i64::from(request.max_output_tokens))
    .fetch_all(&mut *tx)
    .await?;
    let mut selected = None;
    for candidate in candidates {
        let node_id: Uuid = candidate.try_get("node_id")?;
        if check_reserved_capacity_and_policy(&mut tx, node_id, &request.tags, None, None).await? {
            selected = Some(candidate);
            break;
        }
    }
    let selected = selected.ok_or_else(|| {
        ApiError::attestation_unavailable(
            "没有具备未过期本机可复验硬件报告与 TEE runtime 密钥的 Regulated 节点",
        )
    })?;
    let selected_instance_id: Uuid = selected.try_get("model_instance_id")?;
    if instance_canary_quarantined(&mut tx, selected_instance_id).await? {
        return Err(ApiError::attestation_unavailable(
            "候选模型实例在 Regulated route 提交前被 canary 风控隔离，请重试路由",
        ));
    }
    validate_selected_report(&selected, now)?;
    let selected_model_id: Uuid = selected.try_get("model_id")?;
    let selected_model_weights_hash: String = selected.try_get("model_hash")?;
    let billing = load_billing_snapshot(
        &mut tx,
        selected_model_id,
        &selected_model_weights_hash,
        request.estimated_input_tokens,
        request.max_output_tokens,
    )
    .await?;
    let report_expires_at: OffsetDateTime = selected.try_get("report_expires_at")?;
    let collateral_expires_at: OffsetDateTime = selected.try_get("collateral_expires_at")?;
    let attestation_expires_at = (now + PREPARED_ROUTE_TTL)
        .min(report_expires_at)
        .min(collateral_expires_at);
    if attestation_expires_at <= now + MIN_REPORT_REMAINING {
        return Err(ApiError::attestation_unavailable(
            "可用硬件报告剩余时间不足以安全创建 Regulated 任务",
        ));
    }
    let expires_at = attestation_expires_at.min(billing.profile.valid_until);
    if expires_at <= now + MIN_REPORT_REMAINING {
        return Err(billing_profile_unavailable());
    }
    let route_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO regulated_routes
            (id,user_id,idempotency_key,prepare_request_fingerprint,
             model_id,model_instance_id,node_id,
             attestation_report_id,tags,estimated_input_tokens,max_output_tokens,
             priority,expires_at,
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
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
             $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,
             $28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39)
        "#,
    )
    .bind(route_id)
    .bind(principal.user_id)
    .bind(&request.idempotency_key)
    .bind(&request_fingerprint)
    .bind(selected.try_get::<Uuid, _>("model_id")?)
    .bind(selected.try_get::<Uuid, _>("model_instance_id")?)
    .bind(selected.try_get::<Uuid, _>("node_id")?)
    .bind(selected.try_get::<Uuid, _>("report_id")?)
    .bind(&request.tags)
    .bind(request.estimated_input_tokens)
    .bind(request.max_output_tokens)
    .bind(request.priority)
    .bind(expires_at)
    .bind(&billing.profile.contract_version)
    .bind(billing.profile.profile_id)
    .bind(billing.profile.profile_version)
    .bind(&billing.profile.profile_fingerprint)
    .bind(&billing.profile.model_weights_hash)
    .bind(&billing.profile.reference_hardware_class)
    .bind(&billing.profile.evidence_hash)
    .bind(billing.profile.valid_from)
    .bind(billing.profile.valid_until)
    .bind(billing.profile.profile.maximum_input_tokens)
    .bind(billing.profile.profile.maximum_output_tokens)
    .bind(billing.profile.profile.fixed_gpu_time_us)
    .bind(billing.profile.profile.gpu_time_us_per_1k_tokens)
    .bind(billing.profile.profile.reference_vram_mib)
    .bind(billing.profile.profile.token_rate_micro_per_1k)
    .bind(billing.profile.profile.gpu_rate_micro_per_second)
    .bind(billing.profile.profile.vram_rate_micro_per_gib_second)
    .bind(billing.authorized_input_tokens)
    .bind(billing.authorized_max_output_tokens)
    .bind(billing.quote.billable_tokens)
    .bind(billing.quote.reference_gpu_time_us)
    .bind(billing.quote.reference_vram_mib_microseconds)
    .bind(billing.quote.token_cost.as_i64())
    .bind(billing.quote.gpu_cost.as_i64())
    .bind(billing.quote.vram_cost.as_i64())
    .bind(billing.quote.base_cost.as_i64())
    .execute(&mut *tx)
    .await?;
    let response = response_from_selected(&selected, route_id, expires_at, false)?;
    tx.commit().await?;
    Ok(Json(response))
}

pub async fn create_regulated_job(
    State(state): State<AppState>,
    connection: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    headers: HeaderMap,
    Json(request): Json<CreateRegulatedJobRequest>,
) -> Result<Json<CreateJobResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_regulated_job", error.to_string()))?;
    let request_fingerprint = regulated_request_fingerprint(b"create-v1", &request)?;
    if let Some(existing) = load_existing_regulated_job(
        &state.pool,
        principal.user_id,
        &request,
        &request_fingerprint,
    )
    .await?
    {
        return Ok(Json(existing));
    }
    let mut tx = state.pool.begin().await?;
    let lock_domain = format!(
        "regulated-create:{}:{}",
        principal.user_id, request.idempotency_key
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 672003))")
        .bind(lock_domain)
        .execute(&mut *tx)
        .await?;
    if let Some(existing) = sqlx::query(
        r#"
        SELECT j.id,j.status,j.model_id,j.reserved_cost_micro,j.regulated_route_id,
               rr.create_request_fingerprint
        FROM jobs j
        LEFT JOIN regulated_routes rr ON rr.id = j.regulated_route_id
        WHERE j.user_id = $1 AND j.idempotency_key = $2
        "#,
    )
    .bind(principal.user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing.try_get::<Option<Uuid>, _>("regulated_route_id")? != Some(request.route_id)
            || existing.try_get::<Option<String>, _>("create_request_fingerprint")?
                != Some(request_fingerprint.clone())
        {
            return Err(ApiError::conflict(
                "idempotency_binding_mismatch",
                "Regulated 创建幂等键已绑定到不同 route 或 envelope",
            ));
        }
        let response = CreateJobResponse {
            job_id: existing.try_get("id")?,
            status: job_status_from_db(&existing.try_get::<String, _>("status")?)?,
            model_id: Some(existing.try_get("model_id")?),
            reserved_cost_micro: Some(existing.try_get("reserved_cost_micro")?),
            idempotent_replay: true,
        };
        tx.commit().await?;
        return Ok(Json(response));
    }
    super::jobs::assess_job_creation(
        &state,
        &mut tx,
        &principal,
        connection.ok(),
        &headers,
        &request.idempotency_key,
    )
    .await?;

    let route = sqlx::query(
        r#"
        SELECT rr.user_id,rr.status,rr.model_id,rr.model_instance_id,rr.node_id,
               rr.attestation_report_id,rr.tags,rr.estimated_input_tokens,
               rr.max_output_tokens,rr.priority,rr.expires_at,
               rr.billing_contract_version,rr.billing_profile_id,
               rr.billing_profile_version,rr.billing_profile_fingerprint,
               rr.billing_model_weights_hash,rr.billing_reference_hardware_class,
               rr.billing_profile_evidence_hash,rr.billing_profile_valid_from,
               rr.billing_profile_valid_until,rr.billing_profile_max_input_tokens,
               rr.billing_profile_max_output_tokens,rr.billing_fixed_gpu_time_us,
               rr.billing_gpu_time_us_per_1k_tokens,rr.billing_reference_vram_mib,
               rr.billing_token_rate_micro_per_1k,
               rr.billing_gpu_rate_micro_per_second,
               rr.billing_vram_rate_micro_per_gib_second,
               rr.billing_authorized_input_tokens,
               rr.billing_authorized_max_output_tokens,rr.billing_billable_tokens,
               rr.billing_reference_gpu_time_us,
               rr.billing_reference_vram_mib_microseconds,
               rr.billing_token_cost_micro,rr.billing_gpu_cost_micro,
               rr.billing_vram_cost_micro,rr.billing_base_cost_micro,
               m.weights_hash,
               mi.node_id AS current_instance_node,mi.status AS instance_status,
               EXISTS (
                   SELECT 1 FROM model_instance_canary_state canary_risk
                   WHERE canary_risk.model_instance_id=mi.id
                     AND canary_risk.quarantined=TRUE
               ) AS instance_quarantined,
               n.status AS node_status,n.last_seen_at,n.attestation_report_id AS current_report_id,
               n.trust_expires_at,ar.status AS report_status,ar.key_origin,
               ar.model_instance_id AS report_instance_id,ar.node_id AS report_node_id,
               ar.model_hash AS report_model_hash,ar.ephemeral_public_key,
               ar.expires_at AS report_expires_at,ar.collateral_expires_at
        FROM regulated_routes rr
        JOIN models m ON m.id = rr.model_id AND m.enabled = TRUE
        JOIN model_instances mi ON mi.id = rr.model_instance_id
        JOIN nodes n ON n.id = rr.node_id
        JOIN attestation_reports ar ON ar.id = rr.attestation_report_id
        WHERE rr.id = $1
        FOR UPDATE OF rr
        "#,
    )
    .bind(request.route_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("Regulated prepared route"))?;
    if route.try_get::<Uuid, _>("user_id")? != principal.user_id {
        return Err(ApiError::forbidden("无权消费该 Regulated route"));
    }
    if route.try_get::<String, _>("status")? != "prepared" {
        return Err(ApiError::conflict(
            "regulated_route_replay",
            "Regulated route 已消费或过期，拒绝重放",
        ));
    }
    let now = OffsetDateTime::now_utc();
    let model_instance_id: Uuid = route.try_get("model_instance_id")?;
    let node_id: Uuid = route.try_get("node_id")?;
    let report_id: Uuid = route.try_get("attestation_report_id")?;
    let model_hash: String = route.try_get("weights_hash")?;
    if route.try_get::<OffsetDateTime, _>("expires_at")? <= now
        || route.try_get::<String, _>("instance_status")? != "published"
        || route.try_get::<bool, _>("instance_quarantined")?
        || route.try_get::<Uuid, _>("current_instance_node")? != node_id
        || route.try_get::<String, _>("node_status")? != "online"
        || route.try_get::<OffsetDateTime, _>("last_seen_at")? <= now - Duration::seconds(90)
        || route.try_get::<Option<Uuid>, _>("current_report_id")? != Some(report_id)
        || route.try_get::<Option<OffsetDateTime>, _>("trust_expires_at")? <= Some(now)
        || route.try_get::<String, _>("report_status")? != "verified"
        || route.try_get::<String, _>("key_origin")? != "tee_runtime"
        || route.try_get::<Uuid, _>("report_instance_id")? != model_instance_id
        || route.try_get::<Uuid, _>("report_node_id")? != node_id
        || route.try_get::<String, _>("report_model_hash")? != model_hash
        || route.try_get::<OffsetDateTime, _>("report_expires_at")? <= now
        || route.try_get::<OffsetDateTime, _>("collateral_expires_at")? <= now
    {
        return Err(ApiError::attestation_failed(
            "prepared route 的节点、模型或硬件报告在消费前已失效",
        ));
    }
    let billing = BillingSnapshot::from_frozen_row(&route, &model_hash)?;
    let route_tags: Vec<String> = route.try_get("tags")?;
    if !check_reserved_capacity_and_policy(
        &mut tx,
        node_id,
        &route_tags,
        Some(request.route_id),
        Some(report_id),
    )
    .await?
    {
        return Err(ApiError::policy_rejected(
            "prepared route 的固定节点在消费前已满载或不再满足本机策略",
        ));
    }
    // 与 ordinary claim 保持 node/policy -> canary 的统一锁顺序，避免并发领取、
    // route 消费与隔离转换形成 node<->canary 死锁。锁持有至事务提交。
    if instance_canary_quarantined(&mut tx, model_instance_id).await? {
        return Err(ApiError::attestation_failed(
            "prepared route 的固定模型实例已被 canary 风控隔离",
        ));
    }
    if request.envelope.report_id != report_id
        || request.envelope.model_instance_id != model_instance_id
        || request.envelope.sender_public_key
            == route.try_get::<String, _>("ephemeral_public_key")?
    {
        return Err(ApiError::attestation_failed(
            "请求 envelope 与 route/report/model 绑定不一致或使用了错误发送方公钥",
        ));
    }
    let opaque_envelope = serde_json::to_string(&request.envelope)
        .map_err(|_| ApiError::bad_request("invalid_regulated_job", "无法编码 opaque envelope"))?;
    if opaque_envelope.len() > 900_000 {
        return Err(ApiError::bad_request(
            "invalid_regulated_job",
            "Regulated envelope 超过任务载荷上限",
        ));
    }
    let estimated_input_tokens: i32 = route.try_get("estimated_input_tokens")?;
    let max_output_tokens: i32 = route.try_get("max_output_tokens")?;
    if billing.authorized_input_tokens != i64::from(estimated_input_tokens)
        || billing.authorized_max_output_tokens != i64::from(max_output_tokens)
    {
        return Err(billing_profile_unavailable());
    }
    let reservation = billing.reservation_micro;
    let account = sqlx::query(
        "SELECT spendable_micro,reserved_micro FROM quota_accounts WHERE user_id = $1 FOR UPDATE",
    )
    .bind(principal.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let available = account
        .try_get::<i64, _>("spendable_micro")?
        .saturating_sub(account.try_get::<i64, _>("reserved_micro")?);
    if available < reservation {
        return Err(ApiError::insufficient_quota());
    }
    sqlx::query(
        "UPDATE quota_accounts SET reserved_micro = reserved_micro + $2,updated_at = now() WHERE user_id = $1",
    )
    .bind(principal.user_id)
    .bind(reservation)
    .execute(&mut *tx)
    .await?;
    let job_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,model_instance_id,idempotency_key,encrypted_payload,
             payload_encoding,tags,estimated_input_tokens,max_output_tokens,
             reserved_cost_micro,priority,max_attempts,confidentiality_mode,
             regulated_route_id,regulated_node_id,attestation_report_id,
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
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        VALUES
            ($1,$2,$3,$4,$5,$6,'regulated_aead_v1',$7,$8,$9,$10,$11,$12,
             'regulated',$13,$14,$15,
             $16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,
             $30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41)
        "#,
    )
    .bind(job_id)
    .bind(principal.user_id)
    .bind(route.try_get::<Uuid, _>("model_id")?)
    .bind(model_instance_id)
    .bind(&request.idempotency_key)
    .bind(&opaque_envelope)
    .bind(&route_tags)
    .bind(estimated_input_tokens)
    .bind(max_output_tokens)
    .bind(reservation)
    .bind(route.try_get::<i32, _>("priority")?)
    .bind(state.config.max_job_retries.saturating_add(1).max(1))
    .bind(request.route_id)
    .bind(node_id)
    .bind(report_id)
    .bind(&billing.profile.contract_version)
    .bind(billing.profile.profile_id)
    .bind(billing.profile.profile_version)
    .bind(&billing.profile.profile_fingerprint)
    .bind(&billing.profile.model_weights_hash)
    .bind(&billing.profile.reference_hardware_class)
    .bind(&billing.profile.evidence_hash)
    .bind(billing.profile.valid_from)
    .bind(billing.profile.valid_until)
    .bind(billing.profile.profile.maximum_input_tokens)
    .bind(billing.profile.profile.maximum_output_tokens)
    .bind(billing.profile.profile.fixed_gpu_time_us)
    .bind(billing.profile.profile.gpu_time_us_per_1k_tokens)
    .bind(billing.profile.profile.reference_vram_mib)
    .bind(billing.profile.profile.token_rate_micro_per_1k)
    .bind(billing.profile.profile.gpu_rate_micro_per_second)
    .bind(billing.profile.profile.vram_rate_micro_per_gib_second)
    .bind(billing.authorized_input_tokens)
    .bind(billing.authorized_max_output_tokens)
    .bind(billing.quote.billable_tokens)
    .bind(billing.quote.reference_gpu_time_us)
    .bind(billing.quote.reference_vram_mib_microseconds)
    .bind(billing.quote.token_cost.as_i64())
    .bind(billing.quote.gpu_cost.as_i64())
    .bind(billing.quote.vram_cost.as_i64())
    .bind(billing.quote.base_cost.as_i64())
    .execute(&mut *tx)
    .await?;
    let consumed = sqlx::query(
        r#"
        UPDATE regulated_routes
        SET status = 'consumed',consumed_at = now(),job_id = $2,
            create_request_fingerprint = $3
        WHERE id = $1 AND status = 'prepared' AND expires_at > now()
        "#,
    )
    .bind(request.route_id)
    .bind(job_id)
    .bind(&request_fingerprint)
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "regulated_route_replay",
            "Regulated route 已被并发消费或刚刚过期",
        ));
    }
    tx.commit().await?;
    Ok(Json(CreateJobResponse {
        job_id,
        status: JobStatus::Queued,
        model_id: Some(route.try_get("model_id")?),
        reserved_cost_micro: Some(reservation),
        idempotent_replay: false,
    }))
}

async fn load_existing_regulated_job(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    request: &CreateRegulatedJobRequest,
    request_fingerprint: &str,
) -> Result<Option<CreateJobResponse>, ApiError> {
    let existing = sqlx::query(
        r#"
        SELECT j.id,j.status,j.model_id,j.reserved_cost_micro,j.regulated_route_id,
               rr.create_request_fingerprint
        FROM jobs j
        LEFT JOIN regulated_routes rr ON rr.id = j.regulated_route_id
        WHERE j.user_id = $1 AND j.idempotency_key = $2
        "#,
    )
    .bind(user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(pool)
    .await?;
    let Some(existing) = existing else {
        return Ok(None);
    };
    if existing.try_get::<Option<Uuid>, _>("regulated_route_id")? != Some(request.route_id)
        || existing
            .try_get::<Option<String>, _>("create_request_fingerprint")?
            .as_deref()
            != Some(request_fingerprint)
    {
        return Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "Regulated 创建幂等键已绑定到不同 route 或 envelope",
        ));
    }
    Ok(Some(CreateJobResponse {
        job_id: existing.try_get("id")?,
        status: job_status_from_db(&existing.try_get::<String, _>("status")?)?,
        model_id: Some(existing.try_get("model_id")?),
        reserved_cost_micro: Some(existing.try_get("reserved_cost_micro")?),
        idempotent_replay: true,
    }))
}

/// 锁定节点/策略行后计算真实占用与 prepared route 预留，避免并发 prepare
/// 对同一个 max_concurrent 槽位重复承诺。
async fn check_reserved_capacity_and_policy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
    tags: &[String],
    excluded_route_id: Option<Uuid>,
    expected_report_id: Option<Uuid>,
) -> Result<bool, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT n.status,n.last_seen_at,n.trust_level,n.trust_expires_at,
               n.attestation_report_id,p.reject_tags,p.max_concurrent,
               p.gpu_temp_limit_c,p.vram_reserve_mib,
               metrics.gpu_temp_c,metrics.vram_used_mib,metrics.vram_total_mib,
               (
                   SELECT COUNT(*)::bigint FROM jobs active_job
                   WHERE (
                       active_job.status = 'leased'
                       AND active_job.leased_to_node_id = n.id
                       AND active_job.lease_expires_at > now()
                   ) OR (
                       active_job.confidentiality_mode = 'regulated'
                       AND active_job.regulated_node_id = n.id
                       AND active_job.status IN ('queued','retry')
                   )
               ) + (
                   SELECT COUNT(*)::bigint FROM regulated_routes pending_route
                   WHERE pending_route.node_id = n.id
                     AND pending_route.status = 'prepared'
                     AND pending_route.expires_at > now()
                     AND ($2::uuid IS NULL OR pending_route.id <> $2)
               ) + (
                   SELECT COUNT(*)::bigint
                   FROM model_evaluation_challenges hidden_work
                   WHERE hidden_work.node_id = n.id
                     AND hidden_work.status = 'leased'
                     AND hidden_work.lease_expires_at > now()
               ) AS reserved_count
        FROM nodes n
        JOIN node_policies p ON p.node_id = n.id
        LEFT JOIN LATERAL (
            SELECT nm.gpu_temp_c,nm.vram_used_mib,nm.vram_total_mib
            FROM node_metrics nm
            WHERE nm.node_id = n.id
            ORDER BY nm.measured_at DESC,nm.id DESC
            LIMIT 1
        ) metrics ON TRUE
        WHERE n.id = $1
        FOR UPDATE OF n,p
        "#,
    )
    .bind(node_id)
    .bind(excluded_route_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| ApiError::not_found("节点"))?;
    let now = OffsetDateTime::now_utc();
    let last_seen_at = row.try_get::<Option<OffsetDateTime>, _>("last_seen_at")?;
    let trust_expires_at = row.try_get::<Option<OffsetDateTime>, _>("trust_expires_at")?;
    if row.try_get::<String, _>("status")? != "online"
        || row.try_get::<String, _>("trust_level")? != "enhanced"
        || last_seen_at.is_none_or(|value| value <= now - Duration::seconds(90))
        || trust_expires_at.is_none_or(|value| value <= now + MIN_REPORT_REMAINING)
        || expected_report_id.is_some_and(|expected| {
            row.try_get::<Option<Uuid>, _>("attestation_report_id")
                .ok()
                .flatten()
                != Some(expected)
        })
    {
        return Ok(false);
    }
    let rejected = row.try_get::<Vec<String>, _>("reject_tags")?;
    if tags
        .iter()
        .any(|tag| rejected.iter().any(|value| value.eq_ignore_ascii_case(tag)))
    {
        return Ok(false);
    }
    let reserved_count: i64 = row.try_get("reserved_count")?;
    let max_concurrent: i32 = row.try_get("max_concurrent")?;
    if reserved_count >= i64::from(max_concurrent) {
        return Ok(false);
    }
    let temperature_limit: Option<i32> = row.try_get("gpu_temp_limit_c")?;
    let temperature: Option<i32> = row.try_get("gpu_temp_c")?;
    if temperature_limit.is_some_and(|limit| temperature.is_none_or(|value| value >= limit)) {
        return Ok(false);
    }
    let vram_reserve_mib: i64 = row.try_get("vram_reserve_mib")?;
    if vram_reserve_mib > 0 {
        let used: Option<i64> = row.try_get("vram_used_mib")?;
        let total: Option<i64> = row.try_get("vram_total_mib")?;
        if used
            .zip(total)
            .is_none_or(|(used, total)| total.saturating_sub(used) < vram_reserve_mib)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn load_route_response(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    route_id: Uuid,
    idempotent_replay: bool,
) -> Result<PrepareRegulatedJobResponse, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT rr.id AS route_id,rr.model_id,rr.model_instance_id,rr.node_id,
               rr.expires_at,ar.id AS report_id,ar.challenge_id,ar.provider,
               ar.evidence_kind,ar.evidence_base64,ar.evidence_sha256,ar.report_data,
               ar.tee_measurement,ar.policy_hash,ar.runtime_hash,ar.model_hash,
               ar.ephemeral_public_key,ar.issued_at,ar.verified_at,
               ar.expires_at AS report_expires_at,ar.collateral_expires_at,ac.nonce
        FROM regulated_routes rr
        JOIN attestation_reports ar ON ar.id = rr.attestation_report_id
        JOIN attestation_challenges ac ON ac.id = ar.challenge_id
        WHERE rr.id = $1 AND rr.status = 'prepared' AND rr.expires_at > now()
        "#,
    )
    .bind(route_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        ApiError::conflict(
            "regulated_route_replay",
            "Regulated prepared route 已消费或过期",
        )
    })?;
    response_from_selected(
        &row,
        route_id,
        row.try_get("expires_at")?,
        idempotent_replay,
    )
}

fn response_from_selected(
    row: &PgRow,
    route_id: Uuid,
    expires_at: OffsetDateTime,
    idempotent_replay: bool,
) -> Result<PrepareRegulatedJobResponse, ApiError> {
    let provider = provider_from_db(&row.try_get::<String, _>("provider")?)?;
    let evidence_kind = evidence_kind_from_db(&row.try_get::<String, _>("evidence_kind")?)?;
    let nonce: Vec<u8> = row.try_get("nonce")?;
    Ok(PrepareRegulatedJobResponse {
        route_id,
        model_id: row.try_get("model_id")?,
        model_instance_id: row.try_get("model_instance_id")?,
        node_id: row.try_get("node_id")?,
        expires_at,
        idempotent_replay,
        attestation: RegulatedRouteAttestation {
            report_id: row.try_get("report_id")?,
            challenge_id: row.try_get("challenge_id")?,
            node_id: row.try_get("node_id")?,
            model_instance_id: row.try_get("model_instance_id")?,
            provider,
            evidence_kind,
            evidence: row
                .try_get::<Option<String>, _>("evidence_base64")?
                .ok_or_else(|| {
                    ApiError::attestation_unavailable("硬件报告没有可供消费者本机复验的 evidence")
                })?,
            evidence_sha256: row.try_get("evidence_sha256")?,
            challenge_nonce: URL_SAFE_NO_PAD.encode(nonce),
            report_data: row.try_get("report_data")?,
            tee_measurement: row.try_get("tee_measurement")?,
            sandbox_policy_hash: row.try_get("policy_hash")?,
            runtime_binary_hash: row.try_get("runtime_hash")?,
            model_weights_hash: row.try_get("model_hash")?,
            ephemeral_public_key: row.try_get("ephemeral_public_key")?,
            issued_at: row.try_get("issued_at")?,
            verified_at: row.try_get("verified_at")?,
            expires_at: row.try_get("report_expires_at")?,
            collateral_expires_at: row.try_get("collateral_expires_at")?,
        },
    })
}

fn validate_selected_report(row: &PgRow, now: OffsetDateTime) -> Result<(), ApiError> {
    let evidence = row
        .try_get::<Option<String>, _>("evidence_base64")?
        .ok_or_else(|| ApiError::attestation_unavailable("硬件报告缺少原始 evidence"))?;
    let verified_at = row
        .try_get::<Option<OffsetDateTime>, _>("verified_at")?
        .ok_or_else(|| ApiError::attestation_unavailable("硬件报告缺少验证时间"))?;
    let issued_at: OffsetDateTime = row.try_get("issued_at")?;
    if evidence.is_empty()
        || verified_at < issued_at
        || verified_at > now + Duration::seconds(30)
        || row
            .try_get::<Option<String>, _>("tee_measurement")?
            .is_none()
    {
        return Err(ApiError::attestation_unavailable(
            "硬件报告结构或验证时间无效",
        ));
    }
    Ok(())
}

fn provider_from_db(value: &str) -> Result<AttestationProvider, ApiError> {
    match value {
        "amd_sev_snp" => Ok(AttestationProvider::AmdSevSnp),
        "intel_tdx" => Ok(AttestationProvider::IntelTdx),
        _ => Err(ApiError::internal()),
    }
}

fn evidence_kind_from_db(value: &str) -> Result<AttestationEvidenceKind, ApiError> {
    match value {
        "snp_extended_report" => Ok(AttestationEvidenceKind::SnpExtendedReport),
        "tdx_quote" => Ok(AttestationEvidenceKind::TdxQuote),
        _ => Err(ApiError::internal()),
    }
}

fn job_status_from_db(value: &str) -> Result<JobStatus, ApiError> {
    match value {
        "queued" => Ok(JobStatus::Queued),
        "retry" => Ok(JobStatus::Retry),
        "leased" => Ok(JobStatus::Leased),
        "succeeded" => Ok(JobStatus::Succeeded),
        "failed" => Ok(JobStatus::Failed),
        "cancelled" => Ok(JobStatus::Cancelled),
        _ => Err(ApiError::internal()),
    }
}

fn regulated_request_fingerprint<T: Serialize>(
    domain: &[u8],
    request: &T,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(request).map_err(|_| ApiError::internal())?;
    let mut digest = Sha256::new();
    digest.update(b"MindOne regulated idempotency fingerprint v1\0");
    digest.update(domain);
    digest.update([0]);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}
