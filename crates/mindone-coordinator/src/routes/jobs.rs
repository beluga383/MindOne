use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    ops::Deref,
};

use axum::{
    extract::rejection::ExtensionRejection,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use sqlx::{postgres::PgRow, Row};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use mindone_accounting::{
    evaluate_policy, fused_quality, maximum_reservation_micro as maximum_physical_reservation,
    maximum_reservation_quote, rank_models, ModelCandidate, ModelRequirements, NodePolicy,
    NodeRuntime, PhysicalBillingQuote, PolicyDecision, ServerReferenceBillingProfile,
    CONTRIBUTION_ROUTING_MIN_COHORT, CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR,
    CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR, CONTRIBUTION_ROUTING_PERCENTILE_SCALE,
    CONTRIBUTION_ROUTING_WINDOW_DAYS, SERVER_REFERENCE_UPPER_BOUND_V1,
};
use mindone_protocol::{
    parse_speed_qualified_model, AttestationProvider, ChatCompletionsResponse, ClaimJobRequest,
    ClaimJobResponse, CompletionsResponse, ConfidentialityMode, CreateJobRequest, JobErrorClass,
    JobFailRequest, JobFailResponse, JobResultRequest, JobResultResponse, JobStatus,
    JobStreamEvent, JobStreamEventKind, JobStreamEventRequest, JobStreamEventResponse,
    JobStreamReadResponse, MessageContent, PayloadEncoding, RenewJobRequest, StandardJobPayload,
    Validate, MAX_JOB_STREAM_EVENTS, MAX_JOB_STREAM_TOTAL_BYTES,
};

use crate::{
    anti_abuse::{
        assess_before_create_in_transaction, job_assessment_key, AntiAbuseError,
        TrustedNetworkSignal,
    },
    auth::Principal,
    config::RuntimeEnvironment,
    db::authenticate,
    device_binding::{
        exact_claim_device_binding, require_node_device_binding, DEVICE_BINDING_VERSION,
    },
    error::ApiError,
    routes::evaluations::{
        expire_hidden_job_if_needed, get_hidden_job_status, instance_canary_quarantined,
        maybe_claim_hidden_job, prevalidate_hidden_job_result, renew_hidden_job,
        submit_hidden_job_failure, submit_hidden_job_result, HiddenRenewal,
    },
    settlement::{
        complete_job, fail_regulated_lease_attestation, finalize_draining_instance,
        regulated_lease_binding_valid, CompleteJob,
    },
    standard_data::{
        decrypt_from_storage, encrypt_for_storage, request_fingerprint, StorageDirection,
        STORAGE_VERSION,
    },
    AppState,
};

struct SensitiveCreateJobRequest(CreateJobRequest);

impl Deref for SensitiveCreateJobRequest {
    type Target = CreateJobRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct SensitiveJobResultRequest(JobResultRequest);

impl Deref for SensitiveJobResultRequest {
    type Target = JobResultRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct SensitiveJobStreamEventRequest(JobStreamEventRequest);

impl Deref for SensitiveJobStreamEventRequest {
    type Target = JobStreamEventRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJobStreamEventRequest {
    fn drop(&mut self) {
        if let Some(value) = self.0.event_data.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStreamReadQuery {
    #[serde(default)]
    from_sequence: Option<i32>,
    #[serde(default)]
    limit: Option<i32>,
}

impl Drop for SensitiveJobResultRequest {
    fn drop(&mut self) {
        self.0.result_ciphertext.zeroize();
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct SensitiveClaimJobResponse(ClaimJobResponse);

impl SensitiveClaimJobResponse {
    fn zeroize_owned(&mut self) {
        self.0.encrypted_payload.zeroize();
        if let Some(value) = self.0.tee_public_key.as_mut() {
            value.zeroize();
        }
    }
}

impl Drop for SensitiveClaimJobResponse {
    fn drop(&mut self) {
        self.zeroize_owned();
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct SensitiveJsonResponse(serde_json::Value);

impl Drop for SensitiveJsonResponse {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

impl Drop for SensitiveCreateJobRequest {
    fn drop(&mut self) {
        self.0.encrypted_payload.zeroize();
    }
}

struct SensitiveStandardJobPayload(StandardJobPayload);

impl Deref for SensitiveStandardJobPayload {
    type Target = StandardJobPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct SensitiveStreamData(serde_json::Value);

impl Deref for SensitiveStreamData {
    type Target = serde_json::Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveStreamData {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

impl Drop for SensitiveStandardJobPayload {
    fn drop(&mut self) {
        self.0.endpoint.zeroize();
        zeroize_json_value(&mut self.0.request);
    }
}

struct SensitiveChatResponse(ChatCompletionsResponse);

impl Deref for SensitiveChatResponse {
    type Target = ChatCompletionsResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveChatResponse {
    fn drop(&mut self) {
        self.0.id.zeroize();
        self.0.object.zeroize();
        self.0.model.zeroize();
        if let Some(value) = self.0.system_fingerprint.as_mut() {
            value.zeroize();
        }
        for choice in &mut self.0.choices {
            zeroize_message_content(&mut choice.message.content);
            if let Some(value) = choice.message.name.as_mut() {
                value.zeroize();
            }
            if let Some(value) = choice.message.tool_call_id.as_mut() {
                value.zeroize();
            }
        }
    }
}

struct SensitiveCompletionsResponse(CompletionsResponse);

impl Deref for SensitiveCompletionsResponse {
    type Target = CompletionsResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveCompletionsResponse {
    fn drop(&mut self) {
        self.0.id.zeroize();
        self.0.object.zeroize();
        self.0.model.zeroize();
        for choice in &mut self.0.choices {
            choice.text.zeroize();
        }
    }
}

fn zeroize_message_content(content: &mut MessageContent) {
    match content {
        MessageContent::Text(value) => value.zeroize(),
        MessageContent::Parts(parts) => {
            for part in parts {
                match part {
                    mindone_protocol::ContentPart::Text { text } => text.zeroize(),
                    mindone_protocol::ContentPart::ImageUrl { image_url } => {
                        image_url.url.zeroize();
                        if let Some(detail) = image_url.detail.as_mut() {
                            detail.zeroize();
                        }
                    }
                }
            }
        }
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match std::mem::take(value) {
        serde_json::Value::String(mut text) => text.zeroize(),
        serde_json::Value::Array(mut values) => {
            for nested in &mut values {
                zeroize_json_value(nested);
            }
        }
        serde_json::Value::Object(values) => {
            for (mut key, mut nested) in values {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

pub async fn create_job(
    State(state): State<AppState>,
    connection: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    headers: HeaderMap,
    Json(request): Json<CreateJobRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request = SensitiveCreateJobRequest(request);
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    create_job_authenticated(&state, connection.ok(), &headers, &request, &principal).await
}

pub(super) async fn create_job_authenticated(
    state: &AppState,
    connection: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    request: &CreateJobRequest,
    principal: &Principal,
) -> Result<Json<serde_json::Value>, ApiError> {
    let validated = validate_create_job(request, &state.config.standard_data_key)?;

    if let Some(existing) = sqlx::query(
        r#"
        SELECT id,status,model_id,reserved_cost_micro,standard_request_fingerprint,speed_class
        FROM jobs WHERE user_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(principal.user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&state.pool)
    .await?
    {
        return existing_standard_response(existing, &validated.request_fingerprint, true);
    }

    let mut tx = state.pool.begin().await?;
    let lock_domain = format!("{}:{}", principal.user_id, request.idempotency_key);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 672001))")
        .bind(lock_domain)
        .execute(&mut *tx)
        .await?;
    if let Some(existing) = sqlx::query(
        r#"
        SELECT id,status,model_id,reserved_cost_micro,standard_request_fingerprint,speed_class
        FROM jobs WHERE user_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(principal.user_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let response = existing_standard_response(existing, &validated.request_fingerprint, true)?;
        tx.commit().await?;
        return Ok(response);
    }
    assess_job_creation(
        state,
        &mut tx,
        principal,
        connection,
        headers,
        &request.idempotency_key,
    )
    .await?;

    let speed_model = parse_speed_qualified_model(&request.virtual_model)
        .map_err(|error| ApiError::bad_request("invalid_job", error.to_string()))?;
    let model = select_model(
        &mut tx,
        speed_model.base_model,
        &request.tags,
        request.estimated_input_tokens,
        request.max_output_tokens,
    )
    .await?;
    let model_id = model.id;
    let billing = load_billing_snapshot(
        &mut tx,
        model_id,
        &model.weights_hash,
        request.estimated_input_tokens,
        request.max_output_tokens,
    )
    .await?;
    let reservation = billing.reservation_micro;
    let account = sqlx::query(
        "SELECT spendable_micro,reserved_micro FROM quota_accounts WHERE user_id = $1 FOR UPDATE",
    )
    .bind(principal.user_id)
    .fetch_one(&mut *tx)
    .await?;
    let spendable: i64 = account.try_get("spendable_micro")?;
    let reserved: i64 = account.try_get("reserved_micro")?;
    if spendable.saturating_sub(reserved) < reservation {
        return Err(ApiError::insufficient_quota());
    }
    sqlx::query(
        "UPDATE quota_accounts SET reserved_micro = reserved_micro + $2, updated_at = now() WHERE user_id = $1",
    )
    .bind(principal.user_id)
    .bind(reservation)
    .execute(&mut *tx)
    .await?;
    // Worker-visible work item IDs must not encode queue creation time; hidden work uses
    // the same random UUID version so claim-time UUID inspection is not a classifier.
    let job_id = Uuid::new_v4();
    let stored_payload = encrypt_for_storage(
        &state.config.standard_data_key,
        job_id,
        StorageDirection::Payload,
        request.encrypted_payload.as_bytes(),
    )
    .map_err(|error| {
        tracing::error!(error = %error, job_id = %job_id, field = "payload", "Standard 数据静态保护失败");
        ApiError::internal()
    })?;
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             tags,estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             priority,max_attempts,standard_request_fingerprint,
             standard_payload_storage_version,
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
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro,
             speed_class)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
             $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,
             $29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40,$41)
        "#,
    )
    .bind(job_id)
    .bind(principal.user_id)
    .bind(model_id)
    .bind(&request.idempotency_key)
    .bind(stored_payload)
    .bind(request.payload_encoding.as_str())
    .bind(&request.tags)
    .bind(request.estimated_input_tokens)
    .bind(request.max_output_tokens)
    .bind(reservation)
    .bind(request.priority)
    .bind(if validated.stream {
        // 一旦客户端看到首个 SSE delta 就不能安全地把另一 attempt 拼到同一
        // OpenAI 流中；流式任务固定单 attempt，失败会终态释放准备金而不扣款。
        1
    } else {
        state.config.max_job_retries.saturating_add(1).max(1)
    })
    .bind(&validated.request_fingerprint)
    .bind(STORAGE_VERSION)
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
    .bind(speed_model.speed_class.as_str())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "job_id": job_id,
        "status": "queued",
        "model_id": model_id,
        "reserved_cost_micro": reservation,
        "speed_class": speed_model.speed_class.as_str(),
        "idempotent_replay": false
    })))
}

pub async fn get_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    match work_item_kind(&state, job_id).await? {
        WorkItemKind::Hidden => {
            return get_hidden_job_status(&state, &principal, job_id)
                .await?
                .map(|value| Json(SensitiveJsonResponse(value)).into_response())
                .ok_or_else(ApiError::internal);
        }
        WorkItemKind::Ordinary | WorkItemKind::Missing => {}
    }
    let mut tx = state.pool.begin().await?;
    reap_expired_terminal_leases(&mut tx).await?;
    reap_invalid_regulated_jobs(&mut tx).await?;
    let row = sqlx::query(
        r#"
        SELECT j.id,j.user_id,j.status,j.model_id,j.model_instance_id,j.tags,
               j.leased_to_node_id,j.lease_expires_at,j.attempt_count,j.max_attempts,
               j.actual_input_tokens,j.actual_output_tokens,j.result_ciphertext,
               j.standard_result_storage_version,
               j.confidentiality_mode,j.regulated_route_id,j.attestation_report_id,
               j.speed_class,j.created_at,j.updated_at,j.completed_at,
               n.user_id AS node_user_id,
               r.id AS receipt_id,
               latest_attempt.error_class AS attempt_error_class,
               latest_attempt.error_message AS attempt_error_message
        FROM jobs j
        LEFT JOIN nodes n ON n.id = j.leased_to_node_id
        LEFT JOIN receipts r ON r.job_id = j.id
        LEFT JOIN LATERAL (
            SELECT error_class,error_message
            FROM job_attempts
            WHERE job_id = j.id
            ORDER BY attempt_number DESC
            LIMIT 1
        ) latest_attempt ON true
        WHERE j.id = $1
        "#,
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    let consumer_id: Uuid = row.try_get("user_id")?;
    let node_user_id: Option<Uuid> = row.try_get("node_user_id")?;
    if consumer_id != principal.user_id && node_user_id != Some(principal.user_id) {
        return Err(ApiError::forbidden("无权查看此任务"));
    }
    let is_consumer = consumer_id == principal.user_id;
    let confidentiality: String = row.try_get("confidentiality_mode")?;
    let result_ciphertext = if is_consumer {
        let stored_result: Option<String> = row.try_get("result_ciphertext")?;
        if confidentiality == "standard" {
            match stored_result {
                Some(stored) => {
                    if row.try_get::<Option<i16>, _>("standard_result_storage_version")?
                        != Some(STORAGE_VERSION)
                    {
                        return Err(ApiError::internal());
                    }
                    let plaintext = decrypt_from_storage(
                        &state.config.standard_data_key,
                        job_id,
                        StorageDirection::Result,
                        &stored,
                    )
                    .map_err(|error| {
                        tracing::error!(error = %error, job_id = %job_id, field = "result", "Standard 数据静态保护校验失败");
                        ApiError::internal()
                    })?;
                    Some(String::from_utf8(plaintext.to_vec()).map_err(|_| {
                        tracing::error!(job_id = %job_id, field = "result", "Standard 数据静态保护明文编码无效");
                        ApiError::internal()
                    })?)
                }
                None => None,
            }
        } else {
            stored_result
        }
    } else {
        None
    };
    let error_class = stable_job_error_class(
        row.try_get::<Option<String>, _>("attempt_error_class")?
            .as_deref(),
    );
    let response = SensitiveJsonResponse(serde_json::json!({
        "job_id": job_id,
        "status": row.try_get::<String, _>("status")?,
        "model_id": row.try_get::<Uuid, _>("model_id")?,
        "model_instance_id": row.try_get::<Option<Uuid>, _>("model_instance_id")?,
        "tags": row.try_get::<Vec<String>, _>("tags")?,
        "leased_to_node_id": row.try_get::<Option<Uuid>, _>("leased_to_node_id")?,
        "lease_expires_at": row.try_get::<Option<OffsetDateTime>, _>("lease_expires_at")?,
        "attempt_count": row.try_get::<i32, _>("attempt_count")?,
        "max_attempts": row.try_get::<i32, _>("max_attempts")?,
        "actual_input_tokens": row.try_get::<Option<i32>, _>("actual_input_tokens")?,
        "actual_output_tokens": row.try_get::<Option<i32>, _>("actual_output_tokens")?,
        "result_ciphertext": result_ciphertext,
        "speed_class": row.try_get::<String, _>("speed_class")?,
        "confidentiality": confidentiality,
        "regulated_route_id": row.try_get::<Option<Uuid>, _>("regulated_route_id")?,
        "attestation_report_id": row.try_get::<Option<Uuid>, _>("attestation_report_id")?,
        "error_class": error_class,
        "error_message": row.try_get::<Option<String>, _>("attempt_error_message")?,
        "receipt_id": row.try_get::<Option<Uuid>, _>("receipt_id")?,
        "created_at": row.try_get::<OffsetDateTime, _>("created_at")?,
        "updated_at": row.try_get::<OffsetDateTime, _>("updated_at")?,
        "completed_at": row.try_get::<Option<OffsetDateTime>, _>("completed_at")?
    }));
    tx.commit().await?;
    Ok(Json(response).into_response())
}

pub async fn claim_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClaimJobRequest>,
) -> Result<Response, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let policy = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,n.status,n.pause_reason,p.reject_tags,p.max_concurrent,
               p.gpu_temp_limit_c,p.vram_reserve_mib
        FROM nodes n JOIN node_policies p ON p.node_id = n.id
        WHERE n.id = $1 FOR UPDATE OF n,p
        "#,
    )
    .bind(request.node_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("节点"))?;
    require_node_device_binding(
        &principal,
        policy.try_get("user_id")?,
        policy.try_get("device_key_id")?,
    )?;
    if policy.try_get::<String, _>("status")? != "online" {
        return Err(ApiError::policy_rejected("节点当前未处于在线接单状态"));
    }
    reap_expired_terminal_leases(&mut tx).await?;
    reap_invalid_regulated_jobs(&mut tx).await?;
    enforce_current_policy(&mut tx, request.node_id, &policy, None, &[]).await?;
    if let Some(hidden_job) = maybe_claim_hidden_job(
        &state,
        &mut tx,
        &principal,
        request.node_id,
        request.model_instance_id,
    )
    .await?
    {
        tx.commit().await?;
        return Ok((StatusCode::OK, Json(SensitiveClaimJobResponse(hidden_job))).into_response());
    }
    let candidate = sqlx::query(
        r#"
        WITH recent_node_contributions AS (
            SELECT settled_job.leased_to_node_id AS node_id,
                   SUM(receipt.contribution_micro)::numeric AS contribution_micro
            FROM receipts receipt
            JOIN jobs settled_job ON settled_job.id = receipt.job_id
            WHERE settled_job.leased_to_node_id IS NOT NULL
              AND receipt.created_at >= now() - ($3::bigint * interval '1 day')
            GROUP BY settled_job.leased_to_node_id
        )
        SELECT j.id,j.encrypted_payload,j.payload_encoding,j.standard_payload_storage_version,
               j.tags,j.estimated_input_tokens,
               j.max_output_tokens,j.attempt_count,j.max_attempts,
               j.confidentiality_mode,j.regulated_route_id,j.attestation_report_id,
               selected.model_instance_id,
               m.name AS model_name,m.weights_hash,
               ar.provider AS attestation_provider,
               ar.ephemeral_public_key AS tee_public_key
        FROM jobs j
        JOIN LATERAL (
            SELECT prioritized.model_instance_id,prioritized.node_id,
                   prioritized.routing_score
            FROM (
                SELECT node_cohort.*,
                       COUNT(*) OVER () AS cohort_size,
                       MAX(node_cohort.routing_score) OVER () AS best_routing_score,
                       SUM(node_cohort.server_free_slots) OVER () AS server_free_slots_total,
                       (
                           SELECT COUNT(*)::bigint
                           FROM jobs ready_job
                           WHERE ready_job.model_id = j.model_id
                             AND ready_job.confidentiality_mode = j.confidentiality_mode
                             AND ARRAY(
                                   SELECT DISTINCT lower(tag)
                                   FROM unnest(ready_job.tags) AS demand_tag(tag)
                                   ORDER BY lower(tag)
                                 ) = ARRAY(
                                   SELECT DISTINCT lower(tag)
                                   FROM unnest(j.tags) AS current_tag(tag)
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
                       ) AS ready_demand,
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
                           ) * $4::numeric
                           / NULLIF(
                               2::numeric * (COUNT(*) OVER () - 1)::numeric,
                               0::numeric
                           )
                       )::bigint AS contribution_percentile_ppm
                FROM (
                    SELECT DISTINCT ON (ranked.node_id)
                           ranked.model_instance_id,ranked.node_id,
                           ranked.routing_score,ranked.server_free_slots,
                           ranked.contribution_micro,ranked.active_count,
                           ranked.tps_milli
                    FROM (
                SELECT mi.id AS model_instance_id,n.id AS node_id,
                    (
                        (CASE n.trust_level
                            WHEN 'enhanced' THEN 1000000::bigint
                            WHEN 'standard' THEN 850000::bigint
                            WHEN 'standard-limited' THEN 700000::bigint
                            WHEN 'experimental' THEN 400000::bigint
                            ELSE 300000::bigint END) * 25
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
                        + (LEAST(
                            COALESCE(metrics.tps_milli,0::bigint),100000::bigint
                          ) * 10) * 15
                        + GREATEST(
                            0::bigint,
                            1000000::bigint - (
                                GREATEST(
                                    load.active_count,
                                    COALESCE(metrics.current_concurrent,0)::bigint
                                ) * 1000000::bigint
                                / GREATEST(p.max_concurrent,1)::bigint
                            )
                          ) * 15
                        + GREATEST(
                            0::bigint,
                            1000000::bigint - COALESCE(
                                metrics.error_rate_ppm,500000
                            )::bigint
                          ) * 10
                    ) AS routing_score,
                    CASE
                        WHEN j.speed_class = 'slow' THEN GREATEST(
                            p.max_concurrent::bigint - load.active_count,
                            0::bigint
                        )
                        WHEN load.active_count = 0 THEN 1::bigint
                        ELSE 0::bigint
                    END AS server_free_slots,
                    load.active_count AS active_count,
                    COALESCE(metrics.tps_milli,0::bigint) AS tps_milli,
                    COALESCE(
                        recent_contribution.contribution_micro,
                        0::numeric
                    ) AS contribution_micro
                FROM model_instances mi
                JOIN nodes n ON n.id = mi.node_id
                JOIN node_policies p ON p.node_id = n.id
                LEFT JOIN LATERAL (
                    SELECT nm.tps_milli,nm.coordinator_rtt_ms,nm.current_concurrent,
                           nm.gpu_temp_c,nm.vram_used_mib,nm.vram_total_mib,
                           nm.error_rate_ppm
                    FROM node_metrics nm
                    WHERE nm.node_id = n.id
                    ORDER BY nm.measured_at DESC,nm.id DESC
                    LIMIT 1
                ) metrics ON TRUE
                LEFT JOIN recent_node_contributions recent_contribution
                  ON recent_contribution.node_id = n.id
                CROSS JOIN LATERAL (
                    SELECT (
                        SELECT COUNT(*)::bigint
                        FROM jobs active_job
                        WHERE active_job.id <> j.id
                          AND (
                              (
                                  active_job.leased_to_node_id = n.id
                                  AND active_job.status = 'leased'
                                  AND active_job.lease_expires_at > now()
                              ) OR (
                                  active_job.confidentiality_mode = 'regulated'
                                  AND active_job.regulated_node_id = n.id
                                  AND active_job.status IN ('queued','retry')
                              )
                          )
                    ) + (
                        SELECT COUNT(*)::bigint
                        FROM regulated_routes pending_route
                        WHERE pending_route.node_id = n.id
                          AND pending_route.status = 'prepared'
                          AND pending_route.expires_at > now()
                    ) + (
                        SELECT COUNT(*)::bigint
                        FROM model_evaluation_challenges hidden_work
                        WHERE hidden_work.node_id = n.id
                          AND hidden_work.status = 'leased'
                          AND hidden_work.lease_expires_at > now()
                    ) AS active_count
                ) load
                WHERE mi.model_id = j.model_id
                  AND mi.status = 'published'
                  AND NOT EXISTS (
                        SELECT 1 FROM model_instance_canary_state canary_risk
                        WHERE canary_risk.model_instance_id=mi.id
                          AND canary_risk.quarantined=TRUE
                      )
                  AND n.status = 'online'
                  AND n.last_seen_at > now() - interval '90 seconds'
                  AND (
                        metrics.coordinator_rtt_ms IS NULL
                        OR metrics.coordinator_rtt_ms BETWEEN 1 AND 1000
                      )
                  AND (
                        j.confidentiality_mode = 'standard'
                        OR (
                            j.confidentiality_mode = 'regulated'
                            AND mi.id = j.model_instance_id
                            AND n.id = j.regulated_node_id
                            AND EXISTS (
                                SELECT 1 FROM attestation_reports bound_report
                                WHERE bound_report.id = j.attestation_report_id
                                  AND bound_report.node_id = n.id
                                  AND bound_report.model_instance_id = mi.id
                                  AND bound_report.model_hash = (
                                      SELECT bound_model.weights_hash
                                      FROM models bound_model
                                      WHERE bound_model.id = j.model_id
                                  )
                                  AND bound_report.status = 'verified'
                                  AND bound_report.key_origin = 'tee_runtime'
                                  AND bound_report.expires_at > now()
                                  AND bound_report.collateral_expires_at > now()
                            )
                        )
                      )
                  AND NOT EXISTS (
                        SELECT 1
                        FROM unnest(j.tags) AS requested(tag)
                        JOIN unnest(p.reject_tags) AS rejected(tag)
                          ON lower(requested.tag) = lower(rejected.tag)
                      )
                  AND (
                        (
                            j.speed_class = 'slow'
                            AND GREATEST(
                                load.active_count,
                                COALESCE(metrics.current_concurrent,0)::bigint
                            ) < p.max_concurrent::bigint
                        )
                        OR (
                            j.speed_class IN ('fast','standard')
                            AND GREATEST(
                                load.active_count,
                                COALESCE(metrics.current_concurrent,0)::bigint
                            ) = 0
                        )
                      )
                  AND (
                        p.gpu_temp_limit_c IS NULL
                        OR (
                            metrics.gpu_temp_c IS NOT NULL
                            AND metrics.gpu_temp_c < p.gpu_temp_limit_c
                        )
                      )
                  AND (
                        p.vram_reserve_mib = 0
                        OR (
                            metrics.vram_used_mib IS NOT NULL
                            AND metrics.vram_total_mib IS NOT NULL
                            AND metrics.vram_total_mib - metrics.vram_used_mib
                                >= p.vram_reserve_mib
                        )
                      )
                    ) ranked
                    ORDER BY ranked.node_id,ranked.model_instance_id
                ) node_cohort
            ) prioritized
            ORDER BY
                -- fast 与 standard 只使用整台空闲贡献端，避免新增多槽能力让原有
                -- 速度档发生同机争用；所有节点都忙时保持 queued。slow 才能使用
                -- 真实空槽并优先向已有负载节点合并。
                CASE WHEN j.speed_class = 'fast'
                    THEN prioritized.tps_milli END DESC NULLS LAST,
                CASE WHEN j.speed_class = 'slow'
                    THEN prioritized.active_count END DESC NULLS LAST,
                CASE
                    WHEN prioritized.cohort_size >= $5::bigint
                     AND prioritized.ready_demand > prioritized.server_free_slots_total
                     AND prioritized.routing_score * $6::bigint
                         >= prioritized.best_routing_score * $7::bigint
                    THEN prioritized.contribution_percentile_ppm
                    ELSE NULL
                END DESC NULLS LAST,
                prioritized.routing_score DESC,
                prioritized.node_id,
                prioritized.model_instance_id
            LIMIT 1
        ) selected ON selected.node_id = $1 AND selected.model_instance_id = $2
        JOIN models m ON m.id = j.model_id AND m.enabled = TRUE
        LEFT JOIN attestation_reports ar ON ar.id = j.attestation_report_id
        WHERE (
                j.status IN ('queued','retry')
                OR (j.status = 'leased' AND j.lease_expires_at <= now())
          )
          AND j.available_at <= now()
          AND j.attempt_count < j.max_attempts
        ORDER BY j.priority DESC,j.created_at ASC
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(request.node_id)
    .bind(request.model_instance_id)
    .bind(CONTRIBUTION_ROUTING_WINDOW_DAYS)
    .bind(i64::from(CONTRIBUTION_ROUTING_PERCENTILE_SCALE))
    .bind(CONTRIBUTION_ROUTING_MIN_COHORT as i64)
    .bind(CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR)
    .bind(CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(candidate) = candidate else {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let job_id: Uuid = candidate.try_get("id")?;
    let candidate_tags: Vec<String> = candidate.try_get("tags")?;
    enforce_current_policy(&mut tx, request.node_id, &policy, None, &candidate_tags).await?;
    let previous_attempt: i32 = candidate.try_get("attempt_count")?;
    if previous_attempt > 0 {
        sqlx::query(
            r#"
            UPDATE job_attempts SET status = 'expired', finished_at = now()
            WHERE job_id = $1 AND attempt_number = $2 AND status = 'leased'
            "#,
        )
        .bind(job_id)
        .bind(previous_attempt)
        .execute(&mut *tx)
        .await?;
    }
    let attempt = previous_attempt.saturating_add(1);
    let lease_expires_at = expiry(state.config.lease_duration)?;
    let model_instance_id: Uuid = candidate.try_get("model_instance_id")?;
    // SQL 候选过滤与实际租约写入之间必须和 canary 状态转换串行化。若实例在
    // 候选查询后被隔离，本次消费者领取失败关闭；若本事务先取得锁，则已经发出的
    // 租约按既有合同继续执行，随后隔离只影响新的消费者路由。
    if instance_canary_quarantined(&mut tx, model_instance_id).await? {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    // 候选 SQL 只读取实例状态，不能与并发 unpublish 线性化。这里在写入租约前取得
    // 实例共享行锁并复核 published：claim 先赢时 unpublish 会等待并随后看见新租约；
    // unpublish 先赢时本次 claim 失败关闭，不能把任务租给已停止发布的实例。
    let instance = sqlx::query("SELECT status FROM model_instances WHERE id=$1 FOR SHARE")
        .bind(model_instance_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(instance) = instance else {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    if instance.try_get::<String, _>("status")? != "published" {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    sqlx::query(
        r#"
        UPDATE jobs SET status = 'leased',leased_to_node_id = $2,
            model_instance_id = $3,lease_expires_at = $4,attempt_count = $5,
            updated_at = now()
        WHERE id = $1
        "#,
    )
    .bind(job_id)
    .bind(request.node_id)
    .bind(model_instance_id)
    .bind(lease_expires_at)
    .bind(attempt)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO job_attempts
            (id,job_id,node_id,attempt_number,status,lease_started_at,lease_expires_at,
             claim_device_binding_version,claim_device_key_id)
        VALUES ($1,$2,$3,$4,'leased',now(),$5,$6,$7)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .bind(request.node_id)
    .bind(attempt)
    .bind(lease_expires_at)
    .bind(DEVICE_BINDING_VERSION)
    .bind(principal.device_key_id)
    .execute(&mut *tx)
    .await?;
    let confidentiality_raw: String = candidate.try_get("confidentiality_mode")?;
    let encrypted_payload = if confidentiality_raw == "standard" {
        if candidate.try_get::<Option<i16>, _>("standard_payload_storage_version")?
            != Some(STORAGE_VERSION)
        {
            return Err(ApiError::internal());
        }
        let stored_payload: String = candidate.try_get("encrypted_payload")?;
        let plaintext = decrypt_from_storage(
            &state.config.standard_data_key,
            job_id,
            StorageDirection::Payload,
            &stored_payload,
        )
        .map_err(|error| {
            tracing::error!(error = %error, job_id = %job_id, field = "payload", "Standard 数据静态保护校验失败");
            ApiError::internal()
        })?;
        String::from_utf8(plaintext.to_vec()).map_err(|_| {
            tracing::error!(job_id = %job_id, field = "payload", "Standard 数据静态保护明文编码无效");
            ApiError::internal()
        })?
    } else {
        candidate.try_get("encrypted_payload")?
    };
    let response = ClaimJobResponse {
        job_id,
        model_instance_id,
        model: candidate.try_get("model_name")?,
        model_weights_hash: candidate.try_get("weights_hash")?,
        encrypted_payload,
        payload_encoding: payload_encoding_from_db(
            &candidate.try_get::<String, _>("payload_encoding")?,
        )?,
        tags: candidate_tags,
        estimated_input_tokens: candidate.try_get("estimated_input_tokens")?,
        max_output_tokens: candidate.try_get("max_output_tokens")?,
        attempt,
        lease_expires_at,
        policy_check_required_before_execution: true,
        confidentiality: confidentiality_from_db(&confidentiality_raw)?,
        regulated_route_id: candidate.try_get("regulated_route_id")?,
        attestation_report_id: candidate.try_get("attestation_report_id")?,
        attestation_provider: candidate
            .try_get::<Option<String>, _>("attestation_provider")?
            .as_deref()
            .map(attestation_provider_from_db)
            .transpose()?,
        tee_public_key: candidate.try_get("tee_public_key")?,
    };
    tx.commit().await?;
    Ok((StatusCode::OK, Json(SensitiveClaimJobResponse(response))).into_response())
}

pub async fn renew_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
    Json(request): Json<RenewJobRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let work_item_kind = work_item_kind(&state, job_id).await?;
    let mut tx = state.pool.begin().await?;
    let node = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,n.status,p.reject_tags,p.max_concurrent,
               p.gpu_temp_limit_c,p.vram_reserve_mib
        FROM nodes n JOIN node_policies p ON p.node_id = n.id
        WHERE n.id = $1 FOR UPDATE OF n,p
        "#,
    )
    .bind(request.node_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("节点"))?;
    require_node_device_binding(
        &principal,
        node.try_get("user_id")?,
        node.try_get("device_key_id")?,
    )?;
    let node_status = node.try_get::<String, _>("status")?;
    if !matches!(node_status.as_str(), "online" | "paused" | "draining") {
        return Err(ApiError::policy_rejected("节点策略当前暂停执行"));
    }
    if work_item_kind == WorkItemKind::Hidden {
        let outcome = renew_hidden_job(&state, &mut tx, &principal, job_id, request.node_id)
            .await?
            .ok_or_else(ApiError::internal)?;
        let HiddenRenewal::Renewed(response) = outcome else {
            tx.commit().await?;
            return Err(ApiError::conflict(
                "lease_not_renewable",
                "任务租约不存在、已过期或不属于当前节点",
            ));
        };
        // renew_hidden_job 已先完成与普通任务查询等价的租约绑定和状态检查；策略失败时
        // 当前事务回滚，因此不会把提前计算的新到期时间写入数据库。
        enforce_current_policy(&mut tx, request.node_id, &node, Some(job_id), &[]).await?;
        tx.commit().await?;
        return Ok(Json(
            serde_json::to_value(response).map_err(|_| ApiError::internal())?,
        ));
    }
    let task = sqlx::query(
        r#"
        SELECT j.tags,j.confidentiality_mode,
               ja.claim_device_binding_version,ja.claim_device_key_id
        FROM jobs j
        JOIN job_attempts ja
          ON ja.job_id=j.id AND ja.attempt_number=j.attempt_count
        WHERE j.id=$1 AND j.leased_to_node_id=$2 AND j.status='leased'
          AND j.lease_expires_at > now()
        FOR UPDATE OF j,ja
        "#,
    )
    .bind(job_id)
    .bind(request.node_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        ApiError::conflict(
            "lease_not_renewable",
            "任务租约不存在、已过期或不属于当前节点",
        )
    })?;
    if !exact_claim_device_binding(
        &principal,
        Some(principal.user_id),
        task.try_get("claim_device_key_id")?,
        task.try_get("claim_device_binding_version")?,
    ) {
        return Err(ApiError::conflict(
            "lease_not_renewable",
            "任务租约不存在、已过期或不属于当前节点",
        ));
    }
    let confidentiality: String = task.try_get("confidentiality_mode")?;
    if confidentiality == "regulated"
        && !regulated_lease_binding_valid(&mut tx, job_id, request.node_id).await?
    {
        fail_regulated_lease_attestation(
            &mut tx,
            job_id,
            "Regulated 续租时硬件报告、固定节点或模型绑定已失效",
        )
        .await?;
        tx.commit().await?;
        return Err(ApiError::attestation_failed(
            "Regulated 硬件信任已失效；任务已终止、reservation 已释放且未计费",
        ));
    }
    let task_tags: Vec<String> = task.try_get("tags")?;
    enforce_current_policy(&mut tx, request.node_id, &node, Some(job_id), &task_tags).await?;
    let lease_expires_at = expiry(state.config.lease_duration)?;
    let updated = sqlx::query(
        r#"
        UPDATE jobs SET lease_expires_at = $3,updated_at = now()
        WHERE id = $1 AND leased_to_node_id = $2 AND status = 'leased'
          AND lease_expires_at > now()
        "#,
    )
    .bind(job_id)
    .bind(request.node_id)
    .bind(lease_expires_at)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "lease_not_renewable",
            "任务租约不存在、已过期或不属于当前节点",
        ));
    }
    sqlx::query(
        r#"
        UPDATE job_attempts SET lease_expires_at = $2
        WHERE job_id = $1 AND status = 'leased'
        "#,
    )
    .bind(job_id)
    .bind(lease_expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "job_id": job_id,
        "lease_expires_at": lease_expires_at
    })))
}

pub async fn job_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
    Json(request): Json<JobResultRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request = SensitiveJobResultRequest(request);
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    verify_node_owner(&state, request.node_id, &principal).await?;
    request.validate().map_err(|error| {
        ApiError::bad_request("invalid_job_result", format!("任务结果字段无效：{error}"))
    })?;
    match work_item_kind(&state, job_id).await? {
        WorkItemKind::Hidden => {
            prevalidate_hidden_job_result(&state, job_id, &request).await?;
            if expire_hidden_job_if_needed(&state, &principal, job_id, request.node_id).await? {
                return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
            }
            let response = submit_hidden_job_result(&state, &principal, job_id, &request)
                .await?
                .ok_or_else(ApiError::internal)?;
            return Ok(Json(
                serde_json::to_value(response).map_err(|_| ApiError::internal())?,
            ));
        }
        WorkItemKind::Ordinary | WorkItemKind::Missing => {}
    }
    validate_job_result(&state, job_id, &request).await?;
    let outcome = complete_job(
        &state.pool,
        &state.config.standard_data_key,
        CompleteJob {
            job_id,
            node_id: request.node_id,
            worker_user_id: principal.user_id,
            claim_device_key_id: principal.device_key_id,
            idempotency_key: request.idempotency_key.clone(),
            result_ciphertext: Zeroizing::new(request.result_ciphertext.clone()),
            actual_input_tokens: request.actual_input_tokens,
            actual_output_tokens: request.actual_output_tokens,
            execution_telemetry: request.execution_telemetry.clone(),
        },
    )
    .await?;
    let response = JobResultResponse {
        job_id,
        status: JobStatus::Succeeded,
        idempotent_replay: outcome.idempotent_replay,
    };
    Ok(Json(serde_json::to_value(response).map_err(|error| {
        tracing::error!(error = %error, "任务完成确认序列化失败");
        ApiError::internal()
    })?))
}

pub async fn append_job_stream_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
    Json(request): Json<JobStreamEventRequest>,
) -> Result<Json<JobStreamEventResponse>, ApiError> {
    let request = SensitiveJobStreamEventRequest(request);
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    verify_node_owner(&state, request.node_id, &principal).await?;
    request.validate().map_err(|error| {
        ApiError::bad_request("invalid_stream_event", format!("流式事件字段无效：{error}"))
    })?;

    let mut tx = state.pool.begin().await?;
    let job = sqlx::query(
        r#"
        SELECT j.user_id,j.status,j.confidentiality_mode,j.leased_to_node_id,
               j.lease_expires_at,j.attempt_count,j.max_attempts,j.encrypted_payload,
               j.payload_encoding,j.standard_payload_storage_version,
               ja.claim_device_binding_version,ja.claim_device_key_id,
               n.user_id AS node_user_id,m.name AS model_name
        FROM jobs j
        JOIN models m ON m.id=j.model_id
        JOIN nodes n ON n.id=j.leased_to_node_id
        JOIN job_attempts ja
          ON ja.job_id=j.id AND ja.attempt_number=j.attempt_count
        WHERE j.id=$1
        FOR UPDATE OF j
        "#,
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    if job.try_get::<Uuid, _>("node_user_id")? != principal.user_id
        || job.try_get::<Option<Uuid>, _>("leased_to_node_id")? != Some(request.node_id)
        || !exact_claim_device_binding(
            &principal,
            Some(job.try_get("node_user_id")?),
            job.try_get("claim_device_key_id")?,
            job.try_get("claim_device_binding_version")?,
        )
    {
        return Err(ApiError::forbidden("任务租约不属于当前节点设备"));
    }
    if job.try_get::<String, _>("status")? != "leased"
        || job
            .try_get::<Option<OffsetDateTime>, _>("lease_expires_at")?
            .is_none_or(|expires_at| expires_at <= OffsetDateTime::now_utc())
        || job.try_get::<i32, _>("attempt_count")? != request.attempt
    {
        return Err(ApiError::conflict(
            "stream_lease_invalid",
            "流式事件租约不存在、已过期或 attempt 不匹配",
        ));
    }
    if job.try_get::<String, _>("confidentiality_mode")? != "standard" {
        return Err(ApiError::bad_request(
            "stream_not_supported",
            "Regulated 任务当前不支持流式事件，且不会降级为 Standard",
        ));
    }
    let payload = decode_stored_standard_payload(&state, job_id, &job)?;
    let limits = payload
        .validated_limits()
        .map_err(|error| ApiError::bad_request("invalid_standard_payload", error.to_string()))?;
    if !limits.stream || job.try_get::<i32, _>("max_attempts")? != 1 {
        return Err(ApiError::bad_request(
            "stream_not_requested",
            "任务没有请求可恢复的 Standard SSE",
        ));
    }

    if let Some(existing) = sqlx::query(
        r#"
        SELECT attempt_number,sequence_number,idempotency_key,event_kind,
               event_ciphertext,standard_event_storage_version,plaintext_bytes
        FROM job_stream_events
        WHERE job_id=$1 AND (
            (attempt_number=$2 AND sequence_number=$3) OR idempotency_key=$4
        )
        "#,
    )
    .bind(job_id)
    .bind(request.attempt)
    .bind(request.sequence)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        validate_stream_event_replay(&state, job_id, &request, &existing)?;
        tx.commit().await?;
        return Ok(Json(JobStreamEventResponse {
            job_id,
            attempt: request.attempt,
            sequence: request.sequence,
            idempotent_replay: true,
        }));
    }

    let aggregate = sqlx::query(
        r#"
        SELECT COUNT(*)::bigint AS event_count,
               COALESCE(SUM(plaintext_bytes),0)::bigint AS total_bytes,
               COALESCE(BOOL_OR(event_kind='upstream_done'),FALSE) AS upstream_done
        FROM job_stream_events
        WHERE job_id=$1 AND attempt_number=$2
        "#,
    )
    .bind(job_id)
    .bind(request.attempt)
    .fetch_one(&mut *tx)
    .await?;
    let event_count: i64 = aggregate.try_get("event_count")?;
    if event_count != i64::from(request.sequence) || event_count >= i64::from(MAX_JOB_STREAM_EVENTS)
    {
        return Err(ApiError::conflict(
            "stream_sequence_mismatch",
            "流式事件必须按连续 sequence 只追加提交",
        ));
    }
    if aggregate.try_get::<bool, _>("upstream_done")? {
        return Err(ApiError::conflict(
            "stream_already_done",
            "upstream_done 之后不得追加流式事件",
        ));
    }

    let (event_kind, stored_event, storage_version, plaintext_bytes) = match &request.kind {
        JobStreamEventKind::Data => {
            let data = request
                .event_data
                .as_deref()
                .ok_or_else(ApiError::internal)?;
            validate_standard_stream_data(&payload, &limits.model, data)?;
            let byte_count = i32::try_from(data.len()).map_err(|_| ApiError::internal())?;
            if aggregate
                .try_get::<i64, _>("total_bytes")?
                .checked_add(i64::from(byte_count))
                .is_none_or(|total| total > MAX_JOB_STREAM_TOTAL_BYTES)
            {
                return Err(ApiError::bad_request(
                    "stream_too_large",
                    "流式事件累计正文超过安全上限",
                ));
            }
            let stored = encrypt_for_storage(
                &state.config.standard_data_key,
                job_id,
                StorageDirection::StreamEvent {
                    attempt_number: request.attempt,
                    sequence_number: request.sequence,
                },
                data.as_bytes(),
            )
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    job_id = %job_id,
                    attempt = request.attempt,
                    sequence = request.sequence,
                    "Standard SSE 数据静态保护失败"
                );
                ApiError::internal()
            })?;
            ("data", Some(stored), Some(STORAGE_VERSION), byte_count)
        }
        JobStreamEventKind::UpstreamDone => {
            if event_count == 0 {
                return Err(ApiError::bad_request(
                    "invalid_stream_event",
                    "upstream_done 之前至少需要一个真实 data 事件",
                ));
            }
            ("upstream_done", None, None, 0)
        }
    };
    sqlx::query(
        r#"
        INSERT INTO job_stream_events
            (job_id,attempt_number,sequence_number,idempotency_key,event_kind,
             event_ciphertext,standard_event_storage_version,plaintext_bytes)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(job_id)
    .bind(request.attempt)
    .bind(request.sequence)
    .bind(&request.idempotency_key)
    .bind(event_kind)
    .bind(stored_event)
    .bind(storage_version)
    .bind(plaintext_bytes)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(JobStreamEventResponse {
        job_id,
        attempt: request.attempt,
        sequence: request.sequence,
        idempotent_replay: false,
    }))
}

pub async fn get_job_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
    Query(query): Query<JobStreamReadQuery>,
) -> Result<Json<JobStreamReadResponse>, ApiError> {
    const DEFAULT_PAGE_SIZE: i32 = 8;
    const MAX_PAGE_SIZE: i32 = 32;

    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let from_sequence = query.from_sequence.unwrap_or(0);
    if !(0..=MAX_JOB_STREAM_EVENTS).contains(&from_sequence) {
        return Err(ApiError::bad_request(
            "invalid_stream_cursor",
            "from_sequence 超出流式游标范围",
        ));
    }
    let limit = query.limit.unwrap_or(DEFAULT_PAGE_SIZE);
    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(ApiError::bad_request(
            "invalid_stream_cursor",
            "流式读取 limit 必须在 1..=32",
        ));
    }
    Ok(Json(
        read_job_stream_authenticated(&state, &principal, job_id, from_sequence, limit).await?,
    ))
}

pub(crate) async fn read_job_stream_authenticated(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
    from_sequence: i32,
    limit: i32,
) -> Result<JobStreamReadResponse, ApiError> {
    let job = sqlx::query(
        r#"
        SELECT j.user_id,j.status,j.attempt_count,j.max_attempts,j.confidentiality_mode,
               j.encrypted_payload,j.payload_encoding,j.standard_payload_storage_version,
               m.name AS model_name,
               latest_attempt.error_class,latest_attempt.error_message
        FROM jobs j
        JOIN models m ON m.id=j.model_id
        LEFT JOIN LATERAL (
            SELECT error_class,error_message
            FROM job_attempts
            WHERE job_id=j.id
            ORDER BY attempt_number DESC
            LIMIT 1
        ) latest_attempt ON true
        WHERE j.id=$1
        "#,
    )
    .bind(job_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    if job.try_get::<Uuid, _>("user_id")? != principal.user_id {
        return Err(ApiError::forbidden("只有任务消费者可读取流式输出"));
    }
    if job.try_get::<String, _>("confidentiality_mode")? != "standard" {
        return Err(ApiError::bad_request(
            "stream_not_supported",
            "Regulated 任务当前不支持流式读取，且不会降级为 Standard",
        ));
    }
    let payload = decode_stored_standard_payload(state, job_id, &job)?;
    let limits = payload
        .validated_limits()
        .map_err(|error| ApiError::bad_request("invalid_standard_payload", error.to_string()))?;
    if !limits.stream || job.try_get::<i32, _>("max_attempts")? != 1 {
        return Err(ApiError::bad_request(
            "stream_not_requested",
            "任务没有请求可恢复的 Standard SSE",
        ));
    }
    let attempt: i32 = job.try_get("attempt_count")?;
    let rows = if attempt > 0 {
        sqlx::query(
            r#"
            SELECT sequence_number,event_ciphertext,standard_event_storage_version,
                   plaintext_bytes
            FROM job_stream_events
            WHERE job_id=$1 AND attempt_number=$2 AND event_kind='data'
              AND sequence_number >= $3
            ORDER BY sequence_number
            LIMIT $4
            "#,
        )
        .bind(job_id)
        .bind(attempt)
        .bind(from_sequence)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?
    } else {
        Vec::new()
    };
    let mut events = Vec::with_capacity(rows.len());
    let mut next_sequence = from_sequence;
    for row in rows {
        let sequence: i32 = row.try_get("sequence_number")?;
        let storage_version: Option<i16> = row.try_get("standard_event_storage_version")?;
        let ciphertext: Option<String> = row.try_get("event_ciphertext")?;
        if storage_version != Some(STORAGE_VERSION) || ciphertext.is_none() {
            return Err(ApiError::internal());
        }
        let plaintext = decrypt_from_storage(
            &state.config.standard_data_key,
            job_id,
            StorageDirection::StreamEvent {
                attempt_number: attempt,
                sequence_number: sequence,
            },
            ciphertext.as_deref().ok_or_else(ApiError::internal)?,
        )
        .map_err(|error| {
            tracing::error!(
                error = %error,
                job_id = %job_id,
                attempt,
                sequence,
                "Standard SSE 数据静态保护校验失败"
            );
            ApiError::internal()
        })?;
        if i32::try_from(plaintext.len()).map_err(|_| ApiError::internal())?
            != row.try_get::<i32, _>("plaintext_bytes")?
        {
            return Err(ApiError::internal());
        }
        let event_data = String::from_utf8(plaintext.to_vec()).map_err(|_| ApiError::internal())?;
        validate_standard_stream_data(&payload, &limits.model, &event_data)?;
        next_sequence = sequence.checked_add(1).ok_or_else(ApiError::internal)?;
        events.push(JobStreamEvent {
            sequence,
            event_data,
        });
    }
    let stream_state = if attempt > 0 {
        sqlx::query(
            r#"
            SELECT EXISTS(
                       SELECT 1 FROM job_stream_events
                       WHERE job_id=$1 AND attempt_number=$2 AND event_kind='data'
                         AND sequence_number >= $3
                   ) AS has_more,
                   EXISTS(
                       SELECT 1 FROM job_stream_events
                       WHERE job_id=$1 AND attempt_number=$2
                         AND event_kind='upstream_done'
                   ) AS upstream_done
            "#,
        )
        .bind(job_id)
        .bind(attempt)
        .bind(next_sequence)
        .fetch_one(&state.pool)
        .await?
    } else {
        sqlx::query("SELECT FALSE AS has_more,FALSE AS upstream_done")
            .fetch_one(&state.pool)
            .await?
    };
    let status = job_status_from_db(&job.try_get::<String, _>("status")?)?;
    let upstream_done: bool = stream_state.try_get("upstream_done")?;
    if status == JobStatus::Succeeded && !upstream_done {
        tracing::error!(job_id = %job_id, attempt, "已结算 SSE 任务缺少 upstream_done");
        return Err(ApiError::internal());
    }
    Ok(JobStreamReadResponse {
        job_id,
        status,
        attempt,
        events,
        next_sequence,
        has_more: stream_state.try_get("has_more")?,
        upstream_done,
        error_class: stable_job_error_class(
            job.try_get::<Option<String>, _>("error_class")?.as_deref(),
        ),
        error_message: job.try_get("error_message")?,
    })
}

pub async fn job_fail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<Uuid>,
    Json(request): Json<JobFailRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request.validate().map_err(|error| {
        ApiError::bad_request(
            "invalid_failure_report",
            format!("失败报告字段无效：{error}"),
        )
    })?;
    verify_node_owner(&state, request.node_id, &principal).await?;
    match work_item_kind(&state, job_id).await? {
        WorkItemKind::Hidden => {
            if expire_hidden_job_if_needed(&state, &principal, job_id, request.node_id).await? {
                return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
            }
            let response = submit_hidden_job_failure(&state, &principal, job_id, &request)
                .await?
                .ok_or_else(ApiError::internal)?;
            return Ok(Json(
                serde_json::to_value(response).map_err(|_| ApiError::internal())?,
            ));
        }
        WorkItemKind::Ordinary | WorkItemKind::Missing => {}
    }
    let mut tx = state.pool.begin().await?;
    let lock_domain = format!("job-fail:{job_id}:{}", request.idempotency_key);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 672004))")
        .bind(lock_domain)
        .execute(&mut *tx)
        .await?;
    if let Some(existing) = sqlx::query(
        r#"
        SELECT ja.status,ja.node_id,ja.error_class,ja.error_message,
               ja.retryable_requested,ja.claim_device_binding_version,
               ja.claim_device_key_id,n.user_id AS node_user_id
        FROM job_attempts ja
        JOIN nodes n ON n.id=ja.node_id
        WHERE ja.job_id=$1 AND ja.result_idempotency_key=$2
        FOR UPDATE OF ja
        "#,
    )
    .bind(job_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        if existing.try_get::<Uuid, _>("node_user_id")? != principal.user_id
            || existing.try_get::<Uuid, _>("node_id")? != request.node_id
            || !exact_claim_device_binding(
                &principal,
                Some(existing.try_get("node_user_id")?),
                existing.try_get("claim_device_key_id")?,
                existing.try_get("claim_device_binding_version")?,
            )
        {
            return Err(ApiError::forbidden("任务租约不属于当前节点"));
        }
        if existing
            .try_get::<Option<String>, _>("error_class")?
            .as_deref()
            != Some(job_error_class_key(request.error_class))
            || existing
                .try_get::<Option<String>, _>("error_message")?
                .as_deref()
                != Some(request.error_message.as_str())
            || existing.try_get::<Option<bool>, _>("retryable_requested")?
                != Some(request.retryable)
        {
            return Err(ApiError::conflict(
                "idempotency_binding_mismatch",
                "失败报告幂等键已绑定到不同节点或失败内容",
            ));
        }
        tx.commit().await?;
        return Ok(Json(
            serde_json::to_value(JobFailResponse {
                job_id,
                accepted: true,
                idempotent_replay: true,
            })
            .map_err(|_| ApiError::internal())?,
        ));
    }
    let row = sqlx::query(
        r#"
        SELECT j.user_id,j.status,j.leased_to_node_id,j.model_instance_id,
               j.confidentiality_mode,
               j.attempt_count,j.max_attempts,j.reserved_cost_micro,
               (j.lease_expires_at > now()) AS lease_is_valid,
               n.user_id AS node_user_id,
               ja.claim_device_binding_version,ja.claim_device_key_id
        FROM jobs j
        JOIN nodes n ON n.id = j.leased_to_node_id
        JOIN job_attempts ja
          ON ja.job_id=j.id AND ja.attempt_number=j.attempt_count
        WHERE j.id = $1 FOR UPDATE OF j
        "#,
    )
    .bind(job_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    if row.try_get::<Uuid, _>("node_user_id")? != principal.user_id
        || row.try_get::<Uuid, _>("leased_to_node_id")? != request.node_id
        || !exact_claim_device_binding(
            &principal,
            Some(row.try_get("node_user_id")?),
            row.try_get("claim_device_key_id")?,
            row.try_get("claim_device_binding_version")?,
        )
    {
        return Err(ApiError::forbidden("任务租约不属于当前节点"));
    }
    if row.try_get::<String, _>("status")? != "leased" {
        return Err(ApiError::conflict(
            "job_not_leased",
            "任务当前不接受失败报告",
        ));
    }
    if !row.try_get::<bool, _>("lease_is_valid")? {
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    let attempt_count: i32 = row.try_get("attempt_count")?;
    let max_attempts: i32 = row.try_get("max_attempts")?;
    let will_retry = request.retryable && attempt_count < max_attempts;
    sqlx::query(
        r#"
        UPDATE job_attempts SET status = 'failed',finished_at = now(),
            error_class = $3,error_message = $4,result_idempotency_key = $5,
            retryable_requested = $6
        WHERE job_id = $1 AND attempt_number = $2 AND status = 'leased'
        "#,
    )
    .bind(job_id)
    .bind(attempt_count)
    .bind(job_error_class_key(request.error_class))
    .bind(&request.error_message)
    .bind(&request.idempotency_key)
    .bind(request.retryable)
    .execute(&mut *tx)
    .await?;
    if will_retry {
        let backoff_seconds = i64::from(attempt_count).saturating_mul(2).clamp(1, 60);
        let available_at = OffsetDateTime::now_utc()
            .checked_add(time::Duration::seconds(backoff_seconds))
            .ok_or_else(ApiError::internal)?;
        sqlx::query(
            r#"
            UPDATE jobs SET status = 'retry',leased_to_node_id = NULL,
                model_instance_id = CASE
                    WHEN confidentiality_mode = 'regulated' THEN model_instance_id
                    ELSE NULL
                END,
                lease_expires_at = NULL,available_at = $2,
                updated_at = now() WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(available_at)
        .execute(&mut *tx)
        .await?;
    } else {
        let consumer_user_id: Uuid = row.try_get("user_id")?;
        let reserved_cost: i64 = row.try_get("reserved_cost_micro")?;
        let released = sqlx::query(
            r#"
            UPDATE quota_accounts
            SET reserved_micro = reserved_micro - $2,updated_at = now()
            WHERE user_id = $1 AND reserved_micro >= $2
            "#,
        )
        .bind(consumer_user_id)
        .bind(reserved_cost)
        .execute(&mut *tx)
        .await?;
        if released.rows_affected() != 1 {
            return Err(ApiError::internal());
        }
        sqlx::query(
            r#"
            UPDATE jobs SET status = 'failed',completed_at = now(),updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .execute(&mut *tx)
        .await?;
    }
    finalize_draining_instance(
        &mut tx,
        row.try_get::<Option<Uuid>, _>("model_instance_id")?,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        serde_json::to_value(JobFailResponse {
            job_id,
            accepted: true,
            idempotent_replay: false,
        })
        .map_err(|_| ApiError::internal())?,
    ))
}

#[derive(Clone)]
struct SelectedModel {
    id: Uuid,
    weights_hash: String,
}

struct ModelRoutingData {
    base_cost_per_1k_micro: i64,
    weights_hash: String,
    context_length: u32,
    quality: f64,
    intent_match: f64,
}

#[derive(Debug, Clone)]
pub(crate) struct BillingProfileSnapshot {
    pub(crate) contract_version: String,
    pub(crate) profile_id: Uuid,
    pub(crate) profile_version: i64,
    pub(crate) profile_fingerprint: String,
    pub(crate) model_weights_hash: String,
    pub(crate) reference_hardware_class: String,
    pub(crate) evidence_hash: String,
    pub(crate) valid_from: OffsetDateTime,
    pub(crate) valid_until: OffsetDateTime,
    pub(crate) profile: ServerReferenceBillingProfile,
}

#[derive(Debug, Clone)]
pub(crate) struct BillingSnapshot {
    pub(crate) profile: BillingProfileSnapshot,
    pub(crate) authorized_input_tokens: i64,
    pub(crate) authorized_max_output_tokens: i64,
    pub(crate) quote: PhysicalBillingQuote,
    pub(crate) reservation_micro: i64,
}

impl BillingProfileSnapshot {
    fn from_row(row: &PgRow) -> Result<Self, ApiError> {
        let contract_version = row.try_get::<String, _>("billing_contract_version")?;
        if contract_version != SERVER_REFERENCE_UPPER_BOUND_V1 {
            return Err(billing_profile_unavailable());
        }
        Ok(Self {
            contract_version,
            profile_id: row.try_get("billing_profile_id")?,
            profile_version: row.try_get("billing_profile_version")?,
            profile_fingerprint: row.try_get("billing_profile_fingerprint")?,
            model_weights_hash: row.try_get("billing_model_weights_hash")?,
            reference_hardware_class: row.try_get("billing_reference_hardware_class")?,
            evidence_hash: row.try_get("billing_profile_evidence_hash")?,
            valid_from: row.try_get("billing_profile_valid_from")?,
            valid_until: row.try_get("billing_profile_valid_until")?,
            profile: ServerReferenceBillingProfile {
                maximum_input_tokens: row.try_get("billing_profile_max_input_tokens")?,
                maximum_output_tokens: row.try_get("billing_profile_max_output_tokens")?,
                fixed_gpu_time_us: row.try_get("billing_fixed_gpu_time_us")?,
                gpu_time_us_per_1k_tokens: row.try_get("billing_gpu_time_us_per_1k_tokens")?,
                reference_vram_mib: row.try_get("billing_reference_vram_mib")?,
                token_rate_micro_per_1k: row.try_get("billing_token_rate_micro_per_1k")?,
                gpu_rate_micro_per_second: row.try_get("billing_gpu_rate_micro_per_second")?,
                vram_rate_micro_per_gib_second: row
                    .try_get("billing_vram_rate_micro_per_gib_second")?,
            },
        })
    }
}

impl BillingSnapshot {
    fn calculate(
        profile: BillingProfileSnapshot,
        authorized_input_tokens: i64,
        authorized_max_output_tokens: i64,
    ) -> Result<Self, ApiError> {
        let quote = maximum_reservation_quote(
            profile.profile,
            authorized_input_tokens,
            authorized_max_output_tokens,
        )
        .map_err(|error| {
            tracing::error!(error = %error, profile_id = %profile.profile_id, "物理计费 profile 无法生成授权上界报价");
            billing_profile_unavailable()
        })?;
        let reservation_micro = maximum_physical_reservation(
            profile.profile,
            authorized_input_tokens,
            authorized_max_output_tokens,
        )
        .map_err(|error| {
            tracing::error!(error = %error, profile_id = %profile.profile_id, "物理计费 profile 无法生成 High 准备金");
            billing_profile_unavailable()
        })?
        .as_i64();
        Ok(Self {
            profile,
            authorized_input_tokens,
            authorized_max_output_tokens,
            quote,
            reservation_micro,
        })
    }

    pub(crate) fn from_frozen_row(
        row: &PgRow,
        expected_model_weights_hash: &str,
    ) -> Result<Self, ApiError> {
        let contract_version = row.try_get::<Option<String>, _>("billing_contract_version")?;
        if contract_version.as_deref() != Some(SERVER_REFERENCE_UPPER_BOUND_V1) {
            return Err(billing_profile_unavailable());
        }
        let profile = BillingProfileSnapshot::from_row(row)?;
        if profile.model_weights_hash != expected_model_weights_hash {
            return Err(billing_profile_unavailable());
        }
        let authorized_input_tokens = row.try_get("billing_authorized_input_tokens")?;
        let authorized_max_output_tokens = row.try_get("billing_authorized_max_output_tokens")?;
        let snapshot = Self::calculate(
            profile,
            authorized_input_tokens,
            authorized_max_output_tokens,
        )?;
        if snapshot.quote.billable_tokens != row.try_get::<i64, _>("billing_billable_tokens")?
            || snapshot.quote.reference_gpu_time_us
                != row.try_get::<i64, _>("billing_reference_gpu_time_us")?
            || snapshot.quote.reference_vram_mib_microseconds
                != row.try_get::<i64, _>("billing_reference_vram_mib_microseconds")?
            || snapshot.quote.token_cost.as_i64()
                != row.try_get::<i64, _>("billing_token_cost_micro")?
            || snapshot.quote.gpu_cost.as_i64()
                != row.try_get::<i64, _>("billing_gpu_cost_micro")?
            || snapshot.quote.vram_cost.as_i64()
                != row.try_get::<i64, _>("billing_vram_cost_micro")?
            || snapshot.quote.base_cost.as_i64()
                != row.try_get::<i64, _>("billing_base_cost_micro")?
        {
            tracing::error!(profile_id = %snapshot.profile.profile_id, "冻结的物理计费快照与 accounting 报价不一致");
            return Err(billing_profile_unavailable());
        }
        Ok(snapshot)
    }
}

pub(crate) fn billing_profile_unavailable() -> ApiError {
    ApiError::unavailable(
        "billing_profile_unavailable",
        "当前模型没有有效且覆盖本次 Token 授权上界的物理计费 profile",
    )
}

pub(crate) async fn load_billing_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model_id: Uuid,
    model_weights_hash: &str,
    authorized_input_tokens: i32,
    authorized_max_output_tokens: i32,
) -> Result<BillingSnapshot, ApiError> {
    let authorized_input_tokens = i64::from(authorized_input_tokens);
    let authorized_max_output_tokens = i64::from(authorized_max_output_tokens);
    let row = sqlx::query(
        r#"
        SELECT profile.contract_version AS billing_contract_version,
               profile.id AS billing_profile_id,
               profile.profile_version AS billing_profile_version,
               profile.profile_fingerprint AS billing_profile_fingerprint,
               profile.model_weights_hash AS billing_model_weights_hash,
               profile.reference_hardware_class AS billing_reference_hardware_class,
               profile.evidence_hash AS billing_profile_evidence_hash,
               profile.valid_from AS billing_profile_valid_from,
               profile.valid_until AS billing_profile_valid_until,
               profile.maximum_input_tokens AS billing_profile_max_input_tokens,
               profile.maximum_output_tokens AS billing_profile_max_output_tokens,
               profile.fixed_gpu_time_us AS billing_fixed_gpu_time_us,
               profile.gpu_time_us_per_1k_tokens AS billing_gpu_time_us_per_1k_tokens,
               profile.reference_vram_mib AS billing_reference_vram_mib,
               profile.token_rate_micro_per_1k AS billing_token_rate_micro_per_1k,
               profile.gpu_rate_micro_per_second AS billing_gpu_rate_micro_per_second,
               profile.vram_rate_micro_per_gib_second
                   AS billing_vram_rate_micro_per_gib_second
        FROM billing_profiles profile
        WHERE profile.contract_version = $1
          AND profile.model_id = $2
          AND profile.model_weights_hash = $3
          AND profile.valid_from <= now()
          AND profile.valid_until > now()
        ORDER BY profile.profile_version DESC,profile.valid_from DESC,profile.id
        LIMIT 1
        "#,
    )
    .bind(SERVER_REFERENCE_UPPER_BOUND_V1)
    .bind(model_id)
    .bind(model_weights_hash)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(billing_profile_unavailable)?;
    let profile = BillingProfileSnapshot::from_row(&row)?;
    if profile.model_weights_hash != model_weights_hash {
        return Err(billing_profile_unavailable());
    }
    BillingSnapshot::calculate(
        profile,
        authorized_input_tokens,
        authorized_max_output_tokens,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkItemKind {
    Ordinary,
    Hidden,
    Missing,
}

/// UUID 的跨表双命中必须 fail closed；路由不得靠“先查到哪张表”决定处理语义。
async fn work_item_kind(state: &AppState, job_id: Uuid) -> Result<WorkItemKind, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT EXISTS(SELECT 1 FROM jobs WHERE id=$1) AS ordinary,
               EXISTS(SELECT 1 FROM model_evaluation_challenges WHERE id=$1) AS hidden
        "#,
    )
    .bind(job_id)
    .fetch_one(&state.pool)
    .await?;
    match (
        row.try_get::<bool, _>("ordinary")?,
        row.try_get::<bool, _>("hidden")?,
    ) {
        (true, false) => Ok(WorkItemKind::Ordinary),
        (false, true) => Ok(WorkItemKind::Hidden),
        (false, false) => Ok(WorkItemKind::Missing),
        (true, true) => {
            tracing::error!(job_id = %job_id, "普通任务与私有评价发生 UUID 冲突");
            Err(ApiError::internal())
        }
    }
}

fn payload_encoding_from_db(value: &str) -> Result<PayloadEncoding, ApiError> {
    match value {
        "base64" => Ok(PayloadEncoding::Base64),
        "base64url" => Ok(PayloadEncoding::Base64Url),
        "regulated_aead_v1" => Ok(PayloadEncoding::RegulatedAeadV1),
        _ => Err(ApiError::internal()),
    }
}

fn confidentiality_from_db(value: &str) -> Result<ConfidentialityMode, ApiError> {
    match value {
        "standard" => Ok(ConfidentialityMode::Standard),
        "regulated" => Ok(ConfidentialityMode::Regulated),
        _ => Err(ApiError::internal()),
    }
}

fn attestation_provider_from_db(value: &str) -> Result<AttestationProvider, ApiError> {
    match value {
        "amd_sev_snp" => Ok(AttestationProvider::AmdSevSnp),
        "intel_tdx" => Ok(AttestationProvider::IntelTdx),
        _ => Err(ApiError::internal()),
    }
}

async fn select_model(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    virtual_model: &str,
    tags: &[String],
    authorized_input_tokens: i32,
    authorized_max_output_tokens: i32,
) -> Result<SelectedModel, ApiError> {
    let required_context = authorized_input_tokens.saturating_add(authorized_max_output_tokens);
    let rows = sqlx::query(
        r#"
        SELECT m.id,m.weights_hash,m.base_cost_per_1k_micro,m.context_length,
               m.benchmark_normalized,m.glicko_normalized,m.evaluation_samples,
               mi.tags AS instance_tags
        FROM models m
        JOIN model_instances mi ON mi.model_id = m.id AND mi.status = 'published'
        JOIN nodes n ON n.id = mi.node_id
        JOIN node_policies p ON p.node_id = n.id
        JOIN LATERAL (
            SELECT profile.maximum_input_tokens,profile.maximum_output_tokens
            FROM billing_profiles profile
            WHERE profile.contract_version = $4
              AND profile.model_id = m.id
              AND profile.model_weights_hash = m.weights_hash
              AND profile.valid_from <= now()
              AND profile.valid_until > now()
            ORDER BY profile.profile_version DESC,profile.valid_from DESC,profile.id
            LIMIT 1
        ) current_billing_profile
          ON current_billing_profile.maximum_input_tokens >= $5
         AND current_billing_profile.maximum_output_tokens >= $6
        WHERE m.enabled = TRUE
          AND NOT EXISTS (
              SELECT 1 FROM model_instance_canary_state canary_risk
              WHERE canary_risk.model_instance_id=mi.id
                AND canary_risk.quarantined=TRUE
          )
          AND m.context_length >= $3
          AND ($1 = 'auto' OR m.name = $1)
          AND n.status = 'online'
          AND n.last_seen_at > now() - interval '90 seconds'
          AND NOT EXISTS (
              SELECT 1
              FROM unnest($2::text[]) AS requested(tag)
              JOIN unnest(p.reject_tags) AS rejected(tag)
                ON lower(requested.tag) = lower(rejected.tag)
          )
        ORDER BY m.id,mi.id
        "#,
    )
    .bind(virtual_model)
    .bind(tags)
    .bind(required_context)
    .bind(SERVER_REFERENCE_UPPER_BOUND_V1)
    .bind(i64::from(authorized_input_tokens))
    .bind(i64::from(authorized_max_output_tokens))
    .fetch_all(&mut **tx)
    .await?;
    let request_tags = tags
        .iter()
        .map(|tag| tag.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut models = BTreeMap::<Uuid, ModelRoutingData>::new();
    for row in rows {
        let model_id: Uuid = row.try_get("id")?;
        let benchmark = row.try_get::<i32, _>("benchmark_normalized")?;
        let glicko = row.try_get::<i32, _>("glicko_normalized")?;
        let samples = u64::try_from(row.try_get::<i32, _>("evaluation_samples")?)
            .map_err(|_| ApiError::internal())?;
        let quality = fused_quality(
            f64::from(benchmark) / 1_000_000.0,
            f64::from(glicko) / 1_000_000.0,
            samples,
            20,
        )
        .map_err(|error| {
            tracing::error!(error = %error, model_id = %model_id, "模型质量融合失败");
            ApiError::internal()
        })?
        .fused;
        let instance_tags = row
            .try_get::<Vec<String>, _>("instance_tags")?
            .into_iter()
            .map(|tag| tag.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let intent_match = if request_tags.is_empty() {
            1.0
        } else {
            let matches = request_tags.intersection(&instance_tags).count();
            matches as f64 / request_tags.len() as f64
        };
        let context_length = u32::try_from(row.try_get::<i32, _>("context_length")?)
            .map_err(|_| ApiError::internal())?;
        let base_cost_per_1k_micro = row.try_get("base_cost_per_1k_micro")?;
        let weights_hash = row.try_get::<String, _>("weights_hash")?;
        models
            .entry(model_id)
            .and_modify(|model| model.intent_match = model.intent_match.max(intent_match))
            .or_insert(ModelRoutingData {
                base_cost_per_1k_micro,
                weights_hash,
                context_length,
                quality,
                intent_match,
            });
    }
    if models.is_empty() {
        return Err(ApiError::unavailable(
            "no_routable_model",
            "没有满足条件的在线模型",
        ));
    }
    let minimum_cost = models
        .values()
        .map(|model| model.base_cost_per_1k_micro)
        .min()
        .ok_or_else(ApiError::internal)?;
    let maximum_cost = models
        .values()
        .map(|model| model.base_cost_per_1k_micro)
        .max()
        .ok_or_else(ApiError::internal)?;
    let cost_span = maximum_cost.saturating_sub(minimum_cost);
    let candidates = models
        .iter()
        .map(|(id, model)| ModelCandidate {
            id: id.to_string(),
            quality: model.quality,
            intent_match: model.intent_match,
            normalized_cost: if cost_span == 0 {
                0.0
            } else {
                model.base_cost_per_1k_micro.saturating_sub(minimum_cost) as f64 / cost_span as f64
            },
            available: true,
            context_length: model.context_length,
        })
        .collect::<Vec<_>>();
    let minimum_context_length =
        u32::try_from(required_context).map_err(|_| ApiError::internal())?;
    let selected = rank_models(
        &candidates,
        ModelRequirements {
            minimum_context_length,
            ..ModelRequirements::default()
        },
    )
    .map_err(|error| {
        tracing::error!(error = %error, "模型阶段路由失败");
        ApiError::internal()
    })?
    .into_iter()
    .next()
    .ok_or_else(|| ApiError::unavailable("no_routable_model", "没有满足条件的在线模型"))?;
    let model_id = Uuid::parse_str(&selected.id).map_err(|_| ApiError::internal())?;
    let model = models.get(&model_id).ok_or_else(ApiError::internal)?;
    Ok(SelectedModel {
        id: model_id,
        weights_hash: model.weights_hash.clone(),
    })
}

/// 在领取新任务前收口已经耗尽重试次数的过期租约。
///
/// 每个任务、消费者 reservation、attempt 与 draining 模型实例都在同一事务内更新；
/// `FOR UPDATE SKIP LOCKED` 允许多个节点并发领取而不会重复释放额度。
async fn reap_expired_terminal_leases(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), ApiError> {
    let expired = sqlx::query(
        r#"
        SELECT id,user_id,reserved_cost_micro,model_instance_id,attempt_count
        FROM jobs
        WHERE status = 'leased' AND lease_expires_at <= now()
          AND attempt_count >= max_attempts
        ORDER BY user_id,id
        FOR UPDATE SKIP LOCKED
        LIMIT 100
        "#,
    )
    .fetch_all(&mut **tx)
    .await?;
    for job in expired {
        let job_id: Uuid = job.try_get("id")?;
        let user_id: Uuid = job.try_get("user_id")?;
        let reserved_cost_micro: i64 = job.try_get("reserved_cost_micro")?;
        let attempt_count: i32 = job.try_get("attempt_count")?;
        let released = sqlx::query(
            r#"
            UPDATE quota_accounts
            SET reserved_micro = reserved_micro - $2,updated_at = now()
            WHERE user_id = $1 AND reserved_micro >= $2
            "#,
        )
        .bind(user_id)
        .bind(reserved_cost_micro)
        .execute(&mut **tx)
        .await?;
        if released.rows_affected() != 1 {
            return Err(ApiError::internal());
        }
        sqlx::query(
            r#"
            UPDATE job_attempts
            SET status = 'expired',finished_at = now(),
                error_class = 'timeout',
                error_message = '租约过期且已达到最大尝试次数'
            WHERE job_id = $1 AND attempt_number = $2 AND status = 'leased'
            "#,
        )
        .bind(job_id)
        .bind(attempt_count)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE jobs
            SET status = 'failed',completed_at = now(),updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .execute(&mut **tx)
        .await?;
        finalize_draining_instance(tx, job.try_get::<Option<Uuid>, _>("model_instance_id")?)
            .await?;
    }
    sqlx::query(
        r#"
        UPDATE model_instances mi
        SET status = 'unpublished',unpublished_at = now()
        WHERE mi.status = 'draining'
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
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn enforce_current_policy(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node_id: Uuid,
    policy: &sqlx::postgres::PgRow,
    excluded_job_id: Option<Uuid>,
    task_tags: &[String],
) -> Result<(), ApiError> {
    let active: i64 = sqlx::query_scalar(
        r#"
        SELECT (
            SELECT COUNT(*)::bigint FROM jobs
            WHERE leased_to_node_id = $1 AND status = 'leased' AND lease_expires_at > now()
              AND ($2::uuid IS NULL OR id <> $2)
        ) + (
            SELECT COUNT(*)::bigint FROM model_evaluation_challenges
            WHERE node_id = $1 AND status = 'leased' AND lease_expires_at > now()
              AND ($2::uuid IS NULL OR id <> $2)
        )
        "#,
    )
    .bind(node_id)
    .bind(excluded_job_id)
    .fetch_one(&mut **tx)
    .await?;
    let metrics = sqlx::query(
        r#"
        SELECT gpu_temp_c,vram_used_mib,vram_total_mib
        FROM node_metrics WHERE node_id = $1 ORDER BY measured_at DESC LIMIT 1
        "#,
    )
    .bind(node_id)
    .fetch_optional(&mut **tx)
    .await?;
    let (gpu_temp_c, available_vram_mib) = if let Some(metrics) = metrics {
        let gpu_temp = metrics
            .try_get::<Option<i32>, _>("gpu_temp_c")?
            .map(f64::from);
        let used: Option<i64> = metrics.try_get("vram_used_mib")?;
        let total: Option<i64> = metrics.try_get("vram_total_mib")?;
        let available = match (used, total) {
            (Some(used), Some(total)) => u64::try_from(total.saturating_sub(used)).ok(),
            _ => None,
        };
        (gpu_temp, available)
    } else {
        (None, None)
    };
    let reject_tags = policy
        .try_get::<Vec<String>, _>("reject_tags")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let accounting_policy = NodePolicy {
        reject_tags,
        max_concurrent: u32::try_from(policy.try_get::<i32, _>("max_concurrent")?)
            .map_err(|_| ApiError::internal())?,
        gpu_temp_limit_c: policy
            .try_get::<Option<i32>, _>("gpu_temp_limit_c")?
            .map(u16::try_from)
            .transpose()
            .map_err(|_| ApiError::internal())?,
        vram_reserve_mib: u64::try_from(policy.try_get::<i64, _>("vram_reserve_mib")?)
            .map_err(|_| ApiError::internal())?,
        resume_temp_hysteresis_c: 5,
    };
    let runtime = NodeRuntime {
        task_tags: task_tags.iter().cloned().collect(),
        current_concurrent: u32::try_from(active).map_err(|_| ApiError::internal())?,
        gpu_temp_c,
        available_vram_mib,
        paused_for_temperature: false,
    };
    match evaluate_policy(&accounting_policy, &runtime).map_err(|error| {
        tracing::error!(error = %error, node_id = %node_id, "节点策略计算失败");
        ApiError::internal()
    })? {
        PolicyDecision::Accept { .. } => Ok(()),
        PolicyDecision::PauseTemperature { .. } => {
            Err(ApiError::policy_rejected("GPU 温度达到节点阈值"))
        }
        PolicyDecision::Reject { reason } => Err(ApiError::policy_rejected(format!(
            "节点策略拒绝：{reason:?}"
        ))),
    }
}

async fn verify_node_owner(
    state: &AppState,
    node_id: Uuid,
    principal: &Principal,
) -> Result<(), ApiError> {
    let node = sqlx::query("SELECT user_id,device_key_id FROM nodes WHERE id = $1")
        .bind(node_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("节点"))?;
    require_node_device_binding(
        principal,
        node.try_get("user_id")?,
        node.try_get("device_key_id")?,
    )
}

fn decode_stored_standard_payload(
    state: &AppState,
    job_id: Uuid,
    row: &PgRow,
) -> Result<SensitiveStandardJobPayload, ApiError> {
    if row.try_get::<Option<i16>, _>("standard_payload_storage_version")? != Some(STORAGE_VERSION) {
        return Err(ApiError::internal());
    }
    let stored: String = row.try_get("encrypted_payload")?;
    let wire = decrypt_from_storage(
        &state.config.standard_data_key,
        job_id,
        StorageDirection::Payload,
        &stored,
    )
    .map_err(|error| {
        tracing::error!(
            error = %error,
            job_id = %job_id,
            field = "payload",
            "Standard 数据静态保护校验失败"
        );
        ApiError::internal()
    })?;
    let wire = std::str::from_utf8(&wire).map_err(|_| ApiError::internal())?;
    let encoding = payload_encoding_from_db(&row.try_get::<String, _>("payload_encoding")?)?;
    let decoded = decode_standard_payload(encoding, wire)?;
    serde_json::from_slice(&decoded)
        .map(SensitiveStandardJobPayload)
        .map_err(|_| {
            ApiError::bad_request(
                "invalid_standard_payload",
                "任务载荷不符合 Standard 推理协议",
            )
        })
}

fn validate_stream_event_replay(
    state: &AppState,
    job_id: Uuid,
    request: &JobStreamEventRequest,
    existing: &PgRow,
) -> Result<(), ApiError> {
    let expected_kind = match request.kind {
        JobStreamEventKind::Data => "data",
        JobStreamEventKind::UpstreamDone => "upstream_done",
    };
    if existing.try_get::<i32, _>("attempt_number")? != request.attempt
        || existing.try_get::<i32, _>("sequence_number")? != request.sequence
        || existing.try_get::<String, _>("idempotency_key")? != request.idempotency_key
        || existing.try_get::<String, _>("event_kind")? != expected_kind
    {
        return Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "流式事件 sequence 或幂等键已绑定到不同事件",
        ));
    }
    match request.kind {
        JobStreamEventKind::Data => {
            if existing.try_get::<Option<i16>, _>("standard_event_storage_version")?
                != Some(STORAGE_VERSION)
            {
                return Err(ApiError::internal());
            }
            let ciphertext: Option<String> = existing.try_get("event_ciphertext")?;
            let plaintext = decrypt_from_storage(
                &state.config.standard_data_key,
                job_id,
                StorageDirection::StreamEvent {
                    attempt_number: request.attempt,
                    sequence_number: request.sequence,
                },
                ciphertext.as_deref().ok_or_else(ApiError::internal)?,
            )
            .map_err(|error| {
                tracing::error!(
                    error = %error,
                    job_id = %job_id,
                    attempt = request.attempt,
                    sequence = request.sequence,
                    "Standard SSE 重放校验无法解密已存事件"
                );
                ApiError::internal()
            })?;
            let supplied = request
                .event_data
                .as_deref()
                .ok_or_else(ApiError::internal)?;
            let same_length = plaintext.len() == supplied.len();
            let same_bytes =
                same_length && plaintext.as_slice().ct_eq(supplied.as_bytes()).unwrap_u8() == 1;
            if !same_bytes
                || existing.try_get::<i32, _>("plaintext_bytes")?
                    != i32::try_from(supplied.len()).map_err(|_| ApiError::internal())?
            {
                return Err(ApiError::conflict(
                    "idempotency_binding_mismatch",
                    "流式事件幂等键已绑定到不同正文",
                ));
            }
        }
        JobStreamEventKind::UpstreamDone => {
            if existing
                .try_get::<Option<String>, _>("event_ciphertext")?
                .is_some()
                || existing
                    .try_get::<Option<i16>, _>("standard_event_storage_version")?
                    .is_some()
                || existing.try_get::<i32, _>("plaintext_bytes")? != 0
            {
                return Err(ApiError::internal());
            }
        }
    }
    Ok(())
}

fn validate_standard_stream_data(
    payload: &StandardJobPayload,
    authorized_model: &str,
    data: &str,
) -> Result<(), ApiError> {
    let value =
        SensitiveStreamData(serde_json::from_str(data).map_err(|_| {
            ApiError::bad_request("invalid_stream_event", "SSE data 不是合法 JSON")
        })?);
    let object = value.as_object().ok_or_else(|| {
        ApiError::bad_request("invalid_stream_event", "SSE data 必须是 JSON 对象")
    })?;
    let expected_object = match payload.endpoint.as_str() {
        mindone_protocol::OPENAI_CHAT_COMPLETIONS => "chat.completion.chunk",
        mindone_protocol::OPENAI_COMPLETIONS => "text_completion",
        _ => return Err(ApiError::internal()),
    };
    if object.get("object").and_then(serde_json::Value::as_str) != Some(expected_object)
        || object.get("model").and_then(serde_json::Value::as_str) != Some(authorized_model)
        || object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .is_none()
        || object
            .get("created")
            .and_then(serde_json::Value::as_i64)
            .is_none()
    {
        return Err(ApiError::bad_request(
            "invalid_stream_event",
            "SSE 元数据与任务端点或授权模型不一致",
        ));
    }
    let expected_choices = payload
        .request
        .get("n")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let choices = object
        .get("choices")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| ApiError::bad_request("invalid_stream_event", "SSE data 缺少 choices"))?;
    if choices.len() > usize::try_from(expected_choices).map_err(|_| ApiError::internal())? {
        return Err(ApiError::bad_request(
            "invalid_stream_event",
            "SSE choices 超过任务授权数量",
        ));
    }
    for choice in choices {
        let choice = choice.as_object().ok_or_else(|| {
            ApiError::bad_request("invalid_stream_event", "SSE choice 必须是对象")
        })?;
        let index = choice
            .get("index")
            .and_then(serde_json::Value::as_u64)
            .filter(|index| *index < expected_choices)
            .ok_or_else(|| {
                ApiError::bad_request("invalid_stream_event", "SSE choice index 超出授权范围")
            })?;
        let _ = index;
        if !choice
            .get("finish_reason")
            .is_none_or(|reason| reason.is_null() || reason.is_string())
        {
            return Err(ApiError::bad_request(
                "invalid_stream_event",
                "SSE finish_reason 类型无效",
            ));
        }
        match payload.endpoint.as_str() {
            mindone_protocol::OPENAI_CHAT_COMPLETIONS => {
                let delta = choice
                    .get("delta")
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        ApiError::bad_request("invalid_stream_event", "聊天 SSE 缺少 delta")
                    })?;
                for field in ["content", "reasoning_content", "role"] {
                    if !delta
                        .get(field)
                        .is_none_or(|value| value.is_null() || value.is_string())
                    {
                        return Err(ApiError::bad_request(
                            "invalid_stream_event",
                            "聊天 SSE delta 字段类型无效",
                        ));
                    }
                }
            }
            mindone_protocol::OPENAI_COMPLETIONS => {
                if !choice.get("text").is_some_and(serde_json::Value::is_string) {
                    return Err(ApiError::bad_request(
                        "invalid_stream_event",
                        "补全 SSE choice 缺少 text",
                    ));
                }
            }
            _ => return Err(ApiError::internal()),
        }
    }
    if let Some(usage) = object.get("usage") {
        let usage = usage
            .as_object()
            .ok_or_else(|| ApiError::bad_request("invalid_stream_event", "SSE usage 必须是对象"))?;
        let prompt = usage
            .get("prompt_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ApiError::bad_request("invalid_stream_event", "SSE usage 缺少 prompt_tokens")
            })?;
        let completion = usage
            .get("completion_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ApiError::bad_request("invalid_stream_event", "SSE usage 缺少 completion_tokens")
            })?;
        let total = usage
            .get("total_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ApiError::bad_request("invalid_stream_event", "SSE usage 缺少 total_tokens")
            })?;
        if prompt.checked_add(completion) != Some(total) {
            return Err(ApiError::bad_request(
                "invalid_stream_event",
                "SSE usage Token 总数不一致",
            ));
        }
    }
    Ok(())
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

async fn validate_job_result(
    state: &AppState,
    job_id: Uuid,
    request: &JobResultRequest,
) -> Result<(), ApiError> {
    let row = sqlx::query(
        r#"
        SELECT j.confidentiality_mode,j.regulated_route_id,j.attestation_report_id,
               j.model_instance_id,j.encrypted_payload,j.payload_encoding,
               j.standard_payload_storage_version,j.attempt_count,j.max_attempts,
               ar.ephemeral_public_key
        FROM jobs j
        LEFT JOIN attestation_reports ar ON ar.id = j.attestation_report_id
        WHERE j.id = $1
        "#,
    )
    .bind(job_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    let confidentiality = row.try_get::<String, _>("confidentiality_mode")?;
    if confidentiality == "standard" {
        let stream =
            validate_standard_result(&row, request, job_id, &state.config.standard_data_key)?;
        if stream {
            if row.try_get::<i32, _>("max_attempts")? != 1 {
                return Err(ApiError::internal());
            }
            let attempt: i32 = row.try_get("attempt_count")?;
            let transcript = sqlx::query(
                r#"
                SELECT COUNT(*)::bigint AS event_count,
                       COALESCE(MIN(sequence_number),-1) AS first_sequence,
                       COALESCE(MAX(sequence_number),-1) AS last_sequence,
                       COUNT(*) FILTER (WHERE event_kind='upstream_done')::bigint AS done_count,
                       COALESCE(MAX(sequence_number) FILTER (
                           WHERE event_kind='upstream_done'
                       ),-1) AS done_sequence
                FROM job_stream_events
                WHERE job_id=$1 AND attempt_number=$2
                "#,
            )
            .bind(job_id)
            .bind(attempt)
            .fetch_one(&state.pool)
            .await?;
            let event_count: i64 = transcript.try_get("event_count")?;
            if event_count < 2
                || transcript.try_get::<i32, _>("first_sequence")? != 0
                || i64::from(transcript.try_get::<i32, _>("last_sequence")?) != event_count - 1
                || transcript.try_get::<i64, _>("done_count")? != 1
                || transcript.try_get::<i32, _>("done_sequence")?
                    != transcript.try_get::<i32, _>("last_sequence")?
            {
                return Err(ApiError::conflict(
                    "stream_incomplete",
                    "SSE 结果只有在连续事件和 upstream_done 已持久确认后才能结算",
                ));
            }
        }
        return Ok(());
    }
    if confidentiality == "regulated" {
        // Regulated 的 envelope 与当前硬件信任状态必须和结算共享同一事务快照；
        // `complete_job` 在持有任务行锁后完成严格绑定检查。
        return Ok(());
    }
    Err(ApiError::internal())
}

fn validate_standard_result(
    job: &sqlx::postgres::PgRow,
    request: &JobResultRequest,
    job_id: Uuid,
    standard_data_key: &[u8; 32],
) -> Result<bool, ApiError> {
    let payload_encoding: String = job.try_get("payload_encoding")?;
    let encoding = match payload_encoding.as_str() {
        "base64" => PayloadEncoding::Base64,
        "base64url" => PayloadEncoding::Base64Url,
        _ => return Err(ApiError::internal()),
    };
    if job.try_get::<Option<i16>, _>("standard_payload_storage_version")? != Some(STORAGE_VERSION) {
        return Err(ApiError::internal());
    }
    let stored_payload: String = job.try_get("encrypted_payload")?;
    let wire_payload = decrypt_from_storage(
        standard_data_key,
        job_id,
        StorageDirection::Payload,
        &stored_payload,
    )
    .map_err(|error| {
        tracing::error!(error = %error, job_id = %job_id, field = "payload", "Standard 数据静态保护校验失败");
        ApiError::internal()
    })?;
    let wire_payload = std::str::from_utf8(&wire_payload).map_err(|_| ApiError::internal())?;
    let payload_bytes = decode_standard_payload(encoding, wire_payload)?;
    let payload =
        SensitiveStandardJobPayload(serde_json::from_slice(&payload_bytes).map_err(|_| {
            ApiError::bad_request(
                "invalid_standard_payload",
                "任务载荷不符合 Standard 推理协议",
            )
        })?);
    let limits = payload
        .validated_limits()
        .map_err(|error| ApiError::bad_request("invalid_standard_payload", error.to_string()))?;

    // Standard worker/consumer 的公开传输契约固定使用 RFC 4648 Base64。
    let result_bytes = Zeroizing::new(
        BASE64_STANDARD
            .decode(&request.result_ciphertext)
            .map_err(|_| ApiError::bad_request("invalid_job_result", "任务结果 Base64 无效"))?,
    );
    if result_bytes.len() > 900_000 {
        return Err(ApiError::bad_request(
            "invalid_job_result",
            "任务结果超过允许大小",
        ));
    }
    match payload.endpoint.as_str() {
        mindone_protocol::OPENAI_CHAT_COMPLETIONS => {
            let response =
                SensitiveChatResponse(serde_json::from_slice(&result_bytes).map_err(|_| {
                    ApiError::bad_request(
                        "invalid_job_result",
                        "聊天任务结果不符合 OpenAI 响应协议",
                    )
                })?);
            if response.choices.is_empty() {
                return Err(ApiError::bad_request(
                    "invalid_job_result",
                    "聊天任务结果缺少 choices",
                ));
            }
            if response.model != limits.model {
                return Err(ApiError::bad_request(
                    "model_binding_mismatch",
                    "聊天任务结果模型与任务载荷不一致",
                ));
            }
            if !matches!(
                &response.choices[0].message.content,
                MessageContent::Text(value) if !value.trim().is_empty()
            ) {
                return Err(ApiError::bad_request(
                    "invalid_job_result",
                    "聊天任务结果必须包含非空文本",
                ));
            }
            validate_reported_usage(response.usage, request)?;
        }
        mindone_protocol::OPENAI_COMPLETIONS => {
            let response = SensitiveCompletionsResponse(
                serde_json::from_slice(&result_bytes).map_err(|_| {
                    ApiError::bad_request(
                        "invalid_job_result",
                        "补全任务结果不符合 OpenAI 响应协议",
                    )
                })?,
            );
            if response.choices.is_empty() {
                return Err(ApiError::bad_request(
                    "invalid_job_result",
                    "补全任务结果缺少 choices",
                ));
            }
            if response.model != limits.model {
                return Err(ApiError::bad_request(
                    "model_binding_mismatch",
                    "补全任务结果模型与任务载荷不一致",
                ));
            }
            validate_reported_usage(response.usage, request)?;
        }
        _ => return Err(ApiError::internal()),
    }
    Ok(limits.stream)
}

fn validate_reported_usage(
    usage: mindone_protocol::Usage,
    request: &JobResultRequest,
) -> Result<(), ApiError> {
    let expected_total = usage
        .prompt_tokens
        .checked_add(usage.completion_tokens)
        .ok_or_else(|| ApiError::bad_request("invalid_job_result", "usage Token 总数溢出"))?;
    let prompt_tokens = i32::try_from(usage.prompt_tokens)
        .map_err(|_| ApiError::bad_request("invalid_job_result", "prompt_tokens 超出范围"))?;
    let completion_tokens = i32::try_from(usage.completion_tokens)
        .map_err(|_| ApiError::bad_request("invalid_job_result", "completion_tokens 超出范围"))?;
    if usage.total_tokens != expected_total
        || request.actual_input_tokens != prompt_tokens
        || request.actual_output_tokens != completion_tokens
    {
        return Err(ApiError::bad_request(
            "usage_binding_mismatch",
            "结果 usage 与节点上报的实际 Token 不一致",
        ));
    }
    Ok(())
}

/// prepared route 消费后若报告或绑定节点失效，任务不能降级到 Standard 或迁移到
/// 另一节点。这里在同一事务释放 reservation 并生成可审计的 attestation 失败 attempt。
async fn reap_invalid_regulated_jobs(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), ApiError> {
    let invalid = sqlx::query(
        r#"
        SELECT j.id,j.user_id,j.reserved_cost_micro,j.model_instance_id,
               j.regulated_node_id,j.attempt_count
        FROM jobs j
        JOIN nodes n ON n.id = j.regulated_node_id
        JOIN model_instances mi ON mi.id = j.model_instance_id
        JOIN attestation_reports ar ON ar.id = j.attestation_report_id
        WHERE j.confidentiality_mode = 'regulated'
          AND j.status IN ('queued','retry')
          AND (
              n.status <> 'online'
              OR n.last_seen_at <= now() - interval '90 seconds'
              OR n.attestation_report_id IS DISTINCT FROM j.attestation_report_id
              OR n.trust_expires_at <= now()
              OR mi.status <> 'published'
              OR mi.node_id <> j.regulated_node_id
              OR ar.status <> 'verified'
              OR ar.key_origin <> 'tee_runtime'
              OR ar.expires_at <= now()
              OR ar.collateral_expires_at <= now()
          )
        ORDER BY j.user_id,j.id
        FOR UPDATE OF j SKIP LOCKED
        LIMIT 100
        "#,
    )
    .fetch_all(&mut **tx)
    .await?;
    for row in invalid {
        let job_id: Uuid = row.try_get("id")?;
        let user_id: Uuid = row.try_get("user_id")?;
        let reserved_cost_micro: i64 = row.try_get("reserved_cost_micro")?;
        let node_id: Uuid = row
            .try_get::<Option<Uuid>, _>("regulated_node_id")?
            .ok_or_else(ApiError::internal)?;
        let attempt_number = row.try_get::<i32, _>("attempt_count")?.saturating_add(1);
        let released = sqlx::query(
            r#"
            UPDATE quota_accounts
            SET reserved_micro = reserved_micro - $2,updated_at = now()
            WHERE user_id = $1 AND reserved_micro >= $2
            "#,
        )
        .bind(user_id)
        .bind(reserved_cost_micro)
        .execute(&mut **tx)
        .await?;
        if released.rows_affected() != 1 {
            return Err(ApiError::internal());
        }
        sqlx::query(
            r#"
            INSERT INTO job_attempts
                (id,job_id,node_id,attempt_number,status,lease_started_at,
                 lease_expires_at,finished_at,error_class,error_message)
            VALUES ($1,$2,$3,$4,'failed',now(),now(),now(),'attestation',
                    'Regulated route 的硬件报告或固定节点绑定已失效')
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(node_id)
        .bind(attempt_number)
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            r#"
            UPDATE jobs
            SET status = 'failed',attempt_count = $2,completed_at = now(),updated_at = now()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(attempt_number)
        .execute(&mut **tx)
        .await?;
        finalize_draining_instance(tx, row.try_get::<Option<Uuid>, _>("model_instance_id")?)
            .await?;
    }
    Ok(())
}

struct ValidatedStandardJob {
    request_fingerprint: String,
    stream: bool,
}

fn validate_create_job(
    request: &CreateJobRequest,
    standard_data_key: &[u8; 32],
) -> Result<ValidatedStandardJob, ApiError> {
    request
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_job", error.to_string()))?;
    if request.payload_encoding == PayloadEncoding::RegulatedAeadV1 {
        return Err(ApiError::bad_request(
            "invalid_job",
            "Regulated envelope 必须使用独立的两阶段接口",
        ));
    }
    let decoded = decode_standard_payload(request.payload_encoding, &request.encrypted_payload)?;
    let payload = SensitiveStandardJobPayload(serde_json::from_slice(&decoded).map_err(|_| {
        ApiError::bad_request(
            "invalid_standard_payload",
            "任务载荷不符合 Standard 推理协议",
        )
    })?);
    let limits = payload
        .validated_limits()
        .map_err(|error| ApiError::bad_request("invalid_standard_payload", error.to_string()))?;
    if limits.model != request.virtual_model {
        return Err(ApiError::bad_request(
            "model_binding_mismatch",
            "任务路由模型与推理载荷模型不一致",
        ));
    }
    if request.estimated_input_tokens < limits.minimum_input_tokens
        || request.max_output_tokens < limits.maximum_output_tokens
    {
        return Err(ApiError::bad_request(
            "usage_authorization_too_small",
            "任务 Token 授权小于载荷声明所需的安全上限",
        ));
    }
    let encoded = Zeroizing::new(serde_json::to_vec(request).map_err(|_| ApiError::internal())?);
    let fingerprint = request_fingerprint(standard_data_key, &encoded).map_err(|error| {
        tracing::error!(error = %error, field = "request_fingerprint", "Standard 数据静态保护失败");
        ApiError::internal()
    })?;
    Ok(ValidatedStandardJob {
        request_fingerprint: fingerprint,
        stream: limits.stream,
    })
}

fn decode_standard_payload(
    encoding: PayloadEncoding,
    encoded: &str,
) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    let decoded = match encoding {
        PayloadEncoding::Base64 => BASE64_STANDARD.decode(encoded),
        PayloadEncoding::Base64Url => URL_SAFE_NO_PAD.decode(encoded),
        PayloadEncoding::RegulatedAeadV1 => {
            return Err(ApiError::bad_request(
                "invalid_job",
                "Standard 接口不接受 Regulated envelope",
            ))
        }
    }
    .map_err(|_| ApiError::bad_request("invalid_standard_payload", "任务载荷 Base64 无效"))?;
    if decoded.is_empty() || decoded.len() > 900_000 {
        return Err(ApiError::bad_request(
            "invalid_standard_payload",
            "任务载荷解码后为空或超过大小上限",
        ));
    }
    Ok(Zeroizing::new(decoded))
}

fn existing_standard_response(
    existing: sqlx::postgres::PgRow,
    request_fingerprint: &str,
    idempotent_replay: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    if existing
        .try_get::<Option<String>, _>("standard_request_fingerprint")?
        .as_deref()
        != Some(request_fingerprint)
    {
        return Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "Standard 创建幂等键已绑定到不同请求内容",
        ));
    }
    Ok(Json(serde_json::json!({
        "job_id": existing.try_get::<Uuid, _>("id")?,
        "status": existing.try_get::<String, _>("status")?,
        "model_id": existing.try_get::<Uuid, _>("model_id")?,
        "reserved_cost_micro": existing.try_get::<i64, _>("reserved_cost_micro")?,
        "speed_class": existing.try_get::<String, _>("speed_class")?,
        "idempotent_replay": idempotent_replay
    })))
}

pub(super) async fn assess_job_creation(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &Principal,
    connection: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    idempotency_key: &str,
) -> Result<(), ApiError> {
    let peer = connection.map(|ConnectInfo(peer)| peer);
    let network = TrustedNetworkSignal::from_connection(
        peer,
        headers,
        &state.config.token_pepper,
        state.asn_resolver.as_ref(),
        &state.config.trusted_proxy_ips,
    )
    .map_err(map_anti_abuse_error)?;
    let assessment_key =
        job_assessment_key(principal.user_id, idempotency_key).map_err(map_anti_abuse_error)?;
    let decision = assess_before_create_in_transaction(
        tx,
        &state.config.token_pepper,
        principal.user_id,
        principal.session_id,
        &assessment_key,
        network.as_ref(),
        state.config.environment == RuntimeEnvironment::Production,
    )
    .await
    .map_err(map_anti_abuse_error)?;
    if !decision.allowed() {
        return Err(ApiError::anti_abuse_blocked());
    }
    Ok(())
}

fn map_anti_abuse_error(error: AntiAbuseError) -> ApiError {
    match error {
        AntiAbuseError::IdempotencyConflict => ApiError::conflict(
            "idempotency_binding_mismatch",
            "任务幂等键的网络完整性绑定不一致",
        ),
        AntiAbuseError::MissingDeviceBinding => ApiError::anti_abuse_blocked(),
        AntiAbuseError::Database(error) => {
            tracing::error!(error = %error, "反滥用数据库操作失败");
            ApiError::internal()
        }
        AntiAbuseError::InvalidInput(message) => {
            tracing::error!(error = %message, "反滥用内部输入无效");
            ApiError::internal()
        }
    }
}

const fn job_error_class_key(error_class: JobErrorClass) -> &'static str {
    match error_class {
        JobErrorClass::Engine => "engine",
        JobErrorClass::Model => "model",
        JobErrorClass::Policy => "policy",
        JobErrorClass::Timeout => "timeout",
        JobErrorClass::ResourceExhausted => "resource_exhausted",
        JobErrorClass::NodeDisconnected => "node_disconnected",
        JobErrorClass::InvalidRequest => "invalid_request",
        JobErrorClass::Internal => "internal",
        JobErrorClass::Attestation => "attestation",
    }
}

fn stable_job_error_class(value: Option<&str>) -> Option<JobErrorClass> {
    value.map(|value| match value {
        "engine" => JobErrorClass::Engine,
        "model" => JobErrorClass::Model,
        "policy" => JobErrorClass::Policy,
        "timeout" | "lease_expired" => JobErrorClass::Timeout,
        "resource_exhausted" => JobErrorClass::ResourceExhausted,
        "node_disconnected" => JobErrorClass::NodeDisconnected,
        "invalid_request" => JobErrorClass::InvalidRequest,
        "internal" => JobErrorClass::Internal,
        "attestation" => JobErrorClass::Attestation,
        unknown => {
            tracing::warn!(
                error_class = unknown,
                "数据库中存在未知任务失败分类，按 internal 返回"
            );
            JobErrorClass::Internal
        }
    })
}

fn expiry(duration: std::time::Duration) -> Result<OffsetDateTime, ApiError> {
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| ApiError::internal())?;
    OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(seconds))
        .ok_or_else(ApiError::internal)
}

#[cfg(test)]
mod sensitive_response_tests {
    use super::*;

    #[test]
    fn claim_response_zeroizes_owned_payload_and_tee_key() {
        let mut response = SensitiveClaimJobResponse(ClaimJobResponse {
            job_id: Uuid::from_u128(1),
            model_instance_id: Uuid::from_u128(2),
            model: "model".to_owned(),
            model_weights_hash: "11".repeat(32),
            encrypted_payload: "private-prompt-payload".to_owned(),
            payload_encoding: PayloadEncoding::Base64,
            tags: Vec::new(),
            estimated_input_tokens: 1,
            max_output_tokens: 1,
            attempt: 1,
            lease_expires_at: OffsetDateTime::UNIX_EPOCH,
            policy_check_required_before_execution: true,
            confidentiality: ConfidentialityMode::Regulated,
            regulated_route_id: Some(Uuid::from_u128(3)),
            attestation_report_id: Some(Uuid::from_u128(4)),
            attestation_provider: Some(AttestationProvider::AmdSevSnp),
            tee_public_key: Some("private-ephemeral-key".to_owned()),
        });

        response.zeroize_owned();

        assert!(response.0.encrypted_payload.is_empty());
        assert_eq!(response.0.tee_public_key.as_deref(), Some(""));
    }
}
