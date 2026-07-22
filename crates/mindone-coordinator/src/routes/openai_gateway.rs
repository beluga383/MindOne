use std::{
    collections::VecDeque,
    convert::Infallible,
    net::SocketAddr,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::rejection::ExtensionRejection,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use futures_util::stream;
use mindone_protocol::{
    conservative_input_token_authorization, CreateJobRequest, JobStatus, JobStreamEvent,
    PayloadEncoding, StandardJobPayload, OPENAI_CHAT_COMPLETIONS, OPENAI_COMPLETIONS,
};
use sqlx::Row;
use tokio::time::{sleep, timeout};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::Principal,
    db::authenticate_inference,
    error::ApiError,
    settlement::finalize_draining_instance,
    standard_data::{decrypt_from_storage, StorageDirection, STORAGE_VERSION},
    AppState,
};

use super::jobs::{create_job_authenticated, read_job_stream_authenticated};

const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(200);
const STREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

enum GatewayOutput {
    Json(serde_json::Value),
    Stream(Box<GatewayStreamState>),
}

struct GatewayStreamState {
    state: AppState,
    principal: Principal,
    job_id: Uuid,
    next_sequence: i32,
    pending: VecDeque<JobStreamEvent>,
    terminal: Option<GatewayStreamTerminal>,
    finished: bool,
    deadline: Instant,
    last_output: Instant,
}

enum GatewayStreamTerminal {
    Done,
    Error(String),
}

pub async fn chat_completions(
    State(state): State<AppState>,
    connection: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    headers: HeaderMap,
    Json(request): Json<serde_json::Value>,
) -> Response {
    gateway_response(
        run_gateway(
            &state,
            connection.ok(),
            &headers,
            OPENAI_CHAT_COMPLETIONS,
            request,
        )
        .await,
    )
}

pub async fn completions(
    State(state): State<AppState>,
    connection: Result<ConnectInfo<SocketAddr>, ExtensionRejection>,
    headers: HeaderMap,
    Json(request): Json<serde_json::Value>,
) -> Response {
    gateway_response(
        run_gateway(
            &state,
            connection.ok(),
            &headers,
            OPENAI_COMPLETIONS,
            request,
        )
        .await,
    )
}

async fn run_gateway(
    state: &AppState,
    connection: Option<ConnectInfo<SocketAddr>>,
    headers: &HeaderMap,
    endpoint: &str,
    request: serde_json::Value,
) -> Result<GatewayOutput, ApiError> {
    let principal = authenticate_inference(&state.pool, &state.tokens, headers).await?;
    let mut payload = StandardJobPayload {
        endpoint: endpoint.to_owned(),
        request,
    };
    let limits = payload
        .validated_limits()
        .map_err(|error| ApiError::bad_request("invalid_request_error", error.to_string()))?;
    let streaming = limits.stream;
    let estimated_input_tokens = conservative_input_token_authorization(&payload.request)
        .map_err(|error| ApiError::bad_request("invalid_request_error", error.to_string()))?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(&payload)
            .map_err(|_| ApiError::bad_request("invalid_request_error", "请求 JSON 无法编码"))?,
    );
    let mut create_request = CreateJobRequest {
        virtual_model: limits.model,
        encrypted_payload: BASE64_STANDARD.encode(encoded.as_slice()),
        payload_encoding: PayloadEncoding::Base64,
        tags: Vec::new(),
        estimated_input_tokens,
        max_output_tokens: limits.maximum_output_tokens,
        idempotency_key: format!("openai-{}", Uuid::new_v4()),
        priority: 0,
    };
    zeroize_json_value(&mut payload.request);
    let created_result =
        create_job_authenticated(state, connection, headers, &create_request, &principal).await;
    create_request.encrypted_payload.zeroize();
    let created = created_result?;
    let job_id = created
        .0
        .get("job_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(ApiError::internal)?;
    let wait_budget = state
        .config
        .request_timeout
        .saturating_sub(Duration::from_secs(5))
        .max(Duration::from_secs(1));
    if streaming {
        let now = Instant::now();
        return Ok(GatewayOutput::Stream(Box::new(GatewayStreamState {
            state: state.clone(),
            principal,
            job_id,
            next_sequence: 0,
            pending: VecDeque::new(),
            terminal: None,
            finished: false,
            deadline: now + wait_budget,
            last_output: now,
        })));
    }
    match timeout(wait_budget, wait_for_result(state, &principal, job_id)).await {
        Ok(result) => result.map(GatewayOutput::Json),
        Err(_) => {
            cancel_timed_out_job(state, &principal, job_id).await?;
            Err(ApiError::gateway_timeout(
                "推理在网关等待上限内未完成，任务已取消且预留额度已释放",
            ))
        }
    }
}

async fn wait_for_result(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
) -> Result<serde_json::Value, ApiError> {
    loop {
        let row = sqlx::query(
            r#"
            SELECT status,result_ciphertext,standard_result_storage_version
            FROM jobs WHERE id=$1 AND user_id=$2
            "#,
        )
        .bind(job_id)
        .bind(principal.user_id)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| ApiError::not_found("任务"))?;
        match row.try_get::<String, _>("status")?.as_str() {
            "succeeded" => {
                if row.try_get::<Option<i16>, _>("standard_result_storage_version")?
                    != Some(STORAGE_VERSION)
                {
                    return Err(ApiError::internal());
                }
                let stored: String = row
                    .try_get::<Option<String>, _>("result_ciphertext")?
                    .ok_or_else(ApiError::internal)?;
                let plaintext = decrypt_from_storage(
                    &state.config.standard_data_key,
                    job_id,
                    StorageDirection::Result,
                    &stored,
                )
                .map_err(|_| ApiError::internal())?;
                let decoded = Zeroizing::new(
                    BASE64_STANDARD
                        .decode(plaintext.as_slice())
                        .map_err(|_| ApiError::internal())?,
                );
                return serde_json::from_slice(decoded.as_slice())
                    .map_err(|_| ApiError::internal());
            }
            "failed" | "cancelled" => {
                let error_message: Option<String> = sqlx::query_scalar(
                    r#"
                    SELECT error_message FROM job_attempts
                    WHERE job_id=$1 ORDER BY attempt_number DESC LIMIT 1
                    "#,
                )
                .bind(job_id)
                .fetch_optional(&state.pool)
                .await?
                .flatten();
                return Err(ApiError::unavailable(
                    "inference_failed",
                    error_message.unwrap_or_else(|| "远程推理任务失败".to_owned()),
                ));
            }
            "queued" | "retry" | "leased" => {}
            _ => return Err(ApiError::internal()),
        }
        sleep(Duration::from_millis(250)).await;
    }
}

async fn cancel_timed_out_job(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT status,reserved_cost_micro,attempt_count,model_instance_id
        FROM jobs WHERE id=$1 AND user_id=$2 FOR UPDATE
        "#,
    )
    .bind(job_id)
    .bind(principal.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("任务"))?;
    let status: String = row.try_get("status")?;
    if matches!(status.as_str(), "succeeded" | "failed" | "cancelled") {
        tx.commit().await?;
        return Ok(());
    }
    let reservation: i64 = row.try_get("reserved_cost_micro")?;
    let released = sqlx::query(
        r#"
        UPDATE quota_accounts
        SET reserved_micro=reserved_micro-$2,updated_at=now()
        WHERE user_id=$1 AND reserved_micro >= $2
        "#,
    )
    .bind(principal.user_id)
    .bind(reservation)
    .execute(&mut *tx)
    .await?;
    if released.rows_affected() != 1 {
        return Err(ApiError::internal());
    }
    if status == "leased" {
        sqlx::query(
            r#"
            UPDATE job_attempts
            SET status='failed',finished_at=now(),error_class='timeout',
                error_message='公网 OpenAI 网关等待超时并取消任务'
            WHERE job_id=$1 AND attempt_number=$2 AND status='leased'
            "#,
        )
        .bind(job_id)
        .bind(row.try_get::<i32, _>("attempt_count")?)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        r#"
        UPDATE jobs SET status='cancelled',lease_expires_at=NULL,completed_at=now(),updated_at=now()
        WHERE id=$1
        "#,
    )
    .bind(job_id)
    .execute(&mut *tx)
    .await?;
    finalize_draining_instance(
        &mut tx,
        row.try_get::<Option<Uuid>, _>("model_instance_id")?,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn gateway_response(result: Result<GatewayOutput, ApiError>) -> Response {
    match result {
        Ok(GatewayOutput::Json(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(GatewayOutput::Stream(state)) => gateway_stream_response(*state),
        Err(error) => {
            let body = gateway_error_json(error.message(), error.error_type());
            (error.status(), Json(body)).into_response()
        }
    }
}

fn gateway_stream_response(state: GatewayStreamState) -> Response {
    let output = stream::unfold(state, next_gateway_stream_chunk);
    let mut response = Body::from_stream(output).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    response
}

async fn next_gateway_stream_chunk(
    mut state: GatewayStreamState,
) -> Option<(Result<Bytes, Infallible>, GatewayStreamState)> {
    if state.finished {
        return None;
    }
    loop {
        if let Some(mut event) = state.pending.pop_front() {
            let frame = Bytes::from(format!(
                "id: {}\ndata: {}\n\n",
                event.sequence, event.event_data
            ));
            event.event_data.zeroize();
            state.last_output = Instant::now();
            return Some((Ok(frame), state));
        }
        if let Some(terminal) = state.terminal.take() {
            state.finished = true;
            let frame = match terminal {
                GatewayStreamTerminal::Done => Bytes::from_static(b"data: [DONE]\n\n"),
                GatewayStreamTerminal::Error(mut message) => {
                    let error = gateway_error_json(&message, "stream_error");
                    message.zeroize();
                    let encoded = serde_json::to_string(&error).unwrap_or_else(|_| {
                        "{\"error\":{\"message\":\"SSE 失败\",\"type\":\"stream_error\",\"param\":null,\"code\":\"stream_error\"}}".to_owned()
                    });
                    Bytes::from(format!("data: {encoded}\n\ndata: [DONE]\n\n"))
                }
            };
            return Some((Ok(frame), state));
        }
        let now = Instant::now();
        if now >= state.deadline {
            let message =
                match cancel_timed_out_job(&state.state, &state.principal, state.job_id).await {
                    Ok(()) => "推理在网关等待上限内未完成，任务已取消且预留额度已释放".to_owned(),
                    Err(_) => "推理在网关等待上限内未完成，且任务取消未得到确认".to_owned(),
                };
            state.terminal = Some(GatewayStreamTerminal::Error(message));
            continue;
        }
        match read_job_stream_authenticated(
            &state.state,
            &state.principal,
            state.job_id,
            state.next_sequence,
            8,
        )
        .await
        {
            Ok(response) => {
                state.next_sequence = response.next_sequence;
                state.pending.extend(response.events);
                match response.status {
                    JobStatus::Succeeded if !response.has_more && response.upstream_done => {
                        state.terminal = Some(GatewayStreamTerminal::Done);
                    }
                    JobStatus::Failed | JobStatus::Cancelled => {
                        state.terminal = Some(GatewayStreamTerminal::Error(
                            response
                                .error_message
                                .unwrap_or_else(|| "远程推理任务未成功完成".to_owned()),
                        ));
                    }
                    JobStatus::Retry => {
                        state.terminal = Some(GatewayStreamTerminal::Error(
                            "流式任务违反单 attempt 合同，已拒绝拼接重试输出".to_owned(),
                        ));
                    }
                    JobStatus::Queued | JobStatus::Leased | JobStatus::Succeeded => {}
                }
                if !state.pending.is_empty() || state.terminal.is_some() {
                    continue;
                }
            }
            Err(error) => {
                state.terminal = Some(GatewayStreamTerminal::Error(error.message().to_owned()));
                continue;
            }
        }
        if now.duration_since(state.last_output) >= STREAM_KEEPALIVE_INTERVAL {
            state.last_output = now;
            return Some((Ok(Bytes::from_static(b": keep-alive\n\n")), state));
        }
        sleep(STREAM_POLL_INTERVAL).await;
    }
}

fn gateway_error_json(message: &str, error_type: &str) -> serde_json::Value {
    serde_json::json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": null,
            "code": error_type,
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_errors_have_the_standard_top_level_shape() {
        let response = gateway_response(Err(ApiError::authentication("bad key")));
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn zeroize_json_walks_nested_prompt_values() {
        let mut value = serde_json::json!({"messages": [{"content": "secret"}]});
        zeroize_json_value(&mut value);
        assert!(value.is_null());
    }
}
