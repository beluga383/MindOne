mod api_keys;
mod attestation_routes;
mod auth_routes;
pub(crate) mod evaluations;
mod governance;
mod jobs;
mod nodes_models;
mod openai_gateway;
mod quota;
mod regulated_jobs;

pub use api_keys::{create_api_key, list_api_keys, revoke_api_key};
pub use attestation_routes::{create_attestation_challenge, submit_attestation};
pub use auth_routes::{
    auth_device_poll, auth_device_start, auth_logout, auth_refresh, auth_status,
};
pub use governance::transparency_report;
pub use jobs::{
    append_job_stream_event, claim_job, create_job, get_job, get_job_stream, job_fail, job_result,
    renew_job,
};
pub use nodes_models::{
    list_models, node_heartbeat, node_stats, publish_model, register_node, unpublish_model,
};
pub use openai_gateway::{chat_completions, completions};
pub use quota::{quota_balance, quota_history, quota_receipt, reserve_status};
pub use regulated_jobs::{create_regulated_job, prepare_regulated_job};

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::{error::ApiError, AppState};

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "mindone-coordinator",
        version: env!("CARGO_PKG_VERSION"),
    })
}

pub async fn ready(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "就绪检查无法访问数据库");
            ApiError::unavailable("database_not_ready", "数据库尚未就绪")
        })?;
    Ok(Json(HealthResponse {
        status: "ready",
        service: "mindone-coordinator",
        version: env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn fallback() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "ok": false,
            "code": 1,
            "error": {
                "type": "route_not_found",
                "message": "API 路径不存在"
            }
        })),
    )
        .into_response()
}
