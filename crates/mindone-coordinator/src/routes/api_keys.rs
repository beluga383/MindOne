use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use mindone_protocol::{
    ApiKeyListResponse, ApiKeySummary, CreateApiKeyRequest, CreateApiKeyResponse,
    RevokeApiKeyResponse, Validate,
};
use sqlx::Row;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{db::authenticate, error::ApiError, AppState};

pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request
        .validate()
        .map_err(|error| ApiError::bad_request("invalid_api_key", error.to_string()))?;
    let issued = state
        .tokens
        .issue_inference_api_key()
        .map_err(|_| ApiError::internal())?;
    let api_key = Zeroizing::new(issued.api_key);
    let key_id = Uuid::now_v7();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        r#"
        INSERT INTO inference_api_keys
            (id,user_id,created_by_session_id,device_key_id,name,key_prefix,key_hash)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (user_id,name) DO NOTHING
        RETURNING id,name,key_prefix,created_at,last_used_at,revoked_at
        "#,
    )
    .bind(key_id)
    .bind(principal.user_id)
    .bind(principal.session_id)
    .bind(principal.device_key_id)
    .bind(&request.name)
    .bind(&issued.key_prefix)
    .bind(&issued.key_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        ApiError::conflict(
            "api_key_name_exists",
            "同名 API Key 已存在；请更换名称或先撤销旧 Key",
        )
    })?;
    sqlx::query(
        r#"
        INSERT INTO inference_api_key_events (id,api_key_id,user_id,event_type)
        VALUES ($1,$2,$3,'created')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(key_id)
    .bind(principal.user_id)
    .execute(&mut *tx)
    .await?;
    let record = summary_from_row(&row)?;
    tx.commit().await?;
    Ok(Json(CreateApiKeyResponse {
        api_key: api_key.to_string(),
        record,
    }))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiKeyListResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let rows = sqlx::query(
        r#"
        SELECT id,name,key_prefix,created_at,last_used_at,revoked_at
        FROM inference_api_keys
        WHERE user_id=$1
        ORDER BY created_at DESC,id
        LIMIT 200
        "#,
    )
    .bind(principal.user_id)
    .fetch_all(&state.pool)
    .await?;
    let data = rows
        .iter()
        .map(summary_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ApiKeyListResponse { data }))
}

pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key_id): Path<Uuid>,
) -> Result<Json<RevokeApiKeyResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    let mut tx = state.pool.begin().await?;
    let revoked_at = sqlx::query_scalar::<_, Option<time::OffsetDateTime>>(
        "SELECT revoked_at FROM inference_api_keys WHERE id=$1 AND user_id=$2 FOR UPDATE",
    )
    .bind(key_id)
    .bind(principal.user_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("API Key"))?;
    let revoked = revoked_at.is_none();
    if revoked {
        sqlx::query("UPDATE inference_api_keys SET revoked_at=now() WHERE id=$1")
            .bind(key_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO inference_api_key_events (id,api_key_id,user_id,event_type)
            VALUES ($1,$2,$3,'revoked')
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(key_id)
        .bind(principal.user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(RevokeApiKeyResponse {
        id: key_id,
        revoked,
    }))
}

fn summary_from_row(row: &sqlx::postgres::PgRow) -> Result<ApiKeySummary, ApiError> {
    Ok(ApiKeySummary {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        key_prefix: row.try_get("key_prefix")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}
