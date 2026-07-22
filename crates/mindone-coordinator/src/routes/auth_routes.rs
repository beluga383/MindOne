use std::{collections::BTreeMap, time::Duration};

use axum::{
    extract::{rejection::JsonRejection, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

use mindone_accounting::{LedgerEntry, LedgerKind, GENESIS_HASH};
use mindone_protocol::{
    device_key_fingerprint, device_key_possession_message, refresh_key_possession_message,
    AuthStatusResponse, AuthenticatedUser, DeviceBoundRefreshRequest, DeviceKeyAlgorithm,
    DevicePollRequest, DeviceStartRequest, DeviceStartResponse, TrustLevel,
    DEVICE_KEY_CHALLENGE_BYTES, DEVICE_KEY_SIGNATURE_BYTES, DEVICE_PUBLIC_KEY_BYTES,
    REFRESH_KEY_CHALLENGE_BYTES,
};

use crate::{
    auth::{DeviceAuthContext, ProviderError, ProviderPoll},
    config::AuthProviderKind,
    error::ApiError,
    AppState,
};

pub async fn auth_device_start(
    State(state): State<AppState>,
    request: Result<Json<DeviceStartRequest>, JsonRejection>,
) -> Result<Json<DeviceStartResponse>, ApiError> {
    let Json(request) = request.map_err(|_| {
        ApiError::bad_request(
            "invalid_device_key_request",
            "登录必须提供规范 Ed25519 设备公钥与算法",
        )
    })?;
    let public_key_bytes = validate_device_public_key(&request.device_public_key)?;
    let device_public_key = hex::encode(public_key_bytes);
    let device_key_fingerprint = device_key_fingerprint(&public_key_bytes);
    let device_key_algorithm = request.device_key_algorithm.as_str();
    let mut challenge_bytes = [0_u8; DEVICE_KEY_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut challenge_bytes);
    let device_challenge = hex::encode(challenge_bytes);
    let provider = state
        .auth_provider
        .start(&DeviceAuthContext {
            device_public_key: device_public_key.clone(),
            device_key_fingerprint: device_key_fingerprint.clone(),
        })
        .await
        .map_err(map_provider_error)?;
    let flow_id = Uuid::now_v7();
    let expires_at = expiry(provider.expires_in)?;
    let interval_seconds = i32::try_from(provider.interval.as_secs())
        .map_err(|_| ApiError::internal())?
        .max(1);
    sqlx::query(
        r#"
        INSERT INTO auth_device_flows
            (id, provider, provider_device_code, user_code, verification_uri,
             interval_seconds, expires_at, device_public_key, device_key_fingerprint,
             device_key_algorithm, device_key_challenge)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(flow_id)
    .bind(state.auth_provider.name())
    .bind(provider.device_code)
    .bind(&provider.user_code)
    .bind(&provider.verification_uri)
    .bind(interval_seconds)
    .bind(expires_at)
    .bind(device_public_key)
    .bind(device_key_fingerprint)
    .bind(device_key_algorithm)
    .bind(&device_challenge)
    .execute(&state.pool)
    .await?;
    Ok(Json(DeviceStartResponse {
        flow_id,
        user_code: provider.user_code,
        verification_uri: provider.verification_uri,
        expires_in: provider.expires_in.as_secs(),
        interval: u64::try_from(interval_seconds).map_err(|_| ApiError::internal())?,
        device_challenge,
    }))
}

pub async fn auth_device_poll(
    State(state): State<AppState>,
    request: Result<Json<DevicePollRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(request) = request.map_err(|_| {
        ApiError::bad_request(
            "invalid_device_key_proof",
            "设备登录轮询必须包含 flow_id 与 Ed25519 持有证明",
        )
    })?;
    let row = sqlx::query(
        r#"
        SELECT provider, provider_device_code, status, expires_at, interval_seconds,
               last_polled_at, device_public_key, device_key_fingerprint,
               device_key_algorithm, device_key_challenge
        FROM auth_device_flows WHERE id = $1
        "#,
    )
    .bind(request.flow_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("设备登录流程"))?;
    if row.try_get::<String, _>("provider")? != state.auth_provider.name() {
        return Err(ApiError::conflict(
            "auth_provider_changed",
            "认证提供者已经变更，请重新发起登录",
        ));
    }
    let status: String = row.try_get("status")?;
    if status != "pending" {
        return Err(ApiError::conflict(
            "device_flow_completed",
            "设备登录流程已经结束，请重新发起登录",
        ));
    }
    let device_public_key: String = row
        .try_get("device_public_key")
        .map_err(|_| ApiError::authentication("设备登录流程缺少密钥绑定，请重新发起登录"))?;
    let device_key_fingerprint: String = row
        .try_get("device_key_fingerprint")
        .map_err(|_| ApiError::authentication("设备登录流程缺少密钥指纹，请重新发起登录"))?;
    let device_key_algorithm: String = row
        .try_get("device_key_algorithm")
        .map_err(|_| ApiError::authentication("设备登录流程缺少密钥算法，请重新发起登录"))?;
    let device_challenge: String = row
        .try_get("device_key_challenge")
        .map_err(|_| ApiError::authentication("设备登录流程缺少持有证明挑战，请重新发起登录"))?;
    verify_device_key_proof(
        request.flow_id,
        &device_public_key,
        &device_key_fingerprint,
        &device_key_algorithm,
        &device_challenge,
        &request.device_key_signature,
    )?;
    let now = OffsetDateTime::now_utc();
    let expires_at: OffsetDateTime = row.try_get("expires_at")?;
    if expires_at <= now {
        sqlx::query("UPDATE auth_device_flows SET status = 'expired' WHERE id = $1")
            .bind(request.flow_id)
            .execute(&state.pool)
            .await?;
        return Err(ApiError::authentication("设备验证码已经过期"));
    }
    let interval_seconds: i32 = row.try_get("interval_seconds")?;
    let last_polled_at: Option<OffsetDateTime> = row.try_get("last_polled_at")?;
    if let Some(last_polled_at) = last_polled_at {
        if now - last_polled_at < time::Duration::seconds(i64::from(interval_seconds)) {
            return Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending",
                    "interval": interval_seconds
                })),
            )
                .into_response());
        }
    }
    sqlx::query("UPDATE auth_device_flows SET last_polled_at = now() WHERE id = $1")
        .bind(request.flow_id)
        .execute(&state.pool)
        .await?;
    let provider_device_code: String = row.try_get("provider_device_code")?;
    match state
        .auth_provider
        .poll(&provider_device_code)
        .await
        .map_err(map_provider_error)?
    {
        ProviderPoll::Pending => Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "status": "pending",
                "interval": interval_seconds
            })),
        )
            .into_response()),
        ProviderPoll::SlowDown => {
            let next_interval = interval_seconds.saturating_add(5);
            sqlx::query(
                "UPDATE auth_device_flows SET interval_seconds = $2 WHERE id = $1 AND status = 'pending'",
            )
            .bind(request.flow_id)
            .bind(next_interval)
            .execute(&state.pool)
            .await?;
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": "pending",
                    "interval": next_interval
                })),
            )
                .into_response())
        }
        ProviderPoll::Denied => {
            sqlx::query(
                "UPDATE auth_device_flows SET status = 'denied', completed_at = now() WHERE id = $1",
            )
            .bind(request.flow_id)
            .execute(&state.pool)
            .await?;
            Err(ApiError::authentication("用户拒绝了设备登录"))
        }
        ProviderPoll::Expired => {
            sqlx::query(
                "UPDATE auth_device_flows SET status = 'expired', completed_at = now() WHERE id = $1",
            )
            .bind(request.flow_id)
            .execute(&state.pool)
            .await?;
            Err(ApiError::authentication("设备验证码已经过期"))
        }
        ProviderPoll::Authorized(identity) => {
            let mut tx = state.pool.begin().await?;
            let (flow_status, locked_expires_at): (String, OffsetDateTime) = sqlx::query_as(
                "SELECT status,expires_at FROM auth_device_flows WHERE id = $1 FOR UPDATE",
            )
            .bind(request.flow_id)
            .fetch_one(&mut *tx)
            .await?;
            if flow_status != "pending" {
                return Err(ApiError::conflict(
                    "device_flow_completed",
                    "设备登录流程已经被另一请求完成",
                ));
            }
            if locked_expires_at <= OffsetDateTime::now_utc() {
                sqlx::query(
                    "UPDATE auth_device_flows SET status='expired',completed_at=now() WHERE id=$1",
                )
                .bind(request.flow_id)
                .execute(&mut *tx)
                .await?;
                tx.commit().await?;
                return Err(ApiError::authentication("设备验证码已经过期"));
            }
            let user_id: Uuid = if state.config.auth_provider == AuthProviderKind::Email {
                // email 身份已由注册事务建立。Device poll 只能锁定并消费一个
                // 已验证的现有账户，不得经通用 upsert 绕过 email/password 完整性约束。
                sqlx::query_scalar(
                    r#"
                    SELECT id
                    FROM users
                    WHERE provider = 'email'
                      AND provider_subject = $1
                      AND email = $1
                      AND email_verified_at IS NOT NULL
                    FOR UPDATE
                    "#,
                )
                .bind(&identity.subject)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ApiError::authentication("邮箱账户不存在或尚未完成验证"))?
            } else {
                sqlx::query_scalar(
                    r#"
                    INSERT INTO users (id, provider, provider_subject, username)
                    VALUES ($1,$2,$3,$4)
                    ON CONFLICT (provider, provider_subject)
                    DO UPDATE SET username = EXCLUDED.username, updated_at = now()
                    RETURNING id
                    "#,
                )
                .bind(Uuid::now_v7())
                .bind(state.auth_provider.name())
                .bind(&identity.subject)
                .bind(&identity.username)
                .fetch_one(&mut *tx)
                .await?
            };
            let initial_quota = if state.config.auth_provider == AuthProviderKind::LocalDevelopment
            {
                state.config.dev_initial_quota_micro.max(0)
            } else {
                0
            };
            // 账户先以 0 创建，ledger insert trigger 负责更新到 initial_quota
            let account_insert = sqlx::query(
                r#"
                INSERT INTO quota_accounts (user_id)
                VALUES ($1) ON CONFLICT (user_id) DO NOTHING
                "#,
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            if account_insert.rows_affected() == 1 && initial_quota > 0 {
                let ledger_id = Uuid::now_v7();
                let created_at = OffsetDateTime::now_utc();
                let idempotency_key = format!("local-dev-bootstrap:{user_id}");
                let ledger = LedgerEntry::new(
                    ledger_id,
                    user_id,
                    None,
                    &idempotency_key,
                    LedgerKind::BootstrapGrant,
                    initial_quota,
                    0,
                    initial_quota,
                    created_at,
                    GENESIS_HASH,
                    BTreeMap::from([
                        ("environment".to_owned(), "local-development".to_owned()),
                        ("provider".to_owned(), state.auth_provider.name().to_owned()),
                    ]),
                )
                .map_err(|error| {
                    tracing::error!(error = %error, "开发初始额度账本计算失败");
                    ApiError::internal()
                })?;
                let ledger_metadata = serde_json::Value::Object(
                    ledger
                        .metadata
                        .iter()
                        .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
                        .collect(),
                );
                sqlx::query(
                    r#"
                    INSERT INTO quota_ledger
                        (id,user_id,request_id,entry_type,delta_micro,
                         balance_before_micro,balance_after_micro,idempotency_key,
                         prev_hash,entry_hash,hash_version,metadata,created_at)
                    VALUES ($1,$2,NULL,'bootstrap_grant',$3,0,$3,$4,$5,$6,$7,$8,$9)
                    "#,
                )
                .bind(ledger.id)
                .bind(user_id)
                .bind(initial_quota)
                .bind(idempotency_key)
                .bind(ledger.previous_hash)
                .bind(ledger.hash)
                .bind(ledger.hash_version)
                .bind(ledger_metadata)
                .bind(created_at)
                .execute(&mut *tx)
                .await?;
            }
            let device_key_id: Uuid = sqlx::query_scalar(
                r#"
                INSERT INTO device_keys (id,user_id,fingerprint,public_key,algorithm)
                VALUES ($1,$2,$3,$4,$5)
                ON CONFLICT (user_id,fingerprint)
                DO UPDATE SET public_key = EXCLUDED.public_key,
                    algorithm = EXCLUDED.algorithm,
                    revoked_at = NULL,rotated_at = now()
                RETURNING id
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(user_id)
            .bind(&device_key_fingerprint)
            .bind(&device_public_key)
            .bind(&device_key_algorithm)
            .fetch_one(&mut *tx)
            .await?;
            let issued = state.tokens.issue().map_err(map_provider_error)?;
            let refresh_challenge = new_refresh_challenge();
            let session_id = Uuid::now_v7();
            sqlx::query(
                r#"
                INSERT INTO sessions
                    (id,user_id,access_token_hash,refresh_token_hash,
                     access_expires_at,refresh_expires_at,device_key_id,refresh_challenge)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                "#,
            )
            .bind(session_id)
            .bind(user_id)
            .bind(&issued.access_token_hash)
            .bind(&issued.refresh_token_hash)
            .bind(expiry(issued.access_ttl)?)
            .bind(expiry(issued.refresh_ttl)?)
            .bind(device_key_id)
            .bind(&refresh_challenge)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"
                UPDATE auth_device_flows
                SET status = 'authorized', user_id = $2, completed_at = now(),
                    device_key_challenge = NULL
                WHERE id = $1
                "#,
            )
            .bind(request.flow_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "authorized",
                    "access_token": issued.access_token,
                    "refresh_token": issued.refresh_token,
                    "refresh_challenge": refresh_challenge,
                    "token_type": "Bearer",
                    "expires_in": issued.access_ttl.as_secs(),
                    "device_key_fingerprint": device_key_fingerprint,
                    "user": {
                        "id": user_id,
                        "username": identity.username
                    }
                })),
            )
                .into_response())
        }
    }
}

pub async fn auth_refresh(
    State(state): State<AppState>,
    request: Result<Json<DeviceBoundRefreshRequest>, JsonRejection>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let Json(request) = request.map_err(|_| {
        ApiError::authentication("刷新会话必须提供 refresh token 与设备私钥持有证明")
    })?;
    let refresh_hash = state
        .tokens
        .hash(&request.refresh_token)
        .map_err(map_provider_error)?;
    let mut tx = state.pool.begin().await?;
    let session = sqlx::query(
        r#"
        SELECT s.id,s.refresh_challenge,
               dk.public_key,dk.fingerprint,dk.algorithm
        FROM sessions s
        JOIN device_keys dk ON dk.id = s.device_key_id
        WHERE s.refresh_token_hash = $1
          AND s.revoked_at IS NULL
          AND s.refresh_expires_at > now()
          AND dk.revoked_at IS NULL
        FOR UPDATE OF s
        "#,
    )
    .bind(refresh_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::authentication("刷新令牌已失效或已撤销"))?;
    let session_id: Uuid = session.try_get("id")?;
    let refresh_challenge: String = session.try_get("refresh_challenge").map_err(|_| {
        ApiError::authentication("此旧会话没有设备刷新证明，请重新运行 mindone auth login")
    })?;
    verify_refresh_key_proof(
        &request.refresh_token,
        &session.try_get::<String, _>("public_key")?,
        &session.try_get::<String, _>("fingerprint")?,
        &session.try_get::<String, _>("algorithm")?,
        &refresh_challenge,
        &request.device_key_signature,
    )?;
    let issued = state.tokens.issue().map_err(map_provider_error)?;
    let next_refresh_challenge = new_refresh_challenge();
    sqlx::query(
        r#"
        UPDATE sessions
        SET access_token_hash = $2, refresh_token_hash = $3,
            access_expires_at = $4, refresh_expires_at = $5,
            refresh_challenge = $6,last_used_at = now()
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .bind(&issued.access_token_hash)
    .bind(&issued.refresh_token_hash)
    .bind(expiry(issued.access_ttl)?)
    .bind(expiry(issued.refresh_ttl)?)
    .bind(&next_refresh_challenge)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "access_token": issued.access_token,
        "refresh_token": issued.refresh_token,
        "refresh_challenge": next_refresh_challenge,
        "token_type": "Bearer",
        "expires_in": issued.access_ttl.as_secs()
    })))
}

#[derive(Deserialize)]
pub struct LogoutRequest {
    refresh_token: String,
}

pub async fn auth_logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let refresh_hash = state
        .tokens
        .hash(&request.refresh_token)
        .map_err(map_provider_error)?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        "SELECT id,device_key_id FROM sessions WHERE refresh_token_hash = $1 FOR UPDATE",
    )
    .bind(refresh_hash)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::authentication("刷新令牌无效"))?;
    let session_id: Uuid = row.try_get("id")?;
    let device_key_id: Option<Uuid> = row.try_get("device_key_id")?;
    if let Some(device_key_id) = device_key_id {
        sqlx::query(
            "UPDATE sessions SET revoked_at = COALESCE(revoked_at,now()) WHERE device_key_id = $1",
        )
        .bind(device_key_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE device_keys SET revoked_at = COALESCE(revoked_at,now()) WHERE id = $1")
            .bind(device_key_id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE sessions SET revoked_at = COALESCE(revoked_at,now()) WHERE id = $1")
            .bind(session_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Json(serde_json::json!({
        "revoked": true,
        "device_key_revoked": device_key_id.is_some()
    })))
}

pub async fn auth_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let principal = crate::db::authenticate(&state.pool, &state.tokens, &headers).await?;
    let session = sqlx::query(
        r#"
        SELECT s.created_at,s.last_used_at,
               dk.fingerprint,dk.revoked_at AS device_key_revoked_at,
               dk.created_at AS device_key_created_at,dk.rotated_at AS device_key_rotated_at
        FROM sessions s
        LEFT JOIN device_keys dk ON dk.id = s.device_key_id
        WHERE s.id = $1 AND s.user_id = $2
        "#,
    )
    .bind(principal.session_id)
    .bind(principal.user_id)
    .fetch_one(&state.pool)
    .await?;
    let registered_nodes: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM nodes WHERE user_id = $1")
            .bind(principal.user_id)
            .fetch_one(&state.pool)
            .await?;
    let best_node_trust: Option<String> = sqlx::query_scalar(
        r#"
        SELECT trust_level FROM nodes WHERE user_id = $1
        ORDER BY CASE trust_level
            WHEN 'enhanced' THEN 5
            WHEN 'standard' THEN 4
            WHEN 'standard-limited' THEN 3
            WHEN 'experimental' THEN 2
            ELSE 1 END DESC,id
        LIMIT 1
        "#,
    )
    .bind(principal.user_id)
    .fetch_optional(&state.pool)
    .await?;
    let fingerprint: Option<String> = session.try_get("fingerprint")?;
    let device_key_revoked_at: Option<OffsetDateTime> = session.try_get("device_key_revoked_at")?;
    let registered_nodes = u64::try_from(registered_nodes).map_err(|_| ApiError::internal())?;
    Ok(Json(AuthStatusResponse {
        user: AuthenticatedUser {
            id: principal.user_id,
            username: principal.username,
        },
        // 设备公钥目前没有独立 attestation 证据；节点能力不能提升登录设备的权威信任。
        trust_level: TrustLevel::Unverified,
        device_key_fingerprint: fingerprint.clone(),
        logged_in_at: session.try_get("created_at")?,
        last_used_at: session.try_get("last_used_at")?,
        device_key_revoked: fingerprint.map(|_| device_key_revoked_at.is_some()),
        device_key_created_at: session.try_get("device_key_created_at")?,
        device_key_rotated_at: session.try_get("device_key_rotated_at")?,
        registered_nodes,
        best_node_trust_level: best_node_trust
            .as_deref()
            .map(parse_trust_level)
            .transpose()?,
    }))
}

fn parse_trust_level(value: &str) -> Result<TrustLevel, ApiError> {
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

fn expiry(duration: Duration) -> Result<OffsetDateTime, ApiError> {
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| ApiError::internal())?;
    OffsetDateTime::now_utc()
        .checked_add(time::Duration::seconds(seconds))
        .ok_or_else(ApiError::internal)
}

fn map_provider_error(error: ProviderError) -> ApiError {
    tracing::warn!(error = %error, "认证提供者调用失败");
    ApiError::unavailable("auth_provider_unavailable", "认证提供者当前不可用")
}

fn validate_device_public_key(public_key: &str) -> Result<[u8; DEVICE_PUBLIC_KEY_BYTES], ApiError> {
    let bytes = decode_lower_hex::<DEVICE_PUBLIC_KEY_BYTES>(public_key).ok_or_else(|| {
        ApiError::bad_request(
            "invalid_device_public_key",
            "Ed25519 设备公钥必须是 32 字节规范小写十六进制",
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| {
        ApiError::bad_request(
            "invalid_device_public_key",
            "Ed25519 设备公钥不是有效曲线点",
        )
    })?;
    Ok(bytes)
}

fn verify_device_key_proof(
    flow_id: Uuid,
    public_key: &str,
    fingerprint: &str,
    algorithm: &str,
    challenge: &str,
    signature: &str,
) -> Result<(), ApiError> {
    if algorithm != DeviceKeyAlgorithm::Ed25519.as_str() {
        return Err(ApiError::authentication(
            "设备登录流程使用了不受支持的密钥算法，请重新发起登录",
        ));
    }
    let public_key_bytes = decode_lower_hex::<DEVICE_PUBLIC_KEY_BYTES>(public_key)
        .ok_or_else(|| ApiError::authentication("设备登录公钥记录无效，请重新发起登录"))?;
    if device_key_fingerprint(&public_key_bytes) != fingerprint {
        return Err(ApiError::authentication(
            "设备登录公钥与指纹绑定不一致，请重新发起登录",
        ));
    }
    let challenge = decode_lower_hex::<DEVICE_KEY_CHALLENGE_BYTES>(challenge)
        .ok_or_else(|| ApiError::authentication("设备登录持有证明挑战无效，请重新发起登录"))?;
    let signature = decode_lower_hex::<DEVICE_KEY_SIGNATURE_BYTES>(signature)
        .ok_or_else(|| ApiError::authentication("设备密钥持有证明格式无效"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| ApiError::authentication("设备登录公钥记录无效，请重新发起登录"))?;
    let signature = Signature::from_bytes(&signature);
    let message = device_key_possession_message(
        flow_id,
        &challenge,
        &public_key_bytes,
        DeviceKeyAlgorithm::Ed25519,
    );
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ApiError::authentication("设备密钥持有证明无效"))
}

fn verify_refresh_key_proof(
    refresh_token: &str,
    public_key: &str,
    fingerprint: &str,
    algorithm: &str,
    challenge: &str,
    signature: &str,
) -> Result<(), ApiError> {
    if algorithm != DeviceKeyAlgorithm::Ed25519.as_str() {
        return Err(ApiError::authentication(
            "刷新会话绑定了不受支持的设备密钥算法，请重新登录",
        ));
    }
    let public_key_bytes = decode_lower_hex::<DEVICE_PUBLIC_KEY_BYTES>(public_key)
        .ok_or_else(|| ApiError::authentication("刷新会话的设备公钥记录无效，请重新登录"))?;
    if device_key_fingerprint(&public_key_bytes) != fingerprint {
        return Err(ApiError::authentication(
            "刷新会话的设备公钥与指纹不一致，请重新登录",
        ));
    }
    let challenge = decode_lower_hex::<REFRESH_KEY_CHALLENGE_BYTES>(challenge)
        .ok_or_else(|| ApiError::authentication("刷新会话缺少有效一次性 challenge，请重新登录"))?;
    let signature = decode_lower_hex::<DEVICE_KEY_SIGNATURE_BYTES>(signature)
        .ok_or_else(|| ApiError::authentication("刷新会话的设备私钥持有证明格式无效"))?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| ApiError::authentication("刷新会话的设备公钥记录无效，请重新登录"))?;
    let signature = Signature::from_bytes(&signature);
    let message = refresh_key_possession_message(
        &challenge,
        refresh_token,
        &public_key_bytes,
        DeviceKeyAlgorithm::Ed25519,
    );
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ApiError::authentication("刷新会话的设备私钥持有证明无效"))
}

fn new_refresh_challenge() -> String {
    let mut challenge = [0_u8; REFRESH_KEY_CHALLENGE_BYTES];
    OsRng.fill_bytes(&mut challenge);
    hex::encode(challenge)
}

fn decode_lower_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut bytes = [0_u8; N];
    hex::decode_to_slice(value, &mut bytes).ok()?;
    Some(bytes)
}

#[cfg(test)]
mod device_key_tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    #[test]
    fn possession_proof_binds_private_key_flow_and_canonical_fingerprint() {
        let signing_key = SigningKey::from_bytes(&[7_u8; DEVICE_PUBLIC_KEY_BYTES]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key = hex::encode(public_key_bytes);
        let fingerprint = device_key_fingerprint(&public_key_bytes);
        let challenge_bytes = [9_u8; DEVICE_KEY_CHALLENGE_BYTES];
        let challenge = hex::encode(challenge_bytes);
        let flow_id = Uuid::from_u128(11);
        let message = device_key_possession_message(
            flow_id,
            &challenge_bytes,
            &public_key_bytes,
            DeviceKeyAlgorithm::Ed25519,
        );
        let signature = hex::encode(signing_key.sign(&message).to_bytes());

        assert!(verify_device_key_proof(
            flow_id,
            &public_key,
            &fingerprint,
            DeviceKeyAlgorithm::Ed25519.as_str(),
            &challenge,
            &signature,
        )
        .is_ok());
        assert!(verify_device_key_proof(
            Uuid::from_u128(12),
            &public_key,
            &fingerprint,
            DeviceKeyAlgorithm::Ed25519.as_str(),
            &challenge,
            &signature,
        )
        .is_err());
        assert!(validate_device_public_key(&public_key.to_ascii_uppercase()).is_err());
    }

    #[test]
    fn refresh_proof_binds_token_challenge_and_private_key() {
        let signing_key = SigningKey::from_bytes(&[7_u8; DEVICE_PUBLIC_KEY_BYTES]);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key = hex::encode(public_key_bytes);
        let fingerprint = device_key_fingerprint(&public_key_bytes);
        let challenge_bytes = [9_u8; REFRESH_KEY_CHALLENGE_BYTES];
        let challenge = hex::encode(challenge_bytes);
        let refresh_token = "mnr_current";
        let message = refresh_key_possession_message(
            &challenge_bytes,
            refresh_token,
            &public_key_bytes,
            DeviceKeyAlgorithm::Ed25519,
        );
        let signature = hex::encode(signing_key.sign(&message).to_bytes());

        assert!(verify_refresh_key_proof(
            refresh_token,
            &public_key,
            &fingerprint,
            DeviceKeyAlgorithm::Ed25519.as_str(),
            &challenge,
            &signature,
        )
        .is_ok());
        assert!(verify_refresh_key_proof(
            "mnr_stolen_replacement",
            &public_key,
            &fingerprint,
            DeviceKeyAlgorithm::Ed25519.as_str(),
            &challenge,
            &signature,
        )
        .is_err());
        assert!(verify_refresh_key_proof(
            refresh_token,
            &public_key,
            &fingerprint,
            DeviceKeyAlgorithm::Ed25519.as_str(),
            &hex::encode([10_u8; REFRESH_KEY_CHALLENGE_BYTES]),
            &signature,
        )
        .is_err());
    }
}
