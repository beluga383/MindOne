//! 邮箱注册、验证与设备绑定登录页面。
//!
//! 邮箱密码只负责在浏览器中授权一条既有 Device Flow。CLI Token 仍由
//! `/v1/auth/device/poll` 在验证 Ed25519 私钥持有证明后一次性交付；浏览器路由不返回
//! Token，数据库也不持久化原始验证 Token 或 CLI bearer Token。

use std::sync::Arc;

use axum::{
    extract::{
        rejection::{FormRejection, QueryRejection},
        Form, Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sqlx::PgPool;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::TokenService;
use crate::email::{send_verification_email, SmtpConfig};
use crate::error::ApiError;
use crate::password::{hash_password, verify_password};

type Result<T> = std::result::Result<T, ApiError>;

const MAX_EMAIL_BYTES: usize = 254;
const MAX_USERNAME_CHARS: usize = 64;
const MAX_PASSWORD_BYTES: usize = 1_024;
const EMAIL_USER_CODE_CHARS: usize = 12;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterForm {
    pub email: String,
    pub username: String,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    /// 终端显示的规范用户码；它只确认一条既有 Device Flow。
    pub user_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyEmailToken {
    pub token: String,
}

#[derive(Clone)]
pub struct WebAuthState {
    pub smtp: Arc<SmtpConfig>,
    pub token_service: Arc<TokenService>,
    pub base_url: String,
    pub pool: PgPool,
}

pub async fn register_page() -> Html<&'static str> {
    Html(include_str!("../templates/register.html"))
}

pub async fn register_handler(
    State(state): State<WebAuthState>,
    Json(form): Json<RegisterForm>,
) -> Result<Response> {
    let (email, username) = validate_registration(&form)?;
    let password_hash = hash_password(&form.password).await?;
    let verification_token = new_one_time_token("mnev_");
    let verification_token_hash = state
        .token_service
        .hash(verification_token.as_str())
        .map_err(|_| ApiError::internal())?;
    let verification_url = format!(
        "{}/auth/verify-email?token={}",
        state.base_url,
        verification_token.as_str()
    );

    let mut tx = state.pool.begin().await?;
    let user_id = Uuid::now_v7();
    let inserted = sqlx::query(
        r#"
        INSERT INTO users
            (id,provider,provider_subject,username,email,password_hash,created_at,updated_at)
        VALUES ($1,'email',$2,$3,$2,$4,now(),now())
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .bind(&username)
    .bind(password_hash)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "email_exists",
            "该邮箱已注册；请登录或联系运维人员恢复账户",
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO email_verification_tokens
            (id,user_id,token_hash,expires_at,created_at)
        VALUES ($1,$2,$3,$4,now())
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(verification_token_hash)
    .bind(OffsetDateTime::now_utc() + Duration::hours(24))
    .execute(&mut *tx)
    .await?;

    // 发送失败时事务随错误回滚，避免留下无法重试注册的半成品账户。
    send_verification_email(&state.smtp, &email, &username, &verification_url).await?;
    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"message": "注册成功，请检查邮箱完成验证"})),
    )
        .into_response())
}

pub async fn verify_email_page(
    query: std::result::Result<Query<VerifyEmailToken>, QueryRejection>,
) -> Response {
    let Query(query) = match query {
        Ok(query) => query,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "邮箱验证请求格式无效").into_response();
        }
    };
    if !valid_verification_token(&query.token) {
        return (StatusCode::BAD_REQUEST, "验证链接无效").into_response();
    }
    Html(format!(
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>确认邮箱验证</title></head><body><main><h1>确认验证邮箱</h1><p>请仅在你本人刚刚注册 MindOne 时继续。安全扫描器打开此页面不会激活账户。</p><form method=\"post\" action=\"/auth/verify-email\"><input type=\"hidden\" name=\"token\" value=\"{}\"><button type=\"submit\">确认并激活账户</button></form></main></body></html>",
        query.token
    ))
    .into_response()
}

pub async fn verify_email_handler(
    State(state): State<WebAuthState>,
    form: std::result::Result<Form<VerifyEmailToken>, FormRejection>,
) -> Result<Response> {
    let Form(form) = form.map_err(|_| {
        ApiError::bad_request("invalid_verification_request", "邮箱验证请求格式无效")
    })?;
    if !valid_verification_token(&form.token) {
        return Ok((StatusCode::BAD_REQUEST, "验证链接无效").into_response());
    }
    let token_hash = state
        .token_service
        .hash(&form.token)
        .map_err(|_| ApiError::internal())?;
    let mut tx = state.pool.begin().await?;
    let record: Option<(Uuid, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        r#"
        SELECT user_id,expires_at,used_at
        FROM email_verification_tokens
        WHERE token_hash = $1
        FOR UPDATE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((user_id, expires_at, used_at)) = record else {
        return Ok((StatusCode::BAD_REQUEST, "验证链接无效").into_response());
    };
    if used_at.is_some() {
        tx.commit().await?;
        return Ok((
            StatusCode::OK,
            Html(
                "<!doctype html><meta name=\"referrer\" content=\"no-referrer\"><h1>邮箱已验证</h1><p>你的账户已激活，现在可以重新发起终端登录。</p>",
            ),
        )
            .into_response());
    }
    if OffsetDateTime::now_utc() >= expires_at {
        return Ok((StatusCode::BAD_REQUEST, "验证链接已过期").into_response());
    }

    let consumed = sqlx::query(
        "UPDATE email_verification_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL",
    )
    .bind(&token_hash)
    .execute(&mut *tx)
    .await?;
    if consumed.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "verification_already_consumed",
            "验证链接已被消费",
        ));
    }
    sqlx::query(
        "UPDATE users SET email_verified_at = now(),updated_at = now() WHERE id = $1 AND email_verified_at IS NULL",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Html(
            "<!doctype html><meta name=\"referrer\" content=\"no-referrer\"><h1>邮箱验证成功</h1><p>账户已激活。请回到终端重新运行登录命令。</p>",
        ),
    )
        .into_response())
}

pub async fn login_page() -> Html<&'static str> {
    Html(include_str!("../templates/login.html"))
}

pub async fn login_handler(
    State(state): State<WebAuthState>,
    Json(form): Json<LoginForm>,
) -> Result<Response> {
    let email = normalize_email(&form.email)?;
    validate_password_input(&form.password)?;
    let user_code = normalize_user_code(&form.user_code)?;

    let user: Option<(Uuid, Option<String>, Option<OffsetDateTime>)> = sqlx::query_as(
        r#"
        SELECT id,password_hash,email_verified_at
        FROM users
        WHERE provider = 'email' AND provider_subject = $1 AND email = $1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.pool)
    .await?;
    let Some((user_id, password_hash, email_verified_at)) = user else {
        return Err(ApiError::authentication("邮箱或密码错误"));
    };
    if email_verified_at.is_none() {
        return Err(ApiError::forbidden("邮箱尚未验证，请检查邮箱"));
    }
    let Some(password_hash) = password_hash else {
        return Err(ApiError::authentication("邮箱或密码错误"));
    };
    if !verify_password(&form.password, &password_hash).await? {
        return Err(ApiError::authentication("邮箱或密码错误"));
    }

    // Argon2 在事务外的有界 blocking pool 完成。之后开短事务锁定并
    // 重新确认账户未在验证期间被撤销或更改密码。
    let mut tx = state.pool.begin().await?;
    let current_user: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id FROM users
        WHERE id=$1 AND provider='email' AND provider_subject=$2 AND email=$2
          AND password_hash=$3 AND email_verified_at IS NOT NULL
        FOR SHARE
        "#,
    )
    .bind(user_id)
    .bind(&email)
    .bind(&password_hash)
    .fetch_optional(&mut *tx)
    .await?;
    if current_user != Some(user_id) {
        return Err(ApiError::authentication("邮箱或密码错误"));
    }

    let bound = sqlx::query(
        r#"
        UPDATE auth_device_flows
        SET email_authorized_user_id = $2,email_authorized_at = now()
        WHERE provider = 'email'
          AND user_code = $1
          AND status = 'pending'
          AND expires_at > now()
          AND email_authorized_user_id IS NULL
          AND email_authorized_at IS NULL
        "#,
    )
    .bind(&user_code)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;
    if bound.rows_affected() != 1 {
        return Err(ApiError::conflict(
            "device_flow_unavailable",
            "设备登录流程无效、已过期或已被消费，请从终端重新发起登录",
        ));
    }
    tx.commit().await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "身份验证成功，请回到终端完成设备密钥持有证明"
        })),
    )
        .into_response())
}

fn validate_registration(form: &RegisterForm) -> Result<(String, String)> {
    if form.password != form.password_confirm {
        return Err(ApiError::bad_request("password_mismatch", "两次密码不一致"));
    }
    validate_password_input(&form.password)?;
    let email = normalize_email(&form.email)?;
    let username = form.username.trim();
    if username.is_empty()
        || username.chars().count() > MAX_USERNAME_CHARS
        || username.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "invalid_username",
            "用户名必须为 1 到 64 个非控制字符",
        ));
    }
    Ok((email, username.to_owned()))
}

fn normalize_email(value: &str) -> Result<String> {
    let email = value.trim();
    let (local, domain) = email
        .split_once('@')
        .ok_or_else(|| ApiError::bad_request("invalid_email", "邮箱必须包含本地部分和域名"))?;
    if email.len() > MAX_EMAIL_BYTES
        || !email.is_ascii()
        || local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
        || email.chars().any(char::is_whitespace)
    {
        return Err(ApiError::bad_request("invalid_email", "邮箱格式无效"));
    }
    Ok(email.to_ascii_lowercase())
}

fn normalize_user_code(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(ApiError::authentication(
            "设备验证码无效，请核对自己终端显示的验证码",
        ));
    }
    let canonical = value
        .trim()
        .chars()
        .filter(|character| *character != '-' && !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if canonical.len() != EMAIL_USER_CODE_CHARS
        || !canonical.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ApiError::authentication(
            "设备验证码无效，请核对自己终端显示的验证码",
        ));
    }
    Ok(canonical)
}

fn validate_password_input(password: &str) -> Result<()> {
    if !(8..=MAX_PASSWORD_BYTES).contains(&password.len()) {
        return Err(ApiError::bad_request(
            "invalid_password_length",
            "密码长度必须为 8 到 1024 字节",
        ));
    }
    Ok(())
}

fn new_one_time_token(prefix: &str) -> Zeroizing<String> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Zeroizing::new(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn valid_verification_token(token: &str) -> bool {
    token.len() == 48
        && token.starts_with("mnev_")
        && token[5..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        extract::Query,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    use super::{
        normalize_email, normalize_user_code, valid_verification_token, validate_registration,
        verify_email_page, LoginForm, RegisterForm, VerifyEmailToken,
    };

    #[test]
    fn registration_normalizes_bounded_inputs_without_accepting_controls() {
        let form = RegisterForm {
            email: " Alice@Example.COM ".to_owned(),
            username: "爱丽丝".to_owned(),
            password: "correct horse".to_owned(),
            password_confirm: "correct horse".to_owned(),
        };
        let (email, username) = validate_registration(&form).expect("合法注册输入应通过");
        assert_eq!(email, "alice@example.com");
        assert_eq!(username, "爱丽丝");

        let mut invalid = form;
        invalid.username = "bad\nname".to_owned();
        assert!(validate_registration(&invalid).is_err());
    }

    #[test]
    fn email_and_login_payload_are_strict() {
        assert!(normalize_email("missing-at.example.com").is_err());
        assert!(normalize_email("a@localhost").is_err());
        assert!(serde_json::from_value::<LoginForm>(serde_json::json!({
            "email": "a@example.com",
            "password": "password",
            "user_code": "ABCDEF123456",
            "access_token": "must-not-be-accepted"
        }))
        .is_err());
    }

    #[test]
    fn email_user_code_is_canonical_and_bounded() {
        assert_eq!(
            normalize_user_code(" abcd-ef12-3456 ").expect("可读分组用户码应规范化"),
            "ABCDEF123456"
        );
        assert!(normalize_user_code("ABCDEF12345").is_err());
        assert!(normalize_user_code("ABCDEF12345Z").is_err());
        assert!(normalize_user_code("ABCDEF\n123456").is_err());
    }

    #[test]
    fn email_verification_token_shape_is_strict() {
        assert!(valid_verification_token(
            "mnev_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!valid_verification_token(
            "mnev_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(!valid_verification_token(
            "mnev_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!"
        ));
        assert!(!valid_verification_token(
            "otherAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
    }

    #[tokio::test]
    async fn verification_get_only_renders_an_explicit_post_confirmation() {
        let token = "mnev_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let response = verify_email_page(Ok(Query(VerifyEmailToken {
            token: token.to_owned(),
        })))
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 16 * 1024)
            .await
            .expect("确认页正文应可读取");
        let html = std::str::from_utf8(&body).expect("确认页必须是 UTF-8");
        assert!(html.contains("method=\"post\""));
        assert!(html.contains("action=\"/auth/verify-email\""));
        assert!(html.contains(token));
        assert!(!html.contains("邮箱验证成功"));

        let rejected = verify_email_page(Ok(Query(VerifyEmailToken {
            token: "bad".to_owned(),
        })))
        .await;
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verification_query_rejections_are_chinese_and_bounded() {
        let app = Router::new().route("/auth/verify-email", get(verify_email_page));
        for uri in ["/auth/verify-email", "/auth/verify-email?unknown=value"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("测试请求应可构造"),
                )
                .await
                .expect("无状态路由应可响应");
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), 1024)
                .await
                .expect("错误正文应可读取");
            assert_eq!(body.as_ref(), "邮箱验证请求格式无效".as_bytes());
        }
    }
}
