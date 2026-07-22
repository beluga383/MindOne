pub mod anti_abuse;
pub mod attestation;
pub mod auth;
pub mod config;
pub mod db;
mod device_binding;
pub mod email;
pub mod error;
mod execution_fingerprint;
pub mod operator_billing;
pub mod operator_grant;
pub mod operator_quality;
pub mod operator_sla;
pub mod password;
pub mod private_evaluation_catalog;
pub mod quality;
mod routes;
pub mod settlement;
pub mod standard_data;
pub mod web_auth;

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anti_abuse::{ControlledAsnResolver, NoAsnResolver};
use attestation::{ExternalHardwareEvidenceVerifier, HardwareEvidenceVerifier};
use auth::{DeviceAuthProvider, TokenService};
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Router,
};
use config::{Config, PrivateEvaluationBudgetConfig, PrivateEvaluationHmacKey};
use error::ApiError;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::{watch, Mutex};
use tower_http::{
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::{Level, Span};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<Config>,
    pub auth_provider: Arc<dyn DeviceAuthProvider>,
    pub tokens: TokenService,
    pub attestation_verifier: Arc<dyn HardwareEvidenceVerifier>,
    pub asn_resolver: Arc<dyn ControlledAsnResolver>,
    private_evaluation_security: Option<Arc<PrivateEvaluationRuntimeSecurity>>,
    limiter: GlobalRateLimiter,
    web_auth_limiter: GlobalRateLimiter,
}

/// 只能由数据库启动门禁签发的 private-hidden capability。
///
/// 字段保持私有，调用方不能绕过 key-state 校验自行构造。AppState clone 只复制 Arc，
/// 不会为每个请求复制 Secret。
pub struct PrivateEvaluationRuntimeSecurity {
    hmac_key: PrivateEvaluationHmacKey,
    budget: Option<PrivateEvaluationBudgetConfig>,
}

mod private_evaluation_runtime_capability {
    use crate::config::PrivateEvaluationHmacKey;

    /// 只有数据库启动门禁成功后，`AppState` 才能签发此终态能力。
    ///
    /// 构造器只对父模块可见；route 只能消费能力，不能从裸 key 或裸 `AppState`
    /// 自行构造，从类型边界上关闭 v2 fail/expiry/arbitration 的旁路。
    #[derive(Clone, Copy)]
    pub(crate) struct TerminalCapability<'a> {
        hmac_key: &'a PrivateEvaluationHmacKey,
    }

    impl<'a> TerminalCapability<'a> {
        pub(super) const fn new(hmac_key: &'a PrivateEvaluationHmacKey) -> Self {
            Self { hmac_key }
        }

        pub(crate) const fn hmac_key(self) -> &'a PrivateEvaluationHmacKey {
            self.hmac_key
        }
    }
}

pub(crate) use private_evaluation_runtime_capability::TerminalCapability as PrivateEvaluationTerminalCapability;

impl PrivateEvaluationRuntimeSecurity {
    pub(crate) fn new(
        hmac_key: PrivateEvaluationHmacKey,
        budget: Option<PrivateEvaluationBudgetConfig>,
    ) -> Self {
        Self { hmac_key, budget }
    }
}

impl AppState {
    pub fn new(
        pool: PgPool,
        mut config: Config,
        auth_provider: Arc<dyn DeviceAuthProvider>,
    ) -> Self {
        let requests_per_minute = config.requests_per_minute;
        let tokens = TokenService::new(&config);
        let attestation_verifier = Arc::new(ExternalHardwareEvidenceVerifier::from_config(&config));
        // AppState 只保留数据库门禁签发的 capability。清除 Config 中的原始 private
        // 配置，避免 route、测试或嵌入式调用方绕过 prepare 直接拼出 partial 能力。
        config.private_evaluation_hmac_key = None;
        config.private_evaluation_budget = None;
        Self {
            pool,
            config: Arc::new(config),
            auth_provider,
            tokens,
            attestation_verifier,
            asn_resolver: Arc::new(NoAsnResolver),
            private_evaluation_security: None,
            limiter: GlobalRateLimiter::new(requests_per_minute),
            web_auth_limiter: GlobalRateLimiter::new(WEB_AUTH_REQUESTS_PER_MINUTE),
        }
    }

    /// 仅供确定性测试或嵌入式部署注入经过同一严格输出契约的 verifier。
    #[must_use]
    pub fn with_attestation_verifier(
        mut self,
        verifier: Arc<dyn HardwareEvidenceVerifier>,
    ) -> Self {
        self.attestation_verifier = verifier;
        self
    }

    /// 仅接受部署方控制的地址到 ASN 映射；HTTP 请求无法直接提供 ASN。
    #[must_use]
    pub fn with_asn_resolver(mut self, resolver: Arc<dyn ControlledAsnResolver>) -> Self {
        self.asn_resolver = resolver;
        self
    }

    /// 注入由 [`db::prepare_private_evaluation_runtime`] 在数据库事务提交后签发的能力。
    #[must_use]
    pub fn with_private_evaluation_security(
        mut self,
        security: Option<PrivateEvaluationRuntimeSecurity>,
    ) -> Self {
        self.private_evaluation_security = security.map(Arc::new);
        self
    }

    /// 返回只能由 key-state 启动门禁签发的终态能力。
    pub(crate) fn private_evaluation_terminal_capability(
        &self,
    ) -> Option<PrivateEvaluationTerminalCapability<'_>> {
        self.private_evaluation_security
            .as_deref()
            .map(|security| PrivateEvaluationTerminalCapability::new(&security.hmac_key))
    }

    /// 只有 key 与显式预算同时通过启动门禁时才允许签发新的 private-hidden challenge。
    pub(crate) fn private_evaluation_issuance_security(
        &self,
    ) -> Option<(&PrivateEvaluationHmacKey, &PrivateEvaluationBudgetConfig)> {
        self.private_evaluation_security
            .as_deref()
            .and_then(|security| {
                security
                    .budget
                    .as_ref()
                    .map(|budget| (&security.hmac_key, budget))
            })
    }
}

const HIDDEN_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// 运行一次仅兼容 legacy v1/public canary 的有界过期扫描。
///
/// pool-only 调用方没有经过 private-hidden key-state 启动门禁，因此此兼容入口明确
/// 排除 v2 行，不能结束 v2 challenge。协调器后台必须使用下方 prepared 入口。
pub async fn sweep_expired_hidden_jobs(pool: &PgPool) -> Result<u64, ApiError> {
    routes::evaluations::sweep_expired_hidden_jobs(pool, None, false).await
}

/// 使用 `AppState` 中由数据库启动门禁签发的 opaque capability 扫描全部隐藏任务。
///
/// 裸 `AppState::new` 没有该能力；若数据库出现 v2 行，扫描会在任何终态、事件或仲裁
/// 写入前失败关闭。
pub async fn sweep_expired_hidden_jobs_prepared(state: &AppState) -> Result<u64, ApiError> {
    routes::evaluations::sweep_expired_hidden_jobs(
        &state.pool,
        state.private_evaluation_terminal_capability(),
        true,
    )
    .await
}

/// 周期运行隐藏任务过期扫描，关闭信号到达时停止启动新事务，并取消仍在等待的扫描。
pub async fn run_hidden_expiry_sweeper(state: AppState, mut shutdown: watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    let mut ticker = tokio::time::interval(HIDDEN_EXPIRY_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = ticker.tick() => {
                tokio::select! {
                    biased;
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                    }
                    result = sweep_expired_hidden_jobs_prepared(&state) => {
                        match result {
                            Ok(completed) if completed > 0 => {
                                tracing::info!(completed, "已收口过期的隐藏任务租约");
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(error = %error, "隐藏任务过期扫描失败，将在下一周期重试");
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn router(state: AppState) -> Result<Router, ApiError> {
    let request_timeout = state.config.request_timeout;
    let body_limit = state.config.request_body_limit_bytes;

    // 只有 email provider 挂载 Web 认证。路由构造也独立失败关闭，避免嵌入式
    // 调用方绕过 main 中的 build_provider 启动门禁。
    let web_auth_state = if state.config.auth_provider == config::AuthProviderKind::Email {
        let smtp = crate::email::SmtpConfig::from_env(state.config.environment)?;
        smtp.validate()?;
        Some(crate::web_auth::WebAuthState {
            smtp: Arc::new(smtp),
            token_service: Arc::new(state.tokens.clone()),
            base_url: state.config.public_url.clone(),
            pool: state.pool.clone(),
        })
    } else {
        None
    };

    let api = Router::new()
        .route("/auth/device/start", post(routes::auth_device_start))
        .route("/auth/device/poll", post(routes::auth_device_poll))
        .route("/auth/refresh", post(routes::auth_refresh))
        .route("/auth/logout", post(routes::auth_logout))
        .route("/auth/status", get(routes::auth_status))
        .route(
            "/api-keys",
            get(routes::list_api_keys).post(routes::create_api_key),
        )
        .route("/api-keys/{key_id}", delete(routes::revoke_api_key))
        .route("/transparency/report", get(routes::transparency_report))
        .route(
            "/auth/attestation/challenge",
            post(routes::create_attestation_challenge),
        )
        .route("/auth/attestation/submit", post(routes::submit_attestation))
        .route("/nodes/register", post(routes::register_node))
        .route("/nodes/{node_id}/heartbeat", post(routes::node_heartbeat))
        .route("/nodes/{node_id}/stats", get(routes::node_stats))
        .route("/models/publish", post(routes::publish_model))
        .route(
            "/models/{model_instance_id}",
            delete(routes::unpublish_model),
        )
        .route("/models", get(routes::list_models))
        .route("/chat/completions", post(routes::chat_completions))
        .route("/completions", post(routes::completions))
        .route("/jobs", post(routes::create_job))
        .route(
            "/jobs/regulated/prepare",
            post(routes::prepare_regulated_job),
        )
        .route("/jobs/regulated", post(routes::create_regulated_job))
        .route("/jobs/{job_id}", get(routes::get_job))
        .route(
            "/jobs/{job_id}/stream",
            get(routes::get_job_stream).post(routes::append_job_stream_event),
        )
        .route("/jobs/claim", post(routes::claim_job))
        .route("/jobs/{job_id}/renew", post(routes::renew_job))
        .route("/jobs/{job_id}/result", post(routes::job_result))
        .route("/jobs/{job_id}/fail", post(routes::job_fail))
        .route("/quota/balance", get(routes::quota_balance))
        .route("/quota/history", get(routes::quota_history))
        .route("/quota/receipts/{receipt_id}", get(routes::quota_receipt))
        .route("/reserve", get(routes::reserve_status))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_rate_limit,
        ));

    // Web 认证路由（HTML 页面 + API，在 /auth/* 下，不在 /v1 内）
    let mut router = Router::new()
        .route("/health", get(routes::health))
        .route("/ready", get(routes::ready))
        .nest("/v1", api)
        .fallback(routes::fallback)
        .with_state(state.clone());

    // SMTP 只在 email provider 模式下可能出现在状态中。
    if let Some(web_state) = web_auth_state {
        let web_router = Router::new()
            .route("/auth/register", get(crate::web_auth::register_page))
            .route("/auth/register", post(crate::web_auth::register_handler))
            .route("/auth/login", get(crate::web_auth::login_page))
            .route("/auth/login", post(crate::web_auth::login_handler))
            .route(
                "/auth/verify-email",
                get(crate::web_auth::verify_email_page).post(crate::web_auth::verify_email_handler),
            )
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                enforce_web_auth_rate_limit,
            ))
            .route_layer(middleware::from_fn(harden_web_auth_response))
            .with_state(web_state);

        router = router.merge(web_router);
    }

    Ok(router
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(make_http_request_span)
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(state))
}

/// HTTP span 只记录稳定 method 与 path。URI query 可能包含邮箱验证 token
/// 或 Device Flow code，不得进入日志字段。
fn make_http_request_span(request: &Request<Body>) -> Span {
    tracing::info_span!(
        "http_request",
        method = %request.method(),
        path = %request_log_path(request.uri())
    )
}

fn request_log_path(uri: &Uri) -> &str {
    uri.path()
}

#[derive(Clone)]
struct GlobalRateLimiter {
    limit: u32,
    windows: Arc<Mutex<HashMap<RateKey, RateWindow>>>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RateKey([u8; 32]);

#[derive(Clone, Copy)]
struct RateWindow {
    started: Instant,
    count: u32,
}

const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_BUCKETS: usize = 4_096;
const AUTHENTICATED_IP_BURST_MULTIPLIER: u32 = 8;
const WEB_AUTH_REQUESTS_PER_MINUTE: u32 = 10;

impl GlobalRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit: limit.max(1),
            windows: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn allow(&self, keys: &[(RateKey, u32)]) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;
        windows.retain(|_, window| now.duration_since(window.started) < RATE_WINDOW);

        if keys.iter().any(|(key, limit)| {
            windows
                .get(key)
                .is_some_and(|window| window.count >= *limit)
        }) {
            return false;
        }

        for (key, _) in keys {
            if !windows.contains_key(key) && windows.len() >= MAX_RATE_BUCKETS {
                let oldest = windows
                    .iter()
                    .min_by_key(|(_, window)| window.started)
                    .map(|(key, _)| *key);
                if let Some(oldest) = oldest {
                    windows.remove(&oldest);
                }
            }
            let window = windows.entry(*key).or_insert(RateWindow {
                started: now,
                count: 0,
            });
            window.count = window.count.saturating_add(1);
        }
        true
    }

    fn request_limits(
        &self,
        request: &Request<Body>,
        trusted_proxy_ips: &std::collections::BTreeSet<IpAddr>,
    ) -> Vec<(RateKey, u32)> {
        let client = client_rate_key(request, trusted_proxy_ips);
        match authorization_rate_key(request.headers()) {
            Some(authorization) => vec![
                (
                    client,
                    self.limit.saturating_mul(AUTHENTICATED_IP_BURST_MULTIPLIER),
                ),
                (authorization, self.limit),
            ],
            None => vec![(client, self.limit)],
        }
    }
}

async fn enforce_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let limits = state
        .limiter
        .request_limits(&request, &state.config.trusted_proxy_ips);
    if !state.limiter.allow(&limits).await {
        return Err(ApiError::rate_limited());
    }
    Ok(next.run(request).await)
}

async fn enforce_web_auth_rate_limit(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let client = client_rate_key(&request, &state.config.trusted_proxy_ips);
    if !state
        .web_auth_limiter
        .allow(&[(client, WEB_AUTH_REQUESTS_PER_MINUTE)])
        .await
    {
        return Err(ApiError::rate_limited());
    }
    Ok(next.run(request).await)
}

async fn harden_web_auth_response(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    apply_web_auth_security_headers(response.headers_mut());
    response
}

fn apply_web_auth_security_headers(headers: &mut HeaderMap) {
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
}

fn authorization_rate_key(headers: &HeaderMap) -> Option<RateKey> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    if value.is_empty() || value.len() > 8 * 1024 {
        return None;
    }
    Some(hash_rate_key(b"authorization\0", value.as_bytes()))
}

fn client_rate_key(
    request: &Request<Body>,
    trusted_proxy_ips: &std::collections::BTreeSet<IpAddr>,
) -> RateKey {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(address)| *address);
    let forwarded = peer
        .filter(|address| trusted_proxy_ips.contains(&address.ip()))
        .and_then(|_| cloudflare_connecting_ip(request.headers()));
    let address = forwarded.or_else(|| peer.map(|value| value.ip()));
    match address {
        Some(address) => hash_rate_key(b"client-ip\0", normalized_ip_bytes(address).as_slice()),
        None => hash_rate_key(b"client-unknown\0", request.uri().path().as_bytes()),
    }
}

fn cloudflare_connecting_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("cf-connecting-ip")?.to_str().ok()?;
    if value.len() > 64 || value.trim() != value {
        return None;
    }
    value.parse().ok()
}

fn normalized_ip_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    }
}

fn hash_rate_key(domain: &[u8], value: &[u8]) -> RateKey {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    RateKey(digest.finalize().into())
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[test]
    fn request_trace_target_never_contains_query_secrets() {
        let uri: Uri = "/auth/verify-email?token=mnev_should_never_be_logged"
            .parse()
            .expect("测试 URI 应有效");
        assert_eq!(request_log_path(&uri), "/auth/verify-email");
        assert!(!request_log_path(&uri).contains("mnev_"));

        let uri: Uri = "/auth/login?code=mne_should_never_be_logged"
            .parse()
            .expect("测试 URI 应有效");
        assert_eq!(request_log_path(&uri), "/auth/login");
        assert!(!request_log_path(&uri).contains("mne_"));
    }

    #[tokio::test]
    async fn app_state_exposes_private_security_only_as_a_complete_capability() {
        let config = Config::development_for_tests("postgres://invalid".to_owned());
        let security = PrivateEvaluationRuntimeSecurity::new(
            config
                .private_evaluation_hmac_key
                .as_ref()
                .expect("测试 key 应存在")
                .clone(),
            config.private_evaluation_budget.clone(),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy(&config.database_url)
            .expect("测试连接池应惰性构造");
        let provider = auth::build_provider(&config, pool.clone()).expect("测试认证提供者应构造");
        let state = AppState::new(pool, config, provider);
        assert!(state.config.private_evaluation_hmac_key.is_none());
        assert!(state.config.private_evaluation_budget.is_none());
        assert!(state.private_evaluation_terminal_capability().is_none());
        assert!(state.private_evaluation_issuance_security().is_none());

        let state = state.with_private_evaluation_security(Some(security));
        let (key, budget) = state
            .private_evaluation_issuance_security()
            .expect("完整 capability 应同时暴露 key 与预算");
        assert_eq!(key.version(), 1);
        assert_eq!(budget.global_reserve_entries, 1);
        assert_eq!(
            state
                .private_evaluation_terminal_capability()
                .expect("完整 capability 应签发终态能力")
                .hmac_key()
                .version(),
            1
        );
    }

    #[tokio::test]
    async fn key_only_capability_can_finish_v2_but_cannot_issue_new_private_work() {
        let config = Config::development_for_tests("postgres://invalid".to_owned());
        let security = PrivateEvaluationRuntimeSecurity::new(
            config
                .private_evaluation_hmac_key
                .as_ref()
                .expect("测试 key 应存在")
                .clone(),
            None,
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy(&config.database_url)
            .expect("测试连接池应惰性构造");
        let provider = auth::build_provider(&config, pool.clone()).expect("测试认证提供者应构造");
        let state =
            AppState::new(pool, config, provider).with_private_evaluation_security(Some(security));
        assert_eq!(
            state
                .private_evaluation_terminal_capability()
                .expect("key-only capability 应保留终态验证 key")
                .hmac_key()
                .version(),
            1
        );
        assert!(state.private_evaluation_issuance_security().is_none());
    }

    #[tokio::test]
    async fn credentials_have_independent_bounded_windows() {
        let limiter = GlobalRateLimiter::new(1);
        let first = hash_rate_key(b"authorization\0", b"Bearer first");
        let second = hash_rate_key(b"authorization\0", b"Bearer second");
        assert!(limiter.allow(&[(first, 1)]).await);
        assert!(!limiter.allow(&[(first, 1)]).await);
        assert!(limiter.allow(&[(second, 1)]).await);
    }

    #[tokio::test]
    async fn web_auth_has_an_independent_ten_request_window() {
        let limiter = GlobalRateLimiter::new(WEB_AUTH_REQUESTS_PER_MINUTE);
        let client = hash_rate_key(b"client-ip\0", &[127, 0, 0, 1]);
        for _ in 0..WEB_AUTH_REQUESTS_PER_MINUTE {
            assert!(
                limiter
                    .allow(&[(client, WEB_AUTH_REQUESTS_PER_MINUTE)])
                    .await
            );
        }
        assert!(
            !limiter
                .allow(&[(client, WEB_AUTH_REQUESTS_PER_MINUTE)])
                .await
        );
    }

    #[test]
    fn web_auth_security_headers_disable_storage_referrers_and_framing() {
        let mut headers = HeaderMap::new();
        apply_web_auth_security_headers(&mut headers);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert!(headers["content-security-policy"]
            .to_str()
            .expect("CSP 应是 ASCII")
            .contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn rejected_multi_key_request_does_not_consume_other_bucket() {
        let limiter = GlobalRateLimiter::new(1);
        let client = hash_rate_key(b"client-ip\0", &[127, 0, 0, 1]);
        let first = hash_rate_key(b"authorization\0", b"Bearer first");
        let second = hash_rate_key(b"authorization\0", b"Bearer second");
        assert!(limiter.allow(&[(client, 1), (first, 1)]).await);
        assert!(!limiter.allow(&[(client, 1), (second, 1)]).await);
        assert!(limiter.allow(&[(second, 1)]).await);
    }

    #[test]
    fn cloudflare_address_is_only_trusted_from_exact_allowlist_peer() {
        let trusted = [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
            .into_iter()
            .collect();
        let mut loopback = Request::builder()
            .uri("/v1/jobs")
            .header("cf-connecting-ip", "203.0.113.7")
            .body(Body::empty())
            .expect("测试请求应有效");
        loopback
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1234))));
        assert_eq!(
            client_rate_key(&loopback, &trusted),
            hash_rate_key(b"client-ip\0", &[203, 0, 113, 7])
        );

        let mut remote = Request::builder()
            .uri("/v1/jobs")
            .header("cf-connecting-ip", "203.0.113.7")
            .body(Body::empty())
            .expect("测试请求应有效");
        remote
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([198, 51, 100, 9], 1234))));
        assert_eq!(
            client_rate_key(&remote, &trusted),
            hash_rate_key(b"client-ip\0", &[198, 51, 100, 9])
        );

        let mut private_gateway = Request::builder()
            .uri("/v1/jobs")
            .header("cf-connecting-ip", "203.0.113.7")
            .body(Body::empty())
            .expect("测试请求应有效");
        private_gateway
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([192, 168, 65, 1], 1234))));
        assert_eq!(
            client_rate_key(&private_gateway, &trusted),
            hash_rate_key(b"client-ip\0", &[192, 168, 65, 1])
        );
    }
}
