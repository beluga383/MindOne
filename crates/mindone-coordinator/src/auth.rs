use std::{net::SocketAddr, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::Sha256;
use sqlx::{PgPool, Row};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::config::{validate_provider, AuthProviderKind, Config};

#[derive(Clone, Debug)]
pub struct ProviderStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: Duration,
    pub interval: Duration,
}

#[derive(Clone, Debug)]
pub struct ProviderIdentity {
    pub subject: String,
    pub username: String,
}

#[derive(Clone, Debug)]
pub struct DeviceAuthContext {
    pub device_public_key: String,
    pub device_key_fingerprint: String,
}

#[derive(Clone, Debug)]
pub enum ProviderPoll {
    Pending,
    SlowDown,
    Authorized(ProviderIdentity),
    Denied,
    Expired,
}

#[async_trait]
pub trait DeviceAuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn start(&self, context: &DeviceAuthContext) -> Result<ProviderStart, ProviderError>;
    async fn poll(&self, device_code: &str) -> Result<ProviderPoll, ProviderError>;
}

pub fn build_provider(
    config: &Config,
    pool: PgPool,
) -> Result<Arc<dyn DeviceAuthProvider>, ProviderError> {
    validate_provider(config.environment, config.auth_provider)
        .map_err(|error| ProviderError::Configuration(error.to_string()))?;
    match config.auth_provider {
        AuthProviderKind::Github => {
            let client_id = config.github_client_id.clone().ok_or_else(|| {
                ProviderError::Configuration("缺少 GitHub OAuth Client ID".to_owned())
            })?;
            let provider = GithubDeviceProvider::new(client_id, config.github_scope.clone())?;
            Ok(Arc::new(provider))
        }
        AuthProviderKind::Email => {
            // 邮箱模式必须在启动期验证完整 SMTP 配置。不能等到首个注册请求才发现
            // 邮件不可发送，否则 verification URI 会指向一个无法完成的认证流程。
            let smtp = crate::email::SmtpConfig::from_env(config.environment).map_err(|_| {
                ProviderError::Configuration("邮箱认证要求完整且安全的 SMTP 配置".to_owned())
            })?;
            smtp.validate().map_err(|_| {
                ProviderError::Configuration("邮箱认证的 SMTP 发件人与传输配置无效".to_owned())
            })?;
            Ok(Arc::new(EmailDeviceProvider::new(config, pool)?))
        }
        AuthProviderKind::LocalDevelopment => {
            let provider =
                LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)?;
            Ok(Arc::new(provider))
        }
    }
}

pub struct GithubDeviceProvider {
    client: reqwest::Client,
    client_id: String,
    scope: String,
}

impl GithubDeviceProvider {
    fn new(client_id: String, scope: String) -> Result<Self, ProviderError> {
        let client = github_http_client(reqwest::Client::builder())?;
        Ok(Self {
            client,
            client_id,
            scope,
        })
    }
}

fn github_http_client(builder: reqwest::ClientBuilder) -> Result<reqwest::Client, ProviderError> {
    builder
        // OAuth 凭据不得交给继承自进程环境或系统配置的代理。
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .user_agent("mindone-coordinator/1.0.0")
        .redirect(github_redirect_policy())
        .build()
        .map_err(|error| ProviderError::Transport(error.to_string()))
}

fn github_redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        if github_redirect_allowed(attempt.previous(), attempt.url()) {
            attempt.follow()
        } else {
            attempt.error("GitHub OAuth 重定向越过安全同源边界")
        }
    })
}

fn github_redirect_allowed(previous: &[reqwest::Url], next: &reqwest::Url) -> bool {
    let Some(first) = previous.first() else {
        return false;
    };
    previous.len() <= 5
        && next.scheme() == "https"
        && matches!(next.host_str(), Some("github.com" | "api.github.com"))
        && first.origin() == next.origin()
}

#[derive(Deserialize)]
struct GithubDeviceStartResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: Option<u64>,
}

#[derive(Deserialize)]
struct GithubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GithubUserResponse {
    id: u64,
    login: String,
}

#[async_trait]
impl DeviceAuthProvider for GithubDeviceProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    async fn start(&self, _context: &DeviceAuthContext) -> Result<ProviderStart, ProviderError> {
        let response = self
            .client
            .post("https://github.com/login/device/code")
            .header(ACCEPT, "application/json")
            .form(&[("client_id", &self.client_id), ("scope", &self.scope)])
            .send()
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::Upstream(response.status().as_u16()));
        }
        let body: GithubDeviceStartResponse = response
            .json()
            .await
            .map_err(|error| ProviderError::Protocol(error.to_string()))?;
        Ok(ProviderStart {
            device_code: body.device_code,
            user_code: body.user_code,
            verification_uri: body.verification_uri,
            expires_in: Duration::from_secs(body.expires_in),
            interval: Duration::from_secs(body.interval.unwrap_or(5)),
        })
    }

    async fn poll(&self, device_code: &str) -> Result<ProviderPoll, ProviderError> {
        let response = self
            .client
            .post("https://github.com/login/oauth/access_token")
            .header(ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !response.status().is_success() {
            return Err(ProviderError::Upstream(response.status().as_u16()));
        }
        let token: GithubTokenResponse = response
            .json()
            .await
            .map_err(|error| ProviderError::Protocol(error.to_string()))?;
        match token.error.as_deref() {
            Some("authorization_pending") => return Ok(ProviderPoll::Pending),
            Some("slow_down") => return Ok(ProviderPoll::SlowDown),
            Some("access_denied") => return Ok(ProviderPoll::Denied),
            Some("expired_token") => return Ok(ProviderPoll::Expired),
            Some(_) => return Err(ProviderError::Protocol("GitHub 拒绝了设备登录".to_owned())),
            None => {}
        }
        let access_token = token
            .access_token
            .ok_or_else(|| ProviderError::Protocol("GitHub 未返回访问令牌".to_owned()))?;
        let user_response = self
            .client
            .get("https://api.github.com/user")
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "mindone-coordinator/1.0.0")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|error| ProviderError::Transport(error.to_string()))?;
        if !user_response.status().is_success() {
            return Err(ProviderError::Upstream(user_response.status().as_u16()));
        }
        let user: GithubUserResponse = user_response
            .json()
            .await
            .map_err(|error| ProviderError::Protocol(error.to_string()))?;
        Ok(ProviderPoll::Authorized(ProviderIdentity {
            subject: user.id.to_string(),
            username: user.login,
        }))
    }
}

pub struct EmailDeviceProvider {
    pool: PgPool,
    tokens: TokenService,
    verification_uri: Url,
}

impl EmailDeviceProvider {
    fn new(config: &Config, pool: PgPool) -> Result<Self, ProviderError> {
        let mut verification_uri = Url::parse(&config.public_url)
            .map_err(|_| ProviderError::Configuration("MINDONE_PUBLIC_URL 无效".to_owned()))?;
        verification_uri.set_path("/auth/login");
        verification_uri.set_query(None);
        verification_uri.set_fragment(None);
        Ok(Self {
            pool,
            tokens: TokenService::new(config),
            verification_uri,
        })
    }
}

#[async_trait]
impl DeviceAuthProvider for EmailDeviceProvider {
    fn name(&self) -> &'static str {
        "email"
    }

    async fn start(&self, _context: &DeviceAuthContext) -> Result<ProviderStart, ProviderError> {
        // provider secret 只在本调用中存在，DB 只保存带 pepper 的 HMAC。浏览器
        // 经标准用户码确认既有 flow，避免 URL 携带可诱导授权攻击者设备的秘密。
        let provider_secret = random_token("mne_");
        let stored_code = self.tokens.hash(&provider_secret)?;
        let user_code = random_email_user_code();
        Ok(ProviderStart {
            // 这里只持久化带 pepper 的 HMAC；原始 provider secret 立即丢弃。
            device_code: stored_code,
            user_code,
            verification_uri: self.verification_uri.to_string(),
            expires_in: Duration::from_secs(300),
            interval: Duration::from_secs(2),
        })
    }

    async fn poll(&self, device_code: &str) -> Result<ProviderPoll, ProviderError> {
        let row = sqlx::query(
            r#"
            SELECT users.provider_subject,users.username
            FROM auth_device_flows
            JOIN users ON users.id = auth_device_flows.email_authorized_user_id
            WHERE auth_device_flows.provider = 'email'
              AND auth_device_flows.provider_device_code = $1
              AND auth_device_flows.status = 'pending'
              AND auth_device_flows.email_authorized_at IS NOT NULL
              AND auth_device_flows.expires_at > now()
            "#,
        )
        .bind(device_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| ProviderError::Transport(format!("邮箱授权状态读取失败：{error}")))?;
        let Some(row) = row else {
            return Ok(ProviderPoll::Pending);
        };
        Ok(ProviderPoll::Authorized(ProviderIdentity {
            subject: row
                .try_get("provider_subject")
                .map_err(|_| ProviderError::Protocol("邮箱授权缺少用户标识".to_owned()))?,
            username: row
                .try_get("username")
                .map_err(|_| ProviderError::Protocol("邮箱授权缺少用户名".to_owned()))?,
        }))
    }
}

pub struct LocalDevelopmentProvider {
    username_prefix: String,
    verification_uri: String,
}

impl LocalDevelopmentProvider {
    pub fn new(username_prefix: String, bind_addr: SocketAddr) -> Result<Self, ProviderError> {
        let verification_addr = if bind_addr.ip().is_loopback() {
            bind_addr
        } else if bind_addr.ip().is_unspecified() {
            match bind_addr {
                SocketAddr::V4(value) => SocketAddr::from(([127, 0, 0, 1], value.port())),
                SocketAddr::V6(value) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], value.port())),
            }
        } else {
            return Err(ProviderError::Configuration(
                "本地开发认证只允许 loopback 或容器内 unspecified 监听地址".to_owned(),
            ));
        };
        Ok(Self {
            username_prefix,
            verification_uri: format!("http://{verification_addr}/local-development/authorize"),
        })
    }
}

#[async_trait]
impl DeviceAuthProvider for LocalDevelopmentProvider {
    fn name(&self) -> &'static str {
        "local-development"
    }

    async fn start(&self, context: &DeviceAuthContext) -> Result<ProviderStart, ProviderError> {
        let subject_hash = &context.device_key_fingerprint;
        let user_code = subject_hash
            .chars()
            .take(8)
            .collect::<String>()
            .to_ascii_uppercase();
        Ok(ProviderStart {
            device_code: format!("mindone-local-development:{subject_hash}"),
            user_code,
            verification_uri: self.verification_uri.clone(),
            expires_in: Duration::from_secs(600),
            interval: Duration::from_secs(1),
        })
    }

    async fn poll(&self, device_code: &str) -> Result<ProviderPoll, ProviderError> {
        let subject_hash = device_code
            .strip_prefix("mindone-local-development:")
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| ProviderError::Protocol("本地开发设备身份无效".to_owned()))?;
        let short_hash = subject_hash.chars().take(8).collect::<String>();
        Ok(ProviderPoll::Authorized(ProviderIdentity {
            subject: format!("local-device:{subject_hash}"),
            username: format!("{}-{short_hash}", self.username_prefix),
        }))
    }
}

#[derive(Clone)]
pub struct TokenService {
    pepper: Arc<[u8]>,
    access_ttl: Duration,
    refresh_ttl: Duration,
}

impl TokenService {
    pub fn new(config: &Config) -> Self {
        Self {
            pepper: Arc::from(config.token_pepper.as_bytes()),
            access_ttl: config.access_token_ttl,
            refresh_ttl: config.refresh_token_ttl,
        }
    }

    pub fn issue(&self) -> Result<IssuedTokens, ProviderError> {
        let access_token = random_token("mna_");
        let refresh_token = random_token("mnr_");
        Ok(IssuedTokens {
            access_token_hash: self.hash(&access_token)?,
            refresh_token_hash: self.hash(&refresh_token)?,
            access_token,
            refresh_token,
            access_ttl: self.access_ttl,
            refresh_ttl: self.refresh_ttl,
        })
    }

    pub fn issue_inference_api_key(&self) -> Result<IssuedApiKey, ProviderError> {
        let api_key = random_token("mok_");
        let key_prefix = api_key.chars().take(12).collect::<String>();
        Ok(IssuedApiKey {
            key_hash: self.hash(&api_key)?,
            api_key,
            key_prefix,
        })
    }

    pub fn hash(&self, token: &str) -> Result<String, ProviderError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pepper)
            .map_err(|_| ProviderError::Configuration("令牌哈希配置无效".to_owned()))?;
        mac.update(token.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
}

pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
}

pub struct IssuedApiKey {
    pub api_key: String,
    pub key_hash: String,
    pub key_prefix: String,
}

fn random_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn random_email_user_code() -> String {
    let mut bytes = [0_u8; 6];
    OsRng.fill_bytes(&mut bytes);
    hex::encode_upper(bytes)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::{
        github_http_client, github_redirect_allowed, DeviceAuthContext, DeviceAuthProvider,
        EmailDeviceProvider, LocalDevelopmentProvider,
    };
    use crate::config::{AuthProviderKind, Config};

    #[tokio::test]
    async fn email_device_start_persists_only_hmac_and_uses_manual_user_code() {
        let mut config = Config::development_for_tests("postgres://invalid".to_owned());
        config.auth_provider = AuthProviderKind::Email;
        config.public_url = "https://auth.example.com".to_owned();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy(&config.database_url)
            .expect("测试连接池应惰性构造");
        let provider = EmailDeviceProvider::new(&config, pool).expect("email provider 应可构造");
        let start = provider
            .start(&DeviceAuthContext {
                device_public_key: "test-key".to_owned(),
                device_key_fingerprint: "ab".repeat(32),
            })
            .await
            .expect("email Device Flow 应可启动");

        assert_eq!(
            start.verification_uri,
            "https://auth.example.com/auth/login"
        );
        assert!(!start.verification_uri.contains('?'));
        assert!(!start.verification_uri.contains('#'));
        assert_eq!(start.device_code.len(), 43);
        assert!(start
            .device_code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')));
        assert_eq!(start.user_code.len(), 12);
        assert!(start
            .user_code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)));
    }

    #[tokio::test]
    async fn local_development_verification_uri_tracks_the_actual_loopback_bind() {
        let provider = LocalDevelopmentProvider::new(
            "本地测试".to_owned(),
            "127.0.0.1:18788".parse().expect("测试地址应有效"),
        )
        .expect("loopback 本地认证应可构造");
        let start = provider
            .start(&DeviceAuthContext {
                device_public_key: "test-key".to_owned(),
                device_key_fingerprint: "ab".repeat(32),
            })
            .await
            .expect("本地设备登录应可启动");
        assert_eq!(
            start.verification_uri,
            "http://127.0.0.1:18788/local-development/authorize"
        );
        let container_provider = LocalDevelopmentProvider::new(
            "容器测试".to_owned(),
            "0.0.0.0:18789".parse().expect("测试地址应有效"),
        )
        .expect("容器内 unspecified 监听应映射成同端口 loopback 验证地址");
        let container_start = container_provider
            .start(&DeviceAuthContext {
                device_public_key: "container-test-key".to_owned(),
                device_key_fingerprint: "cd".repeat(32),
            })
            .await
            .expect("容器本地设备登录应可启动");
        assert_eq!(
            container_start.verification_uri,
            "http://127.0.0.1:18789/local-development/authorize"
        );
        assert!(LocalDevelopmentProvider::new(
            "不安全".to_owned(),
            "192.0.2.1:18788".parse().expect("测试地址应有效")
        )
        .is_err());
    }

    #[tokio::test]
    async fn github_oauth_client_clears_preconfigured_proxy() {
        let direct_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应能监听直连测试端口");
        let direct_address = direct_listener.local_addr().expect("应有直连测试地址");
        let proxy_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应能监听代理测试端口");
        let proxy_address = proxy_listener.local_addr().expect("应有代理测试地址");

        let direct_server = tokio::spawn(async move {
            let (mut stream, _) = direct_listener.accept().await.expect("应收到直连请求");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.expect("应能读取直连请求");
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("应能写入直连响应");
        });

        let proxy_server = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await.expect("控制请求应命中代理");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await.expect("应能读取代理请求");
            stream
                .write_all(
                    b"HTTP/1.1 418 I'm a teapot\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("应能写入代理响应");

            tokio::time::timeout(Duration::from_millis(250), proxy_listener.accept())
                .await
                .is_ok()
        });

        let target = format!("http://{direct_address}/oauth-proxy-probe");
        let proxy =
            reqwest::Proxy::all(format!("http://{proxy_address}")).expect("测试代理 URL 应有效");
        let control = reqwest::Client::builder()
            .proxy(proxy.clone())
            .build()
            .expect("控制客户端应可构造");
        let control_status = control
            .get(&target)
            .send()
            .await
            .expect("控制请求应完成")
            .status();
        assert_eq!(control_status, reqwest::StatusCode::IM_A_TEAPOT);

        let github_client = github_http_client(reqwest::Client::builder().proxy(proxy))
            .expect("GitHub OAuth 客户端应可构造");
        let direct_status = github_client
            .get(target)
            .send()
            .await
            .expect("禁用代理后应能直连")
            .status();
        assert_eq!(direct_status, reqwest::StatusCode::NO_CONTENT);

        direct_server.await.expect("直连测试服务应正常结束");
        assert!(
            !proxy_server.await.expect("代理测试服务应正常结束"),
            "GitHub OAuth 客户端不得向代理发出第二个请求"
        );
    }

    #[test]
    fn github_oauth_redirects_are_https_same_origin_and_bounded() {
        let github =
            reqwest::Url::parse("https://github.com/login/device/code").expect("测试 URL 应有效");
        let same_origin =
            reqwest::Url::parse("https://github.com/login/device/code/").expect("测试 URL 应有效");
        assert!(github_redirect_allowed(
            std::slice::from_ref(&github),
            &same_origin
        ));

        let api = reqwest::Url::parse("https://api.github.com/user").expect("测试 URL 应有效");
        let insecure =
            reqwest::Url::parse("http://github.com/login/device/code").expect("测试 URL 应有效");
        let attacker = reqwest::Url::parse("https://example.com/oauth").expect("测试 URL 应有效");
        assert!(!github_redirect_allowed(
            std::slice::from_ref(&github),
            &api
        ));
        assert!(!github_redirect_allowed(
            std::slice::from_ref(&github),
            &insecure
        ));
        assert!(!github_redirect_allowed(
            std::slice::from_ref(&github),
            &attacker
        ));
        assert!(!github_redirect_allowed(&vec![github; 6], &same_origin));
    }
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub user_id: Uuid,
    pub username: String,
    pub session_id: Uuid,
    /// 当前访问令牌经非撤销 session 精确绑定的设备公钥身份。
    pub device_key_id: Uuid,
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("认证提供者配置错误：{0}")]
    Configuration(String),
    #[error("认证提供者网络错误：{0}")]
    Transport(String),
    #[error("认证提供者协议错误：{0}")]
    Protocol(String),
    #[error("认证提供者返回 HTTP {0}")]
    Upstream(u16),
}
