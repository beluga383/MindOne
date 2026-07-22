use std::{
    collections::BTreeSet,
    env,
    ffi::OsStr,
    fmt,
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use subtle::ConstantTimeEq;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use sqlx::postgres::{PgConnectOptions, PgSslMode};

// 必须与 0026/runtime role-init 的全局 CONNECTION LIMIT 保持一致。
const MAX_RUNTIME_DATABASE_CONNECTIONS: u32 = 32;
const PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV: &str = "MINDONE_PRIVATE_EVALUATION_HMAC_KEY_FILE";
const PRIVATE_EVALUATION_HMAC_KEY_INLINE_ENV: &str = "MINDONE_PRIVATE_EVALUATION_HMAC_KEY";
const PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX: &[u8] = b"mindone-private-hidden-hmac-v1:";
const PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES: u64 =
    (PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX.len() + 64 + 1) as u64;
const MAX_PRIVATE_EVALUATION_HOURLY_LIMIT: u32 = 4_096;
const MAX_PRIVATE_EVALUATION_COOLDOWN_SECONDS: u64 = 86_400;
const MAX_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES: u32 = 4_095;

const PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT_ENV: &str =
    "MINDONE_PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT";
const PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT_ENV: &str =
    "MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT";
const PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT_ENV: &str =
    "MINDONE_PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT";
const PRIVATE_EVALUATION_NODE_HOURLY_LIMIT_ENV: &str =
    "MINDONE_PRIVATE_EVALUATION_NODE_HOURLY_LIMIT";
const PRIVATE_EVALUATION_COOLDOWN_SECONDS_ENV: &str = "MINDONE_PRIVATE_EVALUATION_COOLDOWN_SECONDS";
const PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES_ENV: &str =
    "MINDONE_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES";

/// private-hidden commitment 的独立 v1 HMAC-SHA256 密钥。
///
/// 原始材料只保存在自动清零的内存中；调试输出永远不会包含密钥。该类型不提供
/// public material accessor，所有调用方必须通过 private evaluation commitment API 使用。
#[derive(Clone)]
pub struct PrivateEvaluationHmacKey {
    version: u8,
    material: Zeroizing<[u8; 32]>,
}

impl PrivateEvaluationHmacKey {
    const VERSION_ONE: u8 = 1;

    fn version_one(material: [u8; 32]) -> Self {
        Self {
            version: Self::VERSION_ONE,
            material: Zeroizing::new(material),
        }
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    pub(crate) fn material(&self) -> &[u8; 32] {
        &self.material
    }
}

impl fmt::Debug for PrivateEvaluationHmacKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateEvaluationHmacKey")
            .field("version", &self.version)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

/// private-hidden catalog 的显式抗耗尽预算。
///
/// 生产环境没有隐式默认值；六个环境变量必须作为一个完整配置组提供。只有启动期
/// 验证到真实签名 catalog 时，这组预算才成为必需条件。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateEvaluationBudgetConfig {
    pub catalog_hourly_limit: u32,
    pub account_hourly_limit: u32,
    pub device_hourly_limit: u32,
    pub node_hourly_limit: u32,
    pub cooldown: Duration,
    pub global_reserve_entries: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEnvironment {
    Production,
    Development,
    Test,
}

impl FromStr for RuntimeEnvironment {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "production" => Ok(Self::Production),
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            other => Err(ConfigError::InvalidValue {
                name: "MINDONE_ENV",
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthProviderKind {
    Github,
    Email,
    LocalDevelopment,
}

#[derive(Clone, Debug, Default)]
pub struct HardwareAttestationConfig {
    /// 固定且已规范化的 verifier adapter 程序；不经 shell 执行。
    pub verifier_path: Option<PathBuf>,
    pub allowed_policy_hashes: BTreeSet<String>,
    pub allowed_runtime_hashes: BTreeSet<String>,
    pub allowed_tee_measurements: BTreeSet<String>,
}

impl HardwareAttestationConfig {
    #[must_use]
    pub fn deployable(&self) -> bool {
        self.verifier_path.is_some()
            && !self.allowed_policy_hashes.is_empty()
            && !self.allowed_runtime_hashes.is_empty()
            && !self.allowed_tee_measurements.is_empty()
    }
}

impl FromStr for AuthProviderKind {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "github" => Ok(Self::Github),
            "email" => Ok(Self::Email),
            "local-development" => Ok(Self::LocalDevelopment),
            other => Err(ConfigError::InvalidValue {
                name: "MINDONE_AUTH_PROVIDER",
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub environment: RuntimeEnvironment,
    pub bind_addr: SocketAddr,
    pub database_url: String,
    pub(crate) max_database_connections: u32,
    pub database_acquire_timeout: Duration,
    /// 公网访问 URL（用于生成邮件验证链接等），例如 "https://api.holarchic.cn"
    pub public_url: String,
    pub auth_provider: AuthProviderKind,
    pub github_client_id: Option<String>,
    pub github_scope: String,
    pub token_pepper: String,
    /// Standard 数据静态保护的独立 256-bit 密钥；不得与 Token pepper 复用。
    pub standard_data_key: Zeroizing<[u8; 32]>,
    /// private-hidden commitment 的独立、可选 HMAC 密钥；只允许从受保护文件加载。
    pub private_evaluation_hmac_key: Option<PrivateEvaluationHmacKey>,
    /// 仅在真实 private catalog 启用时必需；生产环境不提供隐式默认值。
    pub private_evaluation_budget: Option<PrivateEvaluationBudgetConfig>,
    /// Exact direct peers allowed to supply `CF-Connecting-IP`; no CIDR or private-range trust.
    pub trusted_proxy_ips: BTreeSet<IpAddr>,
    /// Optional, immutable local JSON prefix map. Loading it never performs a network request.
    pub asn_map_path: Option<PathBuf>,
    /// 固定的受信质量 evaluator 公钥目录；只由服务器侧运维命令读取。
    pub quality_evaluator_keys_dir: Option<PathBuf>,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
    pub request_timeout: Duration,
    pub request_body_limit_bytes: usize,
    pub requests_per_minute: u32,
    pub lease_duration: Duration,
    pub max_job_retries: i32,
    pub evaluation_draw_denominator: u32,
    pub evaluation_instance_cooldown: Duration,
    pub attestation_challenge_ttl: Duration,
    pub attestation_report_ttl: Duration,
    pub attestation_verifier_timeout: Duration,
    pub amd_sev_snp_attestation: HardwareAttestationConfig,
    pub intel_tdx_attestation: HardwareAttestationConfig,
    pub dev_username: String,
    pub dev_initial_quota_micro: i64,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = env::var("MINDONE_ENV")
            .unwrap_or_else(|_| "production".to_owned())
            .parse()?;
        let auth_provider = env::var("MINDONE_AUTH_PROVIDER")
            .unwrap_or_else(|_| "github".to_owned())
            .parse()?;
        validate_provider(environment, auth_provider)?;

        let bind_addr: SocketAddr = parse_or("MINDONE_BIND", "127.0.0.1:8787")?;
        let allow_non_loopback: bool = parse_or("MINDONE_ALLOW_NON_LOOPBACK", "false")?;
        if !bind_addr.ip().is_loopback() && !allow_non_loopback {
            return Err(ConfigError::UnsafeBind(bind_addr));
        }

        let database_url = required("DATABASE_URL")?;
        validate_database_transport(environment, &database_url)?;
        let public_url = validate_public_url(
            environment,
            auth_provider,
            &env::var("MINDONE_PUBLIC_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".to_owned()),
        )?;
        let github_client_id = env::var("MINDONE_GITHUB_CLIENT_ID").ok();
        if auth_provider == AuthProviderKind::Github && github_client_id.is_none() {
            return Err(ConfigError::Missing("MINDONE_GITHUB_CLIENT_ID"));
        }
        if github_client_id
            .as_deref()
            .is_some_and(|value| !valid_public_identifier(value, 256))
        {
            return Err(ConfigError::InvalidValue {
                name: "MINDONE_GITHUB_CLIENT_ID",
                value: "必须为 1 到 256 字节且不含空白或控制字符".to_owned(),
            });
        }

        let token_pepper = match env::var("MINDONE_TOKEN_PEPPER") {
            Ok(value) if value.len() >= 32 => value,
            Ok(_) => return Err(ConfigError::WeakSecret("MINDONE_TOKEN_PEPPER")),
            Err(_) if environment != RuntimeEnvironment::Production => {
                "mindone-local-development-only-token-pepper".to_owned()
            }
            Err(_) => return Err(ConfigError::Missing("MINDONE_TOKEN_PEPPER")),
        };
        let standard_data_key = standard_data_key_from_env()?;
        let private_evaluation_hmac_key = private_evaluation_hmac_key_from_env()?;
        let private_evaluation_budget = private_evaluation_budget_from_env()?;
        if standard_key_reuses_token_pepper(&token_pepper, &standard_data_key) {
            return Err(ConfigError::SecretReuse(
                "MINDONE_TOKEN_PEPPER",
                "MINDONE_STANDARD_DATA_KEY(_FILE)",
            ));
        }
        if let Some(private_key) = private_evaluation_hmac_key.as_ref() {
            if key_reuses_token_pepper(&token_pepper, private_key.material()) {
                return Err(ConfigError::SecretReuse(
                    "MINDONE_TOKEN_PEPPER",
                    PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV,
                ));
            }
            if private_key_reuses_standard_data_key(private_key, &standard_data_key) {
                return Err(ConfigError::SecretReuse(
                    "MINDONE_STANDARD_DATA_KEY(_FILE)",
                    PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV,
                ));
            }
        }

        let access_token_seconds: u64 = bounded_parse_or(
            "MINDONE_ACCESS_TOKEN_SECONDS",
            "900",
            60,
            if environment == RuntimeEnvironment::Production {
                3_600
            } else {
                86_400
            },
        )?;
        let refresh_token_seconds: u64 =
            bounded_parse_or("MINDONE_REFRESH_TOKEN_SECONDS", "2592000", 300, 31_536_000)?;
        if refresh_token_seconds <= access_token_seconds {
            return Err(ConfigError::InvalidValue {
                name: "MINDONE_REFRESH_TOKEN_SECONDS",
                value: "必须大于访问令牌有效期".to_owned(),
            });
        }
        Ok(Self {
            environment,
            bind_addr,
            database_url,
            max_database_connections: validate_database_max_connections(parse_or(
                "MINDONE_DB_MAX_CONNECTIONS",
                "10",
            )?)?,
            database_acquire_timeout: Duration::from_secs(bounded_parse_or(
                "MINDONE_DB_ACQUIRE_TIMEOUT_SECONDS",
                "5",
                1,
                60,
            )?),
            public_url,
            auth_provider,
            github_client_id,
            github_scope: validated_github_scope()?,
            token_pepper,
            standard_data_key,
            private_evaluation_hmac_key,
            private_evaluation_budget,
            trusted_proxy_ips: trusted_proxy_ips_from_env()?,
            asn_map_path: optional_fixed_data_file("MINDONE_ASN_MAP_PATH")?,
            quality_evaluator_keys_dir: optional_fixed_directory(
                "MINDONE_QUALITY_EVALUATOR_KEYS_DIR",
            )?,
            access_token_ttl: Duration::from_secs(access_token_seconds),
            refresh_token_ttl: Duration::from_secs(refresh_token_seconds),
            request_timeout: Duration::from_secs(bounded_parse_or(
                "MINDONE_REQUEST_TIMEOUT_SECONDS",
                "30",
                1,
                300,
            )?),
            request_body_limit_bytes: bounded_parse_or(
                "MINDONE_REQUEST_BODY_LIMIT_BYTES",
                "1048576",
                1_024,
                16_777_216,
            )?,
            requests_per_minute: bounded_parse_or(
                "MINDONE_REQUESTS_PER_MINUTE",
                "120",
                1,
                100_000,
            )?,
            lease_duration: Duration::from_secs(bounded_parse_or(
                "MINDONE_JOB_LEASE_SECONDS",
                "60",
                5,
                3_600,
            )?),
            max_job_retries: bounded_parse_or("MINDONE_MAX_JOB_RETRIES", "3", 0, 100)?,
            evaluation_draw_denominator: bounded_parse_or(
                "MINDONE_EVALUATION_DRAW_DENOMINATOR",
                "8",
                1,
                10_000,
            )?,
            evaluation_instance_cooldown: Duration::from_secs(bounded_parse_or(
                "MINDONE_EVALUATION_INSTANCE_COOLDOWN_SECONDS",
                "60",
                1,
                3_600,
            )?),
            attestation_challenge_ttl: bounded_duration(
                "MINDONE_ATTESTATION_CHALLENGE_SECONDS",
                300,
                30,
                600,
            )?,
            attestation_report_ttl: bounded_duration(
                "MINDONE_ATTESTATION_REPORT_SECONDS",
                3_600,
                60,
                86_400,
            )?,
            attestation_verifier_timeout: bounded_duration(
                "MINDONE_ATTESTATION_VERIFIER_TIMEOUT_SECONDS",
                15,
                1,
                60,
            )?,
            amd_sev_snp_attestation: attestation_config_from_env(
                "MINDONE_SNP_VERIFIER_PATH",
                "MINDONE_SNP_ALLOWED_POLICY_SHA256",
                "MINDONE_SNP_ALLOWED_RUNTIME_SHA256",
                "MINDONE_SNP_ALLOWED_MEASUREMENTS",
            )?,
            intel_tdx_attestation: attestation_config_from_env(
                "MINDONE_TDX_VERIFIER_PATH",
                "MINDONE_TDX_ALLOWED_POLICY_SHA256",
                "MINDONE_TDX_ALLOWED_RUNTIME_SHA256",
                "MINDONE_TDX_ALLOWED_MEASUREMENTS",
            )?,
            dev_username: env::var("MINDONE_DEV_USERNAME")
                .unwrap_or_else(|_| "本地开发用户".to_owned()),
            dev_initial_quota_micro: bounded_parse_or(
                "MINDONE_DEV_INITIAL_QUOTA_MICRO",
                "10000000",
                0,
                1_000_000_000_000,
            )?,
        })
    }

    pub fn development_for_tests(database_url: String) -> Self {
        Self {
            environment: RuntimeEnvironment::Test,
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8787)),
            database_url,
            max_database_connections: 4,
            database_acquire_timeout: Duration::from_secs(2),
            public_url: "http://127.0.0.1:8787".to_owned(),
            auth_provider: AuthProviderKind::LocalDevelopment,
            github_client_id: None,
            github_scope: "read:user".to_owned(),
            token_pepper: "mindone-test-token-pepper-at-least-32-bytes".to_owned(),
            standard_data_key: Zeroizing::new([0x5a; 32]),
            private_evaluation_hmac_key: Some(PrivateEvaluationHmacKey::version_one([0xa7; 32])),
            // 测试配置显式给出宽松但有限的预算；生产 from_env 没有任何默认值。
            private_evaluation_budget: Some(PrivateEvaluationBudgetConfig {
                catalog_hourly_limit: MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
                account_hourly_limit: MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
                device_hourly_limit: MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
                node_hourly_limit: MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
                cooldown: Duration::from_secs(1),
                global_reserve_entries: 1,
            }),
            trusted_proxy_ips: default_trusted_proxy_ips(),
            asn_map_path: None,
            quality_evaluator_keys_dir: None,
            access_token_ttl: Duration::from_secs(900),
            refresh_token_ttl: Duration::from_secs(3_600),
            request_timeout: Duration::from_secs(5),
            request_body_limit_bytes: 1_048_576,
            requests_per_minute: 10_000,
            lease_duration: Duration::from_secs(60),
            max_job_retries: 2,
            // 普通集成测试默认禁用随机注入，避免与路由/结算断言相互污染；
            // 隐藏评价专用测试会显式设为 1。生产配置仍要求 1..=10_000。
            evaluation_draw_denominator: 0,
            evaluation_instance_cooldown: Duration::from_secs(1),
            attestation_challenge_ttl: Duration::from_secs(300),
            attestation_report_ttl: Duration::from_secs(3_600),
            attestation_verifier_timeout: Duration::from_secs(5),
            amd_sev_snp_attestation: HardwareAttestationConfig::default(),
            intel_tdx_attestation: HardwareAttestationConfig::default(),
            dev_username: "集成测试用户".to_owned(),
            dev_initial_quota_micro: 10_000_000,
        }
    }
}

pub fn validate_provider(
    environment: RuntimeEnvironment,
    provider: AuthProviderKind,
) -> Result<(), ConfigError> {
    if provider == AuthProviderKind::LocalDevelopment
        && environment == RuntimeEnvironment::Production
    {
        return Err(ConfigError::DevelopmentProviderInProduction);
    }
    Ok(())
}

fn validate_public_url(
    environment: RuntimeEnvironment,
    provider: AuthProviderKind,
    value: &str,
) -> Result<String, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidValue {
        name: "MINDONE_PUBLIC_URL",
        value: "必须是绝对 HTTP(S) URL".to_owned(),
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ConfigError::InvalidValue {
            name: "MINDONE_PUBLIC_URL",
            value: "不得包含凭据、路径、查询或片段".to_owned(),
        });
    }

    if provider == AuthProviderKind::Email {
        let loopback = matches!(url.host_str(), Some("localhost"))
            || url
                .host_str()
                .and_then(|host| host.parse::<IpAddr>().ok())
                .is_some_and(|address| address.is_loopback());
        let safe_transport = url.scheme() == "https"
            || (environment != RuntimeEnvironment::Production
                && url.scheme() == "http"
                && loopback);
        if !safe_transport {
            return Err(ConfigError::InvalidValue {
                name: "MINDONE_PUBLIC_URL",
                value: "邮箱认证要求 HTTPS；仅 development/test 的 loopback 可使用 HTTP".to_owned(),
            });
        }
    }

    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn validate_database_transport(
    environment: RuntimeEnvironment,
    database_url: &str,
) -> Result<(), ConfigError> {
    if environment != RuntimeEnvironment::Production {
        return Ok(());
    }

    if !database_url_has_only_transport_query_parameters(database_url) {
        return Err(ConfigError::UnsafeDatabaseTransport);
    }
    let options = database_url
        .parse::<PgConnectOptions>()
        .map_err(|_| ConfigError::UnsafeDatabaseTransport)?;
    if options.get_socket().is_some() {
        return Ok(());
    }

    if matches!(options.get_ssl_mode(), PgSslMode::VerifyFull) {
        Ok(())
    } else {
        Err(ConfigError::UnsafeDatabaseTransport)
    }
}

fn database_url_has_only_transport_query_parameters(database_url: &str) -> bool {
    if database_url.contains('#') {
        return false;
    }
    let Some((_, query)) = database_url.split_once('?') else {
        return true;
    };
    if query.is_empty() {
        return true;
    }
    query.split('&').all(|parameter| {
        let key = parameter.split_once('=').map_or(parameter, |(key, _)| key);
        matches!(
            key,
            "sslmode"
                | "ssl-mode"
                | "sslrootcert"
                | "ssl-root-cert"
                | "ssl-ca"
                | "host"
                | "hostaddr"
                | "port"
        )
    })
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::Missing(name))
}

fn standard_data_key_from_env() -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let inline = env::var_os("MINDONE_STANDARD_DATA_KEY");
    let file = env::var_os("MINDONE_STANDARD_DATA_KEY_FILE");
    if inline.is_some() && file.is_some() {
        return Err(ConfigError::ConflictingSecrets(
            "MINDONE_STANDARD_DATA_KEY",
            "MINDONE_STANDARD_DATA_KEY_FILE",
        ));
    }
    let encoded = match (inline, file) {
        (Some(value), None) => Zeroizing::new(
            value
                .into_string()
                .map_err(|_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY"))?,
        ),
        (None, Some(path)) => read_standard_data_key_file(Path::new(&path))?,
        (None, None) => return Err(ConfigError::Missing("MINDONE_STANDARD_DATA_KEY_FILE")),
        (Some(_), Some(_)) => {
            return Err(ConfigError::ConflictingSecrets(
                "MINDONE_STANDARD_DATA_KEY",
                "MINDONE_STANDARD_DATA_KEY_FILE",
            ))
        }
    };
    decode_standard_data_key(encoded)
}

fn decode_standard_data_key(
    mut encoded: Zeroizing<String>,
) -> Result<Zeroizing<[u8; 32]>, ConfigError> {
    let trimmed_length = encoded.trim_end_matches(['\r', '\n']).len();
    encoded.truncate(trimmed_length);
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        encoded.zeroize();
        return Err(ConfigError::InvalidSecret(
            "MINDONE_STANDARD_DATA_KEY(_FILE)",
        ));
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(encoded.as_bytes(), &mut *key)
        .map_err(|_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY(_FILE)"))?;
    encoded.zeroize();
    Ok(key)
}

fn standard_key_reuses_token_pepper(token_pepper: &str, key: &[u8; 32]) -> bool {
    key_reuses_token_pepper(token_pepper, key)
}

fn key_reuses_token_pepper(token_pepper: &str, key: &[u8; 32]) -> bool {
    let raw_reuse =
        token_pepper.len() == key.len() && token_pepper.as_bytes().ct_eq(key).unwrap_u8() == 1;
    let mut decoded = Zeroizing::new([0_u8; 32]);
    let hex_reuse = token_pepper.len() == 64
        && hex::decode_to_slice(token_pepper.as_bytes(), &mut *decoded).is_ok()
        && decoded.as_slice().ct_eq(key).unwrap_u8() == 1;
    raw_reuse || hex_reuse
}

fn private_key_reuses_standard_data_key(
    private_key: &PrivateEvaluationHmacKey,
    standard_data_key: &[u8; 32],
) -> bool {
    private_key.material().ct_eq(standard_data_key).unwrap_u8() == 1
}

fn private_evaluation_hmac_key_from_env() -> Result<Option<PrivateEvaluationHmacKey>, ConfigError> {
    let inline = env::var_os(PRIVATE_EVALUATION_HMAC_KEY_INLINE_ENV);
    let file = env::var_os(PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV);
    private_evaluation_hmac_key_from_sources(inline.as_deref(), file.as_deref())
}

fn private_evaluation_hmac_key_from_sources(
    inline: Option<&OsStr>,
    file: Option<&OsStr>,
) -> Result<Option<PrivateEvaluationHmacKey>, ConfigError> {
    if inline.is_some() {
        // 有意不接受 inline Secret，避免环境快照、进程检查和崩溃报告泄露密钥。
        return Err(ConfigError::InvalidSecret(
            PRIVATE_EVALUATION_HMAC_KEY_INLINE_ENV,
        ));
    }
    let Some(path) = file else {
        return Ok(None);
    };
    read_private_evaluation_hmac_key_file(Path::new(path)).map(Some)
}

fn private_evaluation_budget_from_env() -> Result<Option<PrivateEvaluationBudgetConfig>, ConfigError>
{
    let catalog = optional_unicode_env(PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT_ENV)?;
    let account = optional_unicode_env(PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT_ENV)?;
    let device = optional_unicode_env(PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT_ENV)?;
    let node = optional_unicode_env(PRIVATE_EVALUATION_NODE_HOURLY_LIMIT_ENV)?;
    let cooldown = optional_unicode_env(PRIVATE_EVALUATION_COOLDOWN_SECONDS_ENV)?;
    let reserve = optional_unicode_env(PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES_ENV)?;
    private_evaluation_budget_from_values(
        catalog.as_deref(),
        account.as_deref(),
        device.as_deref(),
        node.as_deref(),
        cooldown.as_deref(),
        reserve.as_deref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn private_evaluation_budget_from_values(
    catalog_hourly_limit: Option<&str>,
    account_hourly_limit: Option<&str>,
    device_hourly_limit: Option<&str>,
    node_hourly_limit: Option<&str>,
    cooldown_seconds: Option<&str>,
    global_reserve_entries: Option<&str>,
) -> Result<Option<PrivateEvaluationBudgetConfig>, ConfigError> {
    if [
        catalog_hourly_limit,
        account_hourly_limit,
        device_hourly_limit,
        node_hourly_limit,
        cooldown_seconds,
        global_reserve_entries,
    ]
    .iter()
    .all(Option::is_none)
    {
        return Ok(None);
    }

    let catalog_hourly_limit = required_bounded_private_u32(
        PRIVATE_EVALUATION_CATALOG_HOURLY_LIMIT_ENV,
        catalog_hourly_limit,
        1,
        MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
    )?;
    let account_hourly_limit = required_bounded_private_u32(
        PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT_ENV,
        account_hourly_limit,
        1,
        MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
    )?;
    let device_hourly_limit = required_bounded_private_u32(
        PRIVATE_EVALUATION_DEVICE_HOURLY_LIMIT_ENV,
        device_hourly_limit,
        1,
        MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
    )?;
    let node_hourly_limit = required_bounded_private_u32(
        PRIVATE_EVALUATION_NODE_HOURLY_LIMIT_ENV,
        node_hourly_limit,
        1,
        MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
    )?;
    let cooldown_seconds = required_bounded_private_u64(
        PRIVATE_EVALUATION_COOLDOWN_SECONDS_ENV,
        cooldown_seconds,
        1,
        MAX_PRIVATE_EVALUATION_COOLDOWN_SECONDS,
    )?;
    let global_reserve_entries = required_bounded_private_u32(
        PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES_ENV,
        global_reserve_entries,
        0,
        MAX_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES,
    )?;
    Ok(Some(PrivateEvaluationBudgetConfig {
        catalog_hourly_limit,
        account_hourly_limit,
        device_hourly_limit,
        node_hourly_limit,
        cooldown: Duration::from_secs(cooldown_seconds),
        global_reserve_entries,
    }))
}

fn optional_unicode_env(name: &'static str) -> Result<Option<String>, ConfigError> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    value
        .into_string()
        .map(Some)
        .map_err(|_| ConfigError::InvalidValue {
            name,
            value: "不是 UTF-8".to_owned(),
        })
}

fn required_bounded_private_u32(
    name: &'static str,
    raw: Option<&str>,
    minimum: u32,
    maximum: u32,
) -> Result<u32, ConfigError> {
    let raw = raw.ok_or(ConfigError::Missing(name))?;
    raw.parse::<u32>()
        .ok()
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| ConfigError::InvalidValue {
            name,
            value: raw.to_owned(),
        })
}

fn required_bounded_private_u64(
    name: &'static str,
    raw: Option<&str>,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    let raw = raw.ok_or(ConfigError::Missing(name))?;
    raw.parse::<u64>()
        .ok()
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or_else(|| ConfigError::InvalidValue {
            name,
            value: raw.to_owned(),
        })
}

fn read_private_evaluation_hmac_key_file(
    path: &Path,
) -> Result<PrivateEvaluationHmacKey, ConfigError> {
    let invalid = || ConfigError::InvalidSecret(PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV);
    if !path.is_absolute() {
        return Err(invalid());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES
    {
        return Err(invalid());
    }
    let canonical = fs::canonicalize(path).map_err(|_| invalid())?;
    // `Path` 的组件比较会折叠 `.`；Secret 路径合同要求调用方直接提供规范绝对路径，
    // 因此必须比较原始 OS 字符串，不能接受文本上非规范但组件等价的路径。
    if canonical.as_os_str() != path.as_os_str() {
        return Err(invalid());
    }
    validate_private_evaluation_hmac_key_permissions(&canonical, &metadata)?;

    let mut file = File::open(&canonical).map_err(|_| invalid())?;
    let opened = file.metadata().map_err(|_| invalid())?;
    if !same_secret_file(&metadata, &opened) {
        return Err(invalid());
    }
    let capacity =
        usize::try_from(PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES).map_err(|_| invalid())?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    (&mut file)
        .take(PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    if u64::try_from(encoded.len()).map_err(|_| invalid())?
        != PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES
        || !same_secret_file(&opened, &after)
    {
        return Err(invalid());
    }
    decode_private_evaluation_hmac_key(encoded)
}

fn decode_private_evaluation_hmac_key(
    mut encoded: Zeroizing<Vec<u8>>,
) -> Result<PrivateEvaluationHmacKey, ConfigError> {
    let prefix_length = PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX.len();
    let expected_length = usize::try_from(PRIVATE_EVALUATION_HMAC_KEY_FILE_BYTES)
        .map_err(|_| ConfigError::InvalidSecret(PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV))?;
    let hex_end = prefix_length + 64;
    if encoded.len() != expected_length
        || !encoded.starts_with(PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX)
        || encoded.get(hex_end) != Some(&b'\n')
        || !encoded[prefix_length..hex_end]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        encoded.zeroize();
        return Err(ConfigError::InvalidSecret(
            PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV,
        ));
    }
    let mut material = Zeroizing::new([0_u8; 32]);
    if hex::decode_to_slice(&encoded[prefix_length..hex_end], &mut *material).is_err() {
        encoded.zeroize();
        return Err(ConfigError::InvalidSecret(
            PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV,
        ));
    }
    encoded.zeroize();
    Ok(PrivateEvaluationHmacKey::version_one(*material))
}

#[cfg(unix)]
fn validate_private_evaluation_hmac_key_permissions(
    canonical: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let invalid = || ConfigError::InvalidSecret(PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV);
    let permission_bits = metadata.permissions().mode() & 0o777;
    let compose_secret_mount = canonical.parent() == Some(Path::new("/run/secrets"));
    if permission_bits & 0o022 != 0 || (!compose_secret_mount && permission_bits & 0o077 != 0) {
        return Err(invalid());
    }
    for parent in canonical.ancestors().skip(1) {
        let parent_metadata = fs::symlink_metadata(parent).map_err(|_| invalid())?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.permissions().mode() & 0o022 != 0
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_evaluation_hmac_key_permissions(
    _canonical: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(unix)]
fn same_secret_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_secret_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.is_file() == right.is_file()
}

fn read_standard_data_key_file(path: &Path) -> Result<Zeroizing<String>, ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"));
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"))?;
    if canonical != path {
        return Err(ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permission_bits = metadata.permissions().mode() & 0o777;
        let compose_secret_mount = canonical.parent() == Some(Path::new("/run/secrets"));
        if permission_bits & 0o022 != 0 || (!compose_secret_mount && permission_bits & 0o077 != 0) {
            return Err(ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"));
        }
        for parent in canonical.ancestors().skip(1) {
            let parent_metadata = std::fs::symlink_metadata(parent)
                .map_err(|_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"))?;
            if parent_metadata.file_type().is_symlink()
                || !parent_metadata.is_dir()
                || parent_metadata.permissions().mode() & 0o022 != 0
            {
                return Err(ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"));
            }
        }
    }
    Ok(Zeroizing::new(std::fs::read_to_string(canonical).map_err(
        |_| ConfigError::InvalidSecret("MINDONE_STANDARD_DATA_KEY_FILE"),
    )?))
}

fn parse_or<T>(name: &'static str, default: &'static str) -> Result<T, ConfigError>
where
    T: FromStr,
{
    env::var(name)
        .unwrap_or_else(|_| default.to_owned())
        .parse()
        .map_err(|_| ConfigError::InvalidValue {
            name,
            value: env::var(name).unwrap_or_else(|_| default.to_owned()),
        })
}

fn bounded_parse_or<T>(
    name: &'static str,
    default: &'static str,
    minimum: T,
    maximum: T,
) -> Result<T, ConfigError>
where
    T: FromStr + PartialOrd + ToString,
{
    let value = parse_or::<T>(name, default)?;
    if value < minimum || value > maximum {
        return Err(ConfigError::InvalidValue {
            name,
            value: value.to_string(),
        });
    }
    Ok(value)
}

fn validate_database_max_connections(value: u32) -> Result<u32, ConfigError> {
    if !(1..=MAX_RUNTIME_DATABASE_CONNECTIONS).contains(&value) {
        return Err(ConfigError::InvalidValue {
            name: "MINDONE_DB_MAX_CONNECTIONS",
            value: value.to_string(),
        });
    }
    Ok(value)
}

fn valid_public_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value
            .chars()
            .any(|character| character.is_ascii_whitespace() || character.is_control())
}

fn validated_github_scope() -> Result<String, ConfigError> {
    let scope = env::var("MINDONE_GITHUB_SCOPE").unwrap_or_else(|_| "read:user".to_owned());
    if scope != "read:user" {
        return Err(ConfigError::InvalidValue {
            name: "MINDONE_GITHUB_SCOPE",
            value: "v1 只允许最小权限 read:user".to_owned(),
        });
    }
    Ok(scope)
}

fn default_trusted_proxy_ips() -> BTreeSet<IpAddr> {
    [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .collect()
}

fn trusted_proxy_ips_from_env() -> Result<BTreeSet<IpAddr>, ConfigError> {
    let Some(raw) = env::var_os("MINDONE_TRUSTED_PROXY_IPS") else {
        return Ok(default_trusted_proxy_ips());
    };
    let raw = raw.into_string().map_err(|_| ConfigError::InvalidValue {
        name: "MINDONE_TRUSTED_PROXY_IPS",
        value: "不是 UTF-8".to_owned(),
    })?;
    let addresses = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::InvalidValue {
                    name: "MINDONE_TRUSTED_PROXY_IPS",
                    value: "只允许逗号分隔的精确 IPv4/IPv6 地址".to_owned(),
                })
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if addresses.is_empty() || addresses.len() > 32 {
        return Err(ConfigError::InvalidValue {
            name: "MINDONE_TRUSTED_PROXY_IPS",
            value: "必须包含 1 到 32 个精确 IP 地址".to_owned(),
        });
    }
    Ok(addresses)
}

fn bounded_duration(
    name: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<Duration, ConfigError> {
    let value = match env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .map_err(|_| ConfigError::InvalidValue { name, value: raw })?,
        Err(_) => default,
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(ConfigError::InvalidValue {
            name,
            value: value.to_string(),
        });
    }
    Ok(Duration::from_secs(value))
}

fn attestation_config_from_env(
    verifier_name: &'static str,
    policy_name: &'static str,
    runtime_name: &'static str,
    measurement_name: &'static str,
) -> Result<HardwareAttestationConfig, ConfigError> {
    Ok(HardwareAttestationConfig {
        verifier_path: optional_fixed_program(verifier_name)?,
        allowed_policy_hashes: parse_sha256_allowlist(policy_name)?,
        allowed_runtime_hashes: parse_sha256_allowlist(runtime_name)?,
        allowed_tee_measurements: parse_measurement_allowlist(measurement_name)?,
    })
}

fn optional_fixed_program(name: &'static str) -> Result<Option<PathBuf>, ConfigError> {
    let Some(raw) = env::var_os(name) else {
        return Ok(None);
    };
    let path = Path::new(&raw);
    if !path.is_absolute() {
        return Err(ConfigError::InvalidValue {
            name,
            value: path.display().to_string(),
        });
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: path.display().to_string(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::InvalidValue {
            name,
            value: path.display().to_string(),
        });
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: path.display().to_string(),
    })?;
    Ok(Some(canonical))
}

fn optional_fixed_data_file(name: &'static str) -> Result<Option<PathBuf>, ConfigError> {
    let Some(raw) = env::var_os(name) else {
        return Ok(None);
    };
    let path = Path::new(&raw);
    if !path.is_absolute() {
        return Err(ConfigError::InvalidValue {
            name,
            value: "必须是绝对普通文件路径".to_owned(),
        });
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: "文件不存在或不可访问".to_owned(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ConfigError::InvalidValue {
            name,
            value: "必须是非符号链接的普通文件".to_owned(),
        });
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: "无法规范化文件路径".to_owned(),
    })?;
    Ok(Some(canonical))
}

fn optional_fixed_directory(name: &'static str) -> Result<Option<PathBuf>, ConfigError> {
    let Some(raw) = env::var_os(name) else {
        return Ok(None);
    };
    let path = Path::new(&raw);
    if !path.is_absolute() {
        return Err(ConfigError::InvalidValue {
            name,
            value: "必须是规范绝对目录路径".to_owned(),
        });
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: "目录不存在或不可访问".to_owned(),
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ConfigError::InvalidValue {
            name,
            value: "必须是非符号链接目录".to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(ConfigError::InvalidValue {
                name,
                value: "目录不得允许 group/other 写入".to_owned(),
            });
        }
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| ConfigError::InvalidValue {
        name,
        value: "无法规范化目录路径".to_owned(),
    })?;
    if canonical != path {
        return Err(ConfigError::InvalidValue {
            name,
            value: "必须使用规范绝对路径且父链不得含符号链接".to_owned(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for ancestor in canonical.ancestors() {
            let ancestor_metadata =
                std::fs::symlink_metadata(ancestor).map_err(|_| ConfigError::InvalidValue {
                    name,
                    value: "无法检查目录父链权限".to_owned(),
                })?;
            if ancestor_metadata.file_type().is_symlink()
                || !ancestor_metadata.is_dir()
                || ancestor_metadata.permissions().mode() & 0o022 != 0
            {
                return Err(ConfigError::InvalidValue {
                    name,
                    value: "目录及全部父目录不得是符号链接或允许 group/other 写入".to_owned(),
                });
            }
        }
    }
    Ok(Some(canonical))
}

fn parse_sha256_allowlist(name: &'static str) -> Result<BTreeSet<String>, ConfigError> {
    let values = parse_allowlist(name)?;
    if values.iter().any(|value| {
        value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ConfigError::InvalidValue {
            name,
            value: "包含非 64 位小写 SHA-256".to_owned(),
        });
    }
    Ok(values)
}

fn parse_measurement_allowlist(name: &'static str) -> Result<BTreeSet<String>, ConfigError> {
    let values = parse_allowlist(name)?;
    if values.iter().any(|value| {
        value.len() < 64
            || value.len() > 128
            || !value.len().is_multiple_of(2)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ConfigError::InvalidValue {
            name,
            value: "TEE measurement 必须是 32 到 64 字节的小写十六进制".to_owned(),
        });
    }
    Ok(values)
}

fn parse_allowlist(name: &'static str) -> Result<BTreeSet<String>, ConfigError> {
    let Some(raw) = env::var_os(name) else {
        return Ok(BTreeSet::new());
    };
    let raw = raw.into_string().map_err(|_| ConfigError::InvalidValue {
        name,
        value: "不是 UTF-8".to_owned(),
    })?;
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if values.is_empty() {
        return Err(ConfigError::InvalidValue {
            name,
            value: "allowlist 为空".to_owned(),
        });
    }
    Ok(values)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("缺少必需配置 {0}")]
    Missing(&'static str),
    #[error("配置 {name} 的值无效：{value}")]
    InvalidValue { name: &'static str, value: String },
    #[error("{0} 至少需要 32 个字符")]
    WeakSecret(&'static str),
    #[error("{0} 与 {1} 不能同时配置")]
    ConflictingSecrets(&'static str, &'static str),
    #[error("{0} 与 {1} 必须使用彼此独立的 Secret，不能复用相同密钥材料")]
    SecretReuse(&'static str, &'static str),
    #[error("配置 {0} 无效；必须提供恰好 32 字节的小写十六进制 Secret，内容已隐去")]
    InvalidSecret(&'static str),
    #[error("协调服务器默认只允许监听回环地址，拒绝 {0}；容器内使用需显式设置 MINDONE_ALLOW_NON_LOOPBACK=true，并把宿主机端口限制在 127.0.0.1")]
    UnsafeBind(SocketAddr),
    #[error("local-development 认证提供者只能在 development 或 test 环境启用")]
    DevelopmentProviderInProduction,
    #[error("production 环境的 PostgreSQL TCP 连接必须显式使用 sslmode=verify-full；只有 Unix socket 可以不使用 TLS；DATABASE_URL 已隐去")]
    UnsafeDatabaseTransport,
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::Path;
    use std::{ffi::OsStr, time::Duration};

    use super::{
        bounded_parse_or, decode_private_evaluation_hmac_key, decode_standard_data_key,
        default_trusted_proxy_ips, key_reuses_token_pepper, parse_measurement_allowlist,
        parse_sha256_allowlist, private_evaluation_budget_from_values,
        private_evaluation_hmac_key_from_sources, private_key_reuses_standard_data_key,
        standard_key_reuses_token_pepper, valid_public_identifier,
        validate_database_max_connections, validate_database_transport, validate_provider,
        validate_public_url, AuthProviderKind, Config, ConfigError, PrivateEvaluationHmacKey,
        RuntimeEnvironment, MAX_PRIVATE_EVALUATION_COOLDOWN_SECONDS,
        MAX_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES, MAX_PRIVATE_EVALUATION_HOURLY_LIMIT,
        MAX_RUNTIME_DATABASE_CONNECTIONS, PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV,
        PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX,
    };
    #[cfg(unix)]
    use super::{read_private_evaluation_hmac_key_file, read_standard_data_key_file};
    use zeroize::Zeroizing;

    #[test]
    fn production_rejects_local_development_provider() {
        let result = validate_provider(
            RuntimeEnvironment::Production,
            AuthProviderKind::LocalDevelopment,
        );
        assert!(result.is_err());
    }

    #[test]
    fn email_provider_and_public_url_are_fail_closed() {
        assert_eq!(
            "email".parse::<AuthProviderKind>().expect("email 应可解析"),
            AuthProviderKind::Email
        );
        assert_eq!(
            validate_public_url(
                RuntimeEnvironment::Development,
                AuthProviderKind::Email,
                "http://127.0.0.1:8787/",
            )
            .expect("开发 loopback HTTP 应可用"),
            "http://127.0.0.1:8787"
        );
        assert!(validate_public_url(
            RuntimeEnvironment::Production,
            AuthProviderKind::Email,
            "http://example.com",
        )
        .is_err());
        assert!(validate_public_url(
            RuntimeEnvironment::Production,
            AuthProviderKind::Email,
            "https://user:secret@example.com/callback?token=secret",
        )
        .is_err());
    }

    #[test]
    fn development_accepts_local_development_provider() {
        let result = validate_provider(
            RuntimeEnvironment::Development,
            AuthProviderKind::LocalDevelopment,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn production_database_transport_rejects_tcp_without_server_identity_verification() {
        for database_url in [
            "postgres://mindone:very-secret@postgres:5432/mindone",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=disable",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=allow",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=prefer",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=verify-ca",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=require",
            "postgres://mindone:very-secret@127.0.0.1:5432/mindone",
            "postgres://mindone:very-secret@localhost:5432/mindone?sslmode=require",
            "postgres://mindone:very-secret@127.0.0.1:5432/mindone?host=postgres",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=require&debug_token=very-secret",
            "postgres://mindone:very-secret@postgres:5432/mindone?sslmode=require#unsafe-fragment",
        ] {
            let error = validate_database_transport(RuntimeEnvironment::Production, database_url)
                .expect_err("production TCP 数据库必须验证服务端身份");
            assert!(!error.to_string().contains("very-secret"));
        }
    }

    #[test]
    fn production_database_transport_accepts_verify_full() {
        validate_database_transport(
            RuntimeEnvironment::Production,
            "postgres://mindone@postgres:5432/mindone?sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.crt",
        )
        .expect("verify-full 应通过 production 传输门禁");
    }

    #[test]
    fn database_transport_allows_unix_socket_and_development_exception() {
        validate_database_transport(
            RuntimeEnvironment::Production,
            "postgres:///mindone?host=/var/run/postgresql",
        )
        .expect("Unix socket 不经过 TCP");
        validate_database_transport(
            RuntimeEnvironment::Development,
            "postgres://mindone@postgres:5432/mindone",
        )
        .expect("development 环境可以使用隔离的明文测试数据库");
    }

    #[test]
    fn default_test_config_requests_no_email_scope() {
        let config = Config::development_for_tests("postgres://invalid".to_owned());
        assert_eq!(config.github_scope, "read:user");
        assert!(!config.github_scope.contains("email"));
        assert_eq!(config.trusted_proxy_ips, default_trusted_proxy_ips());
        assert!(config.asn_map_path.is_none());
        assert!(config.quality_evaluator_keys_dir.is_none());
        let private_key = config
            .private_evaluation_hmac_key
            .as_ref()
            .expect("测试配置应显式提供独立 private-hidden HMAC key");
        assert_eq!(private_key.version(), 1);
        assert_eq!(private_key.material(), &[0xa7; 32]);
        let budget = config
            .private_evaluation_budget
            .as_ref()
            .expect("测试配置应显式提供有限 private-hidden 预算");
        assert_eq!(budget.catalog_hourly_limit, 4_096);
        assert_eq!(budget.cooldown, Duration::from_secs(1));
        assert_eq!(budget.global_reserve_entries, 1);
    }

    #[test]
    fn private_evaluation_budget_has_no_production_defaults_and_requires_complete_group() {
        assert!(
            private_evaluation_budget_from_values(None, None, None, None, None, None)
                .expect("完全缺失时应保持未配置")
                .is_none()
        );

        let error = private_evaluation_budget_from_values(
            Some("10"),
            None,
            Some("3"),
            Some("4"),
            Some("60"),
            Some("0"),
        )
        .expect_err("部分配置必须失败关闭");
        assert!(matches!(
            error,
            ConfigError::Missing("MINDONE_PRIVATE_EVALUATION_ACCOUNT_HOURLY_LIMIT")
        ));
    }

    #[test]
    fn private_evaluation_budget_is_explicit_bounded_and_allows_zero_reserve() {
        let budget = private_evaluation_budget_from_values(
            Some("10"),
            Some("2"),
            Some("3"),
            Some("4"),
            Some("60"),
            Some("0"),
        )
        .expect("完整预算应解析")
        .expect("完整预算应启用");
        assert_eq!(budget.catalog_hourly_limit, 10);
        assert_eq!(budget.account_hourly_limit, 2);
        assert_eq!(budget.device_hourly_limit, 3);
        assert_eq!(budget.node_hourly_limit, 4);
        assert_eq!(budget.cooldown, Duration::from_secs(60));
        assert_eq!(budget.global_reserve_entries, 0);

        let maximum = private_evaluation_budget_from_values(
            Some(&MAX_PRIVATE_EVALUATION_HOURLY_LIMIT.to_string()),
            Some("1"),
            Some("1"),
            Some("1"),
            Some(&MAX_PRIVATE_EVALUATION_COOLDOWN_SECONDS.to_string()),
            Some(&MAX_PRIVATE_EVALUATION_GLOBAL_RESERVE_ENTRIES.to_string()),
        );
        assert!(maximum.is_ok());

        for invalid in [
            ("0", "1", "1", "1", "60", "0"),
            ("4097", "1", "1", "1", "60", "0"),
            ("1", "1", "1", "1", "0", "0"),
            ("1", "1", "1", "1", "86401", "0"),
            ("1", "1", "1", "1", "60", "4096"),
        ] {
            assert!(private_evaluation_budget_from_values(
                Some(invalid.0),
                Some(invalid.1),
                Some(invalid.2),
                Some(invalid.3),
                Some(invalid.4),
                Some(invalid.5),
            )
            .is_err());
        }
    }

    #[test]
    fn allowlist_parsers_are_fail_closed_without_environment() {
        // 使用不可能与生产配置冲突的测试变量名；未设置必须得到空集合，
        // deployable() 随后会拒绝启动挑战。
        assert!(parse_sha256_allowlist("MINDONE_TEST_ONLY_MISSING_SHA256")
            .expect("缺失 allowlist 应可解析为空")
            .is_empty());
        assert!(
            parse_measurement_allowlist("MINDONE_TEST_ONLY_MISSING_MEASUREMENT")
                .expect("缺失 measurement allowlist 应可解析为空")
                .is_empty()
        );
    }

    #[test]
    fn public_identifiers_reject_whitespace_and_control_characters() {
        assert!(valid_public_identifier("Iv1.0123456789abcdef", 256));
        assert!(!valid_public_identifier("", 256));
        assert!(!valid_public_identifier("client id", 256));
        assert!(!valid_public_identifier("client\nid", 256));
    }

    #[test]
    fn bounded_values_reject_unsafe_defaults_without_touching_process_environment() {
        assert_eq!(
            bounded_parse_or::<u32>("MINDONE_TEST_ONLY_MISSING_BOUND", "10", 1, 20)
                .expect("范围内默认值应通过"),
            10
        );
        assert!(bounded_parse_or::<u32>("MINDONE_TEST_ONLY_MISSING_HIGH", "21", 1, 20).is_err());
        assert!(bounded_parse_or::<i32>("MINDONE_TEST_ONLY_MISSING_LOW", "-1", 0, 20).is_err());
    }

    #[test]
    fn database_pool_limit_matches_runtime_role_contract() {
        assert_eq!(
            validate_database_max_connections(10).expect("默认连接池大小应通过"),
            10
        );
        assert_eq!(
            validate_database_max_connections(MAX_RUNTIME_DATABASE_CONNECTIONS)
                .expect("角色连接上限本身应通过"),
            MAX_RUNTIME_DATABASE_CONNECTIONS
        );
        for value in [0, 33, 256] {
            let error =
                validate_database_max_connections(value).expect_err("越界连接池大小必须失败关闭");
            assert!(error
                .to_string()
                .starts_with("配置 MINDONE_DB_MAX_CONNECTIONS 的值无效"));
            match error {
                ConfigError::InvalidValue {
                    name,
                    value: rejected,
                } => {
                    assert_eq!(name, "MINDONE_DB_MAX_CONNECTIONS");
                    assert_eq!(rejected, value.to_string());
                }
                other => panic!("错误类型不符合配置合同：{other}"),
            }
        }
    }

    #[test]
    fn standard_data_key_requires_exact_lowercase_hex() {
        assert_eq!(
            &*decode_standard_data_key(Zeroizing::new("5a".repeat(32)))
                .expect("64 位小写 hex 应解析"),
            &[0x5a; 32]
        );
        for invalid in ["5A".repeat(32), "5a".repeat(31), "zz".repeat(32)] {
            let error = decode_standard_data_key(Zeroizing::new(invalid.clone()))
                .expect_err("不规范 Secret 必须拒绝");
            assert!(!error.to_string().contains(&invalid));
        }
    }

    #[test]
    fn standard_data_key_must_not_reuse_token_pepper_material() {
        let key = [0x5a; 32];
        assert!(standard_key_reuses_token_pepper(&"Z".repeat(32), &key));
        assert!(standard_key_reuses_token_pepper(&"5a".repeat(32), &key));
        assert!(!standard_key_reuses_token_pepper(&"5b".repeat(32), &key));
        assert!(!standard_key_reuses_token_pepper(
            "mindone-independent-token-pepper-material",
            &key
        ));
    }

    #[test]
    fn private_evaluation_hmac_key_requires_versioned_exact_format() {
        let valid = format!(
            "{}{}\n",
            std::str::from_utf8(PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX)
                .expect("固定前缀应为 UTF-8"),
            "a7".repeat(32)
        );
        let key = decode_private_evaluation_hmac_key(Zeroizing::new(valid.as_bytes().to_vec()))
            .expect("规范 v1 key 文件应通过");
        assert_eq!(key.version(), 1);
        assert_eq!(key.material(), &[0xa7; 32]);

        for invalid in [
            valid.trim_end().as_bytes().to_vec(),
            format!(
                "{}{}\n",
                std::str::from_utf8(PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX)
                    .expect("固定前缀应为 UTF-8"),
                "A7".repeat(32)
            )
            .into_bytes(),
            format!("mindone-private-hidden-hmac-v2:{}\n", "a7".repeat(32)).into_bytes(),
            format!(
                "{}{}\r\n",
                std::str::from_utf8(PRIVATE_EVALUATION_HMAC_KEY_FILE_PREFIX)
                    .expect("固定前缀应为 UTF-8"),
                "a7".repeat(32)
            )
            .into_bytes(),
        ] {
            let rendered = String::from_utf8_lossy(&invalid).into_owned();
            let error = decode_private_evaluation_hmac_key(Zeroizing::new(invalid))
                .expect_err("非规范 key 文件必须失败关闭");
            assert_eq!(
                error.to_string(),
                ConfigError::InvalidSecret(PRIVATE_EVALUATION_HMAC_KEY_FILE_ENV).to_string()
            );
            assert!(!error.to_string().contains(&rendered));
        }
    }

    #[test]
    fn private_evaluation_hmac_key_has_no_inline_source_and_is_optional() {
        assert!(private_evaluation_hmac_key_from_sources(None, None)
            .expect("缺失可选 key 文件应明确禁用 private-hidden HMAC")
            .is_none());
        let inline = OsStr::new("a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7");
        let error = private_evaluation_hmac_key_from_sources(Some(inline), None)
            .expect_err("inline private-hidden HMAC key 必须拒绝");
        assert!(!error
            .to_string()
            .contains(inline.to_string_lossy().as_ref()));
    }

    #[test]
    fn private_evaluation_hmac_key_must_not_reuse_other_secret_material() {
        let private_key = PrivateEvaluationHmacKey::version_one([0xa7; 32]);
        assert!(key_reuses_token_pepper(
            &"a7".repeat(32),
            private_key.material()
        ));
        let raw_key = PrivateEvaluationHmacKey::version_one([b'Z'; 32]);
        assert!(key_reuses_token_pepper(&"Z".repeat(32), raw_key.material()));
        assert!(!key_reuses_token_pepper(
            "mindone-independent-token-pepper-material",
            private_key.material()
        ));
        assert!(private_key_reuses_standard_data_key(
            &private_key,
            &[0xa7; 32]
        ));
        assert!(!private_key_reuses_standard_data_key(
            &private_key,
            &[0x5a; 32]
        ));
    }

    #[test]
    fn private_evaluation_hmac_key_debug_is_redacted() {
        let key = PrivateEvaluationHmacKey::version_one([0xa7; 32]);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("version: 1"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&"a7".repeat(32)));
        assert!(!rendered.contains("167, 167"));
    }

    #[cfg(unix)]
    #[test]
    fn private_evaluation_hmac_key_file_rejects_bad_paths_permissions_and_symlinks() {
        use std::{fs, os::unix::fs::symlink, os::unix::fs::PermissionsExt};

        let parent = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("crate 目录应可规范化");
        let directory = tempfile::Builder::new()
            .prefix(".mindone-private-hmac-key-test-")
            .tempdir_in(parent)
            .expect("应能在受控目录创建临时测试目录");
        let directory = fs::canonicalize(directory.path()).expect("临时目录应可规范化");
        let key_path = directory.join("private-hidden-hmac-key");
        fs::write(
            &key_path,
            format!("mindone-private-hidden-hmac-v1:{}\n", "a7".repeat(32)),
        )
        .expect("应写入测试 Secret");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("应收紧测试 Secret 权限");
        assert!(read_private_evaluation_hmac_key_file(&key_path).is_ok());
        assert!(read_private_evaluation_hmac_key_file(Path::new("relative-key")).is_err());
        assert!(read_private_evaluation_hmac_key_file(
            &directory.join(".").join("private-hidden-hmac-key")
        )
        .is_err());

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
            .expect("应设置不安全测试权限");
        assert!(read_private_evaluation_hmac_key_file(&key_path).is_err());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("应恢复测试权限");
        let link_path = directory.join("linked-private-hidden-hmac-key");
        symlink(&key_path, &link_path).expect("应创建测试符号链接");
        assert!(read_private_evaluation_hmac_key_file(&link_path).is_err());
        assert!(read_private_evaluation_hmac_key_file(&directory).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn standard_data_key_file_rejects_loose_permissions_and_symlinks() {
        use std::{fs, os::unix::fs::symlink, os::unix::fs::PermissionsExt};

        let current = std::env::current_dir().expect("应能读取当前目录");
        let directory = tempfile::Builder::new()
            .prefix(".mindone-standard-key-test-")
            .tempdir_in(current)
            .expect("应能在受控目录创建临时测试目录");
        let key_path = directory.path().join("standard-data-key");
        fs::write(&key_path, format!("{}\n", "5a".repeat(32))).expect("应能写入测试 Secret");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("应能收紧测试 Secret 权限");
        assert!(read_standard_data_key_file(&key_path).is_ok());

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o620))
            .expect("应能设置不安全测试权限");
        assert!(read_standard_data_key_file(&key_path).is_err());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
            .expect("应能设置世界可读测试权限");
        assert!(read_standard_data_key_file(&key_path).is_err());
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("应能恢复测试权限");
        let link_path = directory.path().join("linked-key");
        symlink(&key_path, &link_path).expect("应能创建测试符号链接");
        assert!(read_standard_data_key_file(&link_path).is_err());
    }
}
