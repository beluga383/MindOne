use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{MindOneError, Result};
use crate::paths::validate_data_home_candidate;
use crate::redact::is_sensitive_key;
use crate::transport::validate_url;

/// 新安装客户端的官方协调器。开发与测试必须通过 config set 或隔离配置文件显式
/// 选择 loopback，避免最终用户首次启动 TUI 后误连自己机器上不存在的服务。
pub const DEFAULT_SERVER_URL: &str = "https://api.holarchic.cn";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server_url: String,
    pub github_client_id: Option<String>,
    /// MindOne 专用 Cloudflare Published application 的公开 hostname；不含 scheme/path。
    pub cloudflare_hostname: Option<String>,
    pub default_engine: Option<String>,
    pub log_level: LogLevel,
    pub data_dir: Option<PathBuf>,
    pub update_channel: UpdateChannel,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            github_client_id: None,
            cloudflare_hostname: None,
            default_engine: None,
            log_level: LogLevel::Info,
            data_dir: None,
            update_channel: UpdateChannel::Stable,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn save_atomic(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .ok_or_else(|| MindOneError::Config("配置文件路径必须包含父目录".to_owned()))?;
        fs::create_dir_all(parent)?;
        let serialized = toml::to_string_pretty(self)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary.write_all(serialized.as_bytes())?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| MindOneError::Io(format!("原子替换配置文件失败：{}", error.error)))?;

        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn set(&mut self, raw_key: &str, raw_value: &str) -> Result<()> {
        if is_sensitive_key(raw_key) {
            return Err(MindOneError::Config(
                "敏感值不得通过 config 保存，请使用系统凭证库".to_owned(),
            ));
        }
        let key = ConfigKey::from_str(raw_key)?;
        let value = raw_value.trim();
        match key {
            ConfigKey::ServerUrl => {
                let url = Url::parse(value)
                    .map_err(|error| MindOneError::Config(format!("服务器地址无效：{error}")))?;
                validate_url(&url)?;
                self.server_url = url.to_string();
            }
            ConfigKey::GithubClientId => {
                validate_github_client_id(value)?;
                self.github_client_id = Some(value.to_owned());
            }
            ConfigKey::CloudflareHostname => {
                if value.is_empty() {
                    self.cloudflare_hostname = None;
                } else {
                    validate_cloudflare_hostname(value)?;
                    self.cloudflare_hostname = Some(value.to_ascii_lowercase());
                }
            }
            ConfigKey::DefaultEngine => {
                validate_default_engine(value)?;
                self.default_engine = Some(value.to_owned());
            }
            ConfigKey::LogLevel => self.log_level = LogLevel::from_str(value)?,
            ConfigKey::DataDir => {
                if value.is_empty() {
                    self.data_dir = None;
                } else {
                    let path = PathBuf::from(value);
                    validate_data_home_candidate(&path)?;
                    self.data_dir = Some(path);
                }
            }
            ConfigKey::UpdateChannel => self.update_channel = UpdateChannel::from_str(value)?,
        }
        self.validate()
    }

    pub fn get(&self, raw_key: &str) -> Result<String> {
        let key = ConfigKey::from_str(raw_key)?;
        Ok(match key {
            ConfigKey::ServerUrl => self.server_url.clone(),
            ConfigKey::GithubClientId => self.github_client_id.clone().unwrap_or_default(),
            ConfigKey::CloudflareHostname => self.cloudflare_hostname.clone().unwrap_or_default(),
            ConfigKey::DefaultEngine => self.default_engine.clone().unwrap_or_default(),
            ConfigKey::LogLevel => self.log_level.to_string(),
            ConfigKey::DataDir => self
                .data_dir
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            ConfigKey::UpdateChannel => self.update_channel.to_string(),
        })
    }

    pub fn list(&self) -> BTreeMap<String, String> {
        ConfigKey::ALL
            .iter()
            .filter_map(|key| {
                self.get(key.as_str())
                    .ok()
                    .map(|value| (key.as_str().to_owned(), value))
            })
            .collect()
    }

    pub fn validate(&self) -> Result<()> {
        let server_url = Url::parse(&self.server_url)
            .map_err(|error| MindOneError::Config(format!("服务器地址无效：{error}")))?;
        validate_url(&server_url)?;
        if self
            .github_client_id
            .as_deref()
            .is_some_and(|client_id| validate_github_client_id(client_id).is_err())
        {
            return Err(MindOneError::Config(
                "GitHub OAuth Client ID 无效".to_owned(),
            ));
        }
        if let Some(hostname) = &self.cloudflare_hostname {
            validate_cloudflare_hostname(hostname)?;
        }
        if let Some(engine) = &self.default_engine {
            validate_default_engine(engine)?;
        }
        if let Some(path) = &self.data_dir {
            validate_data_home_candidate(path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKey {
    ServerUrl,
    GithubClientId,
    CloudflareHostname,
    DefaultEngine,
    LogLevel,
    DataDir,
    UpdateChannel,
}

impl ConfigKey {
    pub const ALL: [Self; 7] = [
        Self::ServerUrl,
        Self::GithubClientId,
        Self::CloudflareHostname,
        Self::DefaultEngine,
        Self::LogLevel,
        Self::DataDir,
        Self::UpdateChannel,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServerUrl => "server_url",
            Self::GithubClientId => "github_client_id",
            Self::CloudflareHostname => "cloudflare_hostname",
            Self::DefaultEngine => "default_engine",
            Self::LogLevel => "log_level",
            Self::DataDir => "data_dir",
            Self::UpdateChannel => "update_channel",
        }
    }
}

impl FromStr for ConfigKey {
    type Err = MindOneError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
            "server_url" => Ok(Self::ServerUrl),
            "github_client_id" | "auth.github_client_id" => Ok(Self::GithubClientId),
            "cloudflare_hostname" | "cloudflare.hostname" => Ok(Self::CloudflareHostname),
            "default_engine" => Ok(Self::DefaultEngine),
            "log_level" => Ok(Self::LogLevel),
            "data_dir" => Ok(Self::DataDir),
            "update_channel" => Ok(Self::UpdateChannel),
            _ => Err(MindOneError::Config(format!(
                "未知配置键：{value}；允许的键为 server_url、github_client_id、cloudflare_hostname、default_engine、log_level、data_dir、update_channel"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
    Trace,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        })
    }
}

impl FromStr for LogLevel {
    type Err = MindOneError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(MindOneError::Config(format!("未知日志级别：{value}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    #[default]
    Stable,
    Beta,
    Nightly,
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        })
    }
}

impl FromStr for UpdateChannel {
    type Err = MindOneError;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            "nightly" => Ok(Self::Nightly),
            _ => Err(MindOneError::Config(format!("未知更新通道：{value}"))),
        }
    }
}

fn require_nonempty(value: &str, label: &str) -> Result<()> {
    if value.is_empty() {
        return Err(MindOneError::Config(format!("{label}不能为空")));
    }
    Ok(())
}

fn validate_default_engine(value: &str) -> Result<()> {
    require_nonempty(value, "默认引擎")?;
    if !matches!(value, "llama.cpp" | "vllm" | "ollama" | "tensorrt-llm") {
        return Err(MindOneError::Config(format!(
            "不支持的默认引擎：{value}；允许 llama.cpp、vllm、ollama、tensorrt-llm"
        )));
    }
    Ok(())
}

fn validate_github_client_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return Err(MindOneError::Config(
            "GitHub OAuth Client ID 格式无效".to_owned(),
        ));
    }
    Ok(())
}

fn validate_cloudflare_hostname(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value != value.trim()
        || value.contains(['/', ':', '*'])
        || value.parse::<IpAddr>().is_ok()
    {
        return Err(MindOneError::Config(
            "Cloudflare hostname 无效；只填写公开 DNS hostname，不含 scheme、端口、通配符或路径"
                .to_owned(),
        ));
    }
    let mut labels = value.split('.');
    let first = labels.next().unwrap_or_default();
    let remaining = labels.collect::<Vec<_>>();
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    };
    if !valid_label(first)
        || remaining.is_empty()
        || !remaining.iter().all(|label| valid_label(label))
        || !remaining
            .last()
            .is_some_and(|label| label.bytes().any(|byte| byte.is_ascii_alphabetic()))
    {
        return Err(MindOneError::Config(
            "Cloudflare hostname 必须是完整且有效的公开 DNS hostname".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;

    #[test]
    fn fresh_client_defaults_to_official_tls_origin() {
        let config = Config::default();
        assert_eq!(config.server_url, "https://api.holarchic.cn");
        config.validate().expect("官方默认地址必须通过 TLS 校验");
    }

    #[test]
    fn only_accepts_whitelisted_non_sensitive_keys() {
        let mut config = Config::default();
        config
            .set("server_url", "https://api.example.com")
            .expect("TLS 地址应有效");
        config
            .set("default-engine", "llama.cpp")
            .expect("白名单键应有效");
        config
            .set("auth.github_client_id", "Iv1.example-client")
            .expect("Client ID 不是 secret，应允许保存");
        config
            .set("cloudflare.hostname", "API.Example.COM")
            .expect("公开 hostname 不是 secret，应允许保存并规范化");
        assert_eq!(config.default_engine.as_deref(), Some("llama.cpp"));
        assert_eq!(
            config.github_client_id.as_deref(),
            Some("Iv1.example-client")
        );
        assert_eq!(
            config.cloudflare_hostname.as_deref(),
            Some("api.example.com")
        );
        for invalid in [
            "https://api.example.com",
            "api.example.com/ready",
            "*.example.com",
            "localhost",
            "-api.example.com",
            "api.example.123",
        ] {
            assert!(config.set("cloudflare_hostname", invalid).is_err());
        }
        config
            .set("cloudflare_hostname", "")
            .expect("空值应清除可选 hostname");
        assert!(config.cloudflare_hostname.is_none());
        assert!(config.set("default_engine", "unknown-engine").is_err());
        assert!(config.set("access_token", "secret").is_err());
        assert!(config.set("unknown", "value").is_err());
        assert!(config.set("server_url", "http://example.com").is_err());
    }

    #[test]
    fn atomically_round_trips_config() {
        let current = env::current_dir().expect("应读取当前目录");
        let directory = tempfile::tempdir_in(current).expect("应可创建受控临时目录");
        let path = directory.path().join("config.toml");
        let mut config = Config::default();
        config
            .set("default_engine", "llama.cpp")
            .expect("配置应有效");
        config
            .set("cloudflare_hostname", "api.example.com")
            .expect("Cloudflare hostname 应可持久化");
        config
            .set("data_dir", &directory.path().display().to_string())
            .expect("绝对路径应有效");
        config.save_atomic(&path).expect("保存应成功");
        let loaded = Config::load(&path).expect("读取应成功");
        assert_eq!(loaded, config);
        assert_eq!(loaded.list().len(), ConfigKey::ALL.len());

        config.set("log_level", "debug").expect("更新配置应有效");
        config.save_atomic(&path).expect("原子覆盖应成功");
        assert_eq!(
            Config::load(&path).expect("覆盖后应可读取").log_level,
            LogLevel::Debug
        );
    }

    #[test]
    fn data_dir_rejects_broad_paths_and_empty_value_resets_override() {
        let mut config = Config::default();
        let root = env::current_dir()
            .expect("应读取当前目录")
            .ancestors()
            .last()
            .expect("绝对路径应有根目录")
            .to_path_buf();
        assert!(config.set("data_dir", &root.display().to_string()).is_err());

        let safe = env::current_dir()
            .expect("应读取当前目录")
            .join("target/mindone-config-data");
        config
            .set("data_dir", &safe.display().to_string())
            .expect("受控绝对路径应有效");
        assert_eq!(config.data_dir.as_deref(), Some(safe.as_path()));
        config.set("data_dir", "   ").expect("空值应清除覆盖");
        assert!(config.data_dir.is_none());
    }

    #[test]
    fn denies_unknown_toml_fields() {
        let directory = tempfile::tempdir().expect("应可创建临时目录");
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "server_url = 'http://127.0.0.1:8787'\naccess_token = 'secret'\n",
        )
        .expect("应可写入测试配置");
        assert!(Config::load(&path).is_err());
    }
}
