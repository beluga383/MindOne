use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use mindone_common::redact::is_sensitive_key;
use mindone_common::{validate_endpoint, Config, ConfigKey};
use url::Url;

use crate::error::{CliError, CliResult};

pub type AppConfig = Config;

#[derive(Debug, Clone)]
pub struct ConfigStore {
    path: PathBuf,
}

impl ConfigStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> CliResult<AppConfig> {
        Config::load(&self.path).map_err(common_config_error)
    }

    pub fn save(&self, config: &AppConfig) -> CliResult<()> {
        config.save_atomic(&self.path).map_err(common_config_error)
    }
}

pub fn config_get(config: &AppConfig, key: &str) -> CliResult<String> {
    config
        .get(canonical_config_key(key)?.as_str())
        .map_err(common_config_error)
}

pub fn config_set(config: &mut AppConfig, key: &str, value: &str) -> CliResult<()> {
    if sensitive_config_key(key) {
        return Err(CliError::General(
            "敏感值禁止写入 config.toml；请使用系统凭证库".to_owned(),
        ));
    }
    config
        .set(canonical_config_key(key)?.as_str(), value)
        .map_err(common_config_error)
}

pub fn config_list(config: &AppConfig) -> BTreeMap<String, String> {
    config.list()
}

pub fn validate_server_url(raw: &str) -> CliResult<Url> {
    validate_endpoint(raw)
        .map(|(url, _security)| url)
        .map_err(common_config_error)
}

fn normalize_key(key: &str) -> &str {
    match key {
        "server.url" => "server_url",
        "engine.default" => "default_engine",
        "log.level" => "log_level",
        "data.dir" => "data_dir",
        "update.channel" => "update_channel",
        "oauth.github_client_id" => "github_client_id",
        "cloudflare.hostname" => "cloudflare_hostname",
        other => other,
    }
}

pub fn canonical_config_key(key: &str) -> CliResult<ConfigKey> {
    ConfigKey::from_str(normalize_key(key)).map_err(common_config_error)
}

fn sensitive_config_key(key: &str) -> bool {
    is_sensitive_key(key)
        || key
            .split(['.', '/'])
            .filter(|component| !component.is_empty())
            .any(is_sensitive_key)
        || is_sensitive_key(&key.replace(['.', '/'], "_"))
}

fn common_config_error(error: impl std::fmt::Display) -> CliError {
    CliError::General(error.to_string())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{
        canonical_config_key, config_get, config_set, validate_server_url, AppConfig, ConfigStore,
    };

    #[test]
    fn only_loopback_may_use_http() {
        assert!(validate_server_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_server_url("https://api.example.com").is_ok());
        assert!(validate_server_url("http://api.example.com").is_err());
    }

    #[test]
    fn aliases_map_to_shared_config_keys() {
        let mut config = AppConfig::default();
        config_set(&mut config, "server.url", "https://api.example.com")
            .expect("点号别名应可写入共享配置");
        assert_eq!(
            config_get(&config, "server_url").expect("共享键应可读取"),
            "https://api.example.com/"
        );
        assert!(config_set(&mut config, "auth.token", "secret").is_err());
        assert_eq!(
            canonical_config_key("engine.default")
                .expect("点号别名应规范化")
                .as_str(),
            "default_engine"
        );
        assert_eq!(
            canonical_config_key("cloudflare.hostname")
                .expect("Cloudflare 点号别名应规范化")
                .as_str(),
            "cloudflare_hostname"
        );
        assert_eq!(
            canonical_config_key("default-engine")
                .expect("连字符别名应规范化")
                .as_str(),
            "default_engine"
        );
    }

    #[test]
    fn save_and_load_uses_shared_atomic_implementation() {
        let temp = TempDir::new().expect("应创建临时目录");
        let store = ConfigStore::new(temp.path().join("config.toml"));
        let mut config = AppConfig::default();
        config_set(&mut config, "github_client_id", "Iv1.safe-client-id")
            .expect("Client ID 不是 secret，应允许保存");
        store.save(&config).expect("应保存配置");
        let loaded = store.load().expect("应重新加载配置");
        assert_eq!(
            loaded.github_client_id.as_deref(),
            Some("Iv1.safe-client-id")
        );
    }
}
