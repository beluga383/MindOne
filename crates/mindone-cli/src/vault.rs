use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use mindone_common::{KeyringSecretStore, SecretStore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CliError, CliResult};

const SERVICE_PREFIX: &str = "org.mindone.cli";
const SESSION_ACCOUNT: &str = "session";
const DEVICE_KEY_ACCOUNT: &str = "device-signing-key";
const ATTESTATION_KEY_ACCOUNT: &str = "attestation-x25519-key";
const NAMESPACE_HEX_LENGTH: usize = 24;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CredentialBundle {
    pub access_token: String,
    pub refresh_token: String,
    /// 下一次 refresh 的一次性设备持有证明 challenge。
    /// 旧版凭证缺少时保持空值，refresh 路径会明确要求重新登录。
    #[serde(default)]
    pub refresh_challenge: String,
    #[zeroize(skip)]
    pub user: String,
    #[zeroize(skip)]
    pub uid: String,
    #[zeroize(skip)]
    #[serde(alias = "trust_level")]
    pub local_sandbox_trust_level: String,
    #[zeroize(skip)]
    pub key_fingerprint: String,
    #[zeroize(skip)]
    pub login_at: String,
}

impl fmt::Debug for CredentialBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBundle")
            .field("access_token", &"[已脱敏]")
            .field("refresh_token", &"[已脱敏]")
            .field("refresh_challenge", &"[已脱敏]")
            .field("user", &self.user)
            .field("uid", &self.uid)
            .field("local_sandbox_trust_level", &self.local_sandbox_trust_level)
            .field("key_fingerprint", &self.key_fingerprint)
            .field("login_at", &self.login_at)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct AttestationKeyRecord {
    #[serde(default)]
    private_key_base64: Option<String>,
    #[zeroize(skip)]
    #[serde(default)]
    pub key_origin: mindone_protocol::AttestationKeyOrigin,
    #[serde(default)]
    runtime_key_handle: Option<String>,
    #[zeroize(skip)]
    pub public_key: String,
    #[zeroize(skip)]
    pub challenge_id: String,
    #[zeroize(skip)]
    pub report_id: Option<String>,
    #[zeroize(skip)]
    pub node_id: String,
    #[zeroize(skip)]
    pub model_instance_id: String,
    #[zeroize(skip)]
    pub expires_at: String,
}

impl AttestationKeyRecord {
    #[must_use]
    pub fn pending(
        private_key: &[u8; 32],
        public_key: String,
        challenge_id: String,
        node_id: String,
        model_instance_id: String,
        expires_at: String,
    ) -> Self {
        Self {
            private_key_base64: Some(BASE64_STANDARD.encode(private_key)),
            key_origin: mindone_protocol::AttestationKeyOrigin::ControlSoftware,
            runtime_key_handle: None,
            public_key,
            challenge_id,
            report_id: None,
            node_id,
            model_instance_id,
            expires_at,
        }
    }

    #[must_use]
    pub fn pending_runtime(
        key_handle: String,
        public_key: String,
        challenge_id: String,
        node_id: String,
        model_instance_id: String,
        expires_at: String,
    ) -> Self {
        Self {
            private_key_base64: None,
            key_origin: mindone_protocol::AttestationKeyOrigin::TeeRuntime,
            runtime_key_handle: Some(key_handle),
            public_key,
            challenge_id,
            report_id: None,
            node_id,
            model_instance_id,
            expires_at,
        }
    }

    pub fn mark_verified(&mut self, report_id: String, expires_at: String) {
        self.report_id = Some(report_id);
        self.expires_at = expires_at;
    }

    pub fn private_key(&self) -> CliResult<zeroize::Zeroizing<Vec<u8>>> {
        if self.key_origin != mindone_protocol::AttestationKeyOrigin::ControlSoftware {
            return Err(CliError::Attestation(
                "TEE runtime 证明密钥没有可导出的软件私钥".to_owned(),
            ));
        }
        let encoded = self.private_key_base64.as_deref().ok_or_else(|| {
            CliError::Attestation("系统凭证中的 control-only X25519 私钥缺失".to_owned())
        })?;
        let bytes = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| CliError::Attestation("系统凭证中的 X25519 私钥已损坏".to_owned()))?;
        if bytes.len() != 32 {
            return Err(CliError::Attestation(
                "系统凭证中的 X25519 私钥长度无效".to_owned(),
            ));
        }
        Ok(zeroize::Zeroizing::new(bytes))
    }

    pub fn runtime_key_handle(&self) -> CliResult<&str> {
        if self.key_origin != mindone_protocol::AttestationKeyOrigin::TeeRuntime {
            return Err(CliError::Attestation(
                "当前证明密钥不是 TEE runtime 来源，不能执行 Regulated 任务".to_owned(),
            ));
        }
        self.runtime_key_handle.as_deref().ok_or_else(|| {
            CliError::Attestation("系统凭证中的 TEE runtime key handle 缺失".to_owned())
        })
    }
}

impl fmt::Debug for AttestationKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestationKeyRecord")
            .field("private_key", &"[已脱敏]")
            .field("key_origin", &self.key_origin)
            .field("runtime_key_handle", &"[已脱敏]")
            .field("public_key", &self.public_key)
            .field("challenge_id", &self.challenge_id)
            .field("report_id", &self.report_id)
            .field("node_id", &self.node_id)
            .field("model_instance_id", &self.model_instance_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone)]
pub struct SystemVault {
    store: Arc<dyn SecretStore>,
    service: String,
}

impl SystemVault {
    pub fn for_home(home: &Path) -> CliResult<Self> {
        let service = keyring_service_for_home(home)?;
        let store = KeyringSecretStore::new(&service).map_err(common_auth_error)?;
        Ok(Self {
            store: Arc::new(store),
            service,
        })
    }

    /// 为单元测试创建与系统凭证库语义一致、但不依赖桌面会话的内存凭证库。
    ///
    /// Linux CI、容器和无头节点通常没有 Secret Service/DBus 会话；业务单元测试
    /// 不应因为平台凭证服务缺席而变成非确定性测试。生产构建不会包含此入口。
    #[cfg(test)]
    pub(crate) fn in_memory_for_home(home: &Path) -> CliResult<Self> {
        let service = keyring_service_for_home(home)?;
        Ok(Self {
            store: Arc::new(mindone_common::MemorySecretStore::default()),
            service,
        })
    }

    pub fn load_session(&self) -> CliResult<CredentialBundle> {
        let secret = self
            .store
            .get(SESSION_ACCOUNT)
            .map_err(common_auth_error)?
            .ok_or_else(|| CliError::Authentication("尚未登录 MindOne".to_owned()))?;
        serde_json::from_str(secret.expose_secret()).map_err(|error| {
            CliError::Authentication(format!("系统凭证中的会话数据已损坏：{error}"))
        })
    }

    pub fn has_session(&self) -> CliResult<bool> {
        self.store
            .get(SESSION_ACCOUNT)
            .map(|value| value.is_some())
            .map_err(common_auth_error)
    }

    /// 检查当前数据目录绑定的凭证命名空间是否包含任一受管凭证。
    ///
    /// `data.dir` 切换时不能只看登录 session：设备签名密钥或证明密钥若被留在
    /// 旧命名空间，同样会造成后续身份失联。
    pub fn has_any_credentials(&self) -> CliResult<bool> {
        for account in [SESSION_ACCOUNT, DEVICE_KEY_ACCOUNT, ATTESTATION_KEY_ACCOUNT] {
            if self
                .store
                .get(account)
                .map_err(common_auth_error)?
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn store(&self, session: &CredentialBundle, private_key: &[u8]) -> CliResult<()> {
        let encoded_key = SecretString::from(BASE64_STANDARD.encode(private_key));
        self.store
            .set(DEVICE_KEY_ACCOUNT, &encoded_key)
            .map_err(common_auth_error)?;
        if let Err(error) = self.store_session(session) {
            let _ = self.store.delete(DEVICE_KEY_ACCOUNT);
            return Err(error);
        }
        Ok(())
    }

    pub fn store_session(&self, session: &CredentialBundle) -> CliResult<()> {
        let raw = serde_json::to_string(session)
            .map_err(|error| CliError::Authentication(format!("无法序列化登录凭证：{error}")))?;
        self.store
            .set(SESSION_ACCOUNT, &SecretString::from(raw))
            .map_err(common_auth_error)
    }

    pub fn load_device_signing_key(&self) -> CliResult<Zeroizing<[u8; 32]>> {
        let secret = self
            .store
            .get(DEVICE_KEY_ACCOUNT)
            .map_err(common_auth_error)?
            .ok_or_else(|| {
                CliError::Authentication("本机缺少与会话绑定的设备签名私钥，请重新登录".to_owned())
            })?;
        let bytes = Zeroizing::new(
            BASE64_STANDARD
                .decode(secret.expose_secret())
                .map_err(|_| {
                    CliError::Authentication("系统凭证中的设备签名私钥已损坏".to_owned())
                })?,
        );
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CliError::Authentication("系统凭证中的设备签名私钥长度无效".to_owned()))?;
        Ok(Zeroizing::new(key))
    }

    pub fn store_attestation_key(&self, record: &AttestationKeyRecord) -> CliResult<()> {
        let raw = serde_json::to_string(record).map_err(|error| {
            CliError::Attestation(format!("无法序列化 X25519 证明密钥：{error}"))
        })?;
        self.store
            .set(ATTESTATION_KEY_ACCOUNT, &SecretString::from(raw))
            .map_err(common_auth_error)
    }

    pub fn load_attestation_key(&self) -> CliResult<AttestationKeyRecord> {
        let secret = self
            .store
            .get(ATTESTATION_KEY_ACCOUNT)
            .map_err(common_auth_error)?
            .ok_or_else(|| CliError::Attestation("本机没有已验证的 X25519 证明密钥".to_owned()))?;
        serde_json::from_str(secret.expose_secret()).map_err(|error| {
            CliError::Attestation(format!("系统凭证中的 X25519 证明密钥已损坏：{error}"))
        })
    }

    pub fn clear_attestation_key(&self) -> CliResult<()> {
        self.store
            .delete(ATTESTATION_KEY_ACCOUNT)
            .map_err(common_auth_error)
    }

    pub fn clear(&self) -> CliResult<()> {
        self.store
            .delete(SESSION_ACCOUNT)
            .map_err(common_auth_error)?;
        self.store
            .delete(DEVICE_KEY_ACCOUNT)
            .map_err(common_auth_error)?;
        self.clear_attestation_key()
    }

    pub fn available(&self) -> CliResult<()> {
        self.store
            .get(SESSION_ACCOUNT)
            .map(|_| ())
            .map_err(common_auth_error)
    }
}

impl fmt::Debug for SystemVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemVault")
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

fn keyring_service_for_home(home: &Path) -> CliResult<String> {
    let normalized = normalize_home(home)?;
    let digest = sha2::Sha256::digest(normalized.as_os_str().as_encoded_bytes());
    let fingerprint = hex::encode(digest);
    Ok(format!(
        "{SERVICE_PREFIX}.{}",
        &fingerprint[..NAMESPACE_HEX_LENGTH]
    ))
}

fn normalize_home(home: &Path) -> CliResult<PathBuf> {
    if !home.is_absolute() {
        return Err(CliError::Authentication(
            "系统凭证命名空间要求绝对 MINDONE_HOME".to_owned(),
        ));
    }
    match std::fs::canonicalize(home) {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(home.to_path_buf()),
        Err(error) => Err(CliError::Authentication(format!(
            "无法解析 MINDONE_HOME 的系统凭证命名空间：{error}"
        ))),
    }
}

fn common_auth_error(error: impl std::fmt::Display) -> CliError {
    CliError::Authentication(error.to_string())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use tempfile::TempDir;

    use super::{
        keyring_service_for_home, AttestationKeyRecord, CredentialBundle, SystemVault,
        ATTESTATION_KEY_ACCOUNT, DEVICE_KEY_ACCOUNT, SESSION_ACCOUNT,
    };

    fn session(user: &str) -> CredentialBundle {
        CredentialBundle {
            access_token: format!("access-{user}"),
            refresh_token: format!("refresh-{user}"),
            refresh_challenge: "ab".repeat(32),
            user: user.to_owned(),
            uid: format!("uid-{user}"),
            local_sandbox_trust_level: "Experimental".to_owned(),
            key_fingerprint: "abc".to_owned(),
            login_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    fn memory_vault(home: &std::path::Path) -> SystemVault {
        SystemVault::in_memory_for_home(home).expect("临时目录应可生成内存凭证库")
    }

    #[test]
    fn keyring_namespace_is_stable_isolated_and_does_not_leak_path() {
        let first = TempDir::new().expect("应创建第一个临时目录");
        let second = TempDir::new().expect("应创建第二个临时目录");
        let first_service =
            keyring_service_for_home(first.path()).expect("第一个目录应生成命名空间");
        let first_again = keyring_service_for_home(first.path()).expect("相同目录应生成命名空间");
        let second_service =
            keyring_service_for_home(second.path()).expect("第二个目录应生成命名空间");
        assert_eq!(first_service, first_again);
        assert_ne!(first_service, second_service);
        assert!(!first_service.contains(&first.path().to_string_lossy().to_string()));
        assert_eq!(first_service.len(), "org.mindone.cli.".len() + 24);
    }

    #[test]
    fn memory_store_round_trip_and_clear_are_scoped() {
        let home = TempDir::new().expect("应创建临时目录");
        let vault = memory_vault(home.path());
        vault
            .store(&session("alice"), b"private-key")
            .expect("应写入内存凭证库");
        assert_eq!(vault.load_session().expect("应读取会话").user, "alice");
        assert!(vault.has_session().expect("应检查会话"));
        assert!(vault.has_any_credentials().expect("应检查全部凭证"));
        vault.clear().expect("应清理当前命名空间");
        assert!(!vault.has_session().expect("应确认会话已删除"));
        assert!(!vault.has_any_credentials().expect("应确认全部凭证已删除"));

        // 账户名保持无路径信息，隔离由 service 指纹提供。
        assert_eq!(SESSION_ACCOUNT, "session");
        assert_eq!(DEVICE_KEY_ACCOUNT, "device-signing-key");
        assert_eq!(ATTESTATION_KEY_ACCOUNT, "attestation-x25519-key");
    }

    #[test]
    fn debug_output_redacts_tokens_and_x25519_private_key() {
        let credentials = session("debug-user");
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("access-debug-user"));
        assert!(!debug.contains("refresh-debug-user"));
        assert!(!debug.contains(&"ab".repeat(32)));

        let record = AttestationKeyRecord::pending(
            &[7_u8; 32],
            "11".repeat(32),
            "challenge".to_owned(),
            "node".to_owned(),
            "model".to_owned(),
            "expiry".to_owned(),
        );
        let debug = format!("{record:?}");
        assert!(!debug.contains(&super::BASE64_STANDARD.encode([7_u8; 32])));
    }

    #[test]
    fn stolen_refresh_token_without_device_key_cannot_load_signing_material() {
        let home = TempDir::new().expect("应创建临时目录");
        let vault = memory_vault(home.path());
        vault
            .store_session(&session("token-only"))
            .expect("应只写入被盗会话 token");

        let error = vault
            .load_device_signing_key()
            .expect_err("没有设备私钥时必须拒绝刷新");
        assert!(error.to_string().contains("设备签名私钥"));
        assert!(error.to_string().contains("重新登录"));
    }
}
