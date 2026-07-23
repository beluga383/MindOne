use std::collections::HashMap;
use std::sync::Mutex;

use secrecy::{ExposeSecret, SecretString};

use crate::error::{MindOneError, Result};

/// Secret 存储接口。实现必须避免将 secret 写入普通配置文件。
pub trait SecretStore: Send + Sync {
    fn set(&self, account: &str, secret: &SecretString) -> Result<()>;
    fn get(&self, account: &str) -> Result<Option<SecretString>>;
    fn delete(&self, account: &str) -> Result<()>;
}

/// 使用 macOS Keychain、Windows Credential Manager、Linux Secret Service，
/// 或 Linux 上显式选择的内核 keyutils 的生产实现。
#[derive(Debug, Clone)]
pub struct KeyringSecretStore {
    service: String,
    backend: KeyringBackend,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self> {
        let service = service.into();
        if service.trim().is_empty() {
            return Err(MindOneError::Config(
                "系统凭证库 service 名称不能为空".to_owned(),
            ));
        }
        Ok(Self {
            service,
            backend: KeyringBackend::from_environment()?,
        })
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        validate_account(account)?;
        self.backend
            .entry(&self.service, account)
            .map_err(keyring_error)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum KeyringBackend {
    PlatformDefault,
    #[cfg(target_os = "linux")]
    LinuxKernel,
}

impl KeyringBackend {
    fn from_environment() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let value = std::env::var_os("MINDONE_LINUX_CREDENTIAL_STORE");
            Self::from_linux_value(value.as_deref())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self::PlatformDefault)
        }
    }

    #[cfg(target_os = "linux")]
    fn from_linux_value(value: Option<&std::ffi::OsStr>) -> Result<Self> {
        match value {
            Some(value) if value == "keyutils" => Ok(Self::LinuxKernel),
            Some(value) if value == "secret-service" => Ok(Self::PlatformDefault),
            Some(value) if value.to_str().is_none() => Err(MindOneError::Config(
                "MINDONE_LINUX_CREDENTIAL_STORE 必须是有效 UTF-8".to_owned(),
            )),
            Some(_) => Err(MindOneError::Config(
                "MINDONE_LINUX_CREDENTIAL_STORE 只允许 secret-service 或 keyutils".to_owned(),
            )),
            None => Ok(Self::PlatformDefault),
        }
    }

    fn entry(self, service: &str, account: &str) -> keyring::Result<keyring::Entry> {
        match self {
            Self::PlatformDefault => keyring::Entry::new(service, account),
            #[cfg(target_os = "linux")]
            Self::LinuxKernel => {
                let credential =
                    keyring::keyutils::KeyutilsCredential::new_with_target(None, service, account)?;
                Ok(keyring::Entry::new_with_credential(Box::new(credential)))
            }
        }
    }
}

impl SecretStore for KeyringSecretStore {
    fn set(&self, account: &str, secret: &SecretString) -> Result<()> {
        self.entry(account)?
            .set_password(secret.expose_secret())
            .map_err(keyring_error)
    }

    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        match self.entry(account)?.get_password() {
            Ok(secret) => Ok(Some(SecretString::from(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(error)),
        }
    }

    fn delete(&self, account: &str) -> Result<()> {
        match self.entry(account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(error)),
        }
    }
}

/// 仅用于自动化测试的内存实现；进程结束后内容即丢失。
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    entries: Mutex<HashMap<String, SecretString>>,
}

impl SecretStore for MemorySecretStore {
    fn set(&self, account: &str, secret: &SecretString) -> Result<()> {
        validate_account(account)?;
        let mut entries = self.entries.lock().map_err(lock_error)?;
        entries.insert(
            account.to_owned(),
            SecretString::from(secret.expose_secret().to_owned()),
        );
        Ok(())
    }

    fn get(&self, account: &str) -> Result<Option<SecretString>> {
        validate_account(account)?;
        let entries = self.entries.lock().map_err(lock_error)?;
        Ok(entries
            .get(account)
            .map(|secret| SecretString::from(secret.expose_secret().to_owned())))
    }

    fn delete(&self, account: &str) -> Result<()> {
        validate_account(account)?;
        let mut entries = self.entries.lock().map_err(lock_error)?;
        entries.remove(account);
        Ok(())
    }
}

fn validate_account(account: &str) -> Result<()> {
    if account.trim().is_empty() {
        return Err(MindOneError::Authentication(
            "凭证账户名称不能为空".to_owned(),
        ));
    }
    if account.len() > 255 || account.chars().any(char::is_control) {
        return Err(MindOneError::Authentication("凭证账户名称无效".to_owned()));
    }
    Ok(())
}

fn keyring_error(error: keyring::Error) -> MindOneError {
    MindOneError::Authentication(format!("系统凭证库操作失败：{error}"))
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> MindOneError {
    MindOneError::Authentication("测试凭证库锁已损坏".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_round_trip_and_delete() {
        let store = MemorySecretStore::default();
        let secret = SecretString::from("not-written-to-disk".to_owned());
        store
            .set("access-token", &secret)
            .expect("应可保存测试 secret");
        let loaded = store
            .get("access-token")
            .expect("读取不应失败")
            .expect("secret 应存在");
        assert_eq!(loaded.expose_secret(), "not-written-to-disk");
        store.delete("access-token").expect("删除不应失败");
        assert!(store.get("access-token").expect("读取不应失败").is_none());
    }

    #[test]
    fn rejects_empty_account() {
        let store = MemorySecretStore::default();
        let secret = SecretString::from("secret".to_owned());
        assert!(store.set("", &secret).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_kernel_backend_selects_the_real_keyutils_store() {
        assert_eq!(
            KeyringBackend::from_linux_value(Some(std::ffi::OsStr::new("keyutils")))
                .expect("keyutils 应被接受"),
            KeyringBackend::LinuxKernel
        );
        assert_eq!(
            KeyringBackend::from_linux_value(Some(std::ffi::OsStr::new("secret-service")))
                .expect("Secret Service 应被接受"),
            KeyringBackend::PlatformDefault
        );
        assert!(
            KeyringBackend::from_linux_value(Some(std::ffi::OsStr::new("memory"))).is_err(),
            "production 不能回退到进程内凭证库"
        );
        let builder = keyring::keyutils::default_credential_builder();
        assert!(
            matches!(
                builder.persistence(),
                keyring::credential::CredentialPersistence::UntilReboot
            ),
            "显式 keyutils 后端必须来自内核持久期的真实 builder"
        );
    }
}
