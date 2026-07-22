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

/// 使用 macOS Keychain、Windows Credential Manager 或 Linux Secret Service 的生产实现。
#[derive(Debug, Clone)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self> {
        let service = service.into();
        if service.trim().is_empty() {
            return Err(MindOneError::Config(
                "系统凭证库 service 名称不能为空".to_owned(),
            ));
        }
        Ok(Self { service })
    }

    fn entry(&self, account: &str) -> Result<keyring::Entry> {
        validate_account(account)?;
        keyring::Entry::new(&self.service, account).map_err(keyring_error)
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
}
