//! 密码哈希与验证。
//!
//! Argon2id 是内存/计算密集操作；所有调用都经有界 semaphore 进入
//! `spawn_blocking`，不阻塞 Tokio worker，也不允许无界并发耗尽内存。

use std::sync::{Arc, OnceLock};

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::{Argon2, ParamsBuilder, Version};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::error::ApiError;

type Result<T> = std::result::Result<T, ApiError>;

const MAX_CONCURRENT_ARGON2: usize = 4;
static ARGON2_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn argon2_limit() -> Arc<Semaphore> {
    ARGON2_LIMIT
        .get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_ARGON2)))
        .clone()
}

/// 生成密码哈希（Argon2id，OWASP 推荐参数）。
pub async fn hash_password(password: &str) -> Result<String> {
    let permit = argon2_limit().acquire_owned().await.map_err(|error| {
        tracing::error!(error = %error, "Argon2 并发门禁不可用");
        ApiError::internal()
    })?;
    let password = Zeroizing::new(password.to_owned());
    let result = tokio::task::spawn_blocking(move || hash_password_blocking(password.as_str()))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "Argon2 哈希任务失败");
            ApiError::internal()
        })?;
    drop(permit);
    result.map_err(|error| {
        tracing::error!(error = %error, "Argon2 哈希失败");
        ApiError::internal()
    })
}

/// 验证密码是否匹配哈希。
pub async fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let permit = argon2_limit().acquire_owned().await.map_err(|error| {
        tracing::error!(error = %error, "Argon2 并发门禁不可用");
        ApiError::internal()
    })?;
    let password = Zeroizing::new(password.to_owned());
    let hash = hash.to_owned();
    let result =
        tokio::task::spawn_blocking(move || verify_password_blocking(password.as_str(), &hash))
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "Argon2 验证任务失败");
                ApiError::internal()
            })?;
    drop(permit);
    result.map_err(|error| {
        tracing::error!(error = %error, "Argon2 验证失败");
        ApiError::internal()
    })
}

fn hash_password_blocking(password: &str) -> std::result::Result<String, String> {
    // OWASP 推荐：m=19456 (19 MiB), t=2, p=1。
    let mut params = ParamsBuilder::new();
    let _ = params.m_cost(19_456);
    let _ = params.t_cost(2);
    let _ = params.p_cost(1);
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        params.build().map_err(|error| error.to_string())?,
    );
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| error.to_string())
}

fn verify_password_blocking(password: &str, hash: &str) -> std::result::Result<bool, String> {
    let parsed_hash = PasswordHash::new(hash).map_err(|error| error.to_string())?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn hash_and_verify_correct_password() {
        let password = "correct_horse_battery_staple";
        let hash = hash_password(password).await.expect("哈希应成功");
        assert!(hash.starts_with("$argon2id$"), "应使用 Argon2id");
        assert!(
            verify_password(password, &hash).await.expect("验证应成功"),
            "正确密码应通过"
        );
    }

    #[tokio::test]
    async fn verify_rejects_wrong_password() {
        let hash = hash_password("correct_password").await.expect("哈希应成功");
        assert!(
            !verify_password("wrong_password", &hash)
                .await
                .expect("验证应成功"),
            "错误密码应被拒绝"
        );
    }

    #[tokio::test]
    async fn hash_same_password_twice_produces_different_hashes() {
        let hash1 = hash_password("same_password").await.expect("哈希应成功");
        let hash2 = hash_password("same_password").await.expect("哈希应成功");
        assert_ne!(hash1, hash2, "每次哈希应使用不同 salt");
    }
}
