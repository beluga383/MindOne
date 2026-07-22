use std::future::Future;

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::auth::refresh_session;
use crate::config::{AppConfig, ConfigStore};
use crate::coordinator::CoordinatorClient;
use crate::error::{CliError, CliResult};
use crate::vault::SystemVault;
use mindone_common::MindOnePaths;

#[derive(Debug, Clone)]
pub struct AppContext {
    pub paths: MindOnePaths,
    pub config: AppConfig,
    pub config_store: ConfigStore,
    pub coordinator: CoordinatorClient,
    pub vault: SystemVault,
}

impl AppContext {
    pub fn load() -> CliResult<Self> {
        let discovered = MindOnePaths::discover().map_err(common_error)?;
        discovered.ensure_directories().map_err(common_error)?;
        let config_store = ConfigStore::new(discovered.config.clone());
        let config = config_store.load()?;
        let paths = if std::env::var_os("MINDONE_HOME").is_none() {
            if let Some(data_dir) = &config.data_dir {
                let paths = MindOnePaths::from_home(data_dir.clone()).map_err(common_error)?;
                paths.ensure_directories().map_err(common_error)?;
                paths
            } else {
                discovered
            }
        } else {
            discovered
        };
        let coordinator = CoordinatorClient::new(&config.server_url)?;
        let vault = SystemVault::for_home(&paths.home)?;
        Ok(Self {
            paths,
            config,
            config_store,
            coordinator,
            vault,
        })
    }

    /// 使用当前会话发起 GET 请求。access token 失效时轮换一次会话并仅重试一次。
    pub async fn authorized_get<T: DeserializeOwned>(&self, path: &str) -> CliResult<T> {
        let access_token = self.vault.load_session()?.access_token.clone();
        retry_authentication_once(
            access_token,
            |token| async move { self.coordinator.get(path, Some(&token)).await },
            || refresh_session(self),
        )
        .await
    }

    /// 使用当前会话发起 POST 请求。access token 失效时轮换一次会话并仅重试一次。
    pub async fn authorized_post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> CliResult<T> {
        let access_token = self.vault.load_session()?.access_token.clone();
        retry_authentication_once(
            access_token,
            |token| async move { self.coordinator.post(path, Some(&token), body).await },
            || refresh_session(self),
        )
        .await
    }

    /// 使用当前会话发起可能返回 204 的 POST 请求，并保持同样的单次刷新语义。
    pub async fn authorized_post_optional<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> CliResult<Option<T>> {
        let access_token = self.vault.load_session()?.access_token.clone();
        retry_authentication_once(
            access_token,
            |token| async move {
                self.coordinator
                    .post_optional(path, Some(&token), body)
                    .await
            },
            || refresh_session(self),
        )
        .await
    }

    /// 使用当前会话发起 DELETE 请求。access token 失效时轮换一次会话并仅重试一次。
    pub async fn authorized_delete<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        body: Option<&B>,
    ) -> CliResult<T> {
        let access_token = self.vault.load_session()?.access_token.clone();
        retry_authentication_once(
            access_token,
            |token| async move { self.coordinator.delete(path, Some(&token), body).await },
            || refresh_session(self),
        )
        .await
    }
}

async fn retry_authentication_once<T, Request, RequestFuture, Refresh, RefreshFuture>(
    access_token: String,
    mut request: Request,
    refresh: Refresh,
) -> CliResult<T>
where
    Request: FnMut(String) -> RequestFuture,
    RequestFuture: Future<Output = CliResult<T>>,
    Refresh: FnOnce() -> RefreshFuture,
    RefreshFuture: Future<Output = CliResult<crate::vault::CredentialBundle>>,
{
    match request(access_token).await {
        Ok(value) => Ok(value),
        Err(CliError::Authentication(_)) => {
            let refreshed = refresh().await?;
            request(refreshed.access_token.clone()).await
        }
        Err(error) => Err(error),
    }
}

fn common_error(error: impl std::fmt::Display) -> crate::error::CliError {
    crate::error::CliError::General(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::retry_authentication_once;
    use crate::error::CliError;
    use crate::vault::CredentialBundle;

    fn refreshed_session() -> CredentialBundle {
        CredentialBundle {
            access_token: "new-access".to_owned(),
            refresh_token: "rotated-refresh".to_owned(),
            refresh_challenge: "ab".repeat(32),
            user: "alice".to_owned(),
            uid: "user-id".to_owned(),
            local_sandbox_trust_level: "Standard-Limited".to_owned(),
            key_fingerprint: "fingerprint".to_owned(),
            login_at: "2026-07-17T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn authentication_failure_refreshes_once_and_retries_with_new_token() {
        let request_count = AtomicUsize::new(0);
        let refresh_count = AtomicUsize::new(0);
        let result = retry_authentication_once(
            "expired-access".to_owned(),
            |token| {
                let attempt = request_count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if attempt == 0 {
                        assert_eq!(token, "expired-access");
                        Err(CliError::Authentication("access token 已过期".to_owned()))
                    } else {
                        assert_eq!(token, "new-access");
                        Ok("ok")
                    }
                }
            },
            || {
                refresh_count.fetch_add(1, Ordering::SeqCst);
                async { Ok(refreshed_session()) }
            },
        )
        .await;

        assert_eq!(result.expect("刷新后请求应成功"), "ok");
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn second_authentication_failure_does_not_refresh_again() {
        let request_count = AtomicUsize::new(0);
        let refresh_count = AtomicUsize::new(0);
        let result = retry_authentication_once::<(), _, _, _, _>(
            "expired-access".to_owned(),
            |_| {
                request_count.fetch_add(1, Ordering::SeqCst);
                async { Err(CliError::Authentication("仍未授权".to_owned())) }
            },
            || {
                refresh_count.fetch_add(1, Ordering::SeqCst);
                async { Ok(refreshed_session()) }
            },
        )
        .await;

        assert!(matches!(result, Err(CliError::Authentication(_))));
        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn non_authentication_failure_is_not_refreshed() {
        let refresh_count = AtomicUsize::new(0);
        let result = retry_authentication_once::<(), _, _, _, _>(
            "valid-access".to_owned(),
            |_| async { Err(CliError::PolicyRejected("策略拒绝".to_owned())) },
            || {
                refresh_count.fetch_add(1, Ordering::SeqCst);
                async { Ok(refreshed_session()) }
            },
        )
        .await;

        assert!(matches!(result, Err(CliError::PolicyRejected(_))));
        assert_eq!(refresh_count.load(Ordering::SeqCst), 0);
    }
}
