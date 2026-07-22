use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::config::validate_server_url;
use crate::error::{CliError, CliResult};

#[derive(Debug, Clone)]
pub struct CoordinatorClient {
    base: Url,
    http: reqwest::Client,
}

impl CoordinatorClient {
    pub fn new(server_url: &str) -> CliResult<Self> {
        let mut base = validate_server_url(server_url)?;
        if !base.path().ends_with('/') {
            let path = format!("{}/", base.path());
            base.set_path(&path);
        }
        let redirect_origin = base.clone();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("mindone-cli/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                if attempt.previous().len() >= 5 {
                    return attempt.error("MindOne 拒绝超过 5 次的协调服务器重定向");
                }
                if same_origin(&redirect_origin, attempt.url()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|error| CliError::General(format!("无法初始化安全 HTTP 客户端：{error}")))?;
        Ok(Self { base, http })
    }

    pub fn server_url(&self) -> &str {
        self.base.as_str().trim_end_matches('/')
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str, token: Option<&str>) -> CliResult<T> {
        self.request::<(), T>(Method::GET, path, token, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> CliResult<T> {
        self.request(Method::POST, path, token, Some(body)).await
    }

    pub async fn post_optional<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: &B,
    ) -> CliResult<Option<T>> {
        let relative = path.trim_start_matches('/');
        let url = self
            .base
            .join(relative)
            .map_err(|error| CliError::General(format!("无法构造协调服务器地址：{error}")))?;
        let mut request = self.http.post(url).json(body);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| CliError::General(format!("无法连接协调服务器：{error}")))?;
        let status = response.status();
        if status == StatusCode::NO_CONTENT {
            return Ok(None);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|error| CliError::General(format!("无法读取协调服务器响应：{error}")))?;
        if !status.is_success() {
            return Err(server_error(status, &bytes));
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| CliError::General(format!("协调服务器返回了不兼容的 JSON：{error}")))
    }

    pub async fn delete<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> CliResult<T> {
        self.request(Method::DELETE, path, token, body).await
    }

    async fn request<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&B>,
    ) -> CliResult<T> {
        let relative = path.trim_start_matches('/');
        let url = self
            .base
            .join(relative)
            .map_err(|error| CliError::General(format!("无法构造协调服务器地址：{error}")))?;
        let mut request = self.http.request(method, url);
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| CliError::General(format!("无法连接协调服务器：{error}")))?;
        let status = response.status();
        let bytes = response
            .bytes()
            .await
            .map_err(|error| CliError::General(format!("无法读取协调服务器响应：{error}")))?;
        if !status.is_success() {
            return Err(server_error(status, &bytes));
        }
        serde_json::from_slice(&bytes).map_err(|error| {
            CliError::General(format!(
                "协调服务器返回了不兼容的 JSON（HTTP {status}）：{error}"
            ))
        })
    }
}

fn same_origin(expected: &Url, candidate: &Url) -> bool {
    expected.scheme() == candidate.scheme()
        && expected.host_str() == candidate.host_str()
        && expected.port_or_known_default() == candidate.port_or_known_default()
}

fn server_error(status: StatusCode, bytes: &[u8]) -> CliError {
    let parsed = serde_json::from_slice::<Value>(bytes).ok();
    let server_code = parsed
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(Value::as_i64);
    let server_type = parsed
        .as_ref()
        .and_then(|value| value.pointer("/error/type"))
        .and_then(Value::as_str);
    let message = parsed
        .as_ref()
        .and_then(|value| {
            value
                .pointer("/error/message")
                .or_else(|| value.get("message"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("未知错误").to_owned());
    CliError::from_http_response(
        status,
        format!("协调服务器请求失败（HTTP {}）：{message}", status.as_u16()),
        server_code,
        server_type,
    )
}

#[cfg(test)]
mod tests {
    use super::{same_origin, CoordinatorClient};
    use url::Url;

    #[test]
    fn refuses_non_tls_remote_server() {
        assert!(CoordinatorClient::new("http://example.com").is_err());
        assert!(CoordinatorClient::new("http://127.0.0.1:8787").is_ok());
    }

    #[test]
    fn redirects_must_remain_on_the_exact_origin() {
        let origin = Url::parse("https://api.example.com/v1");
        assert!(origin.is_ok());
        let Ok(origin) = origin else { return };
        let same = Url::parse("https://api.example.com/other");
        let downgrade = Url::parse("http://api.example.com/other");
        let cross_host = Url::parse("https://attacker.example/other");
        assert!(matches!(same, Ok(value) if same_origin(&origin, &value)));
        assert!(matches!(downgrade, Ok(value) if !same_origin(&origin, &value)));
        assert!(matches!(cross_host, Ok(value) if !same_origin(&origin, &value)));
    }
}
