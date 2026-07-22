use url::{Host, Url};

use crate::error::{MindOneError, Result};
use crate::redact::is_sensitive_key;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportSecurity {
    Tls,
    LoopbackPlaintext,
}

pub fn validate_endpoint(value: &str) -> Result<(Url, TransportSecurity)> {
    let url = Url::parse(value)
        .map_err(|error| MindOneError::InvalidEndpoint(format!("URL 解析失败：{error}")))?;
    let security = validate_url(&url)?;
    Ok((url, security))
}

pub fn validate_url(url: &Url) -> Result<TransportSecurity> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(MindOneError::InvalidEndpoint(
            "服务器地址不得包含用户名或密码".to_owned(),
        ));
    }
    if url.fragment().is_some() {
        return Err(MindOneError::InvalidEndpoint(
            "服务器地址不得包含 URL fragment".to_owned(),
        ));
    }
    if url.query_pairs().any(|(key, _)| is_sensitive_key(&key)) {
        return Err(MindOneError::InvalidEndpoint(
            "服务器地址不得通过查询参数携带敏感凭证".to_owned(),
        ));
    }

    match url.scheme() {
        "https" | "wss" => Ok(TransportSecurity::Tls),
        "http" | "ws" if is_loopback(url) => Ok(TransportSecurity::LoopbackPlaintext),
        "http" | "ws" => Err(MindOneError::InvalidEndpoint(
            "跨主机连接必须使用 TLS；明文 HTTP/WS 仅允许回环地址".to_owned(),
        )),
        scheme => Err(MindOneError::InvalidEndpoint(format!(
            "不支持的 URL scheme：{scheme}"
        ))),
    }
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permits_tls_and_loopback_plaintext() {
        let (_, tls) = validate_endpoint("https://api.example.com/v1").expect("HTTPS 应通过");
        let (_, local) = validate_endpoint("http://127.0.0.1:8787").expect("回环 HTTP 应通过");
        let (_, ipv6) = validate_endpoint("ws://[::1]:8787").expect("回环 WS 应通过");
        assert_eq!(tls, TransportSecurity::Tls);
        assert_eq!(local, TransportSecurity::LoopbackPlaintext);
        assert_eq!(ipv6, TransportSecurity::LoopbackPlaintext);
    }

    #[test]
    fn rejects_remote_plaintext_and_embedded_secrets() {
        assert!(validate_endpoint("http://example.com").is_err());
        assert!(validate_endpoint("https://user:password@example.com").is_err());
        assert!(validate_endpoint("https://example.com?access_token=secret").is_err());
        assert!(validate_endpoint("ftp://127.0.0.1/file").is_err());
    }
}
