use serde_json::Value;
use url::Url;

const REDACTED: &str = "[已脱敏]";

#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
    matches!(
        normalized.as_str(),
        "authorization"
            | "token"
            | "access_token"
            | "refresh_token"
            | "password"
            | "secret"
            | "client_secret"
            | "api_key"
            | "private_key"
            | "database_url"
    ) || normalized.ends_with("_token")
        || normalized.ends_with("_password")
        || normalized.ends_with("_secret")
        || normalized.ends_with("_private_key")
}

#[must_use]
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let redacted = if is_sensitive_key(key) {
                        Value::String(REDACTED.to_owned())
                    } else {
                        redact_json(value)
                    };
                    (key.clone(), redacted)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(redact_json).collect()),
        other => other.clone(),
    }
}

#[must_use]
pub fn redact_url(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "[无效 URL，已隐藏]".to_owned();
    };

    if !url.username().is_empty() {
        let _ = url.set_username(REDACTED);
    }
    if url.password().is_some() {
        let _ = url.set_password(Some(REDACTED));
    }

    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, value)| {
            let value = if is_sensitive_key(&key) {
                REDACTED.to_owned()
            } else {
                value.into_owned()
            };
            (key.into_owned(), value)
        })
        .collect();
    if !pairs.is_empty() {
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    url.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_nested_json_but_keeps_fingerprints() {
        let input = serde_json::json!({
            "access_token": "secret",
            "nested": {"password": "secret", "device_key_fingerprint": "abc"},
            "items": [{"client_secret": "secret"}]
        });
        let output = redact_json(&input);
        assert_eq!(output["access_token"], REDACTED);
        assert_eq!(output["nested"]["password"], REDACTED);
        assert_eq!(output["nested"]["device_key_fingerprint"], "abc");
        assert_eq!(output["items"][0]["client_secret"], REDACTED);
    }

    #[test]
    fn redacts_url_credentials_and_sensitive_query() {
        let output = redact_url("https://user:pass@example.com/v1?token=abc&model=safe");
        assert!(!output.contains("user"));
        assert!(!output.contains("pass"));
        assert!(!output.contains("abc"));
        assert!(output.contains("model=safe"));
    }
}
