use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorEnvelope {
    pub ok: bool,
    pub code: i32,
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Enhanced,
    Standard,
    StandardLimited,
    Experimental,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceTier {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Normal,
    Sensitive,
    Regulated,
}

#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("字段 {field} 无效：{message}")]
pub struct ProtocolValidationError {
    pub field: String,
    pub message: String,
}

impl ProtocolValidationError {
    #[must_use]
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
        }
    }
}

pub trait Validate {
    fn validate(&self) -> Result<(), ProtocolValidationError>;
}

pub(crate) fn validate_identifier(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), ProtocolValidationError> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.chars().any(char::is_control)
    {
        return Err(ProtocolValidationError::new(
            field,
            format!("必须为 1 到 {maximum_bytes} 字节且不包含控制字符"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_tags(tags: &[String]) -> Result<(), ProtocolValidationError> {
    if tags.len() > 32 {
        return Err(ProtocolValidationError::new(
            "tags",
            "标签数量不得超过 32 个",
        ));
    }
    if tags
        .iter()
        .any(|tag| tag.is_empty() || tag.len() > 64 || !tag.is_ascii())
    {
        return Err(ProtocolValidationError::new(
            "tags",
            "每个标签必须是 1 到 64 字节的 ASCII 字符串",
        ));
    }
    Ok(())
}

pub(crate) fn validate_sha256(field: &str, value: &str) -> Result<(), ProtocolValidationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolValidationError::new(
            field,
            "必须是 64 位小写 SHA-256",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_envelope_has_stable_type_field() {
        let envelope = ApiErrorEnvelope {
            ok: false,
            code: 21,
            error: ApiErrorBody {
                error_type: "model_validation_failed".to_owned(),
                message: "检测到不安全的模型格式".to_owned(),
            },
        };
        let value = serde_json::to_value(envelope).expect("应可序列化");
        assert_eq!(value["error"]["type"], "model_validation_failed");
    }

    #[test]
    fn tags_are_bounded_and_ascii() {
        assert!(validate_tags(&["coding".to_owned()]).is_ok());
        assert!(validate_tags(&["中文".to_owned()]).is_err());
        assert!(validate_tags(&vec!["tag".to_owned(); 33]).is_err());
    }
}
