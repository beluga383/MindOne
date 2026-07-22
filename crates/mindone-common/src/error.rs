use serde::{Deserialize, Serialize};
use thiserror::Error;

/// CLI 对外稳定退出码。不得复用或改变既有含义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    General = 1,
    Authentication = 10,
    EngineOrSandbox = 20,
    ModelValidation = 21,
    Attestation = 30,
    TrustDowngrade = 31,
    InsufficientQuota = 40,
    PolicyRejected = 50,
}

impl ExitCode {
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

/// 跨 crate 使用的稳定错误类型。
#[derive(Debug, Error)]
pub enum MindOneError {
    #[error("{0}")]
    General(String),
    #[error("认证失败或系统凭证库不可用：{0}")]
    Authentication(String),
    #[error("引擎安装或沙盒初始化失败：{0}")]
    EngineOrSandbox(String),
    #[error("模型安全校验失败：{0}")]
    ModelValidation(String),
    #[error("远程证明失败：{0}")]
    Attestation(String),
    #[error("信任等级已降级：{0}")]
    TrustDowngrade(String),
    #[error("可用额度不足：{0}")]
    InsufficientQuota(String),
    #[error("节点策略拒绝请求：{0}")]
    PolicyRejected(String),
    #[error("配置错误：{0}")]
    Config(String),
    #[error("文件系统操作失败：{0}")]
    Io(String),
    #[error("数据序列化失败：{0}")]
    Serialization(String),
    #[error("网络地址不安全或无效：{0}")]
    InvalidEndpoint(String),
}

impl MindOneError {
    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        match self {
            Self::Authentication(_) => ExitCode::Authentication,
            Self::EngineOrSandbox(_) => ExitCode::EngineOrSandbox,
            Self::ModelValidation(_) => ExitCode::ModelValidation,
            Self::Attestation(_) => ExitCode::Attestation,
            Self::TrustDowngrade(_) => ExitCode::TrustDowngrade,
            Self::InsufficientQuota(_) => ExitCode::InsufficientQuota,
            Self::PolicyRejected(_) => ExitCode::PolicyRejected,
            Self::General(_)
            | Self::Config(_)
            | Self::Io(_)
            | Self::Serialization(_)
            | Self::InvalidEndpoint(_) => ExitCode::General,
        }
    }

    #[must_use]
    pub const fn error_type(&self) -> &'static str {
        match self {
            Self::General(_) => "general_error",
            Self::Authentication(_) => "authentication_failed",
            Self::EngineOrSandbox(_) => "engine_or_sandbox_failed",
            Self::ModelValidation(_) => "model_validation_failed",
            Self::Attestation(_) => "attestation_failed",
            Self::TrustDowngrade(_) => "trust_downgraded",
            Self::InsufficientQuota(_) => "insufficient_quota",
            Self::PolicyRejected(_) => "node_policy_rejected",
            Self::Config(_) => "configuration_error",
            Self::Io(_) => "io_error",
            Self::Serialization(_) => "serialization_error",
            Self::InvalidEndpoint(_) => "invalid_endpoint",
        }
    }

    #[must_use]
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            ok: false,
            code: self.exit_code().as_i32(),
            error: ErrorBody {
                error_type: self.error_type().to_owned(),
                message: self.to_string(),
            },
        }
    }
}

impl From<std::io::Error> for MindOneError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for MindOneError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<toml::de::Error> for MindOneError {
    fn from(value: toml::de::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<toml::ser::Error> for MindOneError {
    fn from(value: toml::ser::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

pub type Result<T> = std::result::Result<T, MindOneError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub code: i32,
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::General.as_i32(), 1);
        assert_eq!(ExitCode::Authentication.as_i32(), 10);
        assert_eq!(ExitCode::EngineOrSandbox.as_i32(), 20);
        assert_eq!(ExitCode::ModelValidation.as_i32(), 21);
        assert_eq!(ExitCode::Attestation.as_i32(), 30);
        assert_eq!(ExitCode::TrustDowngrade.as_i32(), 31);
        assert_eq!(ExitCode::InsufficientQuota.as_i32(), 40);
        assert_eq!(ExitCode::PolicyRejected.as_i32(), 50);
    }

    #[test]
    fn model_validation_envelope_matches_contract() {
        let error = MindOneError::ModelValidation("检测到不安全的模型格式".to_owned());
        let value = serde_json::to_value(error.envelope()).expect("错误 envelope 应可序列化");
        assert_eq!(value["ok"], false);
        assert_eq!(value["code"], 21);
        assert_eq!(value["error"]["type"], "model_validation_failed");
        assert!(value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("检测到不安全的模型格式")));
    }

    #[test]
    fn every_business_error_maps_to_required_code() {
        let cases = [
            (MindOneError::Authentication("x".to_owned()), 10),
            (MindOneError::EngineOrSandbox("x".to_owned()), 20),
            (MindOneError::ModelValidation("x".to_owned()), 21),
            (MindOneError::Attestation("x".to_owned()), 30),
            (MindOneError::TrustDowngrade("x".to_owned()), 31),
            (MindOneError::InsufficientQuota("x".to_owned()), 40),
            (MindOneError::PolicyRejected("x".to_owned()), 50),
        ];
        for (error, expected) in cases {
            assert_eq!(error.exit_code().as_i32(), expected);
            assert_eq!(error.envelope().code, expected);
        }
    }
}
