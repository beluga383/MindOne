use serde::Serialize;
use thiserror::Error;

pub type CliResult<T> = Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    CliParse(String),
    #[error("{0}")]
    General(String),
    /// 协调服务器已经确定拒绝请求；保持通用退出码，但不得按瞬态网络故障重试。
    #[error("{0}")]
    RemoteRejected(String),
    #[error("{0}")]
    Authentication(String),
    #[error("{0}")]
    EngineOrSandbox(String),
    #[error("{0}")]
    ModelValidation(String),
    #[error("{0}")]
    Attestation(String),
    #[error("{0}")]
    TrustDowngraded(String),
    #[error("{0}")]
    InsufficientQuota(String),
    #[error("{0}")]
    PolicyRejected(String),
}

impl CliError {
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::CliParse(_) | Self::General(_) | Self::RemoteRejected(_) => {
                mindone_common::ExitCode::General as u8
            }
            Self::Authentication(_) => mindone_common::ExitCode::Authentication as u8,
            Self::EngineOrSandbox(_) => mindone_common::ExitCode::EngineOrSandbox as u8,
            Self::ModelValidation(_) => mindone_common::ExitCode::ModelValidation as u8,
            Self::Attestation(_) => mindone_common::ExitCode::Attestation as u8,
            Self::TrustDowngraded(_) => mindone_common::ExitCode::TrustDowngrade as u8,
            Self::InsufficientQuota(_) => mindone_common::ExitCode::InsufficientQuota as u8,
            Self::PolicyRejected(_) => mindone_common::ExitCode::PolicyRejected as u8,
        }
    }

    pub const fn error_type(&self) -> &'static str {
        match self {
            Self::CliParse(_) => "cli_parse_failed",
            Self::General(_) | Self::RemoteRejected(_) => "generic_error",
            Self::Authentication(_) => "authentication_failed",
            Self::EngineOrSandbox(_) => "engine_or_sandbox_failed",
            Self::ModelValidation(_) => "model_validation_failed",
            Self::Attestation(_) => "attestation_failed",
            Self::TrustDowngraded(_) => "trust_downgraded",
            Self::InsufficientQuota(_) => "insufficient_quota",
            Self::PolicyRejected(_) => "node_policy_rejected",
        }
    }

    pub fn from_http_response(
        status: reqwest::StatusCode,
        message: String,
        server_code: Option<i64>,
        server_type: Option<&str>,
    ) -> Self {
        match (server_code, server_type) {
            (Some(50), _) | (_, Some("node_policy_rejected")) => Self::PolicyRejected(message),
            (Some(40), _) | (_, Some("insufficient_quota")) => Self::InsufficientQuota(message),
            (Some(31), _) | (_, Some("trust_downgraded")) => Self::TrustDowngraded(message),
            (Some(30), _) | (_, Some("attestation_failed")) => Self::Attestation(message),
            (Some(21), _) | (_, Some("model_validation_failed")) => Self::ModelValidation(message),
            (
                _,
                Some("model_binding_mismatch" | "usage_binding_mismatch" | "invalid_job_result"),
            ) => Self::ModelValidation(message),
            (Some(20), _) | (_, Some("engine_or_sandbox_failed")) => Self::EngineOrSandbox(message),
            (Some(10), _) | (_, Some("authentication_failed" | "forbidden")) => {
                Self::Authentication(message)
            }
            _ => match status.as_u16() {
                401 => Self::Authentication(message),
                402 => Self::InsufficientQuota(message),
                403 if message.contains("policy") || message.contains("策略") => {
                    Self::PolicyRejected(message)
                }
                403 => Self::Authentication(message),
                408 | 425 | 429 | 500..=599 => Self::General(message),
                _ => Self::RemoteRejected(message),
            },
        }
    }
}

impl From<mindone_common::MindOneError> for CliError {
    fn from(error: mindone_common::MindOneError) -> Self {
        match error {
            mindone_common::MindOneError::Authentication(message) => Self::Authentication(message),
            mindone_common::MindOneError::EngineOrSandbox(message) => {
                Self::EngineOrSandbox(message)
            }
            mindone_common::MindOneError::ModelValidation(message) => {
                Self::ModelValidation(message)
            }
            mindone_common::MindOneError::Attestation(message) => Self::Attestation(message),
            mindone_common::MindOneError::TrustDowngrade(message) => Self::TrustDowngraded(message),
            mindone_common::MindOneError::InsufficientQuota(message) => {
                Self::InsufficientQuota(message)
            }
            mindone_common::MindOneError::PolicyRejected(message) => Self::PolicyRejected(message),
            other => Self::General(other.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope<'a> {
    pub ok: bool,
    pub code: u8,
    pub error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody<'a> {
    #[serde(rename = "type")]
    pub kind: &'a str,
    pub message: String,
}

impl<'a> From<&'a CliError> for ErrorEnvelope<'a> {
    fn from(error: &'a CliError) -> Self {
        Self {
            ok: false,
            code: error.exit_code(),
            error: ErrorBody {
                kind: error.error_type(),
                message: error.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CliError;

    #[test]
    fn required_exit_codes_are_stable() {
        let cases = [
            (CliError::CliParse(String::new()), 1, "cli_parse_failed"),
            (CliError::General(String::new()), 1, "generic_error"),
            (CliError::RemoteRejected(String::new()), 1, "generic_error"),
            (
                CliError::Authentication(String::new()),
                10,
                "authentication_failed",
            ),
            (
                CliError::EngineOrSandbox(String::new()),
                20,
                "engine_or_sandbox_failed",
            ),
            (
                CliError::ModelValidation(String::new()),
                21,
                "model_validation_failed",
            ),
            (
                CliError::Attestation(String::new()),
                30,
                "attestation_failed",
            ),
            (
                CliError::TrustDowngraded(String::new()),
                31,
                "trust_downgraded",
            ),
            (
                CliError::InsufficientQuota(String::new()),
                40,
                "insufficient_quota",
            ),
            (
                CliError::PolicyRejected(String::new()),
                50,
                "node_policy_rejected",
            ),
        ];
        for (error, code, kind) in cases {
            assert_eq!(error.exit_code(), code);
            assert_eq!(error.error_type(), kind);
        }
    }

    #[test]
    fn structured_policy_error_wins_over_http_403_auth_fallback() {
        let error = CliError::from_http_response(
            reqwest::StatusCode::FORBIDDEN,
            "节点拒绝任务".to_owned(),
            Some(50),
            Some("node_policy_rejected"),
        );
        assert_eq!(error.exit_code(), 50);
        assert_eq!(error.error_type(), "node_policy_rejected");
    }

    #[test]
    fn structured_trust_downgrade_response_maps_to_exit_31() {
        let by_code = CliError::from_http_response(
            reqwest::StatusCode::CONFLICT,
            "实际信任等级低于请求能力".to_owned(),
            Some(31),
            None,
        );
        assert!(matches!(by_code, CliError::TrustDowngraded(_)));
        assert_eq!(by_code.exit_code(), 31);

        let by_type = CliError::from_http_response(
            reqwest::StatusCode::CONFLICT,
            "实际信任等级低于请求能力".to_owned(),
            None,
            Some("trust_downgraded"),
        );
        assert!(matches!(by_type, CliError::TrustDowngraded(_)));
        assert_eq!(by_type.exit_code(), 31);
    }

    #[test]
    fn deterministic_result_rejection_is_not_a_transient_general_error() {
        let validation = CliError::from_http_response(
            reqwest::StatusCode::BAD_REQUEST,
            "结果模型不匹配".to_owned(),
            Some(1),
            Some("model_binding_mismatch"),
        );
        assert!(matches!(validation, CliError::ModelValidation(_)));

        let rejected = CliError::from_http_response(
            reqwest::StatusCode::CONFLICT,
            "租约已结束".to_owned(),
            Some(1),
            Some("job_not_leased"),
        );
        assert!(matches!(rejected, CliError::RemoteRejected(_)));

        let transient = CliError::from_http_response(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "稍后重试".to_owned(),
            Some(1),
            Some("unavailable"),
        );
        assert!(matches!(transient, CliError::General(_)));
    }
}
