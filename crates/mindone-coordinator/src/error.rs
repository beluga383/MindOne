use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: i32,
    error_type: &'static str,
    message: String,
}

impl ApiError {
    pub fn bad_request(error_type: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, 1, error_type, message)
    }

    pub fn authentication(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            10,
            "authentication_failed",
            message,
        )
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, 10, "forbidden", message)
    }

    pub fn anti_abuse_blocked() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            10,
            "anti_abuse_blocked",
            "请求未通过网络完整性检查",
        )
    }

    pub fn not_found(resource: &'static str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            1,
            "not_found",
            format!("未找到{resource}"),
        )
    }

    pub fn conflict(error_type: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, 1, error_type, message)
    }

    pub fn insufficient_quota() -> Self {
        Self::new(
            StatusCode::PAYMENT_REQUIRED,
            40,
            "insufficient_quota",
            "可用额度不足",
        )
    }

    pub fn policy_rejected(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, 50, "node_policy_rejected", message)
    }

    pub fn rate_limited() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            1,
            "rate_limited",
            "请求过于频繁，请稍后重试",
        )
    }

    pub fn unavailable(error_type: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, 1, error_type, message)
    }

    pub fn gateway_timeout(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, 1, "inference_timeout", message)
    }

    pub(crate) const fn status(&self) -> StatusCode {
        self.status
    }

    pub(crate) const fn error_type(&self) -> &'static str {
        self.error_type
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub fn attestation_failed(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            30,
            "attestation_failed",
            message,
        )
    }

    pub fn attestation_unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            30,
            "attestation_failed",
            message,
        )
    }

    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "internal_error",
            "协调服务器内部错误",
        )
    }

    pub fn internal_msg(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            1,
            "internal_error",
            message,
        )
    }

    fn new(
        status: StatusCode,
        code: i32,
        error_type: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            error_type,
            message: message.into(),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "数据库操作失败");
        Self::internal()
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Serialize)]
struct ErrorEnvelope {
    ok: bool,
    code: i32,
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    #[serde(rename = "type")]
    error_type: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorEnvelope {
            ok: false,
            code: self.code,
            error: ErrorDetail {
                error_type: self.error_type,
                message: self.message,
            },
        };
        (self.status, Json(body)).into_response()
    }
}
