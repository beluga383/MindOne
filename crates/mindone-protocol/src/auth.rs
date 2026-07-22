use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::{validate_identifier, TrustLevel, Validate};
use crate::ProtocolValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKeyAlgorithm {
    Ed25519,
}

impl DeviceKeyAlgorithm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }
}

pub const DEVICE_PUBLIC_KEY_BYTES: usize = 32;
pub const DEVICE_KEY_CHALLENGE_BYTES: usize = 32;
pub const DEVICE_KEY_SIGNATURE_BYTES: usize = 64;
pub const REFRESH_KEY_CHALLENGE_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStartRequest {
    pub device_public_key: String,
    pub device_key_algorithm: DeviceKeyAlgorithm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceStartResponse {
    pub flow_id: Uuid,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
    pub device_challenge: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePollRequest {
    pub flow_id: Uuid,
    pub device_key_signature: String,
}

/// 设备密钥指纹统一对原始 Ed25519 公钥字节取 SHA-256。
///
/// CLI 与协调服务器必须调用同一函数，禁止分别对 hex 文本和原始字节计算，
/// 否则同一密钥会产生两个看似有效但不一致的身份。
#[must_use]
pub fn device_key_fingerprint(public_key: &[u8; DEVICE_PUBLIC_KEY_BYTES]) -> String {
    hex::encode(Sha256::digest(public_key))
}

/// 生成 Device Flow 私钥持有证明的稳定、域分离消息。
///
/// 签名绑定 flow、随机 challenge、规范公钥与算法；签名只能用于这一条登录流，
/// 不能在另一登录流或未来引入的其他算法中重放。
#[must_use]
pub fn device_key_possession_message(
    flow_id: Uuid,
    challenge: &[u8; DEVICE_KEY_CHALLENGE_BYTES],
    public_key: &[u8; DEVICE_PUBLIC_KEY_BYTES],
    algorithm: DeviceKeyAlgorithm,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"MindOne device key possession v1\0";
    let algorithm = algorithm.as_str().as_bytes();
    let mut message = Vec::with_capacity(
        DOMAIN.len()
            + flow_id.as_bytes().len()
            + challenge.len()
            + public_key.len()
            + algorithm.len(),
    );
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(flow_id.as_bytes());
    message.extend_from_slice(challenge);
    message.extend_from_slice(public_key);
    message.extend_from_slice(algorithm);
    message
}

/// 生成 refresh token 轮换所需的设备私钥持有证明消息。
///
/// 消息绑定服务端保存的一次性 challenge、当前 refresh token 的 SHA-256、
/// 原始设备公钥与算法。服务端必须在成功刷新时同时轮换 token 和 challenge；
/// 因此旧请求不能重放，被单独窃取的 refresh token 也不足以创建新会话。
#[must_use]
pub fn refresh_key_possession_message(
    challenge: &[u8; REFRESH_KEY_CHALLENGE_BYTES],
    refresh_token: &str,
    public_key: &[u8; DEVICE_PUBLIC_KEY_BYTES],
    algorithm: DeviceKeyAlgorithm,
) -> Vec<u8> {
    const DOMAIN: &[u8] = b"MindOne refresh key possession v1\0";
    let token_hash = Sha256::digest(refresh_token.as_bytes());
    let algorithm = algorithm.as_str().as_bytes();
    let mut message = Vec::with_capacity(
        DOMAIN.len() + challenge.len() + token_hash.len() + public_key.len() + algorithm.len(),
    );
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(challenge);
    message.extend_from_slice(&token_hash);
    message.extend_from_slice(public_key);
    message.extend_from_slice(algorithm);
    message
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFlowStatus {
    Pending,
    Authorized,
    Denied,
    Expired,
}

/// 含 token 的类型刻意使用脱敏 Debug，避免日志意外泄露凭证。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    /// 下一次 refresh 必须签名的一次性 32 字节 challenge（小写十六进制）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_challenge: Option<String>,
    pub token_type: String,
    pub expires_in: u64,
}

impl fmt::Debug for TokenPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenPair")
            .field("access_token", &"[已脱敏]")
            .field("refresh_token", &"[已脱敏]")
            .field(
                "refresh_challenge",
                &self.refresh_challenge.as_ref().map(|_| "[已脱敏]"),
            )
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub id: Uuid,
    pub username: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePollResponse {
    pub status: DeviceFlowStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenPair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<AuthenticatedUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_key_fingerprint: Option<String>,
}

impl fmt::Debug for DevicePollResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevicePollResponse")
            .field("status", &self.status)
            .field("interval", &self.interval)
            .field("tokens", &self.tokens)
            .field("user", &self.user)
            .field("device_key_fingerprint", &self.device_key_fingerprint)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshRequest")
            .field("refresh_token", &"[已脱敏]")
            .finish()
    }
}

/// v1 设备绑定会话的 refresh 请求。`RefreshRequest` 仅保留给旧客户端做明确的
/// 迁移诊断；协调服务器不会接受缺少签名的刷新。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBoundRefreshRequest {
    pub refresh_token: String,
    pub device_key_signature: String,
}

impl fmt::Debug for DeviceBoundRefreshRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceBoundRefreshRequest")
            .field("refresh_token", &"[已脱敏]")
            .field("device_key_signature", &"[已脱敏]")
            .finish()
    }
}

pub type RefreshResponse = TokenPair;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

impl fmt::Debug for LogoutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LogoutRequest")
            .field("refresh_token", &"[已脱敏]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoutResponse {
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub user: AuthenticatedUser,
    pub trust_level: TrustLevel,
    pub device_key_fingerprint: Option<String>,
    pub logged_in_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub device_key_revoked: Option<bool>,
    pub device_key_created_at: Option<OffsetDateTime>,
    pub device_key_rotated_at: Option<OffsetDateTime>,
    pub registered_nodes: u64,
    pub best_node_trust_level: Option<TrustLevel>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationProvider {
    AmdSevSnp,
    IntelTdx,
    None,
}

impl AttestationProvider {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmdSevSnp => "amd_sev_snp",
            Self::IntelTdx => "intel_tdx",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationEvidenceKind {
    SnpExtendedReport,
    TdxQuote,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKeyOrigin {
    /// 兼容既有控制面：私钥由普通 CLI 生成，只能证明控制面绑定。
    #[default]
    ControlSoftware,
    /// 公钥和私钥句柄由受 measurement 约束的 TEE runtime adapter 生成。
    TeeRuntime,
}

impl AttestationEvidenceKind {
    #[must_use]
    pub const fn matches_provider(self, provider: AttestationProvider) -> bool {
        matches!(
            (self, provider),
            (Self::SnpExtendedReport, AttestationProvider::AmdSevSnp)
                | (Self::TdxQuote, AttestationProvider::IntelTdx)
        )
    }
}

/// 创建一次性远程证明挑战。所有哈希和临时公钥都会进入 TEE REPORTDATA。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChallengeRequest {
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub provider: AttestationProvider,
    pub sandbox_policy_hash: String,
    pub runtime_binary_hash: String,
    /// 32 字节 X25519 公钥的小写十六进制编码。
    pub ephemeral_public_key: String,
    #[serde(default)]
    pub key_origin: AttestationKeyOrigin,
}

impl Validate for AttestationChallengeRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.provider == AttestationProvider::None {
            return Err(ProtocolValidationError::new(
                "provider",
                "必须选择受支持的硬件证明提供者",
            ));
        }
        crate::common::validate_sha256("sandbox_policy_hash", &self.sandbox_policy_hash)?;
        crate::common::validate_sha256("runtime_binary_hash", &self.runtime_binary_hash)?;
        validate_hex_len("ephemeral_public_key", &self.ephemeral_public_key, 32)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChallengeResponse {
    pub challenge_id: Uuid,
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub provider: AttestationProvider,
    /// 32 字节随机 nonce 的 URL-safe base64（无 padding）编码。
    pub nonce: String,
    pub expires_at: OffsetDateTime,
    pub sandbox_policy_hash: String,
    pub runtime_binary_hash: String,
    pub model_weights_hash: String,
    pub ephemeral_public_key: String,
    pub key_origin: AttestationKeyOrigin,
    /// 应写入 SNP REPORTDATA 或 TDX Quote REPORTDATA 的 64 字节小写十六进制值。
    pub report_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSubmitRequest {
    pub challenge_id: Uuid,
    pub provider: AttestationProvider,
    pub evidence_kind: AttestationEvidenceKind,
    /// 厂商原始 SNP extended report 或 TDX Quote 的标准 base64 编码。
    pub evidence: String,
}

impl Validate for AttestationSubmitRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.provider == AttestationProvider::None
            || !self.evidence_kind.matches_provider(self.provider)
        {
            return Err(ProtocolValidationError::new(
                "evidence_kind",
                "证据类型与硬件证明提供者不匹配；Intel TDX 必须提交 Quote，不能提交裸 TDREPORT",
            ));
        }
        if self.evidence.is_empty()
            || self.evidence.len() > 768 * 1024
            || !self.evidence.is_ascii()
            || self.evidence.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(ProtocolValidationError::new(
                "evidence",
                "证明证据必须是非空且不超过 768 KiB 的单行 base64",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSubmitResponse {
    pub report_id: Uuid,
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub provider: AttestationProvider,
    pub trust_level: TrustLevel,
    pub verified_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub ephemeral_public_key: String,
    pub key_origin: AttestationKeyOrigin,
}

pub struct AttestationReportBinding<'a> {
    pub challenge_id: Uuid,
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub nonce: &'a [u8],
    pub sandbox_policy_hash: &'a str,
    pub runtime_binary_hash: &'a str,
    pub model_weights_hash: &'a str,
    pub ephemeral_public_key: &'a str,
    pub key_origin: AttestationKeyOrigin,
}

/// 域分离的 SHA-512 绑定，输出正好可填入 SNP/TDX 的 64 字节 REPORTDATA。
pub fn attestation_report_data(
    binding: &AttestationReportBinding<'_>,
) -> Result<[u8; 64], ProtocolValidationError> {
    if binding.nonce.len() != 32 {
        return Err(ProtocolValidationError::new(
            "nonce",
            "远程证明 nonce 必须正好为 32 字节",
        ));
    }
    crate::common::validate_sha256("sandbox_policy_hash", binding.sandbox_policy_hash)?;
    crate::common::validate_sha256("runtime_binary_hash", binding.runtime_binary_hash)?;
    crate::common::validate_sha256("model_weights_hash", binding.model_weights_hash)?;
    validate_hex_len("ephemeral_public_key", binding.ephemeral_public_key, 32)?;

    let policy = decode_fixed_hex("sandbox_policy_hash", binding.sandbox_policy_hash, 32)?;
    let runtime = decode_fixed_hex("runtime_binary_hash", binding.runtime_binary_hash, 32)?;
    let model = decode_fixed_hex("model_weights_hash", binding.model_weights_hash, 32)?;
    let public_key = decode_fixed_hex("ephemeral_public_key", binding.ephemeral_public_key, 32)?;
    let mut digest = Sha512::new();
    digest.update(b"MindOne Attestation REPORTDATA v2\0");
    digest.update(binding.challenge_id.as_bytes());
    digest.update(binding.node_id.as_bytes());
    digest.update(binding.model_instance_id.as_bytes());
    digest.update((binding.nonce.len() as u64).to_be_bytes());
    digest.update(binding.nonce);
    digest.update(policy);
    digest.update(runtime);
    digest.update(model);
    digest.update(public_key);
    digest.update([match binding.key_origin {
        AttestationKeyOrigin::ControlSoftware => 1,
        AttestationKeyOrigin::TeeRuntime => 2,
    }]);
    Ok(digest.finalize().into())
}

fn validate_hex_len(
    field: &'static str,
    value: &str,
    decoded_len: usize,
) -> Result<(), ProtocolValidationError> {
    if value.len() != decoded_len.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProtocolValidationError::new(
            field,
            format!("必须是 {decoded_len} 字节的小写十六进制"),
        ));
    }
    Ok(())
}

fn decode_fixed_hex(
    field: &'static str,
    value: &str,
    decoded_len: usize,
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_hex_len(field, value, decoded_len)?;
    hex::decode(value).map_err(|_| ProtocolValidationError::new(field, "十六进制编码无效"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub nonce: String,
    pub sandbox_policy_hash: String,
    pub runtime_binary_hash: String,
    pub model_weights_hash: String,
}

impl Validate for AttestationRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("nonce", &self.nonce, 512)?;
        crate::common::validate_sha256("sandbox_policy_hash", &self.sandbox_policy_hash)?;
        crate::common::validate_sha256("runtime_binary_hash", &self.runtime_binary_hash)?;
        crate::common::validate_sha256("model_weights_hash", &self.model_weights_hash)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReport {
    pub id: Uuid,
    pub provider: AttestationProvider,
    pub nonce: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub sandbox_policy_hash: String,
    pub runtime_binary_hash: String,
    pub model_weights_hash: String,
    pub ephemeral_public_key: String,
    pub evidence: String,
    pub certificate_chain: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub supported: bool,
    pub trust_level: TrustLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<AttestationReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_never_contains_tokens() {
        let tokens = TokenPair {
            access_token: "access-secret".to_owned(),
            refresh_token: "refresh-secret".to_owned(),
            refresh_challenge: Some("challenge-secret".to_owned()),
            token_type: "Bearer".to_owned(),
            expires_in: 900,
        };
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("refresh-secret"));
        assert!(!debug.contains("challenge-secret"));
    }

    #[test]
    fn pending_device_response_round_trips() {
        let response = DevicePollResponse {
            status: DeviceFlowStatus::Pending,
            interval: Some(5),
            tokens: None,
            user: None,
            device_key_fingerprint: None,
        };
        let encoded = serde_json::to_string(&response).expect("应可序列化");
        let decoded: DevicePollResponse = serde_json::from_str(&encoded).expect("应可反序列化");
        assert_eq!(decoded, response);
    }

    #[test]
    fn report_data_is_deterministic_and_binds_every_runtime_field() {
        let challenge_id = Uuid::from_u128(1);
        let node_id = Uuid::from_u128(2);
        let model_instance_id = Uuid::from_u128(3);
        let nonce = [7_u8; 32];
        let policy = "11".repeat(32);
        let runtime = "22".repeat(32);
        let model = "33".repeat(32);
        let public_key = "44".repeat(32);
        let binding = AttestationReportBinding {
            challenge_id,
            node_id,
            model_instance_id,
            nonce: &nonce,
            sandbox_policy_hash: &policy,
            runtime_binary_hash: &runtime,
            model_weights_hash: &model,
            ephemeral_public_key: &public_key,
            key_origin: AttestationKeyOrigin::TeeRuntime,
        };
        let first = attestation_report_data(&binding).expect("有效字段应生成 REPORTDATA");
        let repeated = attestation_report_data(&binding).expect("相同字段应生成 REPORTDATA");
        let changed_model = "34".repeat(32);
        let changed_binding = AttestationReportBinding {
            model_weights_hash: &changed_model,
            ..binding
        };
        let changed = attestation_report_data(&changed_binding).expect("变化后的字段仍合法");
        assert_eq!(first, repeated);
        assert_ne!(first, changed);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn tdx_rejects_bare_report_evidence_kind() {
        let request = AttestationSubmitRequest {
            challenge_id: Uuid::nil(),
            provider: AttestationProvider::IntelTdx,
            evidence_kind: AttestationEvidenceKind::SnpExtendedReport,
            evidence: "YWJj".to_owned(),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn authorized_device_response_flattens_token_fields() {
        let response = DevicePollResponse {
            status: DeviceFlowStatus::Authorized,
            interval: None,
            tokens: Some(TokenPair {
                access_token: "access".to_owned(),
                refresh_token: "refresh".to_owned(),
                refresh_challenge: Some("ab".repeat(32)),
                token_type: "Bearer".to_owned(),
                expires_in: 900,
            }),
            user: Some(AuthenticatedUser {
                id: Uuid::nil(),
                username: "developer".to_owned(),
            }),
            device_key_fingerprint: Some("ab".repeat(32)),
        };
        let value = serde_json::to_value(response).expect("应可序列化");
        assert_eq!(value["status"], "authorized");
        assert_eq!(value["access_token"], "access");
        assert_eq!(value["refresh_token"], "refresh");
        assert_eq!(value["refresh_challenge"], "ab".repeat(32));
        assert!(value.get("tokens").is_none());
        assert_eq!(value["device_key_fingerprint"], "ab".repeat(32));
    }

    #[test]
    fn device_key_identity_uses_raw_public_key_and_proof_binds_flow() {
        let public_key = [0x42_u8; DEVICE_PUBLIC_KEY_BYTES];
        let challenge = [0x24_u8; DEVICE_KEY_CHALLENGE_BYTES];
        let flow = Uuid::from_u128(7);
        let fingerprint = device_key_fingerprint(&public_key);
        assert_eq!(fingerprint, hex::encode(Sha256::digest(public_key)));
        assert_ne!(
            fingerprint,
            hex::encode(Sha256::digest(hex::encode(public_key).as_bytes()))
        );

        let message = device_key_possession_message(
            flow,
            &challenge,
            &public_key,
            DeviceKeyAlgorithm::Ed25519,
        );
        let changed_flow = device_key_possession_message(
            Uuid::from_u128(8),
            &challenge,
            &public_key,
            DeviceKeyAlgorithm::Ed25519,
        );
        assert_ne!(message, changed_flow);
    }

    #[test]
    fn refresh_proof_binds_token_challenge_key_and_algorithm() {
        let public_key = [0x42_u8; DEVICE_PUBLIC_KEY_BYTES];
        let other_public_key = [0x43_u8; DEVICE_PUBLIC_KEY_BYTES];
        let challenge = [0x24_u8; REFRESH_KEY_CHALLENGE_BYTES];
        let other_challenge = [0x25_u8; REFRESH_KEY_CHALLENGE_BYTES];
        let message = refresh_key_possession_message(
            &challenge,
            "mnr_current",
            &public_key,
            DeviceKeyAlgorithm::Ed25519,
        );
        assert_eq!(
            message,
            refresh_key_possession_message(
                &challenge,
                "mnr_current",
                &public_key,
                DeviceKeyAlgorithm::Ed25519,
            )
        );
        assert_ne!(
            message,
            refresh_key_possession_message(
                &other_challenge,
                "mnr_current",
                &public_key,
                DeviceKeyAlgorithm::Ed25519,
            )
        );
        assert_ne!(
            message,
            refresh_key_possession_message(
                &challenge,
                "mnr_stolen_replacement",
                &public_key,
                DeviceKeyAlgorithm::Ed25519,
            )
        );
        assert_ne!(
            message,
            refresh_key_possession_message(
                &challenge,
                "mnr_current",
                &other_public_key,
                DeviceKeyAlgorithm::Ed25519,
            )
        );
    }

    #[test]
    fn auth_status_distinguishes_account_node_and_device_state() {
        let response = AuthStatusResponse {
            user: AuthenticatedUser {
                id: Uuid::nil(),
                username: "developer".to_owned(),
            },
            trust_level: TrustLevel::Unverified,
            device_key_fingerprint: None,
            logged_in_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
            device_key_revoked: None,
            device_key_created_at: None,
            device_key_rotated_at: None,
            registered_nodes: 0,
            best_node_trust_level: None,
        };
        let value = serde_json::to_value(response).expect("状态响应应可序列化");
        assert_eq!(value["trust_level"], "unverified");
        assert!(value["device_key_fingerprint"].is_null());
        assert_eq!(value["registered_nodes"], 0);
        assert!(value["best_node_trust_level"].is_null());
        assert!(value.get("server_url").is_none());
    }
}
