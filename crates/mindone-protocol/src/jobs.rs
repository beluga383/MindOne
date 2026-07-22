use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::common::{validate_identifier, validate_tags, Validate};
use crate::ProtocolValidationError;

pub const REGULATED_ENVELOPE_VERSION: u16 = 1;
pub const REGULATED_ALGORITHM: &str = "x25519-hkdf-sha256-chacha20poly1305";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialityMode {
    #[default]
    Standard,
    Regulated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeDirection {
    Request,
    Result,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Retry,
    Leased,
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedClass {
    Fast,
    #[default]
    Standard,
    Slow,
}

impl SpeedClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Standard => "standard",
            Self::Slow => "slow",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedQualifiedModel<'a> {
    pub base_model: &'a str,
    pub speed_class: SpeedClass,
}

/// 仅解析精确的末尾速度后缀；模型名称中间的连字符不会被改写。
pub fn parse_speed_qualified_model(
    model: &str,
) -> Result<SpeedQualifiedModel<'_>, ProtocolValidationError> {
    let (base_model, speed_class) = if let Some(base) = model.strip_suffix("-fast") {
        (base, SpeedClass::Fast)
    } else if let Some(base) = model.strip_suffix("-slow") {
        (base, SpeedClass::Slow)
    } else {
        (model, SpeedClass::Standard)
    };
    if base_model.is_empty() {
        return Err(ProtocolValidationError::new(
            "virtual_model",
            "速度后缀前必须包含模型名称",
        ));
    }
    validate_identifier("virtual_model", base_model, 128)?;
    Ok(SpeedQualifiedModel {
        base_model,
        speed_class,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobAttemptStatus {
    Leased,
    Succeeded,
    Failed,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobErrorClass {
    Engine,
    Model,
    Policy,
    Timeout,
    ResourceExhausted,
    NodeDisconnected,
    InvalidRequest,
    Internal,
    Attestation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PayloadEncoding {
    #[default]
    #[serde(rename = "base64")]
    Base64,
    #[serde(rename = "base64url")]
    Base64Url,
    #[serde(rename = "regulated_aead_v1")]
    RegulatedAeadV1,
}

impl PayloadEncoding {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Base64Url => "base64url",
            Self::RegulatedAeadV1 => "regulated_aead_v1",
        }
    }
}

pub const DEFAULT_NETWORK_MAX_OUTPUT_TOKENS: u32 = 256;
pub const MAX_JOB_STREAM_EVENT_BYTES: usize = 64 * 1024;
pub const MAX_JOB_STREAM_EVENTS: i32 = 65_536;
pub const MAX_JOB_STREAM_TOTAL_BYTES: i64 = 650 * 1024;

/// 计算网络任务在结算前必须授权的保守输入 Token 上界。
///
/// 这里刻意按完整 JSON UTF-8 字节数计费并预留固定模板空间，而不是使用通常的
/// “字符数 / 4”近似。这样消费者、协调器和贡献节点面对中文、控制 Token 或不同
/// tokenizer 时不会因为客户端低估而在真实推理完成后无法结算。
pub fn conservative_input_token_authorization(
    request: &serde_json::Value,
) -> Result<i32, ProtocolValidationError> {
    let serialized = Zeroizing::new(
        serde_json::to_vec(request)
            .map_err(|_| ProtocolValidationError::new("request", "请求 JSON 无法编码"))?,
    );
    let serialized_bytes = serialized.len();
    i32::try_from(serialized_bytes.saturating_add(1_024).max(1)).map_err(|_| {
        ProtocolValidationError::new("estimated_input_tokens", "请求体超过 Token 授权范围")
    })
}

/// Standard 模式下协调器能够检查但不会写入日志的任务载荷。
///
/// 公开 wire 仍是 Base64/Base64URL JSON；协调器只在数据库边界使用自己的
/// authenticated-encryption envelope，不能把它解释为消费者到节点的 E2EE。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardJobPayload {
    pub endpoint: String,
    pub request: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardJobLimits {
    pub model: String,
    pub minimum_input_tokens: i32,
    pub maximum_output_tokens: i32,
    pub stream: bool,
}

struct SensitiveChatRequest(crate::ChatCompletionsRequest);

impl std::ops::Deref for SensitiveChatRequest {
    type Target = crate::ChatCompletionsRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveChatRequest {
    fn drop(&mut self) {
        self.0.model.zeroize();
        for message in &mut self.0.messages {
            zeroize_message_content(&mut message.content);
            if let Some(value) = message.name.as_mut() {
                value.zeroize();
            }
            if let Some(value) = message.tool_call_id.as_mut() {
                value.zeroize();
            }
        }
        if let Some(stop) = self.0.stop.as_mut() {
            zeroize_stop_sequences(stop);
        }
        if let Some(user) = self.0.user.as_mut() {
            user.zeroize();
        }
    }
}

struct SensitiveCompletionsRequest(crate::CompletionsRequest);

impl std::ops::Deref for SensitiveCompletionsRequest {
    type Target = crate::CompletionsRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveCompletionsRequest {
    fn drop(&mut self) {
        self.0.model.zeroize();
        match &mut self.0.prompt {
            crate::Prompt::One(value) => value.zeroize(),
            crate::Prompt::Many(values) => values.zeroize(),
        }
        if let Some(stop) = self.0.stop.as_mut() {
            zeroize_stop_sequences(stop);
        }
        if let Some(user) = self.0.user.as_mut() {
            user.zeroize();
        }
    }
}

fn zeroize_message_content(content: &mut crate::MessageContent) {
    match content {
        crate::MessageContent::Text(value) => value.zeroize(),
        crate::MessageContent::Parts(parts) => {
            for part in parts {
                match part {
                    crate::ContentPart::Text { text } => text.zeroize(),
                    crate::ContentPart::ImageUrl { image_url } => {
                        image_url.url.zeroize();
                        if let Some(detail) = image_url.detail.as_mut() {
                            detail.zeroize();
                        }
                    }
                }
            }
        }
    }
}

fn zeroize_stop_sequences(stop: &mut crate::StopSequences) {
    match stop {
        crate::StopSequences::One(value) => value.zeroize(),
        crate::StopSequences::Many(values) => values.zeroize(),
    }
}

fn validate_standard_request_fields(
    request: &serde_json::Value,
    allowed_fields: &[&str],
) -> Result<(), ProtocolValidationError> {
    let object = request
        .as_object()
        .ok_or_else(|| ProtocolValidationError::new("request", "请求必须是 JSON 对象"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(ProtocolValidationError::new(
            "request",
            format!("请求包含不受支持的字段：{field}"),
        ));
    }
    Ok(())
}

impl StandardJobPayload {
    pub fn validated_limits(&self) -> Result<StandardJobLimits, ProtocolValidationError> {
        let (model, stream, per_choice, choices) = match self.endpoint.as_str() {
            crate::OPENAI_CHAT_COMPLETIONS => {
                validate_standard_request_fields(
                    &self.request,
                    &[
                        "model",
                        "messages",
                        "stream",
                        "max_tokens",
                        "max_completion_tokens",
                        "temperature",
                        "top_p",
                        "seed",
                        "n",
                        "stop",
                        "user",
                    ],
                )?;
                let serialized =
                    Zeroizing::new(serde_json::to_vec(&self.request).map_err(|_| {
                        ProtocolValidationError::new("request", "聊天请求 JSON 无法编码")
                    })?);
                let request =
                    SensitiveChatRequest(serde_json::from_slice(serialized.as_slice()).map_err(
                        |_| ProtocolValidationError::new("request", "聊天请求 JSON 结构无效"),
                    )?);
                request.validate()?;
                if request.max_tokens.is_some() && request.max_completion_tokens.is_some() {
                    return Err(ProtocolValidationError::new(
                        "max_tokens",
                        "max_tokens 与 max_completion_tokens 不能同时设置",
                    ));
                }
                (
                    request.model.clone(),
                    request.stream,
                    request
                        .max_tokens
                        .or(request.max_completion_tokens)
                        .unwrap_or(DEFAULT_NETWORK_MAX_OUTPUT_TOKENS),
                    request.n.unwrap_or(1),
                )
            }
            crate::OPENAI_COMPLETIONS => {
                validate_standard_request_fields(
                    &self.request,
                    &[
                        "model",
                        "prompt",
                        "stream",
                        "max_tokens",
                        "temperature",
                        "top_p",
                        "n",
                        "stop",
                        "user",
                    ],
                )?;
                let serialized =
                    Zeroizing::new(serde_json::to_vec(&self.request).map_err(|_| {
                        ProtocolValidationError::new("request", "补全请求 JSON 无法编码")
                    })?);
                let request = SensitiveCompletionsRequest(
                    serde_json::from_slice(serialized.as_slice()).map_err(|_| {
                        ProtocolValidationError::new("request", "补全请求 JSON 结构无效")
                    })?,
                );
                request.validate()?;
                (
                    request.model.clone(),
                    request.stream,
                    request
                        .max_tokens
                        .unwrap_or(DEFAULT_NETWORK_MAX_OUTPUT_TOKENS),
                    request.n.unwrap_or(1),
                )
            }
            _ => {
                return Err(ProtocolValidationError::new(
                    "endpoint",
                    "只允许 OpenAI chat/completions 或 completions 端点",
                ))
            }
        };
        validate_identifier("model", &model, 128)?;
        let maximum_output_tokens = per_choice
            .checked_mul(choices)
            .and_then(|value| i32::try_from(value).ok())
            .filter(|value| *value > 0 && *value <= 1_000_000)
            .ok_or_else(|| {
                ProtocolValidationError::new("max_output_tokens", "输出 Token 授权上限无效")
            })?;
        let minimum_input_tokens = conservative_input_token_authorization(&self.request)?;
        Ok(StandardJobLimits {
            model,
            minimum_input_tokens,
            maximum_output_tokens,
            stream,
        })
    }
}

impl Validate for StandardJobPayload {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        self.validated_limits().map(|_| ())
    }
}

/// Enhanced 节点 E2EE 载荷。协调器只路由这些不透明字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub version: u16,
    pub algorithm: String,
    pub ephemeral_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_report_id: Option<Uuid>,
}

/// Regulated 数据面唯一允许的 envelope。AAD 不由发送方携带，而由绑定字段确定性计算。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatedEnvelope {
    pub version: u16,
    pub algorithm: String,
    pub direction: EnvelopeDirection,
    pub route_id: Uuid,
    pub report_id: Uuid,
    pub model_instance_id: Uuid,
    /// 请求方向为消费者临时 X25519 公钥，结果方向为证明绑定的 TEE 公钥。
    pub sender_public_key: String,
    /// 96-bit nonce 的 URL-safe base64（无 padding）。
    pub nonce: String,
    /// AEAD ciphertext 与 128-bit tag 的 URL-safe base64（无 padding）。
    pub ciphertext: String,
}

impl Validate for RegulatedEnvelope {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.version != REGULATED_ENVELOPE_VERSION {
            return Err(ProtocolValidationError::new(
                "version",
                "Regulated envelope 版本不受支持",
            ));
        }
        if self.algorithm != REGULATED_ALGORITHM {
            return Err(ProtocolValidationError::new(
                "algorithm",
                "Regulated envelope 算法不受支持",
            ));
        }
        validate_lower_hex("sender_public_key", &self.sender_public_key, 32)?;
        if self.sender_public_key.bytes().all(|byte| byte == b'0') {
            return Err(ProtocolValidationError::new(
                "sender_public_key",
                "X25519 公钥不能是全零值",
            ));
        }
        let nonce = decode_base64url("nonce", &self.nonce, 12, 12)?;
        if nonce.iter().all(|byte| *byte == 0) {
            return Err(ProtocolValidationError::new(
                "nonce",
                "AEAD nonce 不能是全零值",
            ));
        }
        let ciphertext = decode_base64url("ciphertext", &self.ciphertext, 17, 900_000)?;
        if ciphertext.len() < 17 {
            return Err(ProtocolValidationError::new(
                "ciphertext",
                "Regulated ciphertext 缺少 AEAD tag 或明文",
            ));
        }
        Ok(())
    }
}

/// AAD 的稳定二进制编码；调用方不得增加未验证的自由文本。
pub fn regulated_aad(
    direction: EnvelopeDirection,
    route_id: Uuid,
    report_id: Uuid,
    model_instance_id: Uuid,
    model_weights_hash: &str,
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_lower_hex("model_weights_hash", model_weights_hash, 32)?;
    let model_hash = hex::decode(model_weights_hash)
        .map_err(|_| ProtocolValidationError::new("model_weights_hash", "模型哈希编码无效"))?;
    let mut aad = Vec::with_capacity(32 + 1 + 16 * 3 + model_hash.len());
    aad.extend_from_slice(b"MindOne Regulated E2EE AAD v1\0");
    aad.push(match direction {
        EnvelopeDirection::Request => 1,
        EnvelopeDirection::Result => 2,
    });
    aad.extend_from_slice(route_id.as_bytes());
    aad.extend_from_slice(report_id.as_bytes());
    aad.extend_from_slice(model_instance_id.as_bytes());
    aad.extend_from_slice(&model_hash);
    Ok(aad)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRegulatedJobRequest {
    #[serde(default = "default_virtual_model")]
    pub virtual_model: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub estimated_input_tokens: i32,
    pub max_output_tokens: i32,
    pub idempotency_key: String,
    #[serde(default)]
    pub priority: i32,
}

impl Validate for PrepareRegulatedJobRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_job_metadata(
            &self.virtual_model,
            &self.tags,
            self.estimated_input_tokens,
            self.max_output_tokens,
            &self.idempotency_key,
            self.priority,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegulatedRouteAttestation {
    pub report_id: Uuid,
    pub challenge_id: Uuid,
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub provider: crate::AttestationProvider,
    pub evidence_kind: crate::AttestationEvidenceKind,
    pub evidence: String,
    pub evidence_sha256: String,
    pub challenge_nonce: String,
    pub report_data: String,
    pub tee_measurement: String,
    pub sandbox_policy_hash: String,
    pub runtime_binary_hash: String,
    pub model_weights_hash: String,
    pub ephemeral_public_key: String,
    pub issued_at: OffsetDateTime,
    pub verified_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub collateral_expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRegulatedJobResponse {
    pub route_id: Uuid,
    pub model_id: Uuid,
    pub model_instance_id: Uuid,
    pub node_id: Uuid,
    pub expires_at: OffsetDateTime,
    pub idempotent_replay: bool,
    pub attestation: RegulatedRouteAttestation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateRegulatedJobRequest {
    pub route_id: Uuid,
    pub envelope: RegulatedEnvelope,
    pub idempotency_key: String,
}

impl Validate for CreateRegulatedJobRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("idempotency_key", &self.idempotency_key, 200)?;
        self.envelope.validate()?;
        if self.envelope.direction != EnvelopeDirection::Request {
            return Err(ProtocolValidationError::new(
                "direction",
                "提交任务必须使用 request 方向 envelope",
            ));
        }
        if self.envelope.route_id != self.route_id {
            return Err(ProtocolValidationError::new(
                "route_id",
                "envelope 与 prepared route 不匹配",
            ));
        }
        Ok(())
    }
}

impl Validate for EncryptedEnvelope {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.version == 0 {
            return Err(ProtocolValidationError::new(
                "version",
                "加密 envelope 版本必须大于零",
            ));
        }
        validate_identifier("algorithm", &self.algorithm, 128)?;
        validate_identifier("ephemeral_public_key", &self.ephemeral_public_key, 4_096)?;
        validate_identifier("nonce", &self.nonce, 1_024)?;
        validate_identifier("ciphertext", &self.ciphertext, 16 * 1024 * 1024)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJobRequest {
    #[serde(default = "default_virtual_model")]
    pub virtual_model: String,
    pub encrypted_payload: String,
    #[serde(default)]
    pub payload_encoding: PayloadEncoding,
    #[serde(default)]
    pub tags: Vec<String>,
    pub estimated_input_tokens: i32,
    pub max_output_tokens: i32,
    pub idempotency_key: String,
    #[serde(default)]
    pub priority: i32,
}

impl Validate for CreateJobRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.payload_encoding == PayloadEncoding::RegulatedAeadV1 {
            return Err(ProtocolValidationError::new(
                "payload_encoding",
                "Standard 任务不能使用 regulated_aead_v1；请使用 Regulated 任务接口",
            ));
        }
        validate_identifier("encrypted_payload", &self.encrypted_payload, 900_000)?;
        validate_job_metadata(
            &self.virtual_model,
            &self.tags,
            self.estimated_input_tokens,
            self.max_output_tokens,
            &self.idempotency_key,
            self.priority,
        )
    }
}

fn default_virtual_model() -> String {
    "auto".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateJobResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_cost_micro: Option<i64>,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub model_id: Uuid,
    pub model_instance_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub leased_to_node_id: Option<Uuid>,
    pub lease_expires_at: Option<OffsetDateTime>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub actual_input_tokens: Option<i32>,
    pub actual_output_tokens: Option<i32>,
    pub result_ciphertext: Option<String>,
    #[serde(default)]
    pub confidentiality: ConfidentialityMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulated_route_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_report_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<JobErrorClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub completed_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimJobRequest {
    pub node_id: Uuid,
    /// worker 当前实际服务的模型实例；普通任务与隐藏评价共用这一绑定。
    pub model_instance_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimJobResponse {
    pub job_id: Uuid,
    pub model_instance_id: Uuid,
    pub model: String,
    pub model_weights_hash: String,
    pub encrypted_payload: String,
    pub payload_encoding: PayloadEncoding,
    pub tags: Vec<String>,
    pub estimated_input_tokens: i32,
    pub max_output_tokens: i32,
    pub attempt: i32,
    pub lease_expires_at: OffsetDateTime,
    pub policy_check_required_before_execution: bool,
    #[serde(default)]
    pub confidentiality: ConfidentialityMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulated_route_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_report_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_provider: Option<crate::AttestationProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tee_public_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewJobRequest {
    pub node_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewJobResponse {
    pub job_id: Uuid,
    pub lease_expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobExecutionTelemetry {
    /// 节点从本地 HTTP 请求开始发送到首个非空生成 delta 到达，以单调时钟实测的
    /// TTFT；无可见生成 token 或 adapter 不支持流式观测时必须为 null，不能用 0
    /// 或 prompt timing 推导值冒充。它仍是 node-reported 指标，不是远程执行证明。
    pub ttft_ms: Option<i64>,
    /// 本次任务生成阶段吞吐，单位为 tokens/second * 1000。
    pub tps_milli: Option<i64>,
    /// 执行窗口内周期采样得到的设备集合总占用峰值（best effort、node-reported）；
    /// 不是当前 job 的独占显存归因，平台不可读时为 null。
    pub peak_vram_mib: Option<i64>,
    /// 形成 peak_vram_mib 的真实采样次数；0 表示平台没有提供显存计数器。
    pub vram_sample_count: u32,
}

impl Validate for JobExecutionTelemetry {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        const MAX_TTFT_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
        const MAX_TPS_MILLI: i64 = 1_000_000_000_000;
        const MAX_VRAM_MIB: i64 = 1_048_576;
        const MAX_VRAM_SAMPLES: u32 = 10_000_000;

        if self
            .ttft_ms
            .is_some_and(|value| !(1..=MAX_TTFT_MS).contains(&value))
        {
            return Err(ProtocolValidationError::new(
                "execution_telemetry.ttft_ms",
                "TTFT 必须是正数且不超过 7 天",
            ));
        }
        if self
            .tps_milli
            .is_some_and(|value| !(1..=MAX_TPS_MILLI).contains(&value))
        {
            return Err(ProtocolValidationError::new(
                "execution_telemetry.tps_milli",
                "TPS 必须是正数且不超过协议上限",
            ));
        }
        if self
            .peak_vram_mib
            .is_some_and(|value| !(0..=MAX_VRAM_MIB).contains(&value))
        {
            return Err(ProtocolValidationError::new(
                "execution_telemetry.peak_vram_mib",
                "峰值显存不得为负且不得超过协议上限",
            ));
        }
        if self.vram_sample_count > MAX_VRAM_SAMPLES
            || (self.vram_sample_count == 0) != self.peak_vram_mib.is_none()
        {
            return Err(ProtocolValidationError::new(
                "execution_telemetry.vram_sample_count",
                "显存峰值与真实采样次数不一致",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTelemetryVerdict {
    /// 平台计数器或引擎 timing 缺失；保留记录，但不把未知误判为异常。
    InsufficientEvidence,
    /// 服务端在当前保守基线下没有观察到异常；不等价于执行证明。
    NoAnomalyObserved,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResultRequest {
    pub node_id: Uuid,
    pub idempotency_key: String,
    pub result_ciphertext: String,
    pub actual_input_tokens: i32,
    pub actual_output_tokens: i32,
    /// 兼容未上报任务遥测的早期 v1 worker；缺失值只能降级为“证据不足”，
    /// 不能由协调器伪造成 0 或已观测指标。
    #[serde(default)]
    pub execution_telemetry: JobExecutionTelemetry,
}

impl Validate for JobResultRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("idempotency_key", &self.idempotency_key, 200)?;
        validate_identifier("result_ciphertext", &self.result_ciphertext, 900_000)?;
        if self.actual_input_tokens < 0 || self.actual_output_tokens < 0 {
            return Err(ProtocolValidationError::new(
                "actual_tokens",
                "实际 Token 数不得为负",
            ));
        }
        self.execution_telemetry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResultResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStreamEventKind {
    Data,
    UpstreamDone,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStreamEventRequest {
    pub node_id: Uuid,
    pub attempt: i32,
    pub sequence: i32,
    pub idempotency_key: String,
    pub kind: JobStreamEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_data: Option<String>,
}

impl Validate for JobStreamEventRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.attempt <= 0 {
            return Err(ProtocolValidationError::new(
                "attempt",
                "流式事件 attempt 必须大于零",
            ));
        }
        if !(0..MAX_JOB_STREAM_EVENTS).contains(&self.sequence) {
            return Err(ProtocolValidationError::new(
                "sequence",
                "流式事件 sequence 超出协议上限",
            ));
        }
        validate_identifier("idempotency_key", &self.idempotency_key, 200)?;
        match (&self.kind, &self.event_data) {
            (JobStreamEventKind::Data, Some(data)) => {
                if data.is_empty() || data.len() > MAX_JOB_STREAM_EVENT_BYTES {
                    return Err(ProtocolValidationError::new(
                        "event_data",
                        "流式 data 事件为空或超过安全上限",
                    ));
                }
                let value: serde_json::Value = serde_json::from_str(data).map_err(|_| {
                    ProtocolValidationError::new("event_data", "流式 data 事件不是合法 JSON")
                })?;
                if !value.is_object() {
                    return Err(ProtocolValidationError::new(
                        "event_data",
                        "流式 data 事件必须是 JSON 对象",
                    ));
                }
            }
            (JobStreamEventKind::UpstreamDone, None) => {}
            (JobStreamEventKind::Data, None) => {
                return Err(ProtocolValidationError::new(
                    "event_data",
                    "流式 data 事件缺少正文",
                ));
            }
            (JobStreamEventKind::UpstreamDone, Some(_)) => {
                return Err(ProtocolValidationError::new(
                    "event_data",
                    "upstream_done 事件不得携带正文",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStreamEventResponse {
    pub job_id: Uuid,
    pub attempt: i32,
    pub sequence: i32,
    pub idempotent_replay: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStreamEvent {
    pub sequence: i32,
    pub event_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStreamReadResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub attempt: i32,
    pub events: Vec<JobStreamEvent>,
    pub next_sequence: i32,
    pub has_more: bool,
    pub upstream_done: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<JobErrorClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobFailRequest {
    pub node_id: Uuid,
    pub idempotency_key: String,
    pub error_class: JobErrorClass,
    pub error_message: String,
    #[serde(default)]
    pub retryable: bool,
}

impl Validate for JobFailRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("idempotency_key", &self.idempotency_key, 200)?;
        validate_identifier("error_message", &self.error_message, 1_000)
    }
}

fn validate_job_metadata(
    virtual_model: &str,
    tags: &[String],
    estimated_input_tokens: i32,
    max_output_tokens: i32,
    idempotency_key: &str,
    priority: i32,
) -> Result<(), ProtocolValidationError> {
    validate_identifier("virtual_model", virtual_model, 128)?;
    validate_identifier("idempotency_key", idempotency_key, 200)?;
    validate_tags(tags)?;
    if estimated_input_tokens < 0 || max_output_tokens <= 0 {
        return Err(ProtocolValidationError::new(
            "token_limits",
            "输入 Token 估算不得为负，最大输出 Token 必须大于零",
        ));
    }
    if max_output_tokens > 1_000_000 {
        return Err(ProtocolValidationError::new(
            "max_output_tokens",
            "不得超过 1000000",
        ));
    }
    if !(-100..=100).contains(&priority) {
        return Err(ProtocolValidationError::new(
            "priority",
            "优先级必须在 -100 到 100 之间",
        ));
    }
    Ok(())
}

fn validate_lower_hex(
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

fn decode_base64url(
    field: &'static str,
    value: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<u8>, ProtocolValidationError> {
    if value.is_empty()
        || value.len()
            > maximum
                .saturating_mul(4)
                .saturating_div(3)
                .saturating_add(4)
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'=')
    {
        return Err(ProtocolValidationError::new(
            field,
            "必须是无 padding 的 URL-safe base64",
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ProtocolValidationError::new(field, "URL-safe base64 编码无效"))?;
    if !(minimum..=maximum).contains(&decoded.len()) {
        return Err(ProtocolValidationError::new(
            field,
            "解码后长度超出协议范围",
        ));
    }
    Ok(decoded)
}

#[cfg(test)]
mod regulated_tests {
    use super::*;

    fn envelope() -> RegulatedEnvelope {
        RegulatedEnvelope {
            version: REGULATED_ENVELOPE_VERSION,
            algorithm: REGULATED_ALGORITHM.to_owned(),
            direction: EnvelopeDirection::Request,
            route_id: Uuid::from_u128(1),
            report_id: Uuid::from_u128(2),
            model_instance_id: Uuid::from_u128(3),
            sender_public_key: "11".repeat(32),
            nonce: URL_SAFE_NO_PAD.encode([7_u8; 12]),
            ciphertext: URL_SAFE_NO_PAD.encode([9_u8; 17]),
        }
    }

    #[test]
    fn regulated_envelope_rejects_tampered_shape_and_zero_keys() {
        assert!(envelope().validate().is_ok());
        let mut value = envelope();
        value.sender_public_key = "00".repeat(32);
        assert!(value.validate().is_err());
        let mut value = envelope();
        value.nonce = URL_SAFE_NO_PAD.encode([0_u8; 12]);
        assert!(value.validate().is_err());
    }

    #[test]
    fn aad_binds_direction_and_every_route_identity() {
        let request = regulated_aad(
            EnvelopeDirection::Request,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            &"44".repeat(32),
        )
        .expect("有效绑定应可编码");
        let result = regulated_aad(
            EnvelopeDirection::Result,
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Uuid::from_u128(3),
            &"44".repeat(32),
        )
        .expect("有效绑定应可编码");
        assert_ne!(request, result);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobFailResponse {
    pub job_id: Uuid,
    pub accepted: bool,
    pub idempotent_replay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn speed_suffix_parser_only_consumes_exact_terminal_suffixes() {
        let fast = parse_speed_qualified_model("Qwen/Qwen3-8B-fast").expect("fast 应解析");
        assert_eq!(fast.base_model, "Qwen/Qwen3-8B");
        assert_eq!(fast.speed_class, SpeedClass::Fast);
        let slow = parse_speed_qualified_model("auto-slow").expect("slow 应解析");
        assert_eq!(slow.base_model, "auto");
        assert_eq!(slow.speed_class, SpeedClass::Slow);
        let standard = parse_speed_qualified_model("model-fast-preview").expect("中间连字符应保留");
        assert_eq!(standard.base_model, "model-fast-preview");
        assert_eq!(standard.speed_class, SpeedClass::Standard);
        assert!(parse_speed_qualified_model("-fast").is_err());
        assert!(parse_speed_qualified_model("-slow").is_err());
    }

    fn chat_payload() -> StandardJobPayload {
        StandardJobPayload {
            endpoint: crate::OPENAI_CHAT_COMPLETIONS.to_owned(),
            request: serde_json::json!({
                "model": "auto",
                "messages": [{"role": "user", "content": "只回复：MindOne 已连接"}],
                "max_tokens": 64,
                "n": 2
            }),
        }
    }

    #[test]
    fn payload_encoding_has_stable_wire_names() {
        assert_eq!(PayloadEncoding::Base64.as_str(), "base64");
        assert_eq!(PayloadEncoding::Base64Url.as_str(), "base64url");
        assert_eq!(
            PayloadEncoding::RegulatedAeadV1.as_str(),
            "regulated_aead_v1"
        );
        assert_eq!(
            serde_json::to_value(PayloadEncoding::Base64Url).expect("编码名称应可序列化"),
            serde_json::json!("base64url")
        );
    }

    #[test]
    fn standard_payload_derives_model_and_conservative_token_limits() {
        let payload = chat_payload();
        let limits = payload.validated_limits().expect("规范请求应通过校验");
        let serialized_bytes = serde_json::to_vec(&payload.request)
            .expect("请求 JSON 应可编码")
            .len();
        assert_eq!(limits.model, "auto");
        assert_eq!(limits.maximum_output_tokens, 128);
        assert_eq!(
            limits.minimum_input_tokens,
            i32::try_from(serialized_bytes + 1_024).expect("测试请求应在协议范围内")
        );
        assert_eq!(
            conservative_input_token_authorization(&payload.request).expect("共享授权函数应成功"),
            limits.minimum_input_tokens
        );
    }

    #[test]
    fn standard_payload_uses_one_shared_default_output_limit() {
        let payload = StandardJobPayload {
            endpoint: crate::OPENAI_COMPLETIONS.to_owned(),
            request: serde_json::json!({"model": "auto", "prompt": "hello"}),
        };
        let limits = payload.validated_limits().expect("规范请求应通过校验");
        assert_eq!(
            limits.maximum_output_tokens,
            i32::try_from(DEFAULT_NETWORK_MAX_OUTPUT_TOKENS).expect("默认上限应在 i32 范围内")
        );
    }

    #[test]
    fn standard_payload_rejects_unknown_outer_fields() {
        let value = serde_json::json!({
            "endpoint": crate::OPENAI_CHAT_COMPLETIONS,
            "request": {
                "model": "auto",
                "messages": [{"role": "user", "content": "hello"}]
            },
            "unexpected": true
        });
        assert!(serde_json::from_value::<StandardJobPayload>(value).is_err());
    }

    #[test]
    fn standard_payload_rejects_unknown_request_fields() {
        let mut payload = chat_payload();
        payload.request["unsupported"] = serde_json::json!(true);
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("请求未知字段必须拒绝")
                .field,
            "request"
        );
    }

    #[test]
    fn standard_payload_rejects_endpoint_model_and_token_ambiguity_but_preserves_stream() {
        let mut payload = chat_payload();
        payload.endpoint = "/v1/embeddings".to_owned();
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("未知端点必须拒绝")
                .field,
            "endpoint"
        );

        let mut payload = chat_payload();
        payload.request["model"] = serde_json::json!("");
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("空模型必须拒绝")
                .field,
            "model"
        );

        let mut payload = chat_payload();
        payload.request["model"] = serde_json::json!("m".repeat(129));
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("网络模型标识符不得超过任务协议上限")
                .field,
            "model"
        );

        let mut payload = chat_payload();
        payload.request["stream"] = serde_json::json!(true);
        assert!(
            payload
                .validated_limits()
                .expect("Standard 应支持真实流式任务")
                .stream
        );

        let mut payload = chat_payload();
        payload.request["max_completion_tokens"] = serde_json::json!(64);
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("两个输出上限字段不能并存")
                .field,
            "max_tokens"
        );
    }

    #[test]
    fn stream_event_shape_is_strict_and_bounded() {
        let valid = JobStreamEventRequest {
            node_id: Uuid::from_u128(1),
            attempt: 1,
            sequence: 0,
            idempotency_key: "stream:job:1:0".to_owned(),
            kind: JobStreamEventKind::Data,
            event_data: Some(r#"{"object":"chat.completion.chunk"}"#.to_owned()),
        };
        assert!(valid.validate().is_ok());

        let mut invalid_done = valid.clone();
        invalid_done.kind = JobStreamEventKind::UpstreamDone;
        assert_eq!(
            invalid_done.validate().expect_err("DONE 不得带正文").field,
            "event_data"
        );

        let mut oversized = valid;
        oversized.event_data = Some("x".repeat(MAX_JOB_STREAM_EVENT_BYTES + 1));
        assert_eq!(
            oversized.validate().expect_err("超大事件必须拒绝").field,
            "event_data"
        );
    }

    #[test]
    fn standard_payload_rejects_zero_or_excessive_output_authorization() {
        let mut payload = chat_payload();
        payload.request["max_tokens"] = serde_json::json!(0);
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("零输出上限必须拒绝")
                .field,
            "max_tokens"
        );

        let mut payload = chat_payload();
        payload.request["max_tokens"] = serde_json::json!(1_000_000);
        payload.request["n"] = serde_json::json!(2);
        assert_eq!(
            payload
                .validated_limits()
                .expect_err("总输出授权超过协议上限必须拒绝")
                .field,
            "max_output_tokens"
        );
    }

    #[test]
    fn create_job_defaults_match_coordinator_contract() {
        let value = serde_json::json!({
            "encrypted_payload": "ciphertext",
            "estimated_input_tokens": 10,
            "max_output_tokens": 20,
            "idempotency_key": "request-1"
        });
        let request: CreateJobRequest = serde_json::from_value(value).expect("应可解析");
        assert_eq!(request.virtual_model, "auto");
        assert_eq!(request.payload_encoding, PayloadEncoding::Base64);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn execution_telemetry_rejects_impossible_values_and_keeps_unknown_explicit() {
        let unknown = JobExecutionTelemetry {
            ttft_ms: None,
            tps_milli: None,
            peak_vram_mib: None,
            vram_sample_count: 0,
        };
        assert!(unknown.validate().is_ok());

        let negative_peak = JobExecutionTelemetry {
            peak_vram_mib: Some(-1),
            vram_sample_count: 1,
            ..unknown.clone()
        };
        assert!(negative_peak.validate().is_err());
        let fabricated_sample_shape = JobExecutionTelemetry {
            peak_vram_mib: Some(1_024),
            vram_sample_count: 0,
            ..unknown
        };
        assert!(fabricated_sample_shape.validate().is_err());
    }

    #[test]
    fn legacy_result_without_telemetry_degrades_to_insufficient_evidence() {
        let request: JobResultRequest = serde_json::from_value(serde_json::json!({
            "node_id": Uuid::from_u128(1),
            "idempotency_key": "request-1",
            "result_ciphertext": "e30=",
            "actual_input_tokens": 1,
            "actual_output_tokens": 1
        }))
        .expect("早期 v1 worker 缺少遥测时仍应可解析");
        assert_eq!(
            request.execution_telemetry,
            JobExecutionTelemetry::default()
        );
        assert!(request.execution_telemetry.validate().is_ok());
    }

    #[test]
    fn rejects_empty_payload_and_bad_priority() {
        let request = CreateJobRequest {
            virtual_model: "auto".to_owned(),
            encrypted_payload: String::new(),
            payload_encoding: PayloadEncoding::Base64,
            tags: Vec::new(),
            estimated_input_tokens: 0,
            max_output_tokens: 10,
            idempotency_key: "request-1".to_owned(),
            priority: 101,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn create_job_rejects_unknown_fields_and_regulated_encoding() {
        let value = serde_json::json!({
            "encrypted_payload": "e30=",
            "estimated_input_tokens": 1024,
            "max_output_tokens": 20,
            "idempotency_key": "request-1",
            "unknown": "must-not-be-ignored"
        });
        assert!(serde_json::from_value::<CreateJobRequest>(value).is_err());

        let request = CreateJobRequest {
            virtual_model: "auto".to_owned(),
            encrypted_payload: "opaque-envelope".to_owned(),
            payload_encoding: PayloadEncoding::RegulatedAeadV1,
            tags: Vec::new(),
            estimated_input_tokens: 1_024,
            max_output_tokens: 20,
            idempotency_key: "request-1".to_owned(),
            priority: 0,
        };
        let error = request
            .validate()
            .expect_err("Regulated 编码必须走独立接口");
        assert_eq!(error.field, "payload_encoding");
    }
}
