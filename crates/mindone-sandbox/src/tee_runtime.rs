use std::{env, path::PathBuf, process::Stdio, time::Duration};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use mindone_protocol::{
    AttestationEvidenceKind, AttestationProvider, EnvelopeDirection, RegulatedEnvelope, Validate,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;
use uuid::Uuid;

const ADAPTER_SCHEMA: &str = "mindone.tee.runtime.v1";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const INFERENCE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TeeRuntimeError {
    #[error("此设备没有可访问的 {0} guest 证明设备")]
    DeviceUnavailable(&'static str),
    #[error("缺少固定 TEE runtime adapter 配置 MINDONE_TEE_RUNTIME_PATH")]
    MissingProgram,
    #[error("TEE runtime adapter 必须是绝对路径下非符号链接的普通文件")]
    InvalidProgram,
    #[error("无法启动 TEE runtime adapter")]
    Spawn,
    #[error("TEE runtime adapter 超时")]
    Timeout,
    #[error("TEE runtime adapter 执行失败")]
    ExitFailure,
    #[error("TEE runtime adapter 输出超过限制")]
    OutputTooLarge,
    #[error("TEE runtime adapter 输出不是严格 v1 JSON")]
    InvalidOutput,
    #[error("TEE runtime adapter 输出与证明绑定不匹配")]
    BindingMismatch,
}

#[derive(Clone)]
pub struct ExternalTeeRuntime {
    provider: AttestationProvider,
    program: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeePreparedKey {
    pub key_handle: String,
    pub public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeCollectedEvidence {
    pub provider: AttestationProvider,
    pub evidence_kind: AttestationEvidenceKind,
    pub evidence_base64: String,
}

pub struct TeePrepareRequest<'a> {
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub sandbox_policy_hash: &'a str,
    pub runtime_binary_hash: &'a str,
    pub model_weights_hash: &'a str,
}

pub struct TeeInferRequest<'a> {
    pub key_handle: &'a str,
    pub tee_public_key: &'a str,
    pub node_id: Uuid,
    pub job_id: Uuid,
    pub route_id: Uuid,
    pub report_id: Uuid,
    pub model_instance_id: Uuid,
    pub model_weights_hash: &'a str,
    pub request_envelope: &'a RegulatedEnvelope,
    pub estimated_input_tokens: i32,
    pub max_output_tokens: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeInferenceResult {
    pub result_envelope: RegulatedEnvelope,
    pub actual_input_tokens: i32,
    pub actual_output_tokens: i32,
}

#[derive(Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum AdapterInput<'a> {
    Prepare {
        schema_version: &'static str,
        provider: AttestationProvider,
        node_id: Uuid,
        model_instance_id: Uuid,
        sandbox_policy_hash: &'a str,
        runtime_binary_hash: &'a str,
        model_weights_hash: &'a str,
    },
    Attest {
        schema_version: &'static str,
        provider: AttestationProvider,
        key_handle: &'a str,
        report_data: &'a str,
    },
    Infer {
        schema_version: &'static str,
        provider: AttestationProvider,
        key_handle: &'a str,
        tee_public_key: &'a str,
        node_id: Uuid,
        job_id: Uuid,
        route_id: Uuid,
        report_id: Uuid,
        model_instance_id: Uuid,
        model_weights_hash: &'a str,
        request_envelope: &'a RegulatedEnvelope,
        estimated_input_tokens: i32,
        max_output_tokens: i32,
    },
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum AdapterOutput {
    Prepare {
        schema_version: String,
        provider: AttestationProvider,
        key_handle: String,
        public_key: String,
    },
    Attest {
        schema_version: String,
        provider: AttestationProvider,
        evidence_kind: AttestationEvidenceKind,
        evidence: String,
        public_key: String,
    },
    Infer {
        schema_version: String,
        provider: AttestationProvider,
        key_handle: String,
        result_envelope: RegulatedEnvelope,
        actual_input_tokens: i32,
        actual_output_tokens: i32,
    },
}

impl ExternalTeeRuntime {
    pub fn from_environment(provider: AttestationProvider) -> Result<Self, TeeRuntimeError> {
        let device_name = match provider {
            AttestationProvider::AmdSevSnp => "AMD SEV-SNP",
            AttestationProvider::IntelTdx => "Intel TDX",
            AttestationProvider::None => "TEE",
        };
        if provider == AttestationProvider::None
            || !crate::attestation::provider_device_usable(provider)
        {
            return Err(TeeRuntimeError::DeviceUnavailable(device_name));
        }
        let raw = env::var_os("MINDONE_TEE_RUNTIME_PATH").ok_or(TeeRuntimeError::MissingProgram)?;
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(TeeRuntimeError::InvalidProgram);
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| TeeRuntimeError::InvalidProgram)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(TeeRuntimeError::InvalidProgram);
        }
        let program = std::fs::canonicalize(path).map_err(|_| TeeRuntimeError::InvalidProgram)?;
        Ok(Self { provider, program })
    }

    pub async fn prepare(
        &self,
        request: TeePrepareRequest<'_>,
    ) -> Result<TeePreparedKey, TeeRuntimeError> {
        validate_hash(request.sandbox_policy_hash)?;
        validate_hash(request.runtime_binary_hash)?;
        validate_hash(request.model_weights_hash)?;
        let output = self
            .invoke(
                &AdapterInput::Prepare {
                    schema_version: ADAPTER_SCHEMA,
                    provider: self.provider,
                    node_id: request.node_id,
                    model_instance_id: request.model_instance_id,
                    sandbox_policy_hash: request.sandbox_policy_hash,
                    runtime_binary_hash: request.runtime_binary_hash,
                    model_weights_hash: request.model_weights_hash,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        match output {
            AdapterOutput::Prepare {
                schema_version,
                provider,
                key_handle,
                public_key,
            } if schema_version == ADAPTER_SCHEMA && provider == self.provider => {
                validate_handle(&key_handle)?;
                validate_public_key(&public_key)?;
                Ok(TeePreparedKey {
                    key_handle,
                    public_key,
                })
            }
            _ => Err(TeeRuntimeError::BindingMismatch),
        }
    }

    pub async fn attest(
        &self,
        key: &TeePreparedKey,
        report_data: &str,
    ) -> Result<TeeCollectedEvidence, TeeRuntimeError> {
        validate_handle(&key.key_handle)?;
        validate_public_key(&key.public_key)?;
        validate_report_data(report_data)?;
        let output = self
            .invoke(
                &AdapterInput::Attest {
                    schema_version: ADAPTER_SCHEMA,
                    provider: self.provider,
                    key_handle: &key.key_handle,
                    report_data,
                },
                CONTROL_TIMEOUT,
            )
            .await?;
        match output {
            AdapterOutput::Attest {
                schema_version,
                provider,
                evidence_kind,
                evidence,
                public_key,
            } if schema_version == ADAPTER_SCHEMA
                && provider == self.provider
                && evidence_kind.matches_provider(provider)
                && public_key == key.public_key =>
            {
                validate_evidence(&evidence)?;
                Ok(TeeCollectedEvidence {
                    provider,
                    evidence_kind,
                    evidence_base64: evidence,
                })
            }
            _ => Err(TeeRuntimeError::BindingMismatch),
        }
    }

    pub async fn infer(
        &self,
        request: TeeInferRequest<'_>,
    ) -> Result<TeeInferenceResult, TeeRuntimeError> {
        validate_handle(request.key_handle)?;
        validate_public_key(request.tee_public_key)?;
        validate_hash(request.model_weights_hash)?;
        request
            .request_envelope
            .validate()
            .map_err(|_| TeeRuntimeError::InvalidOutput)?;
        if request.request_envelope.direction != EnvelopeDirection::Request
            || request.request_envelope.route_id != request.route_id
            || request.request_envelope.report_id != request.report_id
            || request.request_envelope.model_instance_id != request.model_instance_id
            || request.estimated_input_tokens < 0
            || request.max_output_tokens <= 0
        {
            return Err(TeeRuntimeError::BindingMismatch);
        }
        let output = self
            .invoke(
                &AdapterInput::Infer {
                    schema_version: ADAPTER_SCHEMA,
                    provider: self.provider,
                    key_handle: request.key_handle,
                    tee_public_key: request.tee_public_key,
                    node_id: request.node_id,
                    job_id: request.job_id,
                    route_id: request.route_id,
                    report_id: request.report_id,
                    model_instance_id: request.model_instance_id,
                    model_weights_hash: request.model_weights_hash,
                    request_envelope: request.request_envelope,
                    estimated_input_tokens: request.estimated_input_tokens,
                    max_output_tokens: request.max_output_tokens,
                },
                INFERENCE_TIMEOUT,
            )
            .await?;
        match output {
            AdapterOutput::Infer {
                schema_version,
                provider,
                key_handle,
                result_envelope,
                actual_input_tokens,
                actual_output_tokens,
            } if schema_version == ADAPTER_SCHEMA
                && provider == self.provider
                && key_handle == request.key_handle
                && actual_input_tokens >= 0
                && actual_output_tokens >= 0 =>
            {
                result_envelope
                    .validate()
                    .map_err(|_| TeeRuntimeError::InvalidOutput)?;
                if result_envelope.direction != EnvelopeDirection::Result
                    || result_envelope.route_id != request.route_id
                    || result_envelope.report_id != request.report_id
                    || result_envelope.model_instance_id != request.model_instance_id
                    || result_envelope.sender_public_key != request.tee_public_key
                {
                    return Err(TeeRuntimeError::BindingMismatch);
                }
                Ok(TeeInferenceResult {
                    result_envelope,
                    actual_input_tokens,
                    actual_output_tokens,
                })
            }
            _ => Err(TeeRuntimeError::BindingMismatch),
        }
    }

    async fn invoke(
        &self,
        input: &AdapterInput<'_>,
        deadline: Duration,
    ) -> Result<AdapterOutput, TeeRuntimeError> {
        let metadata = std::fs::symlink_metadata(&self.program)
            .map_err(|_| TeeRuntimeError::InvalidProgram)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(TeeRuntimeError::InvalidProgram);
        }
        let encoded = serde_json::to_vec(input).map_err(|_| TeeRuntimeError::InvalidOutput)?;
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| TeeRuntimeError::Spawn)?;
        let output =
            crate::bounded_process::communicate(&mut child, &encoded, deadline, MAX_OUTPUT_BYTES)
                .await
                .map_err(|error| match error {
                    crate::bounded_process::BoundedProcessError::Timeout => {
                        TeeRuntimeError::Timeout
                    }
                    crate::bounded_process::BoundedProcessError::OutputTooLarge => {
                        TeeRuntimeError::OutputTooLarge
                    }
                    crate::bounded_process::BoundedProcessError::Io => TeeRuntimeError::ExitFailure,
                })?;
        if !output.status.success() {
            return Err(TeeRuntimeError::ExitFailure);
        }
        serde_json::from_slice(&output.stdout).map_err(|_| TeeRuntimeError::InvalidOutput)
    }
}

fn validate_handle(value: &str) -> Result<(), TeeRuntimeError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), TeeRuntimeError> {
    if value.len() != 64 || !is_lower_hex(value) || value.bytes().all(|byte| byte == b'0') {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), TeeRuntimeError> {
    if value.len() != 64 || !is_lower_hex(value) {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    Ok(())
}

fn validate_report_data(value: &str) -> Result<(), TeeRuntimeError> {
    if value.len() != 128 || !is_lower_hex(value) {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    Ok(())
}

fn validate_evidence(value: &str) -> Result<(), TeeRuntimeError> {
    if value.is_empty()
        || value.len() > 768 * 1024
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    let evidence = BASE64_STANDARD
        .decode(value)
        .map_err(|_| TeeRuntimeError::InvalidOutput)?;
    if evidence.is_empty() || evidence.len() > 576 * 1024 {
        return Err(TeeRuntimeError::InvalidOutput);
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_and_public_keys_are_strict() {
        assert!(validate_handle("sealed-key:abc_123").is_ok());
        assert!(validate_handle("../../private").is_err());
        assert!(validate_public_key(&"11".repeat(32)).is_ok());
        assert!(validate_public_key(&"00".repeat(32)).is_err());
    }

    #[test]
    fn evidence_is_real_base64_and_bounded() {
        assert!(validate_evidence("YWJj").is_ok());
        assert!(validate_evidence("not base64").is_err());
    }
}
