use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use mindone_protocol::{AttestationEvidenceKind, AttestationProvider};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::process::Command;

const ADAPTER_SCHEMA: &str = "mindone.attestation.verifier.v1";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClientVerificationError {
    #[error("本机没有配置固定硬件 evidence verifier 或完整 allowlist")]
    Unavailable,
    #[error("本机硬件 evidence verifier 路径必须是绝对路径下非符号链接的普通文件")]
    InvalidProgram,
    #[error("本机硬件 evidence allowlist 格式无效")]
    InvalidAllowlist,
    #[error("prepared route 的策略、运行时或 TEE measurement 不在本机 allowlist")]
    NotAllowed,
    #[error("硬件 evidence 不是有效且受限的标准 base64")]
    InvalidEvidence,
    #[error("无法启动本机硬件 evidence verifier")]
    Spawn,
    #[error("本机硬件 evidence verifier 超时")]
    Timeout,
    #[error("本机硬件 evidence verifier 执行失败")]
    ExitFailure,
    #[error("本机硬件 evidence verifier 输出超过限制")]
    OutputTooLarge,
    #[error("本机硬件 evidence verifier 输出不是严格 v1 JSON")]
    InvalidOutput,
    #[error("本机 verifier 返回的 provider、证据类型或 REPORTDATA 不匹配")]
    BindingMismatch,
    #[error("本机 verifier 未确认签名、证书链、TCB 或 collateral")]
    HardwareRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientVerificationClaims {
    pub verifier_name: String,
    pub tee_measurement: String,
    pub collateral_expires_at: OffsetDateTime,
}

#[derive(Clone)]
pub struct ClientEvidenceVerifier {
    provider: AttestationProvider,
    program: PathBuf,
    allowed_policy_hashes: BTreeSet<String>,
    allowed_runtime_hashes: BTreeSet<String>,
    allowed_measurements: BTreeSet<String>,
    timeout: Duration,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterInput<'a> {
    schema_version: &'static str,
    provider: AttestationProvider,
    evidence_kind: AttestationEvidenceKind,
    evidence_base64: &'a str,
    expected_report_data: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterOutput {
    schema_version: String,
    verifier_name: String,
    provider: AttestationProvider,
    evidence_kind: AttestationEvidenceKind,
    verified: bool,
    report_data: String,
    tee_measurement: String,
    signature_verified: bool,
    certificate_chain_verified: bool,
    tcb_current: bool,
    collateral_current: bool,
    collateral_expires_at_unix: i64,
}

pub struct ClientVerificationInput<'a> {
    pub evidence_kind: AttestationEvidenceKind,
    pub evidence_base64: &'a str,
    pub expected_report_data: &'a str,
    pub sandbox_policy_hash: &'a str,
    pub runtime_binary_hash: &'a str,
    pub expected_measurement: &'a str,
    pub now: OffsetDateTime,
}

impl ClientEvidenceVerifier {
    pub fn from_environment(
        provider: AttestationProvider,
    ) -> Result<Self, ClientVerificationError> {
        let (program_name, policy_name, runtime_name, measurement_name) = match provider {
            AttestationProvider::AmdSevSnp => (
                "MINDONE_SNP_VERIFIER_PATH",
                "MINDONE_SNP_ALLOWED_POLICY_SHA256",
                "MINDONE_SNP_ALLOWED_RUNTIME_SHA256",
                "MINDONE_SNP_ALLOWED_MEASUREMENTS",
            ),
            AttestationProvider::IntelTdx => (
                "MINDONE_TDX_VERIFIER_PATH",
                "MINDONE_TDX_ALLOWED_POLICY_SHA256",
                "MINDONE_TDX_ALLOWED_RUNTIME_SHA256",
                "MINDONE_TDX_ALLOWED_MEASUREMENTS",
            ),
            AttestationProvider::None => return Err(ClientVerificationError::Unavailable),
        };
        let raw = env::var_os(program_name).ok_or(ClientVerificationError::Unavailable)?;
        let program = fixed_program(Path::new(&raw))?;
        let allowed_policy_hashes = parse_allowlist(policy_name, HashKind::Sha256)?;
        let allowed_runtime_hashes = parse_allowlist(runtime_name, HashKind::Sha256)?;
        let allowed_measurements = parse_allowlist(measurement_name, HashKind::Measurement)?;
        if allowed_policy_hashes.is_empty()
            || allowed_runtime_hashes.is_empty()
            || allowed_measurements.is_empty()
        {
            return Err(ClientVerificationError::Unavailable);
        }
        Ok(Self {
            provider,
            program,
            allowed_policy_hashes,
            allowed_runtime_hashes,
            allowed_measurements,
            timeout: Duration::from_secs(30),
        })
    }

    pub async fn verify(
        &self,
        input: ClientVerificationInput<'_>,
    ) -> Result<ClientVerificationClaims, ClientVerificationError> {
        if !self
            .allowed_policy_hashes
            .contains(input.sandbox_policy_hash)
            || !self
                .allowed_runtime_hashes
                .contains(input.runtime_binary_hash)
            || !self
                .allowed_measurements
                .contains(input.expected_measurement)
        {
            return Err(ClientVerificationError::NotAllowed);
        }
        validate_lower_hex(input.expected_report_data, 128)?;
        let evidence = BASE64_STANDARD
            .decode(input.evidence_base64)
            .map_err(|_| ClientVerificationError::InvalidEvidence)?;
        if evidence.is_empty() || evidence.len() > 576 * 1024 {
            return Err(ClientVerificationError::InvalidEvidence);
        }
        let metadata = std::fs::symlink_metadata(&self.program)
            .map_err(|_| ClientVerificationError::InvalidProgram)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ClientVerificationError::InvalidProgram);
        }
        let encoded = serde_json::to_vec(&AdapterInput {
            schema_version: ADAPTER_SCHEMA,
            provider: self.provider,
            evidence_kind: input.evidence_kind,
            evidence_base64: input.evidence_base64,
            expected_report_data: input.expected_report_data,
        })
        .map_err(|_| ClientVerificationError::InvalidOutput)?;
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|_| ClientVerificationError::Spawn)?;
        let output = crate::bounded_process::communicate(
            &mut child,
            &encoded,
            self.timeout,
            MAX_OUTPUT_BYTES,
        )
        .await
        .map_err(|error| match error {
            crate::bounded_process::BoundedProcessError::Timeout => {
                ClientVerificationError::Timeout
            }
            crate::bounded_process::BoundedProcessError::OutputTooLarge => {
                ClientVerificationError::OutputTooLarge
            }
            crate::bounded_process::BoundedProcessError::Io => ClientVerificationError::ExitFailure,
        })?;
        if !output.status.success() {
            return Err(ClientVerificationError::ExitFailure);
        }
        let output: AdapterOutput = serde_json::from_slice(&output.stdout)
            .map_err(|_| ClientVerificationError::InvalidOutput)?;
        validate_output(self, &output, &input)
    }
}

fn validate_output(
    verifier: &ClientEvidenceVerifier,
    output: &AdapterOutput,
    input: &ClientVerificationInput<'_>,
) -> Result<ClientVerificationClaims, ClientVerificationError> {
    if output.schema_version != ADAPTER_SCHEMA
        || output.verifier_name.is_empty()
        || output.verifier_name.len() > 128
        || !output.verifier_name.is_ascii()
    {
        return Err(ClientVerificationError::InvalidOutput);
    }
    validate_lower_hex(&output.report_data, 128)?;
    if !(64..=128).contains(&output.tee_measurement.len())
        || !output.tee_measurement.len().is_multiple_of(2)
    {
        return Err(ClientVerificationError::InvalidOutput);
    }
    validate_lower_hex(&output.tee_measurement, output.tee_measurement.len())?;
    if output.provider != verifier.provider
        || output.evidence_kind != input.evidence_kind
        || output.report_data != input.expected_report_data
        || output.tee_measurement != input.expected_measurement
    {
        return Err(ClientVerificationError::BindingMismatch);
    }
    let collateral_expires_at =
        OffsetDateTime::from_unix_timestamp(output.collateral_expires_at_unix)
            .map_err(|_| ClientVerificationError::InvalidOutput)?;
    if !output.verified
        || !output.signature_verified
        || !output.certificate_chain_verified
        || !output.tcb_current
        || !output.collateral_current
        || collateral_expires_at <= input.now
    {
        return Err(ClientVerificationError::HardwareRejected);
    }
    Ok(ClientVerificationClaims {
        verifier_name: output.verifier_name.clone(),
        tee_measurement: output.tee_measurement.clone(),
        collateral_expires_at,
    })
}

fn fixed_program(path: &Path) -> Result<PathBuf, ClientVerificationError> {
    if !path.is_absolute() {
        return Err(ClientVerificationError::InvalidProgram);
    }
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ClientVerificationError::InvalidProgram)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ClientVerificationError::InvalidProgram);
    }
    std::fs::canonicalize(path).map_err(|_| ClientVerificationError::InvalidProgram)
}

#[derive(Clone, Copy)]
enum HashKind {
    Sha256,
    Measurement,
}

fn parse_allowlist(
    name: &'static str,
    kind: HashKind,
) -> Result<BTreeSet<String>, ClientVerificationError> {
    let raw = env::var(name).map_err(|_| ClientVerificationError::Unavailable)?;
    let values = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if values.iter().any(|value| match kind {
        HashKind::Sha256 => validate_lower_hex(value, 64).is_err(),
        HashKind::Measurement => {
            !(64..=128).contains(&value.len())
                || !value.len().is_multiple_of(2)
                || validate_lower_hex(value, value.len()).is_err()
        }
    }) {
        return Err(ClientVerificationError::InvalidAllowlist);
    }
    Ok(values)
}

fn validate_lower_hex(value: &str, exact_len: usize) -> Result<(), ClientVerificationError> {
    if value.len() != exact_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClientVerificationError::InvalidOutput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_output_rejects_server_boolean_without_hardware_conclusions() {
        let output = AdapterOutput {
            schema_version: ADAPTER_SCHEMA.to_owned(),
            verifier_name: "test".to_owned(),
            provider: AttestationProvider::IntelTdx,
            evidence_kind: AttestationEvidenceKind::TdxQuote,
            verified: true,
            report_data: "11".repeat(64),
            tee_measurement: "22".repeat(48),
            signature_verified: true,
            certificate_chain_verified: false,
            tcb_current: true,
            collateral_current: true,
            collateral_expires_at_unix: 2_000_000_000,
        };
        let verifier = ClientEvidenceVerifier {
            provider: AttestationProvider::IntelTdx,
            program: PathBuf::from("/test/verifier"),
            allowed_policy_hashes: BTreeSet::new(),
            allowed_runtime_hashes: BTreeSet::new(),
            allowed_measurements: BTreeSet::from([output.tee_measurement.clone()]),
            timeout: Duration::from_secs(1),
        };
        let input = ClientVerificationInput {
            evidence_kind: AttestationEvidenceKind::TdxQuote,
            evidence_base64: "YWJj",
            expected_report_data: &output.report_data,
            sandbox_policy_hash: &"33".repeat(32),
            runtime_binary_hash: &"44".repeat(32),
            expected_measurement: &output.tee_measurement,
            now: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(
            validate_output(&verifier, &output, &input),
            Err(ClientVerificationError::HardwareRejected)
        );
    }
}
