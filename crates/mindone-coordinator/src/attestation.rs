use std::{path::PathBuf, process::Stdio, time::Duration};

use async_trait::async_trait;
use mindone_protocol::{AttestationEvidenceKind, AttestationProvider};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    time::timeout,
};

use crate::config::Config;

const ADAPTER_SCHEMA: &str = "mindone.attestation.verifier.v1";
const MAX_VERIFIER_OUTPUT_BYTES: usize = 1024 * 1024;

pub struct VerificationInput<'a> {
    pub provider: AttestationProvider,
    pub evidence_kind: AttestationEvidenceKind,
    pub evidence_base64: &'a str,
    pub expected_report_data: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationClaims {
    pub verifier_name: String,
    pub provider: AttestationProvider,
    pub evidence_kind: AttestationEvidenceKind,
    pub verified: bool,
    pub report_data: String,
    pub tee_measurement: String,
    pub signature_verified: bool,
    pub certificate_chain_verified: bool,
    pub tcb_current: bool,
    pub collateral_current: bool,
    pub collateral_expires_at: OffsetDateTime,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerificationError {
    #[error("未配置该硬件提供者的 verifier adapter")]
    Unavailable,
    #[error("verifier adapter 程序路径不再是已配置的普通文件")]
    ProgramChanged,
    #[error("无法启动 verifier adapter")]
    Spawn,
    #[error("verifier adapter 超时")]
    Timeout,
    #[error("verifier adapter 执行失败")]
    ExitFailure,
    #[error("verifier adapter 输出超过限制")]
    OutputTooLarge,
    #[error("verifier adapter 输出不是严格的 v1 JSON")]
    InvalidOutput,
    #[error("verifier adapter 输出与请求的 provider 或证据类型不匹配")]
    ProviderMismatch,
}

impl VerificationError {
    #[must_use]
    pub const fn audit_code(&self) -> &'static str {
        match self {
            Self::Unavailable => "verifier_unavailable",
            Self::ProgramChanged => "verifier_program_changed",
            Self::Spawn => "verifier_spawn_failed",
            Self::Timeout => "verifier_timeout",
            Self::ExitFailure => "verifier_exit_failed",
            Self::OutputTooLarge => "verifier_output_too_large",
            Self::InvalidOutput => "verifier_output_invalid",
            Self::ProviderMismatch => "verifier_provider_mismatch",
        }
    }
}

#[async_trait]
pub trait HardwareEvidenceVerifier: Send + Sync {
    async fn verify(
        &self,
        input: VerificationInput<'_>,
    ) -> Result<VerificationClaims, VerificationError>;
}

#[derive(Clone)]
pub struct ExternalHardwareEvidenceVerifier {
    amd_sev_snp_path: Option<PathBuf>,
    intel_tdx_path: Option<PathBuf>,
    timeout: Duration,
}

impl ExternalHardwareEvidenceVerifier {
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        Self {
            amd_sev_snp_path: config.amd_sev_snp_attestation.verifier_path.clone(),
            intel_tdx_path: config.intel_tdx_attestation.verifier_path.clone(),
            timeout: config.attestation_verifier_timeout,
        }
    }

    fn path_for(&self, provider: AttestationProvider) -> Option<&PathBuf> {
        match provider {
            AttestationProvider::AmdSevSnp => self.amd_sev_snp_path.as_ref(),
            AttestationProvider::IntelTdx => self.intel_tdx_path.as_ref(),
            AttestationProvider::None => None,
        }
    }
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

#[async_trait]
impl HardwareEvidenceVerifier for ExternalHardwareEvidenceVerifier {
    async fn verify(
        &self,
        input: VerificationInput<'_>,
    ) -> Result<VerificationClaims, VerificationError> {
        let path = self
            .path_for(input.provider)
            .ok_or(VerificationError::Unavailable)?;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| VerificationError::ProgramChanged)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(VerificationError::ProgramChanged);
        }
        let canonical =
            std::fs::canonicalize(path).map_err(|_| VerificationError::ProgramChanged)?;
        if canonical != *path {
            return Err(VerificationError::ProgramChanged);
        }
        let encoded = serde_json::to_vec(&AdapterInput {
            schema_version: ADAPTER_SCHEMA,
            provider: input.provider,
            evidence_kind: input.evidence_kind,
            evidence_base64: input.evidence_base64,
            expected_report_data: input.expected_report_data,
        })
        .map_err(|_| VerificationError::InvalidOutput)?;
        let mut child = Command::new(path);
        child
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = child.spawn().map_err(|_| VerificationError::Spawn)?;
        let output = communicate_bounded(
            &mut child,
            &encoded,
            self.timeout,
            MAX_VERIFIER_OUTPUT_BYTES,
        )
        .await?;
        if !output.status.success() {
            return Err(VerificationError::ExitFailure);
        }
        parse_adapter_output(&output.stdout, input.provider, input.evidence_kind)
    }
}

struct BoundedVerifierOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
}

async fn communicate_bounded(
    child: &mut Child,
    input: &[u8],
    deadline: Duration,
    maximum_stdout: usize,
) -> Result<BoundedVerifierOutput, VerificationError> {
    let mut stdin = child.stdin.take().ok_or(VerificationError::Spawn)?;
    let stdout = child.stdout.take().ok_or(VerificationError::Spawn)?;
    let operation = async {
        stdin
            .write_all(input)
            .await
            .map_err(|_| VerificationError::ExitFailure)?;
        stdin
            .shutdown()
            .await
            .map_err(|_| VerificationError::ExitFailure)?;
        drop(stdin);
        let mut stdout = stdout.take(maximum_stdout.saturating_add(1) as u64);
        let mut bytes = Vec::with_capacity(maximum_stdout.min(64 * 1024));
        let first_status = {
            let read = stdout.read_to_end(&mut bytes);
            let wait = child.wait();
            tokio::pin!(read);
            tokio::pin!(wait);
            tokio::select! {
                read_result = &mut read => {
                    read_result.map_err(|_| VerificationError::ExitFailure)?;
                    None
                }
                status = &mut wait => Some(status.map_err(|_| VerificationError::ExitFailure)?),
            }
        };
        if bytes.len() > maximum_stdout {
            return Err(VerificationError::OutputTooLarge);
        }
        let status = if let Some(status) = first_status {
            stdout
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| VerificationError::ExitFailure)?;
            if bytes.len() > maximum_stdout {
                return Err(VerificationError::OutputTooLarge);
            }
            status
        } else {
            child
                .wait()
                .await
                .map_err(|_| VerificationError::ExitFailure)?
        };
        Ok(BoundedVerifierOutput {
            status,
            stdout: bytes,
        })
    };
    let result = timeout(deadline, operation).await;
    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(error)) => {
            terminate(child).await;
            Err(error)
        }
        Err(_) => {
            terminate(child).await;
            Err(VerificationError::Timeout)
        }
    }
}

async fn terminate(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(Duration::from_secs(2), child.wait()).await;
}

fn parse_adapter_output(
    bytes: &[u8],
    provider: AttestationProvider,
    evidence_kind: AttestationEvidenceKind,
) -> Result<VerificationClaims, VerificationError> {
    let output: AdapterOutput =
        serde_json::from_slice(bytes).map_err(|_| VerificationError::InvalidOutput)?;
    if output.schema_version != ADAPTER_SCHEMA
        || output.verifier_name.is_empty()
        || output.verifier_name.len() > 128
        || !output.verifier_name.is_ascii()
        || output.report_data.len() != 128
        || !is_lower_hex(&output.report_data)
        || !(64..=128).contains(&output.tee_measurement.len())
        || !output.tee_measurement.len().is_multiple_of(2)
        || !is_lower_hex(&output.tee_measurement)
    {
        return Err(VerificationError::InvalidOutput);
    }
    if output.provider != provider || output.evidence_kind != evidence_kind {
        return Err(VerificationError::ProviderMismatch);
    }
    let collateral_expires_at =
        OffsetDateTime::from_unix_timestamp(output.collateral_expires_at_unix)
            .map_err(|_| VerificationError::InvalidOutput)?;
    Ok(VerificationClaims {
        verifier_name: output.verifier_name,
        provider: output.provider,
        evidence_kind: output.evidence_kind,
        verified: output.verified,
        report_data: output.report_data,
        tee_measurement: output.tee_measurement,
        signature_verified: output.signature_verified,
        certificate_chain_verified: output.certificate_chain_verified,
        tcb_current: output.tcb_current,
        collateral_current: output.collateral_current,
        collateral_expires_at,
    })
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_output() -> serde_json::Value {
        serde_json::json!({
            "schema_version": ADAPTER_SCHEMA,
            "verifier_name": "test-qvl",
            "provider": "intel_tdx",
            "evidence_kind": "tdx_quote",
            "verified": true,
            "report_data": "11".repeat(64),
            "tee_measurement": "22".repeat(48),
            "signature_verified": true,
            "certificate_chain_verified": true,
            "tcb_current": true,
            "collateral_current": true,
            "collateral_expires_at_unix": 2_000_000_000_i64
        })
    }

    #[test]
    fn strict_output_requires_every_verification_conclusion() {
        let encoded = serde_json::to_vec(&valid_output()).expect("测试输出应可编码");
        let claims = parse_adapter_output(
            &encoded,
            AttestationProvider::IntelTdx,
            AttestationEvidenceKind::TdxQuote,
        )
        .expect("完整输出应通过结构检查");
        assert!(claims.verified);
        assert!(claims.signature_verified);
        assert!(claims.certificate_chain_verified);
    }

    #[test]
    fn strict_output_rejects_unknown_fields_and_provider_mismatch() {
        let mut output = valid_output();
        output["client_claimed_trusted"] = serde_json::json!(true);
        let encoded = serde_json::to_vec(&output).expect("测试输出应可编码");
        assert_eq!(
            parse_adapter_output(
                &encoded,
                AttestationProvider::IntelTdx,
                AttestationEvidenceKind::TdxQuote,
            ),
            Err(VerificationError::InvalidOutput)
        );

        let encoded = serde_json::to_vec(&valid_output()).expect("测试输出应可编码");
        assert_eq!(
            parse_adapter_output(
                &encoded,
                AttestationProvider::AmdSevSnp,
                AttestationEvidenceKind::SnpExtendedReport,
            ),
            Err(VerificationError::ProviderMismatch)
        );
    }
}
