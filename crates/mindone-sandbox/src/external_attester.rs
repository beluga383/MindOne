use std::{env, path::PathBuf, process::Stdio, time::Duration};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use mindone_protocol::{AttestationEvidenceKind, AttestationProvider};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::process::Command;

const ADAPTER_SCHEMA: &str = "mindone.attestation.attester.v1";
const MAX_ADAPTER_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExternalAttesterError {
    #[error("此设备没有可访问的 {0} guest 证明设备")]
    DeviceUnavailable(&'static str),
    #[error("缺少固定 attester adapter 配置 {0}")]
    MissingProgram(&'static str),
    #[error("attester adapter 必须是绝对路径下非符号链接的普通文件")]
    InvalidProgram,
    #[error("无法启动 attester adapter")]
    Spawn,
    #[error("attester adapter 超时")]
    Timeout,
    #[error("attester adapter 执行失败")]
    ExitFailure,
    #[error("attester adapter 输出超过限制")]
    OutputTooLarge,
    #[error("attester adapter 输出不是严格的 v1 JSON")]
    InvalidOutput,
    #[error("attester adapter 返回了错误 provider 或证据类型")]
    ProviderMismatch,
}

#[derive(Clone)]
pub struct ExternalAttester {
    provider: AttestationProvider,
    program: PathBuf,
    timeout: Duration,
}

pub struct CollectedEvidence {
    pub provider: AttestationProvider,
    pub evidence_kind: AttestationEvidenceKind,
    pub evidence_base64: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterInput<'a> {
    schema_version: &'static str,
    provider: AttestationProvider,
    report_data: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterOutput {
    schema_version: String,
    provider: AttestationProvider,
    evidence_kind: AttestationEvidenceKind,
    evidence: String,
}

impl ExternalAttester {
    pub fn from_environment(provider: AttestationProvider) -> Result<Self, ExternalAttesterError> {
        let (variable, device_name) = match provider {
            AttestationProvider::AmdSevSnp => ("MINDONE_SNP_ATTESTER_PATH", "AMD SEV-SNP"),
            AttestationProvider::IntelTdx => ("MINDONE_TDX_ATTESTER_PATH", "Intel TDX"),
            AttestationProvider::None => {
                return Err(ExternalAttesterError::DeviceUnavailable("TEE"));
            }
        };
        if !crate::attestation::provider_device_usable(provider) {
            return Err(ExternalAttesterError::DeviceUnavailable(device_name));
        }
        let raw = env::var_os(variable).ok_or(ExternalAttesterError::MissingProgram(variable))?;
        let path = PathBuf::from(raw);
        if !path.is_absolute() {
            return Err(ExternalAttesterError::InvalidProgram);
        }
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|_| ExternalAttesterError::InvalidProgram)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ExternalAttesterError::InvalidProgram);
        }
        let program =
            std::fs::canonicalize(path).map_err(|_| ExternalAttesterError::InvalidProgram)?;
        Ok(Self {
            provider,
            program,
            timeout: Duration::from_secs(30),
        })
    }

    pub async fn collect(
        &self,
        report_data: &str,
    ) -> Result<CollectedEvidence, ExternalAttesterError> {
        if report_data.len() != 128 || !is_lower_hex(report_data) {
            return Err(ExternalAttesterError::InvalidOutput);
        }
        let metadata = std::fs::symlink_metadata(&self.program)
            .map_err(|_| ExternalAttesterError::InvalidProgram)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ExternalAttesterError::InvalidProgram);
        }
        let encoded = serde_json::to_vec(&AdapterInput {
            schema_version: ADAPTER_SCHEMA,
            provider: self.provider,
            report_data,
        })
        .map_err(|_| ExternalAttesterError::InvalidOutput)?;
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|_| ExternalAttesterError::Spawn)?;
        let output = crate::bounded_process::communicate(
            &mut child,
            &encoded,
            self.timeout,
            MAX_ADAPTER_OUTPUT_BYTES,
        )
        .await
        .map_err(|error| match error {
            crate::bounded_process::BoundedProcessError::Timeout => ExternalAttesterError::Timeout,
            crate::bounded_process::BoundedProcessError::OutputTooLarge => {
                ExternalAttesterError::OutputTooLarge
            }
            crate::bounded_process::BoundedProcessError::Io => ExternalAttesterError::ExitFailure,
        })?;
        if !output.status.success() {
            return Err(ExternalAttesterError::ExitFailure);
        }
        parse_output(&output.stdout, self.provider)
    }
}

fn parse_output(
    bytes: &[u8],
    provider: AttestationProvider,
) -> Result<CollectedEvidence, ExternalAttesterError> {
    let output: AdapterOutput =
        serde_json::from_slice(bytes).map_err(|_| ExternalAttesterError::InvalidOutput)?;
    if output.schema_version != ADAPTER_SCHEMA
        || output.provider != provider
        || !output.evidence_kind.matches_provider(provider)
    {
        return Err(ExternalAttesterError::ProviderMismatch);
    }
    if output.evidence.is_empty()
        || output.evidence.len() > 768 * 1024
        || !output.evidence.is_ascii()
        || output
            .evidence
            .bytes()
            .any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ExternalAttesterError::InvalidOutput);
    }
    let decoded = BASE64_STANDARD
        .decode(&output.evidence)
        .map_err(|_| ExternalAttesterError::InvalidOutput)?;
    if decoded.is_empty() || decoded.len() > 576 * 1024 {
        return Err(ExternalAttesterError::InvalidOutput);
    }
    Ok(CollectedEvidence {
        provider,
        evidence_kind: output.evidence_kind,
        evidence_base64: output.evidence,
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

    #[test]
    fn tdx_only_accepts_a_quote() {
        let bare_report = serde_json::json!({
            "schema_version": ADAPTER_SCHEMA,
            "provider": "intel_tdx",
            "evidence_kind": "snp_extended_report",
            "evidence": "YWJj"
        });
        let encoded = serde_json::to_vec(&bare_report).expect("测试输出应可编码");
        assert!(matches!(
            parse_output(&encoded, AttestationProvider::IntelTdx),
            Err(ExternalAttesterError::ProviderMismatch)
        ));
    }

    #[test]
    fn output_is_strict_and_base64_is_bounded() {
        let mut valid = serde_json::json!({
            "schema_version": ADAPTER_SCHEMA,
            "provider": "amd_sev_snp",
            "evidence_kind": "snp_extended_report",
            "evidence": "YWJj"
        });
        let encoded = serde_json::to_vec(&valid).expect("测试输出应可编码");
        assert!(parse_output(&encoded, AttestationProvider::AmdSevSnp).is_ok());
        valid["trusted"] = serde_json::json!(true);
        let encoded = serde_json::to_vec(&valid).expect("测试输出应可编码");
        assert!(matches!(
            parse_output(&encoded, AttestationProvider::AmdSevSnp),
            Err(ExternalAttesterError::InvalidOutput)
        ));
    }
}
