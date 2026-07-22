use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

const HASH_LEN: usize = 32;
const MIN_NONCE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub provider: String,
    pub nonce: Vec<u8>,
    pub issued_at_unix: i64,
    pub sandbox_policy_hash: [u8; HASH_LEN],
    pub runtime_binary_hash: [u8; HASH_LEN],
    pub model_weights_hash: [u8; HASH_LEN],
    pub report: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate_chain: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationExpectation {
    pub nonce: Vec<u8>,
    pub sandbox_policy_hash: [u8; HASH_LEN],
    pub runtime_binary_hash: [u8; HASH_LEN],
    pub model_weights_hash: [u8; HASH_LEN],
    pub now: OffsetDateTime,
    pub max_age: Duration,
    pub max_clock_skew: Duration,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AttestationError {
    #[error("此设备不支持 Enhanced 远程证明")]
    Unsupported,
    #[error("远程证明 nonce 无效")]
    InvalidNonce,
    #[error("检测到远程证明重放")]
    Replay,
    #[error("远程证明时间戳无效或已过期")]
    InvalidTimestamp,
    #[error("远程证明策略哈希不匹配")]
    PolicyHashMismatch,
    #[error("远程证明运行时哈希不匹配")]
    RuntimeHashMismatch,
    #[error("远程证明模型哈希不匹配")]
    ModelHashMismatch,
    #[error("远程证明硬件证书链或签名验证失败：{0}")]
    SignatureInvalid(String),
    #[error("远程证明报告结构无效：{0}")]
    InvalidReport(String),
}

#[async_trait]
pub trait AttestationProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_supported(&self) -> bool;
    async fn collect(
        &self,
        nonce: &[u8],
        sandbox_policy_hash: [u8; HASH_LEN],
        runtime_binary_hash: [u8; HASH_LEN],
        model_weights_hash: [u8; HASH_LEN],
    ) -> Result<AttestationEvidence, AttestationError>;
}

pub trait EvidenceSignatureVerifier: Send + Sync {
    /// 验证硬件厂商证书链、撤销状态、report 签名及 report 内 measurements。
    fn verify_hardware_evidence(
        &self,
        evidence: &AttestationEvidence,
    ) -> Result<(), AttestationError>;
}

pub trait ReplayGuard: Send + Sync {
    /// 原子记录 report 指纹；已存在时返回 `false`。
    fn record_once(&self, fingerprint: [u8; HASH_LEN]) -> bool;
}

#[derive(Debug, Default)]
pub struct InMemoryReplayGuard {
    seen: Mutex<HashSet<[u8; HASH_LEN]>>,
}

impl ReplayGuard for InMemoryReplayGuard {
    fn record_once(&self, fingerprint: [u8; HASH_LEN]) -> bool {
        self.seen
            .lock()
            .map(|mut seen| seen.insert(fingerprint))
            .unwrap_or(false)
    }
}

pub struct AttestationValidator<'a> {
    verifier: &'a dyn EvidenceSignatureVerifier,
    replay_guard: &'a dyn ReplayGuard,
}

impl<'a> AttestationValidator<'a> {
    pub fn new(
        verifier: &'a dyn EvidenceSignatureVerifier,
        replay_guard: &'a dyn ReplayGuard,
    ) -> Self {
        Self {
            verifier,
            replay_guard,
        }
    }

    pub fn validate(
        &self,
        evidence: &AttestationEvidence,
        expected: &AttestationExpectation,
    ) -> Result<[u8; HASH_LEN], AttestationError> {
        if expected.nonce.len() < MIN_NONCE_LEN || evidence.nonce != expected.nonce {
            return Err(AttestationError::InvalidNonce);
        }
        let issued_at = OffsetDateTime::from_unix_timestamp(evidence.issued_at_unix)
            .map_err(|error| AttestationError::InvalidReport(error.to_string()))?;
        let oldest = expected.now - expected.max_age;
        let newest = expected.now + expected.max_clock_skew;
        if issued_at < oldest || issued_at > newest {
            return Err(AttestationError::InvalidTimestamp);
        }
        if evidence.sandbox_policy_hash != expected.sandbox_policy_hash {
            return Err(AttestationError::PolicyHashMismatch);
        }
        if evidence.runtime_binary_hash != expected.runtime_binary_hash {
            return Err(AttestationError::RuntimeHashMismatch);
        }
        if evidence.model_weights_hash != expected.model_weights_hash {
            return Err(AttestationError::ModelHashMismatch);
        }
        if evidence.report.is_empty()
            || evidence.signature.is_empty()
            || evidence.certificate_chain.is_empty()
        {
            return Err(AttestationError::InvalidReport(
                "缺少 report、签名或硬件证书链".to_owned(),
            ));
        }
        self.verifier.verify_hardware_evidence(evidence)?;

        let fingerprint = evidence_fingerprint(evidence)?;
        if !self.replay_guard.record_once(fingerprint) {
            return Err(AttestationError::Replay);
        }
        Ok(fingerprint)
    }
}

fn evidence_fingerprint(
    evidence: &AttestationEvidence,
) -> Result<[u8; HASH_LEN], AttestationError> {
    let encoded = serde_json::to_vec(evidence)
        .map_err(|error| AttestationError::InvalidReport(error.to_string()))?;
    let digest = Sha256::digest(encoded);
    let mut value = [0_u8; HASH_LEN];
    value.copy_from_slice(&digest);
    Ok(value)
}

/// 只返回当前进程能够打开的真实 Linux TEE guest 设备。
///
/// 设备节点只能证明“可能采集 quote”，不能证明服务端已经验证证书链、TCB、
/// measurement 或撤销状态，因此调用方绝不能据此直接升级 Enhanced。
pub fn detected_provider_name() -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        if usable_tee_character_device("/dev/sev-guest") {
            return Some("amd-sev-snp");
        }
        // 新内核文档使用 /dev/tdx-guest；部分旧发行版仍暴露下划线名称。
        if usable_tee_character_device("/dev/tdx-guest")
            || usable_tee_character_device("/dev/tdx_guest")
        {
            return Some("intel-tdx");
        }
    }
    None
}

/// 仅表示相应 guest 设备节点是当前进程可打开的字符设备。
#[must_use]
pub fn provider_device_usable(provider: mindone_protocol::AttestationProvider) -> bool {
    #[cfg(target_os = "linux")]
    {
        match provider {
            mindone_protocol::AttestationProvider::AmdSevSnp => {
                usable_tee_character_device("/dev/sev-guest")
            }
            mindone_protocol::AttestationProvider::IntelTdx => {
                usable_tee_character_device("/dev/tdx-guest")
                    || usable_tee_character_device("/dev/tdx_guest")
            }
            mindone_protocol::AttestationProvider::None => false,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = provider;
        false
    }
}

#[cfg(target_os = "linux")]
fn usable_tee_character_device(path: &str) -> bool {
    use std::os::unix::fs::FileTypeExt;

    let path = std::path::Path::new(path);
    let is_character_device = std::fs::metadata(path)
        .map(|metadata| metadata.file_type().is_char_device())
        .unwrap_or(false);
    is_character_device
        && std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptKnownTestVector;

    impl EvidenceSignatureVerifier for AcceptKnownTestVector {
        fn verify_hardware_evidence(
            &self,
            evidence: &AttestationEvidence,
        ) -> Result<(), AttestationError> {
            if evidence.report == b"known-vendor-test-vector"
                && evidence.signature == b"known-signature"
            {
                Ok(())
            } else {
                Err(AttestationError::SignatureInvalid(
                    "测试向量不匹配".to_owned(),
                ))
            }
        }
    }

    fn fixture(now: OffsetDateTime) -> (AttestationEvidence, AttestationExpectation) {
        let nonce = vec![7_u8; MIN_NONCE_LEN];
        let policy = [1_u8; HASH_LEN];
        let runtime = [2_u8; HASH_LEN];
        let model = [3_u8; HASH_LEN];
        (
            AttestationEvidence {
                provider: "vendor-test".to_owned(),
                nonce: nonce.clone(),
                issued_at_unix: now.unix_timestamp(),
                sandbox_policy_hash: policy,
                runtime_binary_hash: runtime,
                model_weights_hash: model,
                report: b"known-vendor-test-vector".to_vec(),
                signature: b"known-signature".to_vec(),
                certificate_chain: vec![b"known-test-root".to_vec()],
            },
            AttestationExpectation {
                nonce,
                sandbox_policy_hash: policy,
                runtime_binary_hash: runtime,
                model_weights_hash: model,
                now,
                max_age: Duration::minutes(5),
                max_clock_skew: Duration::seconds(30),
            },
        )
    }

    #[test]
    fn validates_once_and_rejects_replay() {
        let now = OffsetDateTime::now_utc();
        let (evidence, expected) = fixture(now);
        let guard = InMemoryReplayGuard::default();
        let verifier = AcceptKnownTestVector;
        let validator = AttestationValidator::new(&verifier, &guard);
        assert!(validator.validate(&evidence, &expected).is_ok());
        assert_eq!(
            validator.validate(&evidence, &expected),
            Err(AttestationError::Replay)
        );
    }

    #[test]
    fn rejects_stale_and_hash_mismatch() {
        let now = OffsetDateTime::now_utc();
        let (mut evidence, expected) = fixture(now);
        evidence.issued_at_unix = (now - Duration::hours(1)).unix_timestamp();
        let guard = InMemoryReplayGuard::default();
        let verifier = AcceptKnownTestVector;
        let validator = AttestationValidator::new(&verifier, &guard);
        assert_eq!(
            validator.validate(&evidence, &expected),
            Err(AttestationError::InvalidTimestamp)
        );

        evidence.issued_at_unix = now.unix_timestamp();
        evidence.model_weights_hash = [9_u8; HASH_LEN];
        assert_eq!(
            validator.validate(&evidence, &expected),
            Err(AttestationError::ModelHashMismatch)
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_never_detects_hardware_provider() {
        assert_eq!(detected_provider_name(), None);
    }
}
