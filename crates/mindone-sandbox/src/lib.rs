//! MindOne 的平台隔离与远程证明边界。
//!
//! 本 crate 只报告实际探测到或实际应用的机制。无法应用隔离时返回明确错误，
//! 不会把“计划启用”展示成“已启用”。

pub mod attestation;
mod bounded_process;
pub mod capability;
pub mod client_verifier;
pub mod external_attester;
pub mod launch;
pub mod linux_supervisor;
pub mod tee_runtime;
pub mod windows_supervisor;

pub use attestation::{
    detected_provider_name, AttestationError, AttestationEvidence, AttestationExpectation,
    AttestationProvider, AttestationValidator, EvidenceSignatureVerifier, InMemoryReplayGuard,
    ReplayGuard,
};
pub use capability::{
    detect_capabilities, detect_capabilities_with_supervisor, CapabilityReport, IsolationMechanism,
    Platform, TrustLevel,
};
pub use client_verifier::{
    ClientEvidenceVerifier, ClientVerificationClaims, ClientVerificationError,
    ClientVerificationInput,
};
pub use external_attester::{CollectedEvidence, ExternalAttester, ExternalAttesterError};
pub use launch::{
    build_launch_plan, build_launch_plan_with_supervisor, LaunchPlan, SandboxAccess, SandboxError,
};
pub use linux_supervisor::{
    probe_linux_seccomp, probe_linux_security_layers, run_linux_seccomp_supervisor,
    run_linux_supervisor, LinuxSupervisorError,
};
pub use tee_runtime::{
    ExternalTeeRuntime, TeeCollectedEvidence, TeeInferRequest, TeeInferenceResult,
    TeePrepareRequest, TeePreparedKey, TeeRuntimeError,
};
pub use windows_supervisor::{run_windows_job_supervisor, WindowsSupervisorError};
