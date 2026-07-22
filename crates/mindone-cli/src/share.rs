use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use bytes::Bytes;
use futures_util::StreamExt;
use mindone_engine::{managed_share_slot_id, MANAGED_SHARE_MAX_CONCURRENT};
use mindone_protocol::{
    AttestationKeyOrigin, ClaimJobRequest, ClaimJobResponse, ConfidentialityMode,
    EnvelopeDirection, GpuProfile, HardwareProfile, HeartbeatRequest, HeartbeatResponse,
    JobErrorClass, JobExecutionTelemetry, JobFailRequest, JobFailResponse, JobResultRequest,
    JobResultResponse, JobStreamEventKind, JobStreamEventRequest, JobStreamEventResponse,
    ModelFormat, ModelInstanceStatus, NetworkHonorLabel, NetworkHonorLeaderboard,
    NetworkHonorTiePolicy, NodeHonorStats, NodePolicyDto, NodeStatsResponse, PayloadEncoding,
    PerformanceTier, PublishModelRequest, PublishModelResponse, RegisterNodeRequest,
    RegisterNodeResponse, RegulatedEnvelope, RenewJobRequest, RenewJobResponse, SandboxMechanism,
    StandardJobLimits, StandardJobPayload, UnpublishModelResponse, Validate,
};
use same_file::Handle as FileIdentity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sysinfo::{Pid, ProcessesToUpdate, System};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::refresh_session;
use crate::cli::{SharePublishArgs, ShareUnpublishArgs};
use crate::context::AppContext;
use crate::coordinator::CoordinatorClient;
use crate::error::{CliError, CliResult};
use crate::model::find_verified_model;
use crate::node::{
    evaluate_policy, hardware_metrics, load_persisted_policy, load_policy, save_policy,
    write_metrics, HardwareMetrics, ShareMetrics,
};
use crate::output::CommandOutput;
use crate::quota::format_micro;
use crate::serve;
use crate::storage::{read_json, write_json_atomic};
use crate::vault::CredentialBundle;

const STATE_FILE: &str = "share.json";
const STOP_FILE: &str = "share.stop";
const LOG_FILE: &str = "share-worker.log";
const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
const LOG_GENERATIONS: u8 = 5;
const LOG_MONITOR_INTERVAL: Duration = Duration::from_secs(1);
const HEARTBEAT_SECONDS: u64 = 15;
const DEFAULT_CONTEXT_LENGTH: i32 = 2_048;
const DEFAULT_BASE_COST_PER_1K_MICRO: i64 = 1_000_000;
const SUBMISSION_MAX_ATTEMPTS: usize = 5;
const SUBMISSION_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const SUBMISSION_MAX_BACKOFF: Duration = Duration::from_secs(2);
const WORKER_IDENTITY_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_FORCE_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const WORKER_COMMAND: [&str; 3] = ["__worker", "share", "--quiet"];
const MAX_INFERENCE_RESPONSE_BYTES: usize = 650 * 1024;
const STREAM_EVENT_CHANNEL_CAPACITY: usize = 8;
const VRAM_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
const CONTRIBUTION_PROGRESS_BAR_WIDTH: usize = 24;
const PROGRESS_PPM_SCALE: u32 = 1_000_000;

struct SensitiveHttpBody(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SensitiveHttpBody {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

struct SensitiveJobResultRequest(JobResultRequest);

impl std::ops::Deref for SensitiveJobResultRequest {
    type Target = JobResultRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct SensitiveJobStreamEventRequest(JobStreamEventRequest);

impl std::ops::Deref for SensitiveJobStreamEventRequest {
    type Target = JobStreamEventRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJobStreamEventRequest {
    fn drop(&mut self) {
        if let Some(value) = self.0.event_data.as_mut() {
            value.zeroize();
        }
    }
}

struct PendingStreamEvent {
    sequence: i32,
    kind: JobStreamEventKind,
    event_data: Option<String>,
}

struct StandardStreamForwarding {
    sender: tokio::sync::mpsc::Sender<PendingStreamEvent>,
    authorized_model: String,
}

impl Drop for PendingStreamEvent {
    fn drop(&mut self) {
        if let Some(value) = self.event_data.as_mut() {
            value.zeroize();
        }
    }
}

impl Drop for SensitiveJobResultRequest {
    fn drop(&mut self) {
        self.0.result_ciphertext.zeroize();
    }
}

struct SensitiveClaimJob(ClaimJobResponse);

impl std::ops::Deref for SensitiveClaimJob {
    type Target = ClaimJobResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveClaimJob {
    fn drop(&mut self) {
        self.0.encrypted_payload.zeroize();
        if let Some(value) = self.0.tee_public_key.as_mut() {
            value.zeroize();
        }
    }
}

struct SensitiveStandardJobPayload(StandardJobPayload);

impl std::ops::Deref for SensitiveStandardJobPayload {
    type Target = StandardJobPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SensitiveStandardJobPayload {
    fn take_request(&mut self) -> SensitiveJsonValue {
        SensitiveJsonValue(std::mem::take(&mut self.0.request))
    }
}

impl Drop for SensitiveStandardJobPayload {
    fn drop(&mut self) {
        self.0.endpoint.zeroize();
        zeroize_json_value(&mut self.0.request);
    }
}

struct SensitiveJsonValue(Value);

impl std::fmt::Debug for SensitiveJsonValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveJsonValue(<redacted>)")
    }
}

impl std::ops::Deref for SensitiveJsonValue {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveJsonValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

fn zeroize_json_value(value: &mut Value) {
    match std::mem::take(value) {
        Value::String(mut text) => text.zeroize(),
        Value::Array(mut values) => {
            for nested in &mut values {
                zeroize_json_value(nested);
            }
        }
        Value::Object(values) => {
            for (mut key, mut nested) in values {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[derive(Debug, Serialize)]
struct HonorObservation {
    observed_requests: u64,
    observed_failures: u64,
    observed_zero_failures: Option<bool>,
    contribution_rank_percentile: Option<f64>,
    zero_failure_streak_days: Option<u64>,
    previous_contribution_milestone_micro: Option<i64>,
    next_contribution_milestone_micro: Option<i64>,
    contribution_progress: Option<ContributionProgress>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct ContributionProgress {
    current_micro: i64,
    previous_milestone_micro: i64,
    next_milestone_micro: i64,
    completed_micro: i64,
    span_micro: i64,
    progress_ppm: u32,
}

#[derive(Debug, Clone, Copy)]
struct SubmissionRetryPolicy {
    max_attempts: usize,
    initial_backoff: Duration,
    max_backoff: Duration,
}

/// Owns the exact process handle until a newly spawned worker has completed
/// identity binding and its first heartbeat. Error paths can therefore attempt
/// to stop and reap that exact child instead of guessing from an incomplete PID
/// state file.
struct SpawnedWorker {
    child: Option<Child>,
}

impl SpawnedWorker {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> CliResult<u32> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| CliError::General("新共享 worker 的进程句柄已被释放".to_owned()))
    }

    fn stop_and_reap(&mut self) -> CliResult<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Err(error) = stop_and_reap_exact_child(&mut child) {
            self.child = Some(child);
            return Err(error);
        }
        Ok(())
    }

    fn release_if_running(&mut self) -> CliResult<()> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| CliError::General("新共享 worker 的进程句柄已被释放".to_owned()))?;
        match child.try_wait() {
            Ok(None) => {
                drop(self.child.take());
                Ok(())
            }
            Ok(Some(status)) => Err(CliError::General(format!(
                "共享 worker 在启动确认完成前已退出（状态：{status}）"
            ))),
            Err(error) => Err(CliError::General(format!(
                "无法确认共享 worker 在启动完成时仍存活：{error}"
            ))),
        }
    }
}

impl Drop for SpawnedWorker {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = stop_and_reap_exact_child(child);
        }
    }
}

fn stop_and_reap_exact_child(child: &mut Child) -> CliResult<()> {
    match child.try_wait() {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => {
            return Err(CliError::General(format!(
                "无法确认新共享 worker 是否已退出：{error}"
            )));
        }
    }

    if let Err(kill_error) = child.kill() {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) | Err(_) => {
                return Err(CliError::General(format!(
                    "无法终止新共享 worker：{kill_error}"
                )));
            }
        }
    }
    child.wait().map(|_| ()).map_err(|error| {
        CliError::General(format!("新共享 worker 已收到终止请求但无法回收：{error}"))
    })
}

#[derive(Clone, Copy)]
struct LogRotationConfig {
    max_bytes: u64,
    generations: u8,
    poll_interval: Duration,
}

impl LogRotationConfig {
    const PRODUCTION: Self = Self {
        max_bytes: LOG_ROTATE_BYTES,
        generations: LOG_GENERATIONS,
        poll_interval: LOG_MONITOR_INTERVAL,
    };

    fn validate(self) -> io::Result<Self> {
        if self.max_bytes == 0 || self.generations == 0 || self.poll_interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "共享日志轮转参数必须大于零",
            ));
        }
        Ok(self)
    }
}

struct WorkerLogMonitor {
    stop: Arc<AtomicBool>,
    failure: tokio::sync::watch::Receiver<Option<String>>,
    thread: Option<JoinHandle<()>>,
}

impl WorkerLogMonitor {
    fn start(
        path: PathBuf,
        config: LogRotationConfig,
        require_worker_stdio: bool,
    ) -> CliResult<Self> {
        let config = config
            .validate()
            .map_err(|error| CliError::General(format!("共享日志轮转配置无效：{error}")))?;
        let mut file = open_worker_log_file(&path)?;
        if require_worker_stdio {
            verify_worker_stdio_uses_log(&file)?;
        }
        rotate_worker_log_if_needed(&path, &mut file, config)
            .map_err(|error| CliError::General(format!("无法初始化共享日志轮转：{error}")))?;

        let stop = Arc::new(AtomicBool::new(false));
        let (failure_sender, failure) = tokio::sync::watch::channel(None);
        let thread_stop = Arc::clone(&stop);
        let monitor_thread = thread::Builder::new()
            .name("mindone-share-log-monitor".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    thread::sleep(config.poll_interval);
                    if thread_stop.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(error) = rotate_worker_log_if_needed(&path, &mut file, config) {
                        let message = format!("共享日志持续轮转失败，worker 将停止：{error}");
                        let _ = writeln!(io::stderr().lock(), "错误：{message}");
                        let _ = failure_sender.send(Some(message));
                        break;
                    }
                }
            })
            .map_err(|error| CliError::General(format!("无法启动共享日志监控线程：{error}")))?;
        Ok(Self {
            stop,
            failure,
            thread: Some(monitor_thread),
        })
    }

    fn ensure_healthy(&self) -> CliResult<()> {
        if let Some(message) = self.failure.borrow().as_ref() {
            return Err(CliError::General(message.clone()));
        }
        if self.thread.as_ref().is_none_or(JoinHandle::is_finished) {
            return Err(CliError::General(
                "共享日志监控线程意外退出，worker 拒绝继续运行".to_owned(),
            ));
        }
        Ok(())
    }

    async fn wait_for_failure(&self) -> CliError {
        let mut failure = self.failure.clone();
        loop {
            if let Some(message) = failure.borrow().as_ref() {
                return CliError::General(message.clone());
            }
            if failure.changed().await.is_err() {
                return CliError::General(
                    "共享日志监控线程意外退出，worker 拒绝继续运行".to_owned(),
                );
            }
        }
    }
}

impl Drop for WorkerLogMonitor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn open_worker_log_file(path: &Path) -> CliResult<File> {
    open_worker_log_file_io(path)
        .map_err(|error| CliError::General(format!("无法安全打开共享日志：{error}")))
}

fn open_worker_log_file_io(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "共享日志必须使用绝对路径",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "共享日志缺少父目录"))?;
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&parent_metadata)
        || !parent_metadata.is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "共享日志父目录不是安全的普通目录",
        ));
    }
    validate_existing_regular_log(path, None)?;

    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    configure_no_follow_log_open(&mut options);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "共享日志目标不是安全的普通文件",
        ));
    }
    verify_log_path_matches_file(path, &file)?;
    Ok(file)
}

#[cfg(unix)]
fn configure_no_follow_log_open(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
}

#[cfg(windows)]
fn configure_no_follow_log_open(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow_log_open(_options: &mut OpenOptions) {}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn verify_worker_stdio_uses_log(file: &File) -> CliResult<()> {
    let log_identity = file_identity(file)
        .map_err(|error| CliError::General(format!("无法读取共享日志文件身份：{error}")))?;
    let stdout = FileIdentity::stdout()
        .map_err(|error| CliError::General(format!("无法读取 worker stdout 身份：{error}")))?;
    let stderr = FileIdentity::stderr()
        .map_err(|error| CliError::General(format!("无法读取 worker stderr 身份：{error}")))?;
    if stdout != log_identity || stderr != log_identity {
        return Err(CliError::General(
            "共享 worker stdout/stderr 未绑定到受控日志文件，拒绝运行".to_owned(),
        ));
    }
    Ok(())
}

fn file_identity(file: &File) -> io::Result<FileIdentity> {
    FileIdentity::from_file(file.try_clone()?)
}

fn verify_log_path_matches_file(path: &Path, file: &File) -> io::Result<()> {
    validate_existing_regular_log(path, None)?;
    let path_identity = FileIdentity::from_path(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "共享日志路径已被替换，拒绝轮转其他文件",
            )
        } else {
            error
        }
    })?;
    if path_identity != file_identity(file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "共享日志路径已被替换，拒绝轮转其他文件",
        ));
    }
    Ok(())
}

fn generation_path(path: &Path, generation: u8) -> PathBuf {
    path.with_extension(format!("log.{generation}"))
}

fn validate_existing_regular_log(path: &Path, max_bytes: Option<u64>) -> io::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("拒绝跟随或覆盖非普通日志路径 {}", path.display()),
        ));
    }
    if max_bytes.is_some_and(|limit| metadata.len() > limit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("日志代文件 {} 超出单代大小上限", path.display()),
        ));
    }
    Ok(())
}

fn rotate_worker_log_if_needed(
    path: &Path,
    file: &mut File,
    config: LogRotationConfig,
) -> io::Result<bool> {
    let config = config.validate()?;
    verify_log_path_matches_file(path, file)?;
    for generation in 1..=config.generations {
        validate_existing_regular_log(&generation_path(path, generation), Some(config.max_bytes))?;
    }
    let size = file.metadata()?.len();
    if size < config.max_bytes {
        return Ok(false);
    }

    let oldest_generation = generation_path(path, config.generations);
    match std::fs::remove_file(&oldest_generation) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    for generation in (2..=config.generations).rev() {
        let source = generation_path(path, generation - 1);
        let destination = generation_path(path, generation);
        if source.exists() {
            std::fs::rename(&source, &destination)?;
        }
    }

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "共享日志缺少父目录"))?;
    let mut snapshot = tempfile::NamedTempFile::new_in(parent)?;
    let mut source = file.try_clone()?;
    source.seek(SeekFrom::Start(size.saturating_sub(config.max_bytes)))?;
    io::copy(&mut source.take(config.max_bytes), snapshot.as_file_mut())?;
    snapshot.as_file_mut().flush()?;
    snapshot.as_file().sync_data()?;
    let first_generation = generation_path(path, 1);
    snapshot
        .persist_noclobber(&first_generation)
        .map_err(|error| error.error)?;
    file.set_len(0)?;
    file.sync_data()?;
    verify_log_path_matches_file(path, file)?;
    Ok(true)
}

impl SubmissionRetryPolicy {
    const PRODUCTION: Self = Self {
        max_attempts: SUBMISSION_MAX_ATTEMPTS,
        initial_backoff: SUBMISSION_INITIAL_BACKOFF,
        max_backoff: SUBMISSION_MAX_BACKOFF,
    };
}

#[derive(Clone, Copy)]
enum JobSubmission<'a> {
    Result(&'a JobResultRequest),
    Failure(&'a JobFailRequest),
    StreamEvent(&'a JobStreamEventRequest),
}

struct ExecutionAttempt {
    result: CliResult<WorkerExecutionResult>,
    lease_expires_at: OffsetDateTime,
    vram_peak: VramPeakObservation,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct VramPeakObservation {
    peak_vram_mib: Option<i64>,
    sample_count: u32,
}

impl VramPeakObservation {
    fn observe(&mut self, metrics: &HardwareMetrics) {
        let Some(bytes) = metrics.vram_used_bytes else {
            return;
        };
        let mib = bytes.saturating_add(1_048_575) / 1_048_576;
        let Ok(mib) = i64::try_from(mib) else {
            return;
        };
        self.peak_vram_mib = Some(self.peak_vram_mib.unwrap_or(mib).max(mib));
        self.sample_count = self.sample_count.saturating_add(1);
    }

    fn merge(&mut self, other: Self) {
        if let Some(peak) = other.peak_vram_mib {
            self.peak_vram_mib = Some(self.peak_vram_mib.unwrap_or(peak).max(peak));
        }
        self.sample_count = self.sample_count.saturating_add(other.sample_count);
    }
}

struct VramPeakSampler {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<VramPeakObservation>>,
}

impl VramPeakSampler {
    fn start() -> Self {
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut observation = VramPeakObservation::default();
            loop {
                if let Ok(metrics) = tokio::task::spawn_blocking(hardware_metrics).await {
                    observation.observe(&metrics);
                }
                tokio::select! {
                    _ = &mut stopped => break,
                    () = tokio::time::sleep(VRAM_SAMPLE_INTERVAL) => {}
                }
            }
            observation
        });
        Self {
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn finish(mut self) -> VramPeakObservation {
        let mut observation = VramPeakObservation::default();
        if let Ok(metrics) = tokio::task::spawn_blocking(hardware_metrics).await {
            observation.observe(&metrics);
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            match task.await {
                Ok(sampled) => observation.merge(sampled),
                Err(error) => tracing::warn!(error = %error, "任务显存峰值采样器异常结束"),
            }
        }
        observation
    }
}

impl Drop for VramPeakSampler {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct StandardExecutionResult {
    response: SensitiveJsonValue,
    /// 从本地 HTTP 请求开始发送到首个非空生成 delta 到达的单调时钟实测值。
    /// 没有可见生成 token 时保持未知，绝不以 prompt timing 推导。
    measured_ttft_ms: Option<i64>,
}

enum WorkerExecutionResult {
    Standard(StandardExecutionResult),
    Regulated(mindone_sandbox::TeeInferenceResult),
}

impl WorkerExecutionResult {
    /// 读取本机推理引擎实际返回的生成吞吐，而不是把模型哈希复验、租约续期和
    /// 结果上传时间混入 TPS。llama.cpp 在非流式 OpenAI 响应的 `timings` 中给出
    /// 真实 token 生成计时；值缺失或异常时保持未知，绝不伪造为 0。
    fn inference_tps(&self) -> Option<f64> {
        match self {
            Self::Standard(value) => positive_finite(
                value
                    .response
                    .pointer("/timings/predicted_per_second")
                    .and_then(Value::as_f64),
            ),
            Self::Regulated(_) => None,
        }
    }

    /// 只返回流式 HTTP 路径用单调时钟观测到的首个生成 token 到达时间。
    /// Regulated adapter 尚未提供等价事件，因此保持未知。
    fn measured_ttft_ms(&self) -> Option<i64> {
        match self {
            Self::Standard(value) => value.measured_ttft_ms,
            Self::Regulated(_) => None,
        }
    }
}

fn job_execution_telemetry(
    result: &WorkerExecutionResult,
    vram_peak: VramPeakObservation,
) -> JobExecutionTelemetry {
    JobExecutionTelemetry {
        ttft_ms: result.measured_ttft_ms(),
        tps_milli: result
            .inference_tps()
            .and_then(|value| rounded_positive_i64(value * 1_000.0)),
        peak_vram_mib: vram_peak.peak_vram_mib,
        vram_sample_count: vram_peak.sample_count,
    }
}

fn rounded_positive_i64(value: f64) -> Option<i64> {
    if !value.is_finite() || value <= 0.0 || value > i64::MAX as f64 {
        return None;
    }
    Some(value.round().max(1.0) as i64)
}

fn positive_finite(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value > 0.0)
}

struct ActiveJobLiveness<'a> {
    context: &'a AppContext,
    state: &'a mut ShareState,
    metrics: &'a ShareMetrics,
    heartbeat_interval: Duration,
    next_heartbeat: tokio::time::Instant,
    slot_id: u32,
    active_count: Arc<AtomicU16>,
    heartbeat_lock: Arc<tokio::sync::Mutex<()>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
struct SharedJobRuntime {
    active_count: Arc<AtomicU16>,
    heartbeat_lock: Arc<tokio::sync::Mutex<()>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedWorkerIdentity {
    process_start_marker: String,
    executable: PathBuf,
    command: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareState {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_start_marker: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_executable: Option<PathBuf>,
    #[serde(default)]
    pub worker_command: Vec<String>,
    pub node_id: Uuid,
    #[serde(default)]
    pub model_id: Uuid,
    pub model_instance_id: Uuid,
    pub model_name: String,
    pub model_path: PathBuf,
    pub model_weights_hash: String,
    pub alias: String,
    pub tags: Vec<String>,
    pub local_port: u16,
    pub tier: PerformanceTier,
    pub trust_level: String,
    pub started_at: String,
    pub last_heartbeat_at: Option<String>,
    /// 上一次由当前 worker 完整收到并解码成功的协调服务器心跳往返时延。
    ///
    /// 该值随下一次心跳上报；旧版状态缺少字段时必须安全退化为无样本。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_coordinator_rtt_ms: Option<i64>,
    #[serde(default)]
    pub paused_for_temperature: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveAttestationTarget {
    pub node_id: Uuid,
    pub model_instance_id: Uuid,
    pub model_path: PathBuf,
    pub model_weights_hash: String,
    pub runtime_binary_hash: String,
    pub sandbox_policy_hash: String,
}

pub async fn load_attestation_target(context: &AppContext) -> CliResult<ActiveAttestationTarget> {
    let state: ShareState =
        read_json(&context.paths.runtime.join(STATE_FILE)).map_err(|error| {
            CliError::Attestation(format!(
                "没有活动的 share 发布状态；请先运行 mindone share publish：{error}"
            ))
        })?;
    if !worker_process_is_running(&state)? {
        return Err(CliError::Attestation(
            "share worker 未运行，拒绝为非活动节点生成证明".to_owned(),
        ));
    }
    let serve_state = serve::load_state(context)
        .await
        .map_err(|error| CliError::Attestation(format!("推理服务未通过身份和健康检查：{error}")))?;
    if serve_state.model_path != state.model_path {
        return Err(CliError::Attestation(
            "share 与 serve 的模型路径不一致，拒绝生成证明".to_owned(),
        ));
    }
    let actual_model_hash = mindone_common::sha256_file(&state.model_path)
        .map_err(|error| CliError::Attestation(format!("无法计算活动模型哈希：{error}")))?;
    if !mindone_common::constant_time_sha256_eq(&actual_model_hash, &state.model_weights_hash) {
        return Err(CliError::Attestation(
            "活动模型文件已变化，拒绝生成证明".to_owned(),
        ));
    }
    let runtime_binary_hash = mindone_common::sha256_file(&serve_state.engine_path)
        .map_err(|error| CliError::Attestation(format!("无法计算推理运行时哈希：{error}")))?;
    if !is_sha256(&serve_state.sandbox_policy_hash) {
        return Err(CliError::Attestation(
            "活动服务状态没有有效的实际沙盒策略哈希；请重启 serve".to_owned(),
        ));
    }
    Ok(ActiveAttestationTarget {
        node_id: state.node_id,
        model_instance_id: state.model_instance_id,
        model_path: state.model_path,
        model_weights_hash: actual_model_hash,
        runtime_binary_hash,
        sandbox_policy_hash: serve_state.sandbox_policy_hash,
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub async fn publish(context: &AppContext, args: &SharePublishArgs) -> CliResult<CommandOutput> {
    let state_path = context.paths.runtime.join(STATE_FILE);
    if state_path.exists() {
        let state: ShareState = read_json(&state_path)?;
        if worker_process_is_running(&state)? {
            return Err(CliError::General(format!(
                "共享 worker 已运行（PID {}，模型 {}）",
                state.pid, state.model_name
            )));
        }
        return Err(CliError::General(format!(
            "模型实例 {} 仍有本地发布状态；请先运行 mindone share unpublish 确认服务端终态",
            state.model_instance_id
        )));
    }
    remove_if_exists(&context.paths.runtime.join(STOP_FILE))?;
    let mut session = context.vault.load_session()?;
    let alias = args
        .alias
        .clone()
        .unwrap_or_else(|| stable_node_alias(&session));
    validate_alias(&alias)?;
    let tags = normalize_tags(&args.tags)?;
    let model = find_verified_model(context, &args.model)?;
    let serve_state = serve::load_state(context).await?;
    if serve_state.model_path != model.path {
        return Err(CliError::General(format!(
            "当前本地服务运行模型 {}，与待发布模型 {} 不一致",
            serve_state.model_name, model.name
        )));
    }
    let policy = load_policy(context)?;
    evaluate_policy(&policy, &[], 0, &hardware_metrics())?;
    // 把生效策略持久化为节点本地权威文件，使领取前与执行前两次策略检查都读取
    // 同一份可审计文件，运维也能直接查看/修改当前策略；缺失时用校验通过的默认值
    // 落盘，而不是只在内存里回退默认。
    save_policy(context, &policy)?;
    let hardware = protocol_hardware_profile(&serve_state.sandbox_mechanisms)?;
    let register_request = RegisterNodeRequest {
        alias: alias.clone(),
        hardware_profile: hardware,
        reject_tags: policy.reject_tags.clone(),
        max_concurrent: u32::from(policy.max_concurrent),
        gpu_temp_limit_c: policy.gpu_temp_limit_c,
        vram_reserve_mib: gib_to_mib_u64(policy.vram_reserve_gb)?,
    };
    register_request
        .validate()
        .map_err(|error| CliError::PolicyRejected(error.to_string()))?;
    let registered: RegisterNodeResponse = context
        .authorized_post(mindone_protocol::NODES_REGISTER, &register_request)
        .await?;
    let context_length = local_context_length(serve_state.backend_port)
        .await
        .unwrap_or(DEFAULT_CONTEXT_LENGTH);
    let publish_request = PublishModelRequest {
        node_id: registered.node_id,
        name: model.name.clone(),
        alias: model.name.clone(),
        format: match model.format {
            mindone_engine::ModelFormat::Gguf => ModelFormat::Gguf,
            mindone_engine::ModelFormat::Safetensors => ModelFormat::Safetensors,
        },
        weights_hash: model.sha256.clone(),
        size_bytes: i64::try_from(model.size_bytes)
            .map_err(|_| CliError::ModelValidation("模型大小超出协议范围".to_owned()))?,
        context_length,
        benchmark_normalized: 0,
        glicko_normalized: 0,
        evaluation_samples: 0,
        base_cost_per_1k_micro: DEFAULT_BASE_COST_PER_1K_MICRO,
        tags: tags.clone(),
    };
    publish_request
        .validate()
        .map_err(|error| CliError::ModelValidation(error.to_string()))?;
    let started_at = now_rfc3339()?;
    let published: PublishModelResponse = context
        .authorized_post(mindone_protocol::MODELS_PUBLISH, &publish_request)
        .await?;
    let state = ShareState {
        pid: 0,
        process_start_marker: None,
        worker_executable: None,
        worker_command: Vec::new(),
        node_id: registered.node_id,
        model_id: published.model_id,
        model_instance_id: published.model_instance_id,
        model_name: model.name,
        model_path: model.path,
        model_weights_hash: model.sha256,
        alias,
        tags,
        // share worker 复用自身严格的 SSE 校验与同步 erase，必须直连受管内部端口；
        // 外部应用只能访问 public proxy，避免同一请求发生两次 erase。
        local_port: serve_state.backend_port,
        tier: published.tier,
        trust_level: format!("{:?}", registered.trust_level),
        started_at,
        last_heartbeat_at: None,
        last_coordinator_rtt_ms: None,
        paused_for_temperature: false,
    };
    let mut state = state;
    let mut spawned_worker = None;
    let activated: CliResult<ShareState> = async {
        write_json_atomic(&state_path, &state)?;
        let executable = std::env::current_exe()
            .map_err(|error| CliError::General(format!("无法定位 mindone 可执行文件：{error}")))?;
        let log_path = context.paths.logs.join(LOG_FILE);
        let stdout = open_worker_log_file(&log_path)?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| CliError::General(format!("无法复制共享日志句柄：{error}")))?;
        let mut worker = Command::new(&executable);
        worker.args(WORKER_COMMAND);
        if std::env::var_os("MINDONE_HOME").is_some() {
            worker.env("MINDONE_HOME", &context.paths.home);
        }
        let child = worker
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| CliError::General(format!("无法启动共享 worker：{error}")))?;
        let owned_worker = SpawnedWorker::new(child);
        state.pid = owned_worker.id()?;
        spawned_worker = Some(owned_worker);
        state.worker_executable = Some(executable.clone());
        state.worker_command = expected_worker_command();
        let observed =
            wait_for_worker_identity(state.pid, &executable, WORKER_IDENTITY_TIMEOUT).await?;
        state.process_start_marker = Some(observed.process_start_marker);
        write_json_atomic(&state_path, &state)?;
        wait_for_first_heartbeat(context, state.pid, Duration::from_secs(20)).await?;
        read_json(&state_path)
    }
    .await;
    let activated = match activated {
        Ok(state) => match spawned_worker.as_mut() {
            Some(worker) => worker.release_if_running().map(|()| state),
            None => Err(CliError::General(
                "共享 worker 启动完成但进程句柄不存在".to_owned(),
            )),
        },
        Err(error) => Err(error),
    };
    let state = match activated {
        Ok(state) => state,
        Err(start_error) => {
            match compensate_failed_publish(context, &mut session, &state, spawned_worker.take())
                .await
            {
                Ok(()) => return Err(start_error),
                Err(compensation_error) => {
                    return Err(CliError::General(format!(
                        "{start_error}；发布补偿未完全完成：{compensation_error}"
                    )));
                }
            }
        }
    };
    CommandOutput::new(
        format!(
            "模型已真实发布，节点 worker 正在运行\n节点 ID：{}\n模型实例：{}\n模型：{}\nTier：{:?}\nPID：{}\n心跳：{}\n通信：出站 HTTPS/loopback 推理，未暴露 llama-server",
            state.node_id,
            state.model_instance_id,
            state.model_name,
            state.tier,
            state.pid,
            state.last_heartbeat_at.as_deref().unwrap_or("等待中")
        ),
        state,
    )
}

async fn compensate_failed_publish(
    context: &AppContext,
    session: &mut CredentialBundle,
    state: &ShareState,
    spawned_worker: Option<SpawnedWorker>,
) -> CliResult<()> {
    let state_path = context.paths.runtime.join(STATE_FILE);
    let stop_path = context.paths.runtime.join(STOP_FILE);
    let mut local_issues = Vec::new();
    let mut preserve_worker_identity = false;
    let mut recovery_state = read_json::<ShareState>(&state_path)
        .ok()
        .filter(|stored| stored.model_instance_id == state.model_instance_id)
        .unwrap_or_else(|| state.clone());

    if let Some(mut worker) = spawned_worker {
        let pid = worker.id()?;
        recovery_state.pid = pid;
        merge_known_worker_identity(&mut recovery_state, state);
        match worker.stop_and_reap() {
            Ok(()) => clear_worker_identity(&mut recovery_state),
            Err(error) => {
                merge_observed_worker_identity(&mut recovery_state);
                local_issues.push(format!(
                    "无法通过新建进程句柄回收 worker PID {pid}：{error}"
                ));
                preserve_worker_identity = true;
            }
        }
    }

    if let Err(error) = write_json_atomic(&state_path, &recovery_state) {
        local_issues.push(format!("无法保留恢复状态：{error}"));
    }

    let remote = delete_model_instance(context, session, state.model_instance_id).await;
    match remote {
        Ok(response) if response.status == ModelInstanceStatus::Unpublished => {
            if preserve_worker_identity {
                local_issues.push(preserved_worker_identity_message(&recovery_state));
            } else if let Err(error) =
                reconcile_local_unpublish_state(&state_path, &stop_path, &recovery_state, &response)
            {
                local_issues.push(error.to_string());
            }
            if local_issues.is_empty() {
                Ok(())
            } else {
                Err(CliError::General(format!(
                    "服务端已取消发布，但本地清理存在问题：{}",
                    local_issues.join("；")
                )))
            }
        }
        Ok(response) => {
            if preserve_worker_identity {
                local_issues.push(preserved_worker_identity_message(&recovery_state));
            } else if let Err(error) =
                reconcile_local_unpublish_state(&state_path, &stop_path, &recovery_state, &response)
            {
                local_issues.push(error.to_string());
            }
            Err(CliError::General(format!(
                "服务端补偿状态为{}，仍有 {} 个活动任务；本地状态已保留，可继续运行 mindone share unpublish{}",
                model_instance_status_zh(response.status),
                response.active_jobs,
                format_local_issues(&local_issues)
            )))
        }
        Err(error) => {
            if let Err(cleanup_error) = remove_if_exists(&stop_path) {
                local_issues.push(cleanup_error.to_string());
            }
            Err(CliError::General(format!(
                "无法向服务端确认取消发布：{error}；本地状态已保留，可继续运行 mindone share unpublish{}",
                format_local_issues(&local_issues)
            )))
        }
    }
}

pub async fn unpublish(
    context: &AppContext,
    args: &ShareUnpublishArgs,
) -> CliResult<CommandOutput> {
    let state_path = context.paths.runtime.join(STATE_FILE);
    let state: ShareState = read_json(&state_path)
        .map_err(|_| CliError::General("本机没有活动的模型发布".to_owned()))?;
    if let Some(id) = &args.id {
        if id != &state.model_instance_id.to_string() {
            return Err(CliError::General(format!(
                "活动实例为 {}，与 --id {id} 不匹配",
                state.model_instance_id
            )));
        }
    }
    if let Some(model) = &args.model {
        if model != &state.model_name {
            return Err(CliError::General(format!(
                "活动模型为 {}，与 --model {model} 不匹配",
                state.model_name
            )));
        }
    }
    let stop_path = context.paths.runtime.join(STOP_FILE);
    let initially_running = worker_process_is_running(&state)?;
    if initially_running {
        std::fs::write(&stop_path, b"drain\n")
            .map_err(|error| CliError::General(format!("无法请求 worker 排空任务：{error}")))?;
    }
    let stopped_gracefully =
        wait_for_verified_worker_stop(&state, Duration::from_secs(args.timeout)).await?;
    let forced = if stopped_gracefully {
        false
    } else {
        stop_verified_worker(&state, WORKER_FORCE_STOP_TIMEOUT).await?;
        true
    };
    // 远端取消前再做一次 PID+启动标记复核。失败会在下面的请求前
    // 直接返回非零，因而状态中的 worker 身份不会被清空。
    if !wait_for_verified_worker_stop(&state, Duration::from_millis(50)).await? {
        return Err(CliError::General(format!(
            "共享 worker PID {} 在停止信号后仍存活；已保留 PID 与启动标记",
            state.pid
        )));
    }
    let mut session = context.vault.load_session()?;
    let remote = delete_model_instance(context, &mut session, state.model_instance_id).await;
    let response = remote?;
    let state_preserved =
        reconcile_local_unpublish_state(&state_path, &stop_path, &state, &response)?;
    unpublish_command_output(&state, forced, &response, state_preserved)
}

fn reconcile_local_unpublish_state(
    state_path: &std::path::Path,
    stop_path: &std::path::Path,
    state: &ShareState,
    response: &UnpublishModelResponse,
) -> CliResult<bool> {
    remove_if_exists(stop_path)?;
    if response.status == ModelInstanceStatus::Unpublished {
        remove_if_exists(state_path)?;
        Ok(false)
    } else {
        let mut stopped_state = state.clone();
        clear_worker_identity(&mut stopped_state);
        write_json_atomic(state_path, &stopped_state)?;
        Ok(true)
    }
}

fn unpublish_command_output(
    state: &ShareState,
    forced: bool,
    response: &UnpublishModelResponse,
    state_preserved: bool,
) -> CliResult<CommandOutput> {
    let unpublished = response.status == ModelInstanceStatus::Unpublished;
    let human = if unpublished {
        if forced {
            "排空等待超时，已停止 worker；服务端已确认取消发布，未完成任务将由租约机制重试"
                .to_owned()
        } else {
            "已停止领取新任务、排空已有任务，服务端已确认取消发布".to_owned()
        }
    } else {
        format!(
            "已停止 worker；服务端当前状态为{}，仍有 {} 个活动任务。本地状态已保留，请稍后再次运行 mindone share unpublish 确认终态",
            model_instance_status_zh(response.status),
            response.active_jobs
        )
    };
    let output = CommandOutput::new(
        human,
        serde_json::json!({
            "unpublished": unpublished,
            "status": response.status,
            "active_jobs": response.active_jobs,
            "model_instance_id": state.model_instance_id,
            "forced": forced,
            "state_preserved": state_preserved,
        }),
    )?;
    Ok(if unpublished {
        output
    } else {
        output.with_exit_code(1)
    })
}

pub async fn stats(context: &AppContext) -> CliResult<CommandOutput> {
    let state: ShareState = read_json(&context.paths.runtime.join(STATE_FILE))
        .map_err(|_| CliError::General("本机没有活动的模型发布".to_owned()))?;
    let server: NodeStatsResponse = context
        .authorized_get(&mindone_protocol::node_stats(state.node_id))
        .await?;
    let local: Option<ShareMetrics> =
        read_json(&context.paths.runtime.join("share-metrics.json")).ok();
    let honor = honor_observation(
        server.requests,
        server.failed,
        server.contribution_earned_micro,
        &server.honor,
    )?;
    let honor_human = match honor.observed_zero_failures {
        Some(true) => format!(
            "当前记录零失败（{} 个请求；这不是连续天数认证）",
            honor.observed_requests
        ),
        Some(false) => format!("当前记录有 {} 次失败", honor.observed_failures),
        None => "未知（尚无请求样本）".to_owned(),
    };
    let success_rate = if server.requests <= 0 {
        0.0
    } else {
        server.succeeded as f64 / server.requests as f64 * 100.0
    };
    let worker_running = worker_process_is_running(&state)?;
    let uptime_human = server
        .uptime_seconds
        .map(|seconds| format!("{seconds} 秒（相邻已验证心跳累计）"))
        .unwrap_or_else(|| "未知（尚无已验证心跳）".to_owned());
    let progress_human = contribution_progress_human(honor.contribution_progress.as_ref());
    let rank_human = honor.contribution_rank_percentile.map_or_else(
        || {
            if server.honor.network_leaderboard.suppressed {
                format!(
                    "已抑制（贡献 cohort 不足 {} 个节点）",
                    server.honor.contribution_rank_privacy_threshold
                )
            } else {
                "未知（当前节点尚未进入正贡献 cohort）".to_owned()
            }
        },
        |percentile| {
            format!(
                "{}；percentile {:.2}%（并列共享 midrank）",
                individual_contribution_rank_label(percentile),
                percentile * 100.0,
            )
        },
    );
    let network_leaderboard_human =
        network_honor_leaderboard_human(&server.honor.network_leaderboard)?;
    let streak_human = honor
        .zero_failure_streak_days
        .map(|days| format!("{days} 天（UTC 终态任务日）"))
        .unwrap_or_else(|| "未知（尚无终态任务日）".to_owned());
    let canary_risk_human = server
        .instance_canary_risk
        .iter()
        .find(|risk| risk.model_instance_id == state.model_instance_id)
        .map_or_else(
            || "未知（服务端尚无实例风控状态）".to_owned(),
            |risk| {
                if risk.quarantined {
                    format!(
                        "路由隔离（连续失败 {}；恢复进度 {}/{}）",
                        risk.consecutive_failures,
                        risk.recovery_passes,
                        risk.recovery_pass_threshold
                    )
                } else {
                    format!(
                        "正常（连续失败 {}/{}）",
                        risk.consecutive_failures, risk.quarantine_failure_threshold
                    )
                }
            },
        );
    CommandOutput::new(
        format!(
            "节点：{}\n模型实例：{}\nWorker：{}\n请求：{}\n成功率：{success_rate:.2}%\n失败：{}\n运行时间：{uptime_human}\n首 Token TTFT（实测）：{}\nTPS：{}\n协调服务器 RTT（节点实测）：{}\nTier：{}\nTrust：{:?}\nCanary 风控：{canary_risk_human}\n可用额度收益：{}\n贡献进度（服务端实时累计）：{progress_human}\n贡献排名：{rank_human}\n荣誉观察：{honor_human}\n零故障连续天数：{streak_human}\n全网匿名荣誉榜：\n{network_leaderboard_human}",
            state.node_id,
            state.model_instance_id,
            if worker_running { "运行" } else { "停止" },
            server.requests,
            server.failed,
            server
                .metrics
                .as_ref()
                .map(|metrics| format!("{}ms", metrics.ttft_ms))
                .unwrap_or_else(|| "暂无有效指标".to_owned()),
            server
                .metrics
                .as_ref()
                .map(|metrics| format!("{:.3}", metrics.tps_milli as f64 / 1000.0))
                .unwrap_or_else(|| "暂无真实指标".to_owned()),
            server
                .metrics
                .as_ref()
                .and_then(|metrics| metrics.coordinator_rtt_ms)
                .map(|rtt_ms| format!("{rtt_ms}ms"))
                .unwrap_or_else(|| "暂无有效样本".to_owned()),
            server
                .tier
                .map(|tier| format!("{tier:?}"))
                .unwrap_or_else(|| "Unranked".to_owned()),
            server.trust_level,
            server
                .spendable_earned_micro
                .map(format_micro)
                .unwrap_or_else(|| "未知（服务端未提供）".to_owned()),
        ),
        serde_json::json!({
            "server": server,
            "local": local,
            "contribution_progress": &honor.contribution_progress,
            "honor": honor,
            "worker_running": worker_running,
            "last_heartbeat_at": state.last_heartbeat_at,
            "last_coordinator_rtt_ms": state.last_coordinator_rtt_ms,
            "model_instance_id": state.model_instance_id,
            "node_id": state.node_id,
        }),
    )
}

fn honor_observation(
    requests: i64,
    failures: i64,
    contribution_earned_micro: Option<i64>,
    server_honor: &NodeHonorStats,
) -> CliResult<HonorObservation> {
    let observed_requests = u64::try_from(requests).map_err(|_| {
        CliError::General("协调服务器返回了负数请求统计，拒绝生成荣誉观察".to_owned())
    })?;
    let observed_failures = u64::try_from(failures).map_err(|_| {
        CliError::General("协调服务器返回了负数失败统计，拒绝生成荣誉观察".to_owned())
    })?;
    if server_honor
        .contribution_rank_percentile
        .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
    {
        return Err(CliError::General(
            "协调服务器返回了无效贡献 percentile，拒绝生成动态标签".to_owned(),
        ));
    }
    let contribution_progress = contribution_progress(
        contribution_earned_micro,
        server_honor.previous_contribution_milestone_micro,
        server_honor.next_contribution_milestone_micro,
    )?;
    Ok(HonorObservation {
        observed_requests,
        observed_failures,
        observed_zero_failures: (observed_requests > 0).then_some(observed_failures == 0),
        contribution_rank_percentile: server_honor.contribution_rank_percentile,
        zero_failure_streak_days: server_honor.zero_failure_streak_days,
        previous_contribution_milestone_micro: server_honor.previous_contribution_milestone_micro,
        next_contribution_milestone_micro: server_honor.next_contribution_milestone_micro,
        contribution_progress,
    })
}

fn contribution_progress(
    current_micro: Option<i64>,
    previous_milestone_micro: Option<i64>,
    next_milestone_micro: Option<i64>,
) -> CliResult<Option<ContributionProgress>> {
    if current_micro.is_some_and(|value| value < 0) {
        return Err(CliError::General(
            "协调服务器返回了负数贡献值，拒绝生成进度".to_owned(),
        ));
    }
    let (Some(current_micro), Some(previous_milestone_micro), Some(next_milestone_micro)) = (
        current_micro,
        previous_milestone_micro,
        next_milestone_micro,
    ) else {
        if previous_milestone_micro.is_some() || next_milestone_micro.is_some() {
            return Err(CliError::General(
                "协调服务器返回了不完整的贡献里程碑区间".to_owned(),
            ));
        }
        // 允许旧服务端只返回累计值，但不伪造里程碑进度。
        return Ok(None);
    };
    if previous_milestone_micro < 0
        || next_milestone_micro <= previous_milestone_micro
        || current_micro < previous_milestone_micro
        || current_micro >= next_milestone_micro
    {
        return Err(CliError::General(
            "协调服务器返回了无效贡献里程碑区间".to_owned(),
        ));
    }
    let completed_micro = current_micro - previous_milestone_micro;
    let span_micro = next_milestone_micro - previous_milestone_micro;
    let progress_ppm = u32::try_from(
        i128::from(completed_micro) * i128::from(PROGRESS_PPM_SCALE) / i128::from(span_micro),
    )
    .map_err(|_| CliError::General("贡献进度超出可表示范围".to_owned()))?;
    Ok(Some(ContributionProgress {
        current_micro,
        previous_milestone_micro,
        next_milestone_micro,
        completed_micro,
        span_micro,
        progress_ppm,
    }))
}

fn contribution_progress_human(progress: Option<&ContributionProgress>) -> String {
    let Some(progress) = progress else {
        return "未知（服务端未提供完整里程碑区间）".to_owned();
    };
    let filled = usize::try_from(progress.progress_ppm)
        .unwrap_or_default()
        .saturating_mul(CONTRIBUTION_PROGRESS_BAR_WIDTH)
        / usize::try_from(PROGRESS_PPM_SCALE).unwrap_or(1);
    let empty = CONTRIBUTION_PROGRESS_BAR_WIDTH.saturating_sub(filled);
    format!(
        "[{}{}] {:.2}%（累计 {}；区间 {} → {}）",
        "#".repeat(filled),
        "-".repeat(empty),
        f64::from(progress.progress_ppm) / 10_000.0,
        format_micro(progress.current_micro),
        format_micro(progress.previous_milestone_micro),
        format_micro(progress.next_milestone_micro),
    )
}

fn individual_contribution_rank_label(percentile: f64) -> &'static str {
    if percentile >= 0.99 {
        "Top 1% 贡献者"
    } else if percentile >= 0.95 {
        "Top 5% 贡献者"
    } else if percentile >= 0.90 {
        "Top 10% 贡献者"
    } else if percentile >= 0.75 {
        "Top 25% 贡献者"
    } else if percentile >= 0.50 {
        "Top 50% 贡献者"
    } else {
        "贡献者"
    }
}

fn network_honor_label_zh(label: NetworkHonorLabel) -> &'static str {
    match label {
        NetworkHonorLabel::Top1Percent => "Top 1% 贡献者",
        NetworkHonorLabel::Top5Percent => "Top 5% 贡献者",
        NetworkHonorLabel::Top10Percent => "Top 10% 贡献者",
        NetworkHonorLabel::Top25Percent => "Top 25% 贡献者",
        NetworkHonorLabel::Top50Percent => "Top 50% 贡献者",
        NetworkHonorLabel::Contributor => "全网贡献者",
        NetworkHonorLabel::ZeroFailure100Days => "零故障运行 100+ 天",
    }
}

fn network_honor_leaderboard_human(leaderboard: &NetworkHonorLeaderboard) -> CliResult<String> {
    if leaderboard.aggregation_version == "unavailable" {
        if leaderboard.cohort_nodes == 0 && leaderboard.entries.is_empty() && leaderboard.suppressed
        {
            return Ok("未知（服务端未提供隐私安全榜单）".to_owned());
        }
        return Err(CliError::General(
            "协调服务器返回了自相矛盾的未发布榜单".to_owned(),
        ));
    }
    if leaderboard.privacy_threshold < 5
        || leaderboard.count_granularity < leaderboard.privacy_threshold
        || leaderboard.tie_policy != NetworkHonorTiePolicy::MidrankSharedBand
    {
        return Err(CliError::General(
            "协调服务器返回的榜单隐私参数无效".to_owned(),
        ));
    }
    if leaderboard.suppressed {
        if leaderboard.cohort_nodes != 0 || !leaderboard.entries.is_empty() {
            return Err(CliError::General(
                "协调服务器在榜单抑制状态下仍返回了精确记录".to_owned(),
            ));
        }
        return Ok(format!(
            "  已整表抑制：贡献 cohort 不足 {} 个节点",
            leaderboard.privacy_threshold
        ));
    }
    if leaderboard.cohort_nodes < leaderboard.privacy_threshold {
        return Err(CliError::General(
            "协调服务器返回了低于隐私阈值的榜单".to_owned(),
        ));
    }
    let mut labels = BTreeSet::new();
    let mut lines = Vec::with_capacity(leaderboard.entries.len().saturating_add(1));
    lines.push(format!(
        "  口径：{} 个贡献节点；人数仅发布 {} 的倍数下界；并列共享 midrank 档",
        leaderboard.cohort_nodes, leaderboard.count_granularity
    ));
    for entry in &leaderboard.entries {
        if !labels.insert(entry.label)
            || entry.qualifying_nodes_lower_bound < leaderboard.privacy_threshold
            || entry.qualifying_nodes_lower_bound > leaderboard.cohort_nodes
            || entry.qualifying_nodes_lower_bound % leaderboard.count_granularity != 0
        {
            return Err(CliError::General(
                "协调服务器返回了无效或重复的匿名榜单档位".to_owned(),
            ));
        }
        lines.push(format!(
            "  - {}：至少 {} 个节点",
            network_honor_label_zh(entry.label),
            entry.qualifying_nodes_lower_bound
        ));
    }
    Ok(lines.join("\n"))
}

pub async fn run_worker(context: &AppContext) -> CliResult<CommandOutput> {
    let log_monitor = WorkerLogMonitor::start(
        context.paths.logs.join(LOG_FILE),
        LogRotationConfig::PRODUCTION,
        true,
    )?;
    tokio::select! {
        result = run_worker_loop(context, &log_monitor) => result,
        error = log_monitor.wait_for_failure() => Err(error),
    }
}

async fn refresh_worker_session(
    context: &AppContext,
    refresh_lock: &tokio::sync::Mutex<()>,
    failed_access_token: String,
) -> CliResult<CredentialBundle> {
    let _refresh_guard = refresh_lock.lock().await;
    let current = context.vault.load_session()?;
    if current.access_token != failed_access_token {
        return Ok(current);
    }
    refresh_session(context).await
}

async fn run_worker_loop(
    context: &AppContext,
    log_monitor: &WorkerLogMonitor,
) -> CliResult<CommandOutput> {
    let state_path = context.paths.runtime.join(STATE_FILE);
    let mut state: ShareState = read_json(&state_path)?;
    state.pid = std::process::id();
    // RTT 样本只绑定当前 worker 生命周期；重启后先发送 None，禁止把旧进程
    // 甚至旧网络路径的观测冒充为新 worker 的实时指标。
    state.last_coordinator_rtt_ms = None;
    let executable = std::env::current_exe()
        .map_err(|error| CliError::General(format!("无法定位共享 worker 可执行文件：{error}")))?;
    let observed =
        wait_for_worker_identity(state.pid, &executable, WORKER_IDENTITY_TIMEOUT).await?;
    state.process_start_marker = Some(observed.process_start_marker);
    state.worker_executable = Some(executable);
    state.worker_command = expected_worker_command();
    write_json_atomic(&state_path, &state)?;
    let mut session = context.vault.load_session()?;
    let mut metrics = initial_metrics(context, &state)?;
    let mut disconnect_backoff = 1_u64;
    let active_count = Arc::new(AtomicU16::new(0));
    let heartbeat_lock = Arc::new(tokio::sync::Mutex::new(()));
    let refresh_lock = Arc::new(tokio::sync::Mutex::new(()));
    let mut available_slots = (0..MANAGED_SHARE_MAX_CONCURRENT)
        .filter_map(managed_share_slot_id)
        .collect::<VecDeque<_>>();
    let mut tasks = tokio::task::JoinSet::new();
    let metrics_path = context.paths.runtime.join("share-metrics.json");
    loop {
        log_monitor.ensure_healthy()?;
        while let Some(joined) = tasks.try_join_next() {
            let outcome = joined
                .map_err(|error| CliError::General(format!("贡献任务执行器异常退出：{error}")))??;
            apply_job_task_outcome(
                outcome,
                context,
                &mut state,
                &mut session,
                &mut metrics,
                &mut available_slots,
                &active_count,
            )?;
        }
        if context.paths.runtime.join(STOP_FILE).exists() {
            if !tasks.is_empty() {
                if let Some(joined) = tasks.join_next().await {
                    let outcome = joined.map_err(|error| {
                        CliError::General(format!("排空贡献任务时执行器异常退出：{error}"))
                    })??;
                    apply_job_task_outcome(
                        outcome,
                        context,
                        &mut state,
                        &mut session,
                        &mut metrics,
                        &mut available_slots,
                        &active_count,
                    )?;
                }
                continue;
            }
            match delete_model_instance(context, &mut session, state.model_instance_id).await {
                Ok(response) => {
                    if response.status == ModelInstanceStatus::Unpublished {
                        return CommandOutput::message(
                            "共享 worker 已排空，服务端已确认取消发布；本地 PID 身份留给控制进程在退出后复核",
                        );
                    }
                    return CommandOutput::message(format!(
                        "共享 worker 已排空；服务端仍在{}，活动任务 {} 个，本地 PID 身份留给控制进程复核",
                        model_instance_status_zh(response.status),
                        response.active_jobs
                    ));
                }
                Err(error) => {
                    tracing::warn!(
                        error_type = error.error_type(),
                        "取消发布请求失败，worker 等待重试"
                    );
                    tokio::time::sleep(Duration::from_secs(disconnect_backoff)).await;
                    disconnect_backoff = (disconnect_backoff * 2).min(HEARTBEAT_SECONDS);
                    continue;
                }
            }
        }
        metrics.uptime_seconds =
            elapsed_seconds(&state.started_at).unwrap_or(metrics.uptime_seconds);
        let policy = load_persisted_policy(context)?;
        let hardware = hardware_metrics();
        let paused_for_temperature = update_temperature_pause(
            state.paused_for_temperature,
            policy.gpu_temp_limit_c,
            hardware.gpu_temperature_c,
        );
        if paused_for_temperature != state.paused_for_temperature {
            state.paused_for_temperature = paused_for_temperature;
            write_json_atomic(&state_path, &state)?;
        }
        let current_concurrent = active_count.load(Ordering::SeqCst);
        let policy_state = evaluate_policy(&policy, &[], current_concurrent, &hardware);
        let locally_accepting = policy_state.is_ok() && !state.paused_for_temperature;
        let heartbeat = heartbeat_request(
            &metrics,
            &hardware,
            &policy,
            state.last_coordinator_rtt_ms,
            i32::from(current_concurrent),
            false,
        )?;
        let heartbeat_result = {
            let _heartbeat_guard = heartbeat_lock.lock().await;
            let refresh_lock = Arc::clone(&refresh_lock);
            post_heartbeat_request_with_refresh(
                context,
                &mut session,
                &mut state,
                &heartbeat,
                move |failed_access_token| async move {
                    refresh_worker_session(context, &refresh_lock, failed_access_token).await
                },
            )
            .await
        };
        match heartbeat_result {
            Ok(response) => {
                disconnect_backoff = 1;
                if !response.accepting_jobs {
                    tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECONDS)).await;
                    continue;
                }
            }
            Err(error) => {
                tracing::warn!(error_type = error.error_type(), "节点心跳失败，等待重连");
                tokio::time::sleep(Duration::from_secs(disconnect_backoff)).await;
                disconnect_backoff = (disconnect_backoff * 2).min(HEARTBEAT_SECONDS);
                continue;
            }
        }
        if !locally_accepting {
            tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECONDS)).await;
            continue;
        }
        if current_concurrent >= policy.max_concurrent {
            if let Some(joined) = tasks.join_next().await {
                let outcome = joined.map_err(|error| {
                    CliError::General(format!("等待贡献 slot 时执行器异常退出：{error}"))
                })??;
                apply_job_task_outcome(
                    outcome,
                    context,
                    &mut state,
                    &mut session,
                    &mut metrics,
                    &mut available_slots,
                    &active_count,
                )?;
            }
            continue;
        }
        let job = match context
            .coordinator
            .post_optional::<_, ClaimJobResponse>(
                mindone_protocol::JOBS_CLAIM,
                Some(&session.access_token),
                &ClaimJobRequest {
                    node_id: state.node_id,
                    model_instance_id: state.model_instance_id,
                },
            )
            .await
        {
            Ok(job) => job,
            Err(CliError::Authentication(_)) => {
                session =
                    refresh_worker_session(context, &refresh_lock, session.access_token.clone())
                        .await?;
                continue;
            }
            Err(error) => {
                tracing::warn!(error_type = error.error_type(), "任务领取失败，等待重试");
                tokio::time::sleep(Duration::from_secs(disconnect_backoff)).await;
                disconnect_backoff = (disconnect_backoff * 2).min(HEARTBEAT_SECONDS);
                continue;
            }
        };
        let Some(job) = job else {
            if tasks.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
            } else {
                tokio::select! {
                    joined = tasks.join_next() => {
                        if let Some(joined) = joined {
                            let outcome = joined.map_err(|error| {
                                CliError::General(format!("等待贡献任务时执行器异常退出：{error}"))
                            })??;
                            apply_job_task_outcome(
                                outcome,
                                context,
                                &mut state,
                                &mut session,
                                &mut metrics,
                                &mut available_slots,
                                &active_count,
                            )?;
                        }
                    }
                    () = tokio::time::sleep(Duration::from_secs(2)) => {}
                }
            }
            continue;
        };
        let slot_id = available_slots.pop_front().ok_or_else(|| {
            CliError::General("服务端已领取任务，但本地没有可用贡献 slot；已失败关闭".to_owned())
        })?;
        let next_active = active_count
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1);
        if next_active > policy.max_concurrent || next_active > MANAGED_SHARE_MAX_CONCURRENT {
            active_count.fetch_sub(1, Ordering::SeqCst);
            available_slots.push_front(slot_id);
            return Err(CliError::PolicyRejected(format!(
                "领取后的本地并发 {next_active} 超过策略或受管 slot 上限"
            )));
        }
        metrics.requests = metrics.requests.saturating_add(1);
        write_metrics(&metrics_path, &metrics)?;
        tasks.spawn(process_claimed_job(
            context.clone(),
            state.clone(),
            metrics.clone(),
            session.clone(),
            SensitiveClaimJob(job),
            slot_id,
            SharedJobRuntime {
                active_count: Arc::clone(&active_count),
                heartbeat_lock: Arc::clone(&heartbeat_lock),
                refresh_lock: Arc::clone(&refresh_lock),
            },
        ));
    }
}

struct JobTaskOutcome {
    slot_id: u32,
    job_id: Uuid,
    state: ShareState,
    completed_successfully: bool,
    measured_tps: Option<f64>,
    measured_ttft_ms: Option<f64>,
}

fn apply_job_task_outcome(
    outcome: JobTaskOutcome,
    context: &AppContext,
    state: &mut ShareState,
    session: &mut CredentialBundle,
    metrics: &mut ShareMetrics,
    available_slots: &mut VecDeque<u32>,
    active_count: &AtomicU16,
) -> CliResult<()> {
    let previous = active_count.fetch_sub(1, Ordering::SeqCst);
    if previous == 0 {
        active_count.store(0, Ordering::SeqCst);
        return Err(CliError::General(
            "贡献 worker 活动任务计数下溢，已失败关闭".to_owned(),
        ));
    }
    if available_slots.contains(&outcome.slot_id) {
        return Err(CliError::General(format!(
            "贡献 slot {} 被重复归还，已失败关闭",
            outcome.slot_id
        )));
    }
    available_slots.push_back(outcome.slot_id);
    *state = outcome.state;
    // 并发任务可能先后刷新同一会话。只从系统凭据库读取最后一次已提交的
    // 轮换结果，禁止较晚结束的旧任务把父循环回退到过期 access token。
    *session = context.vault.load_session()?;
    if outcome.completed_successfully {
        metrics.successes = metrics.successes.saturating_add(1);
        record_performance_observation(metrics, outcome.measured_tps, outcome.measured_ttft_ms);
    } else {
        metrics.failures = metrics.failures.saturating_add(1);
    }
    write_metrics(&context.paths.runtime.join("share-metrics.json"), metrics)?;
    tracing::info!(
        job_id = %outcome.job_id,
        slot_id = outcome.slot_id,
        active_count = active_count.load(Ordering::SeqCst),
        "贡献任务已到达终态并归还独立 slot"
    );
    Ok(())
}

async fn process_claimed_job(
    context: AppContext,
    mut state: ShareState,
    metrics: ShareMetrics,
    mut session: CredentialBundle,
    job: SensitiveClaimJob,
    slot_id: u32,
    runtime: SharedJobRuntime,
) -> CliResult<JobTaskOutcome> {
    let job_id = job.job_id;
    if job.confidentiality == ConfidentialityMode::Standard {
        if let Err(rejection) = validate_standard_claim_identity(&state, &job) {
            let mut liveness = ActiveJobLiveness::with_shared_runtime(
                &context,
                &mut state,
                &metrics,
                Duration::from_secs(HEARTBEAT_SECONDS),
                slot_id,
                runtime,
            )?;
            if let Err(error) = liveness.heartbeat_now(&mut session).await {
                tracing::warn!(
                    job_id = %job.job_id,
                    error_type = error.error_type(),
                    "模型绑定拒绝任务时的活动心跳首次上报失败，失败报告仍由租约保护"
                );
            }
            if let Err(upload_error) = submit_failure(
                &context,
                &mut session,
                &mut liveness,
                &job,
                &rejection,
                false,
                job.lease_expires_at,
            )
            .await
            {
                tracing::warn!(
                    job_id = %job.job_id,
                    error_type = upload_error.error_type(),
                    http_status = submission_http_status(&upload_error),
                    "模型绑定拒绝结果未能在有限重试内确认，worker 继续运行"
                );
            }
            return Ok(JobTaskOutcome {
                slot_id,
                job_id,
                state,
                completed_successfully: false,
                measured_tps: None,
                measured_ttft_ms: None,
            });
        }
    }

    let execution_policy = load_persisted_policy(&context)?;
    let active_before_execution = runtime
        .active_count
        .load(Ordering::SeqCst)
        .saturating_sub(1);
    if let Err(rejection) = evaluate_policy(
        &execution_policy,
        &job.tags,
        active_before_execution,
        &hardware_metrics(),
    ) {
        let mut liveness = ActiveJobLiveness::with_shared_runtime(
            &context,
            &mut state,
            &metrics,
            Duration::from_secs(HEARTBEAT_SECONDS),
            slot_id,
            runtime,
        )?;
        if let Err(error) = liveness.heartbeat_now(&mut session).await {
            tracing::warn!(
                job_id = %job.job_id,
                error_type = error.error_type(),
                "已领取任务的活动心跳首次上报失败，失败报告仍由租约保护"
            );
        }
        if let Err(upload_error) = submit_failure(
            &context,
            &mut session,
            &mut liveness,
            &job,
            &rejection,
            false,
            job.lease_expires_at,
        )
        .await
        {
            tracing::warn!(
                job_id = %job.job_id,
                error_type = upload_error.error_type(),
                http_status = submission_http_status(&upload_error),
                "策略拒绝结果未能在有限重试内确认，worker 继续运行"
            );
        }
        return Ok(JobTaskOutcome {
            slot_id,
            job_id,
            state,
            completed_successfully: false,
            measured_tps: None,
            measured_ttft_ms: None,
        });
    }

    let mut liveness = ActiveJobLiveness::with_shared_runtime(
        &context,
        &mut state,
        &metrics,
        Duration::from_secs(HEARTBEAT_SECONDS),
        slot_id,
        runtime,
    )?;
    if let Err(error) = liveness.heartbeat_now(&mut session).await {
        tracing::warn!(
            job_id = %job.job_id,
            error_type = error.error_type(),
            "已领取任务的活动心跳首次上报失败，推理仍由租约保护"
        );
    }
    let execution = execute_with_lease(&mut session, &mut liveness, &job).await;
    let ExecutionAttempt {
        result: execution_result,
        lease_expires_at,
        vram_peak,
    } = execution;
    let mut completed_successfully = false;
    let mut measured_tps = None;
    let mut measured_ttft_ms = None;
    match execution_result {
        Ok(result) => {
            let inference_tps = result.inference_tps();
            let observed_ttft_ms = result.measured_ttft_ms().map(|value| value as f64);
            let execution_telemetry = job_execution_telemetry(&result, vram_peak);
            if submit_result_or_terminal_failure(
                &context,
                &mut session,
                &mut liveness,
                &job,
                &result,
                &execution_telemetry,
                lease_expires_at,
            )
            .await
            {
                completed_successfully = true;
                measured_tps = inference_tps;
                measured_ttft_ms = observed_ttft_ms;
            }
        }
        Err(error) => {
            if let Err(upload_error) = submit_failure(
                &context,
                &mut session,
                &mut liveness,
                &job,
                &error,
                true,
                lease_expires_at,
            )
            .await
            {
                tracing::warn!(
                    job_id = %job.job_id,
                    error_type = upload_error.error_type(),
                    http_status = submission_http_status(&upload_error),
                    "任务失败状态未能在有限重试内确认，worker 继续运行"
                );
            }
        }
    }
    drop(liveness);
    Ok(JobTaskOutcome {
        slot_id,
        job_id,
        state,
        completed_successfully,
        measured_tps,
        measured_ttft_ms,
    })
}

async fn execute_with_lease(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
) -> ExecutionAttempt {
    let mut lease_expires_at = job.lease_expires_at;
    // 采样窗口覆盖执行前的模型/进程/哈希绑定复验和实际推理，独立于 15 秒心跳，
    // 因而持久化的是本任务 250ms 周期内观测到的峰值，而不是某次心跳瞬时值。
    let sampler = VramPeakSampler::start();
    let result = execute_with_lease_inner(session, liveness, job, &mut lease_expires_at).await;
    let vram_peak = sampler.finish().await;
    ExecutionAttempt {
        result,
        lease_expires_at,
        vram_peak,
    }
}

async fn execute_with_lease_inner(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    lease_expires_at: &mut OffsetDateTime,
) -> CliResult<WorkerExecutionResult> {
    match job.confidentiality {
        ConfidentialityMode::Standard => {
            execute_standard_with_lease(session, liveness, job, lease_expires_at).await
        }
        ConfidentialityMode::Regulated => {
            execute_regulated_with_lease(session, liveness, job, lease_expires_at).await
        }
    }
}

async fn execute_standard_with_lease(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    lease_expires_at: &mut OffsetDateTime,
) -> CliResult<WorkerExecutionResult> {
    let mut payload = decode_job_payload(job)?;
    let limits = validate_standard_job_authorization(job, &payload)?;
    let endpoint = match payload.endpoint.as_str() {
        "/v1/chat/completions" => "/v1/chat/completions",
        "/v1/completions" => "/v1/completions",
        other => {
            return Err(CliError::General(format!(
                "任务请求了不支持的本地推理端点：{other}"
            )));
        }
    };
    let request = payload.take_request();
    let local_port = liveness.local_port();
    let authorized_model = Zeroizing::new(limits.model);
    let (stream_forwarding, mut stream_receiver) = if limits.stream {
        let (sender, receiver) = tokio::sync::mpsc::channel(STREAM_EVENT_CHANNEL_CAPACITY);
        (
            Some(StandardStreamForwarding {
                sender,
                authorized_model: authorized_model.to_string(),
            }),
            Some(receiver),
        )
    } else {
        (None, None)
    };
    let slot_id = liveness.slot_id();
    let active_requests = liveness
        .active_count
        .load(Ordering::SeqCst)
        .saturating_sub(1);
    let validation_context = liveness.context.clone();
    let validation_state = liveness.state.clone();
    let validation_job = SensitiveClaimJob(job.clone());
    let inference = async move {
        // 完整模型 SHA-256 可能需要数十秒甚至数分钟，必须置于和推理相同的
        // 租约/心跳监督循环内；否则大模型会在安全复验完成前丢失短租约。
        validate_standard_worker_binding(&validation_context, &validation_state, &validation_job)
            .await?;
        // 领取后的第二次策略检查可能与数十秒甚至数分钟的模型
        // 重新哈希相隔。必须在完整 binding 复验返回后再从磁盘读一次
        // 策略并重新采集硬件上下文；只有该最终闸门通过才能发出本地
        // llama 推理请求，避免节点主在哈希窗口内更新的拒绝策略失效。
        let mut response = execute_local_inference_after_final_policy(
            &validation_context,
            &validation_job.tags,
            active_requests,
            FinalPolicyInference {
                local_port,
                endpoint,
                request,
                stream_forwarding,
                slot_id,
            },
        )
        .await?;
        normalize_standard_response_model(&mut response.response, authorized_model.as_str())?;
        Ok(WorkerExecutionResult::Standard(response))
    };
    wait_for_inference_with_lease(
        session,
        liveness,
        job,
        lease_expires_at,
        stream_receiver.as_mut(),
        inference,
    )
    .await
}

/// 紧贴 Standard 本地推理 HTTP 请求的最终节点策略闸门。
///
/// 调用方必须先完成当前受管进程、模型登记和文件 SHA-256 绑定复验。
/// 本函数不接受缓存的 `NodePolicy` 或硬件样本，以免重新哈希期间的
/// 策略/硬件变化被忽略。任何策略加载或评估失败都统一转为 code 50，
/// 且在调用 `execute_local_inference` 之前返回，因此不会产生本地推理、
/// slot 擦除或成功结算请求。
struct FinalPolicyInference {
    local_port: u16,
    endpoint: &'static str,
    request: SensitiveJsonValue,
    stream_forwarding: Option<StandardStreamForwarding>,
    slot_id: u32,
}

async fn execute_local_inference_after_final_policy(
    context: &AppContext,
    job_tags: &[String],
    active_requests: u16,
    inference: FinalPolicyInference,
) -> CliResult<StandardExecutionResult> {
    let policy = load_persisted_policy(context).map_err(|error| {
        CliError::PolicyRejected(format!(
            "执行前最终策略复核无法读取节点策略，拒绝调用本地模型并禁止结算：{error}"
        ))
    })?;
    let current_hardware = hardware_metrics();
    evaluate_policy(&policy, job_tags, active_requests, &current_hardware).map_err(|error| {
        CliError::PolicyRejected(format!(
            "执行前最终策略复核拒绝任务：{error}；未调用本地模型，拒绝提交和结算"
        ))
    })?;
    execute_local_inference(
        inference.local_port,
        inference.endpoint,
        inference.request,
        inference.stream_forwarding,
        inference.slot_id,
    )
    .await
}

/// llama.cpp 会把本地已加载模型名写入 OpenAI `model` 字段，即使消费者使用的是
/// `auto` 或其他虚拟路由名。执行前的进程、实例、文件和权重哈希绑定已经确定真实
/// 模型；这里仅把响应恢复为消费者获授权的虚拟模型名，使结果仍满足创建请求的
/// OpenAI/幂等绑定，不能被本地引擎的展示名破坏结算。
fn normalize_standard_response_model(
    response: &mut Value,
    authorized_model: &str,
) -> CliResult<()> {
    let object = response
        .as_object_mut()
        .ok_or_else(|| CliError::EngineOrSandbox("本地 llama.cpp 响应不是 JSON 对象".to_owned()))?;
    if object
        .get("model")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(CliError::EngineOrSandbox(
            "本地 llama.cpp 响应缺少有效 model 字段".to_owned(),
        ));
    }
    object.insert(
        "model".to_owned(),
        Value::String(authorized_model.to_owned()),
    );
    Ok(())
}

/// 将 Standard 任务绑定到当前 worker 发布的确切模型实例、受管服务和经重新
/// 结构验证的模型文件。该检查只适用于 Standard；Regulated 保持其独立的
/// TEE/report/envelope 绑定路径，不能被此处的本地 serve 检查降级。
async fn validate_standard_worker_binding(
    context: &AppContext,
    state: &ShareState,
    job: &ClaimJobResponse,
) -> CliResult<()> {
    validate_standard_claim_identity(state, job)?;

    let serve_state = serve::load_state(context).await.map_err(|error| {
        CliError::EngineOrSandbox(format!(
            "Standard 任务拒绝执行：受管 llama.cpp 服务未通过实时身份和健康检查：{error}"
        ))
    })?;
    let blocking_context = context.clone();
    let model_name = state.model_name.clone();
    let registered_model =
        tokio::task::spawn_blocking(move || find_verified_model(&blocking_context, &model_name))
            .await
            .map_err(|error| {
                CliError::EngineOrSandbox(format!("模型安全复验任务异常结束：{error}"))
            })??;
    // `find_verified_model` 已在本次领取后重新读取整个文件、计算 SHA-256 并验证
    // GGUF 结构。直接使用该次重验结果，避免对多 GiB 模型连续做两次完全相同的
    // 哈希；重复读取会让短租约在真正推理前过期，却不会增加新的 TOCTOU 保证。
    let actual_model_hash = registered_model.sha256.clone();
    validate_standard_runtime_model_binding(
        state,
        &serve_state.model_name,
        &serve_state.model_path,
        serve_state.backend_port,
        &registered_model.path,
        &registered_model.sha256,
        &actual_model_hash,
    )
}

fn validate_standard_claim_identity(state: &ShareState, job: &ClaimJobResponse) -> CliResult<()> {
    if job.model_instance_id != state.model_instance_id {
        return Err(CliError::ModelValidation(
            "Standard 任务模型实例与当前 share 发布实例不一致，拒绝调用本地模型".to_owned(),
        ));
    }
    if !mindone_common::constant_time_sha256_eq(&job.model_weights_hash, &state.model_weights_hash)
    {
        return Err(CliError::ModelValidation(
            "Standard 任务模型权重哈希与当前 share 发布权重不一致，拒绝调用本地模型".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_standard_runtime_model_binding(
    state: &ShareState,
    serve_model_name: &str,
    serve_model_path: &Path,
    serve_port: u16,
    registered_model_path: &Path,
    registered_model_hash: &str,
    actual_model_hash: &str,
) -> CliResult<()> {
    if serve_port != state.local_port
        || serve_model_name != state.model_name
        || !paths_refer_to_same_file(serve_model_path, &state.model_path)
    {
        return Err(CliError::EngineOrSandbox(
            "Standard 任务拒绝执行：受管 llama.cpp 服务不再对应当前 share 的模型或端口".to_owned(),
        ));
    }
    if !paths_refer_to_same_file(registered_model_path, &state.model_path)
        || !mindone_common::constant_time_sha256_eq(
            registered_model_hash,
            &state.model_weights_hash,
        )
        || !mindone_common::constant_time_sha256_eq(actual_model_hash, &state.model_weights_hash)
    {
        return Err(CliError::ModelValidation(
            "Standard 任务拒绝执行：当前模型文件或受管模型登记已变化".to_owned(),
        ));
    }
    Ok(())
}

fn validate_standard_job_authorization(
    job: &ClaimJobResponse,
    payload: &StandardJobPayload,
) -> CliResult<StandardJobLimits> {
    let limits = payload
        .validated_limits()
        .map_err(|error| CliError::General(format!("Standard 任务载荷未通过协议校验：{error}")))?;
    if job.estimated_input_tokens < limits.minimum_input_tokens {
        return Err(CliError::General(
            "Standard 任务输入 Token 授权低于协议保守上界，拒绝执行".to_owned(),
        ));
    }
    if job.max_output_tokens < limits.maximum_output_tokens {
        return Err(CliError::General(
            "Standard 任务输出 Token 授权低于请求上限，拒绝执行".to_owned(),
        ));
    }
    Ok(limits)
}

async fn execute_regulated_with_lease(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    lease_expires_at: &mut OffsetDateTime,
) -> CliResult<WorkerExecutionResult> {
    if job.payload_encoding != PayloadEncoding::RegulatedAeadV1 {
        return Err(CliError::Attestation(
            "Regulated 任务没有使用 regulated_aead_v1 payload encoding".to_owned(),
        ));
    }
    let route_id = job.regulated_route_id.ok_or_else(|| {
        CliError::Attestation("Regulated 任务缺少 prepared route 绑定".to_owned())
    })?;
    let report_id = job
        .attestation_report_id
        .ok_or_else(|| CliError::Attestation("Regulated 任务缺少硬件报告绑定".to_owned()))?;
    let provider = job
        .attestation_provider
        .ok_or_else(|| CliError::Attestation("Regulated 任务缺少硬件证明 provider".to_owned()))?;
    let tee_public_key = job
        .tee_public_key
        .as_deref()
        .ok_or_else(|| CliError::Attestation("Regulated 任务缺少证明绑定 TEE 公钥".to_owned()))?;
    let record = liveness.context.vault.load_attestation_key()?;
    let report_id_text = report_id.to_string();
    let node_id = liveness.node_id();
    let node_id_text = node_id.to_string();
    let model_instance_id_text = job.model_instance_id.to_string();
    if record.key_origin != AttestationKeyOrigin::TeeRuntime
        || record.report_id.as_deref() != Some(report_id_text.as_str())
        || record.node_id != node_id_text
        || record.model_instance_id != model_instance_id_text
        || record.public_key != tee_public_key
        || job.model_weights_hash != liveness.state.model_weights_hash
    {
        return Err(CliError::Attestation(
            "本机 TEE key handle 与任务 report/node/model/public-key 绑定不一致".to_owned(),
        ));
    }
    let key_expires_at = OffsetDateTime::parse(&record.expires_at, &Rfc3339)
        .map_err(|_| CliError::Attestation("本机 TEE key handle 有效期已损坏".to_owned()))?;
    if key_expires_at <= OffsetDateTime::now_utc() {
        return Err(CliError::Attestation(
            "本机 TEE key handle 绑定报告已过期".to_owned(),
        ));
    }
    let envelope: RegulatedEnvelope = serde_json::from_str(&job.encrypted_payload)
        .map_err(|_| CliError::Attestation("Regulated 请求不是严格 envelope JSON".to_owned()))?;
    envelope
        .validate()
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    if envelope.direction != EnvelopeDirection::Request
        || envelope.route_id != route_id
        || envelope.report_id != report_id
        || envelope.model_instance_id != job.model_instance_id
        || envelope.sender_public_key == tee_public_key
    {
        return Err(CliError::Attestation(
            "Regulated 请求 envelope 与 route/report/model 绑定不一致".to_owned(),
        ));
    }
    let runtime = mindone_sandbox::ExternalTeeRuntime::from_environment(provider)
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    let key_handle = record.runtime_key_handle()?;
    let inference = async {
        runtime
            .infer(mindone_sandbox::TeeInferRequest {
                key_handle,
                tee_public_key,
                node_id,
                job_id: job.job_id,
                route_id,
                report_id,
                model_instance_id: job.model_instance_id,
                model_weights_hash: &job.model_weights_hash,
                request_envelope: &envelope,
                estimated_input_tokens: job.estimated_input_tokens,
                max_output_tokens: job.max_output_tokens,
            })
            .await
            .map(WorkerExecutionResult::Regulated)
            .map_err(|error| CliError::Attestation(error.to_string()))
    };
    wait_for_inference_with_lease(session, liveness, job, lease_expires_at, None, inference).await
}

async fn wait_for_inference_with_lease<F>(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    lease_expires_at: &mut OffsetDateTime,
    mut stream_receiver: Option<&mut tokio::sync::mpsc::Receiver<PendingStreamEvent>>,
    inference: F,
) -> CliResult<WorkerExecutionResult>
where
    F: Future<Output = CliResult<WorkerExecutionResult>>,
{
    tokio::pin!(inference);
    let lease_seconds = (job.lease_expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(2);
    let mut renew_timer = tokio::time::interval(Duration::from_secs(
        u64::try_from(lease_seconds / 2).unwrap_or(1),
    ));
    renew_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let _ = renew_timer.tick().await;
    let mut stream_upload_error = None;
    loop {
        let heartbeat_due = tokio::time::sleep_until(liveness.next_heartbeat);
        tokio::pin!(heartbeat_due);
        tokio::select! {
            response = &mut inference => {
                if let Some(receiver) = stream_receiver.as_mut() {
                    while let Some(event) = receiver.recv().await {
                        if stream_upload_error.is_none() {
                            if let Err(error) = submit_stream_event(
                                session,
                                liveness,
                                job,
                                event,
                                *lease_expires_at,
                            ).await {
                                stream_upload_error = Some(error);
                            }
                        }
                    }
                }
                return match stream_upload_error {
                    Some(error) => Err(error),
                    None => response,
                };
            },
            event = async {
                match stream_receiver.as_mut() {
                    Some(receiver) => receiver.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                if let Some(event) = event {
                    if stream_upload_error.is_none() {
                        if let Err(error) = submit_stream_event(
                            session,
                            liveness,
                            job,
                            event,
                            *lease_expires_at,
                        ).await {
                            // 继续消费本地流直到 slot cleanup 完成；事件上传已经断裂，
                            // 最终结果必须失败且不会进入结算事务。
                            stream_upload_error = Some(error);
                        }
                    }
                } else {
                    stream_receiver = None;
                }
            },
            _ = renew_timer.tick() => {
                *lease_expires_at = renew_job_lease(
                    session,
                    liveness,
                    job,
                ).await?;
            }
            () = &mut heartbeat_due => {
                if let Err(error) = liveness.heartbeat_now(session).await {
                    tracing::warn!(
                        job_id = %job.job_id,
                        error_type = error.error_type(),
                        "长推理期间活动任务心跳失败，将继续推理和租约续期"
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalOpenAiStreamKind {
    Chat,
    Completion,
}

impl LocalOpenAiStreamKind {
    fn from_endpoint(endpoint: &str) -> CliResult<Self> {
        match endpoint {
            "/v1/chat/completions" => Ok(Self::Chat),
            "/v1/completions" => Ok(Self::Completion),
            _ => Err(CliError::EngineOrSandbox(
                "本地流式 TTFT 采集只支持 OpenAI chat/completions 与 completions".to_owned(),
            )),
        }
    }

    const fn stream_object(self) -> &'static str {
        match self {
            Self::Chat => "chat.completion.chunk",
            Self::Completion => "text_completion",
        }
    }

    const fn response_object(self) -> &'static str {
        match self {
            Self::Chat => "chat.completion",
            Self::Completion => "text_completion",
        }
    }
}

#[derive(Default)]
struct StreamMetadata {
    id: String,
    created: Option<i64>,
    model: String,
    system_fingerprint: String,
}

impl Drop for StreamMetadata {
    fn drop(&mut self) {
        self.id.zeroize();
        self.model.zeroize();
        self.system_fingerprint.zeroize();
    }
}

#[derive(Default)]
struct ChatStreamChoice {
    role_seen: bool,
    content: String,
    reasoning_content: String,
    reasoning_seen: bool,
    finish_reason: Option<String>,
}

impl Drop for ChatStreamChoice {
    fn drop(&mut self) {
        self.content.zeroize();
        self.reasoning_content.zeroize();
        if let Some(value) = self.finish_reason.as_mut() {
            value.zeroize();
        }
    }
}

#[derive(Default)]
struct CompletionStreamChoice {
    text: String,
    finish_reason: Option<String>,
}

impl Drop for CompletionStreamChoice {
    fn drop(&mut self) {
        self.text.zeroize();
        if let Some(value) = self.finish_reason.as_mut() {
            value.zeroize();
        }
    }
}

enum StreamChoice {
    Chat(ChatStreamChoice),
    Completion(CompletionStreamChoice),
}

struct OpenAiStreamAccumulator {
    kind: LocalOpenAiStreamKind,
    expected_choices: u32,
    metadata: StreamMetadata,
    choices: BTreeMap<u32, StreamChoice>,
    usage: Option<Value>,
    timings: Option<Value>,
    measured_ttft_ms: Option<i64>,
    terminal_stats_seen: u32,
    event_count: usize,
}

impl Drop for OpenAiStreamAccumulator {
    fn drop(&mut self) {
        if let Some(value) = self.usage.as_mut() {
            zeroize_json_value(value);
        }
        if let Some(value) = self.timings.as_mut() {
            zeroize_json_value(value);
        }
    }
}

impl OpenAiStreamAccumulator {
    fn new(kind: LocalOpenAiStreamKind, expected_choices: u32) -> Self {
        Self {
            kind,
            expected_choices,
            metadata: StreamMetadata::default(),
            choices: BTreeMap::new(),
            usage: None,
            timings: None,
            measured_ttft_ms: None,
            terminal_stats_seen: 0,
            event_count: 0,
        }
    }

    fn observe(&mut self, chunk: &Value, elapsed: Duration) -> CliResult<()> {
        const MAX_STREAM_EVENTS: usize = 65_536;
        self.event_count = self.event_count.saturating_add(1);
        if self.event_count > MAX_STREAM_EVENTS {
            return Err(local_stream_error(
                "SSE 事件数量超过安全上限，已拒绝提交和结算",
            ));
        }
        if self.terminal_stats_seen >= self.expected_choices {
            return Err(local_stream_error("全部 SSE 终态统计之后仍出现数据事件"));
        }
        let object = chunk
            .as_object()
            .ok_or_else(|| local_stream_error("SSE data 不是 JSON 对象"))?;
        self.observe_metadata(object)?;
        let choices = object
            .get("choices")
            .and_then(Value::as_array)
            .ok_or_else(|| local_stream_error("SSE data 缺少 choices 数组"))?;

        match self.kind {
            LocalOpenAiStreamKind::Chat => {
                for choice in choices {
                    self.observe_chat_choice(choice, elapsed)?;
                }
            }
            LocalOpenAiStreamKind::Completion => {
                if choices.is_empty() {
                    return Err(local_stream_error("completions SSE 出现空 choices"));
                }
                for choice in choices {
                    self.observe_completion_choice(choice, elapsed)?;
                }
            }
        }

        if object.contains_key("usage") || object.contains_key("timings") {
            match self.kind {
                LocalOpenAiStreamKind::Chat if !choices.is_empty() => {
                    return Err(local_stream_error(
                        "chat SSE 的终态 usage/timings 必须位于空 choices 事件",
                    ));
                }
                LocalOpenAiStreamKind::Completion if choices.is_empty() => {
                    return Err(local_stream_error(
                        "completions SSE 的终态统计缺少最终 choice",
                    ));
                }
                _ => self.observe_terminal_stats(object)?,
            }
        } else if choices.is_empty() {
            return Err(local_stream_error(
                "chat SSE 空 choices 事件缺少 usage/timings",
            ));
        }
        Ok(())
    }

    fn observe_metadata(&mut self, object: &serde_json::Map<String, Value>) -> CliResult<()> {
        let id = required_stream_string(object, "id")?;
        let created = object
            .get("created")
            .and_then(Value::as_i64)
            .filter(|value| *value > 0)
            .ok_or_else(|| local_stream_error("SSE data 缺少整数 created"))?;
        let model = required_stream_string(object, "model")?;
        let fingerprint = required_stream_string(object, "system_fingerprint")?;
        let stream_object = required_stream_string(object, "object")?;
        if stream_object != self.kind.stream_object() {
            return Err(local_stream_error("SSE object 与请求端点不匹配"));
        }
        store_consistent_stream_string(&mut self.metadata.id, id, "id")?;
        if self.metadata.created.is_none() {
            self.metadata.created = Some(created);
        }
        store_consistent_stream_string(&mut self.metadata.model, model, "model")?;
        store_consistent_stream_string(
            &mut self.metadata.system_fingerprint,
            fingerprint,
            "system_fingerprint",
        )
    }

    fn observe_chat_choice(&mut self, value: &Value, elapsed: Duration) -> CliResult<()> {
        let object = value
            .as_object()
            .ok_or_else(|| local_stream_error("chat SSE choice 不是对象"))?;
        let index = stream_choice_index(object, self.expected_choices)?;
        let finish_reason = stream_finish_reason(object)?;
        let delta = object
            .get("delta")
            .and_then(Value::as_object)
            .ok_or_else(|| local_stream_error("chat SSE choice 缺少 delta 对象"))?;
        if delta
            .keys()
            .any(|key| !matches!(key.as_str(), "role" | "content" | "reasoning_content"))
        {
            return Err(local_stream_error(
                "chat SSE 包含当前授权合同之外的 delta 字段",
            ));
        }
        let mut observed_token = false;
        {
            let entry = self
                .choices
                .entry(index)
                .or_insert_with(|| StreamChoice::Chat(ChatStreamChoice::default()));
            let StreamChoice::Chat(choice) = entry else {
                return Err(local_stream_error("SSE choice 类型发生漂移"));
            };
            if choice.finish_reason.is_some() {
                return Err(local_stream_error("chat SSE 已结束 choice 又收到数据"));
            }
            if let Some(role) = optional_stream_string(delta, "role")? {
                if role != "assistant" || choice.role_seen {
                    return Err(local_stream_error("chat SSE role 无效或重复"));
                }
                choice.role_seen = true;
            }
            if let Some(content) = optional_stream_string(delta, "content")? {
                append_stream_text(&mut choice.content, content)?;
                observed_token |= !content.is_empty();
            }
            if let Some(reasoning) = optional_stream_string(delta, "reasoning_content")? {
                append_stream_text(&mut choice.reasoning_content, reasoning)?;
                choice.reasoning_seen = true;
                observed_token |= !reasoning.is_empty();
            }
            if let Some(reason) = finish_reason {
                if delta.values().any(|value| !value.is_null()) {
                    return Err(local_stream_error("chat SSE 结束 choice 的 delta 必须为空"));
                }
                choice.finish_reason = Some(reason.to_owned());
            }
        }
        if observed_token {
            self.observe_first_token("token", elapsed);
        }
        Ok(())
    }

    fn observe_completion_choice(&mut self, value: &Value, elapsed: Duration) -> CliResult<()> {
        let object = value
            .as_object()
            .ok_or_else(|| local_stream_error("completions SSE choice 不是对象"))?;
        let index = stream_choice_index(object, self.expected_choices)?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| local_stream_error("completions SSE choice 缺少 text"))?;
        let finish_reason = stream_finish_reason(object)?;
        let mut observed_token = false;
        {
            let entry = self
                .choices
                .entry(index)
                .or_insert_with(|| StreamChoice::Completion(CompletionStreamChoice::default()));
            let StreamChoice::Completion(choice) = entry else {
                return Err(local_stream_error("SSE choice 类型发生漂移"));
            };
            if choice.finish_reason.is_some() {
                return Err(local_stream_error(
                    "completions SSE 已结束 choice 又收到数据",
                ));
            }
            if let Some(reason) = finish_reason {
                if !text.is_empty() && text != choice.text {
                    return Err(local_stream_error(
                        "completions SSE 最终文本与已流式接收内容不一致",
                    ));
                }
                choice.finish_reason = Some(reason.to_owned());
            } else {
                append_stream_text(&mut choice.text, text)?;
                observed_token = !text.is_empty();
            }
        }
        if observed_token {
            self.observe_first_token("token", elapsed);
        }
        Ok(())
    }

    fn observe_first_token(&mut self, text: &str, elapsed: Duration) {
        if text.is_empty() || self.measured_ttft_ms.is_some() {
            return;
        }
        let millis = elapsed.as_micros().saturating_add(999) / 1_000;
        self.measured_ttft_ms = i64::try_from(millis.max(1)).ok();
    }

    fn observe_terminal_stats(&mut self, object: &serde_json::Map<String, Value>) -> CliResult<()> {
        let usage = object
            .get("usage")
            .and_then(Value::as_object)
            .ok_or_else(|| local_stream_error("SSE 终态缺少 usage 对象"))?;
        let timings = object
            .get("timings")
            .and_then(Value::as_object)
            .ok_or_else(|| local_stream_error("SSE 终态缺少 timings 对象"))?;
        let prompt_tokens = required_stream_u64(usage, "prompt_tokens")?;
        let completion_tokens = required_stream_u64(usage, "completion_tokens")?;
        let total_tokens = required_stream_u64(usage, "total_tokens")?;
        if prompt_tokens.checked_add(completion_tokens) != Some(total_tokens)
            || i32::try_from(prompt_tokens).is_err()
            || i32::try_from(completion_tokens).is_err()
        {
            return Err(local_stream_error(
                "SSE usage Token 统计不一致或超出协议范围",
            ));
        }
        if completion_tokens > 0 && self.measured_ttft_ms.is_none() {
            return Err(local_stream_error(
                "SSE 声称生成了 Token，但没有可观测的首 Token 事件",
            ));
        }
        if completion_tokens == 0 && self.measured_ttft_ms.is_some() {
            return Err(local_stream_error(
                "SSE 首 Token 事件与 completion_tokens=0 冲突",
            ));
        }
        if completion_tokens > 0 {
            let tps = timings
                .get("predicted_per_second")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && *value > 0.0)
                .ok_or_else(|| local_stream_error("SSE timings 缺少有效生成 TPS"))?;
            if !tps.is_finite() {
                return Err(local_stream_error("SSE timings 生成 TPS 无效"));
            }
        }
        let finished_choices = self
            .choices
            .values()
            .filter(|choice| match choice {
                StreamChoice::Chat(value) => value.finish_reason.is_some(),
                StreamChoice::Completion(value) => value.finish_reason.is_some(),
            })
            .count();
        if finished_choices <= self.terminal_stats_seen as usize {
            return Err(local_stream_error(
                "SSE usage/timings 没有对应的新结束 choice",
            ));
        }
        merge_stream_usage(
            &mut self.usage,
            object.get("usage"),
            prompt_tokens,
            completion_tokens,
        )?;
        merge_stream_timings(&mut self.timings, object.get("timings"))?;
        self.terminal_stats_seen = self.terminal_stats_seen.saturating_add(1);
        Ok(())
    }

    fn finish(mut self, saw_done: bool) -> CliResult<StandardExecutionResult> {
        if !saw_done || self.terminal_stats_seen != self.expected_choices {
            return Err(local_stream_error(
                "本地 llama.cpp SSE 未完整结束或缺少终态统计",
            ));
        }
        if self.choices.len() != self.expected_choices as usize {
            return Err(local_stream_error("SSE choice 数量与授权请求不一致"));
        }
        if self.kind == LocalOpenAiStreamKind::Chat
            && !matches!(
                self.choices.get(&0),
                Some(StreamChoice::Chat(choice)) if !choice.content.trim().is_empty()
            )
        {
            // 协调器的 Standard/隐藏评价结果合同要求第一条 chat choice 含非空
            // 可见 content。推理模型可能只产生 reasoning_content 并在 Token 上限
            // 处结束；必须在本地把它作为执行失败提交，而不是先发一个确定会被
            // 400 拒绝的 result、再占住租约直到过期。
            return Err(local_stream_error(
                "chat SSE 第一条 choice 缺少非空可见 content",
            ));
        }
        let mut response_choices = Vec::with_capacity(self.expected_choices as usize);
        for index in 0..self.expected_choices {
            let entry = self
                .choices
                .remove(&index)
                .ok_or_else(|| local_stream_error("SSE choice 索引不连续"))?;
            match (self.kind, entry) {
                (LocalOpenAiStreamKind::Chat, StreamChoice::Chat(mut choice)) => {
                    let finish_reason = choice
                        .finish_reason
                        .take()
                        .ok_or_else(|| local_stream_error("chat SSE choice 缺少结束原因"))?;
                    let mut message = serde_json::Map::new();
                    message.insert("role".to_owned(), Value::String("assistant".to_owned()));
                    message.insert(
                        "content".to_owned(),
                        Value::String(std::mem::take(&mut choice.content)),
                    );
                    if choice.reasoning_seen {
                        message.insert(
                            "reasoning_content".to_owned(),
                            Value::String(std::mem::take(&mut choice.reasoning_content)),
                        );
                    }
                    response_choices.push(serde_json::json!({
                        "index": index,
                        "message": message,
                        "finish_reason": finish_reason,
                    }));
                }
                (LocalOpenAiStreamKind::Completion, StreamChoice::Completion(mut choice)) => {
                    let finish_reason = choice
                        .finish_reason
                        .take()
                        .ok_or_else(|| local_stream_error("completions SSE choice 缺少结束原因"))?;
                    response_choices.push(serde_json::json!({
                        "index": index,
                        "text": std::mem::take(&mut choice.text),
                        "logprobs": Value::Null,
                        "finish_reason": finish_reason,
                    }));
                }
                _ => return Err(local_stream_error("SSE choice 类型与端点不一致")),
            }
        }
        let usage = self
            .usage
            .take()
            .ok_or_else(|| local_stream_error("SSE 缺少 usage 终态"))?;
        let timings = self
            .timings
            .take()
            .ok_or_else(|| local_stream_error("SSE 缺少 timings 终态"))?;
        let id = std::mem::take(&mut self.metadata.id);
        let created = self
            .metadata
            .created
            .ok_or_else(|| local_stream_error("SSE 缺少 created 元数据"))?;
        let model = std::mem::take(&mut self.metadata.model);
        let system_fingerprint = std::mem::take(&mut self.metadata.system_fingerprint);
        let response = serde_json::json!({
            "id": id,
            "object": self.kind.response_object(),
            "created": created,
            "model": model,
            "choices": response_choices,
            "usage": usage,
            "timings": timings,
            "system_fingerprint": system_fingerprint,
        });
        Ok(StandardExecutionResult {
            response: SensitiveJsonValue(response),
            measured_ttft_ms: self.measured_ttft_ms,
        })
    }
}

fn local_stream_error(message: impl Into<String>) -> CliError {
    CliError::EngineOrSandbox(format!("本地 llama.cpp 流式响应无效：{}", message.into()))
}

fn required_stream_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> CliResult<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| local_stream_error(format!("SSE data 缺少有效 {field}")))
}

fn optional_stream_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> CliResult<Option<&'a str>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(local_stream_error(format!(
            "SSE {field} 必须是字符串或 null"
        ))),
    }
}

fn required_stream_u64(object: &serde_json::Map<String, Value>, field: &str) -> CliResult<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| local_stream_error(format!("SSE usage 缺少非负整数 {field}")))
}

fn merge_stream_usage(
    stored: &mut Option<Value>,
    observed: Option<&Value>,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> CliResult<()> {
    let observed = observed.ok_or_else(|| local_stream_error("SSE 终态缺少 usage"))?;
    let Some(existing) = stored.as_mut() else {
        *stored = Some(observed.clone());
        return Ok(());
    };
    let existing = existing
        .as_object_mut()
        .ok_or_else(|| local_stream_error("已聚合 usage 不是对象"))?;
    let existing_prompt = required_stream_u64(existing, "prompt_tokens")?;
    let existing_completion = required_stream_u64(existing, "completion_tokens")?;
    if existing_prompt != prompt_tokens {
        return Err(local_stream_error("多 choice SSE 的 prompt_tokens 不一致"));
    }
    let aggregate_completion = existing_completion
        .checked_add(completion_tokens)
        .filter(|value| i32::try_from(*value).is_ok())
        .ok_or_else(|| local_stream_error("聚合 completion_tokens 超出协议范围"))?;
    let aggregate_total = prompt_tokens
        .checked_add(aggregate_completion)
        .ok_or_else(|| local_stream_error("聚合 total_tokens 溢出"))?;
    existing.insert(
        "completion_tokens".to_owned(),
        Value::from(aggregate_completion),
    );
    existing.insert("total_tokens".to_owned(), Value::from(aggregate_total));
    Ok(())
}

fn merge_stream_timings(stored: &mut Option<Value>, observed: Option<&Value>) -> CliResult<()> {
    let observed = observed.ok_or_else(|| local_stream_error("SSE 终态缺少 timings"))?;
    let Some(existing) = stored.as_mut() else {
        *stored = Some(observed.clone());
        return Ok(());
    };
    let existing = existing
        .as_object_mut()
        .ok_or_else(|| local_stream_error("已聚合 timings 不是对象"))?;
    let observed = observed
        .as_object()
        .ok_or_else(|| local_stream_error("SSE timings 不是对象"))?;
    let existing_tps = existing
        .get("predicted_per_second")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| local_stream_error("已聚合 timings 缺少有效 TPS"))?;
    let observed_tps = observed
        .get("predicted_per_second")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .ok_or_else(|| local_stream_error("SSE timings 缺少有效 TPS"))?;

    let aggregate_n = existing
        .get("predicted_n")
        .and_then(Value::as_u64)
        .zip(observed.get("predicted_n").and_then(Value::as_u64))
        .and_then(|(left, right)| left.checked_add(right));
    let aggregate_ms = existing
        .get("predicted_ms")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite() && *value > 0.0)
        .zip(
            observed
                .get("predicted_ms")
                .and_then(Value::as_f64)
                .filter(|value| value.is_finite() && *value > 0.0),
        )
        .map(|(left, right)| left + right)
        .filter(|value| value.is_finite() && *value > 0.0);
    let aggregate_tps = match (aggregate_n, aggregate_ms) {
        (Some(tokens), Some(milliseconds)) if tokens > 0 => {
            (tokens as f64 * 1_000.0) / milliseconds
        }
        _ => existing_tps.min(observed_tps),
    };
    let number = serde_json::Number::from_f64(aggregate_tps)
        .ok_or_else(|| local_stream_error("无法编码聚合 TPS"))?;
    existing.insert("predicted_per_second".to_owned(), Value::Number(number));
    if let Some(tokens) = aggregate_n {
        existing.insert("predicted_n".to_owned(), Value::from(tokens));
    }
    if let Some(milliseconds) = aggregate_ms {
        let number = serde_json::Number::from_f64(milliseconds)
            .ok_or_else(|| local_stream_error("无法编码聚合 predicted_ms"))?;
        existing.insert("predicted_ms".to_owned(), Value::Number(number));
    }
    Ok(())
}

fn store_consistent_stream_string(
    stored: &mut String,
    observed: &str,
    field: &str,
) -> CliResult<()> {
    if stored.is_empty() {
        *stored = observed.to_owned();
        return Ok(());
    }
    if stored == observed {
        Ok(())
    } else {
        Err(local_stream_error(format!("SSE {field} 在事件间发生变化")))
    }
}

fn stream_choice_index(
    object: &serde_json::Map<String, Value>,
    expected_choices: u32,
) -> CliResult<u32> {
    let index = object
        .get("index")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| local_stream_error("SSE choice 缺少有效 index"))?;
    if index >= expected_choices {
        return Err(local_stream_error("SSE choice index 超出授权范围"));
    }
    Ok(index)
}

fn stream_finish_reason(object: &serde_json::Map<String, Value>) -> CliResult<Option<&str>> {
    match object.get("finish_reason") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value))
            if matches!(value.as_str(), "stop" | "length" | "content_filter") =>
        {
            Ok(Some(value))
        }
        _ => Err(local_stream_error("SSE choice finish_reason 无效")),
    }
}

fn append_stream_text(destination: &mut String, value: &str) -> CliResult<()> {
    if value.len() > MAX_INFERENCE_RESPONSE_BYTES.saturating_sub(destination.len()) {
        return Err(local_stream_error(
            "聚合后的生成文本超过安全上限，已拒绝提交和结算",
        ));
    }
    destination.push_str(value);
    Ok(())
}

fn prepare_internal_stream_request(
    endpoint: &str,
    request: &mut SensitiveJsonValue,
    slot_id: u32,
) -> CliResult<(LocalOpenAiStreamKind, u32, bool)> {
    let kind = LocalOpenAiStreamKind::from_endpoint(endpoint)?;
    let object = request
        .as_object_mut()
        .ok_or_else(|| CliError::EngineOrSandbox("本地 llama.cpp 请求不是 JSON 对象".to_owned()))?;
    let consumer_stream_requested = object.get("stream").and_then(Value::as_bool) == Some(true);
    let expected_choices = object
        .get("n")
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| (1..=16).contains(value))
                .ok_or_else(|| CliError::EngineOrSandbox("请求 n 超出 1..=16".to_owned()))
        })
        .transpose()?
        .unwrap_or(1);
    object.insert("stream".to_owned(), Value::Bool(true));
    object.insert("id_slot".to_owned(), Value::from(slot_id));
    // 每个并发贡献任务绑定独立 slot，并在终态只 erase 同一个 slot。请求本身也
    // 关闭 prompt cache，避免任何前一请求的 KV 被本次推理复用。
    object.insert("cache_prompt".to_owned(), Value::Bool(false));
    object.insert(
        "stream_options".to_owned(),
        serde_json::json!({"include_usage": true}),
    );
    Ok((kind, expected_choices, consumer_stream_requested))
}

fn normalize_stream_event_model(
    event: &mut SensitiveJsonValue,
    authorized_model: &str,
) -> CliResult<()> {
    let object = event
        .as_object_mut()
        .ok_or_else(|| CliError::EngineOrSandbox("已验证 SSE data 不再是 JSON 对象".to_owned()))?;
    if object
        .get("model")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(local_stream_error("SSE data 缺少有效 model 字段"));
    }
    object.insert(
        "model".to_owned(),
        Value::String(authorized_model.to_owned()),
    );
    Ok(())
}

async fn execute_local_inference(
    port: u16,
    endpoint: &'static str,
    request: SensitiveJsonValue,
    stream_forwarding: Option<StandardStreamForwarding>,
    slot_id: u32,
) -> CliResult<StandardExecutionResult> {
    let inference =
        execute_local_inference_stream(port, endpoint, request, stream_forwarding, slot_id).await;
    let cleanup = erase_managed_llama_slot(port, slot_id).await;
    match (inference, cleanup) {
        (Ok(result), Ok(tokens_erased)) if tokens_erased > 0 => Ok(result),
        (Ok(_), Ok(_)) => Err(CliError::EngineOrSandbox(
            "llama.cpp 返回成功，但受管 slot 没有确认清除任何 KV token；拒绝提交和结算".to_owned(),
        )),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(inference_error), Ok(_)) => Err(inference_error),
        (Err(inference_error), Err(cleanup_error)) => Err(CliError::EngineOrSandbox(format!(
            "{inference_error}；请求失败后 KV Cache 逻辑清理也失败：{cleanup_error}"
        ))),
    }
}

async fn execute_local_inference_stream(
    port: u16,
    endpoint: &'static str,
    mut request: SensitiveJsonValue,
    stream_forwarding: Option<StandardStreamForwarding>,
    slot_id: u32,
) -> CliResult<StandardExecutionResult> {
    let (kind, expected_choices, consumer_stream_requested) =
        prepare_internal_stream_request(endpoint, &mut request, slot_id)?;
    if consumer_stream_requested != stream_forwarding.is_some() {
        return Err(local_stream_error(
            "消费者 stream 标志与持久事件通道不一致，拒绝静默降级",
        ));
    }
    let request_bytes = Zeroizing::new(serde_json::to_vec(&*request).map_err(|error| {
        CliError::EngineOrSandbox(format!("无法编码本地 llama.cpp 请求：{error}"))
    })?);
    let request_started = Instant::now();
    let response = loopback_http_client(None)?
        .post(format!("http://127.0.0.1:{port}{endpoint}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(Bytes::from_owner(SensitiveHttpBody(request_bytes)))
        .send()
        .await
        .map_err(|error| CliError::EngineOrSandbox(format!("本地 llama.cpp 推理失败：{error}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(CliError::EngineOrSandbox(format!(
            "本地 llama.cpp 推理返回 HTTP {}",
            status.as_u16()
        )));
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("text/event-stream") {
        return Err(local_stream_error(
            "响应 Content-Type 不是 text/event-stream",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_INFERENCE_RESPONSE_BYTES as u64)
    {
        return Err(CliError::EngineOrSandbox(format!(
            "本地 llama.cpp 响应体超过 {MAX_INFERENCE_RESPONSE_BYTES} bytes 安全上限，已拒绝提交和结算"
        )));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(MAX_INFERENCE_RESPONSE_BYTES),
    ));
    let mut accumulator = OpenAiStreamAccumulator::new(kind, expected_choices);
    let mut event_data = Zeroizing::new(Vec::new());
    let mut parse_cursor = 0usize;
    let mut saw_done = false;
    let mut event_sequence = 0_i32;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            CliError::EngineOrSandbox(format!("读取本地 llama.cpp 响应失败：{error}"))
        })?;
        if chunk.len() > MAX_INFERENCE_RESPONSE_BYTES.saturating_sub(bytes.len()) {
            return Err(CliError::EngineOrSandbox(format!(
                "本地 llama.cpp 响应体超过 {MAX_INFERENCE_RESPONSE_BYTES} bytes 安全上限，已拒绝提交和结算"
            )));
        }
        bytes.extend_from_slice(&chunk);
        while let Some(relative_newline) =
            bytes[parse_cursor..].iter().position(|byte| *byte == b'\n')
        {
            let line_end = parse_cursor.saturating_add(relative_newline);
            let mut line = &bytes[parse_cursor..line_end];
            if line.last() == Some(&b'\r') {
                line = &line[..line.len().saturating_sub(1)];
            }
            parse_cursor = line_end.saturating_add(1);
            if line.is_empty() {
                if event_data.is_empty() {
                    continue;
                }
                if saw_done {
                    return Err(local_stream_error("[DONE] 之后仍出现 SSE data"));
                }
                if event_data.as_slice() == b"[DONE]" {
                    saw_done = true;
                } else {
                    let value = serde_json::from_slice::<Value>(&event_data)
                        .map_err(|_| local_stream_error("SSE data 包含无效 JSON（正文已隐藏）"))?;
                    let mut sensitive = SensitiveJsonValue(value);
                    accumulator.observe(&sensitive, request_started.elapsed())?;
                    if let Some(forwarding) = stream_forwarding.as_ref() {
                        normalize_stream_event_model(&mut sensitive, &forwarding.authorized_model)?;
                        let serialized = serde_json::to_string(&*sensitive).map_err(|_| {
                            local_stream_error("无法编码已验证的 SSE data（正文已隐藏）")
                        })?;
                        forwarding
                            .sender
                            .send(PendingStreamEvent {
                                sequence: event_sequence,
                                kind: JobStreamEventKind::Data,
                                event_data: Some(serialized),
                            })
                            .await
                            .map_err(|_| {
                                local_stream_error("持久 SSE 事件通道提前关闭，拒绝结算")
                            })?;
                        event_sequence = event_sequence
                            .checked_add(1)
                            .ok_or_else(|| local_stream_error("SSE 事件 sequence 超出协议范围"))?;
                    }
                }
                event_data.zeroize();
                event_data.clear();
                continue;
            }
            if line.starts_with(b":") {
                continue;
            }
            let Some(data) = line.strip_prefix(b"data:") else {
                return Err(local_stream_error("SSE 包含不受支持的字段"));
            };
            if saw_done {
                return Err(local_stream_error("[DONE] 之后仍出现 SSE data"));
            }
            let data = data.strip_prefix(b" ").unwrap_or(data);
            if !event_data.is_empty() {
                event_data.push(b'\n');
            }
            if data.len() > MAX_INFERENCE_RESPONSE_BYTES.saturating_sub(event_data.len()) {
                return Err(local_stream_error("单个 SSE 事件超过安全上限"));
            }
            event_data.extend_from_slice(data);
        }
    }
    if parse_cursor != bytes.len() || !event_data.is_empty() {
        return Err(local_stream_error("SSE 在不完整行或事件中断开"));
    }
    let result = accumulator.finish(saw_done)?;
    if let Some(forwarding) = stream_forwarding.as_ref() {
        forwarding
            .sender
            .send(PendingStreamEvent {
                sequence: event_sequence,
                kind: JobStreamEventKind::UpstreamDone,
                event_data: None,
            })
            .await
            .map_err(|_| local_stream_error("持久 SSE 完成标记通道提前关闭，拒绝结算"))?;
    }
    Ok(result)
}

#[derive(Debug, Deserialize)]
struct LlamaSlotEraseResponse {
    id_slot: u32,
    n_erased: u64,
}

/// b10064 受审计单模型 server 的同步、精确 slot erase。上游实现会对该 sequence 调用
/// `common_context_seq_rm` 并清空 prompt token 表；这证明逻辑 KV sequence 已移除，
/// 不声称底层 CUDA/Metal 分配器物理页已经逐字节覆写。
async fn erase_managed_llama_slot(port: u16, slot_id: u32) -> CliResult<u64> {
    const MAX_ERASE_RESPONSE_BYTES: usize = 4 * 1024;
    let response = loopback_http_client(Some(Duration::from_secs(10)))?
        .post(format!(
            "http://127.0.0.1:{port}/slots/{slot_id}?action=erase"
        ))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body("{}")
        .send()
        .await
        .map_err(|error| {
            CliError::EngineOrSandbox(format!(
                "无法执行 llama.cpp 请求后 KV Cache 逻辑清理：{error}"
            ))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(CliError::EngineOrSandbox(format!(
            "llama.cpp 请求后 KV Cache 逻辑清理返回 HTTP {}",
            status.as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERASE_RESPONSE_BYTES as u64)
    {
        return Err(CliError::EngineOrSandbox(
            "llama.cpp KV 清理回执超过安全上限".to_owned(),
        ));
    }
    let bytes = response.bytes().await.map_err(|error| {
        CliError::EngineOrSandbox(format!("无法读取 llama.cpp KV 清理回执：{error}"))
    })?;
    if bytes.len() > MAX_ERASE_RESPONSE_BYTES {
        return Err(CliError::EngineOrSandbox(
            "llama.cpp KV 清理回执超过安全上限".to_owned(),
        ));
    }
    let receipt: LlamaSlotEraseResponse = serde_json::from_slice(&bytes)
        .map_err(|_| CliError::EngineOrSandbox("llama.cpp KV 清理回执不是有效 JSON".to_owned()))?;
    if receipt.id_slot != slot_id {
        return Err(CliError::EngineOrSandbox(
            "llama.cpp KV 清理回执 slot 绑定不一致".to_owned(),
        ));
    }
    Ok(receipt.n_erased)
}

async fn renew_job_lease(
    session: &mut CredentialBundle,
    liveness: &ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
) -> CliResult<OffsetDateTime> {
    let context = liveness.context;
    let request = RenewJobRequest {
        node_id: liveness.node_id(),
    };
    let path = mindone_protocol::job_renew(job.job_id);
    let response: CliResult<RenewJobResponse> = context
        .coordinator
        .post(&path, Some(&session.access_token), &request)
        .await;
    match response {
        Ok(response) => Ok(response.lease_expires_at),
        Err(CliError::Authentication(_)) => {
            *session = refresh_worker_session(
                context,
                &liveness.refresh_lock,
                session.access_token.clone(),
            )
            .await?;
            let response: RenewJobResponse = context
                .coordinator
                .post(&path, Some(&session.access_token), &request)
                .await
                .map_err(|error| CliError::General(format!("任务租约续期失败：{error}")))?;
            Ok(response.lease_expires_at)
        }
        Err(error) => Err(CliError::General(format!("任务租约续期失败：{error}"))),
    }
}

/// worker 的 stdout/stderr 会被持久化和轮转。协调服务器的 message 属于不受信
/// 远端输入，绝不能作为 tracing 字段写入；这里只保留固定 error_type、数值 HTTP
/// 状态和 job_id。无法可靠提取 HTTP 状态时使用 0 表示 transport/local failure。
fn warn_result_upload_failure(job_id: Uuid, error: &CliError) {
    tracing::warn!(
        job_id = %job_id,
        error_type = error.error_type(),
        http_status = submission_http_status(error),
        "推理结果未能在有限重试内确认，worker 继续运行"
    );
}

fn submission_http_status(error: &CliError) -> u16 {
    const MARKER: &str = "协调服务器请求失败（HTTP ";

    let message = error.to_string();
    let Some((_, suffix)) = message.split_once(MARKER) else {
        return 0;
    };
    let digit_count = suffix.bytes().take_while(u8::is_ascii_digit).count();
    let Some(text) = suffix.get(..digit_count) else {
        return 0;
    };
    text.parse::<u16>()
        .ok()
        .filter(|status| (100..=599).contains(status))
        .unwrap_or(0)
}

fn result_submission_requires_terminal_failure(error: &CliError) -> bool {
    // 当前协调器所有结果结构、usage 与模型绑定拒绝均为 HTTP 400。认证、策略、
    // 租约冲突及瞬时服务错误不得改写为 worker failure。
    submission_http_status(error) == 400
}

async fn submit_result(
    context: &AppContext,
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    result: &WorkerExecutionResult,
    execution_telemetry: &JobExecutionTelemetry,
    lease_expires_at: OffsetDateTime,
) -> CliResult<()> {
    let node_id = liveness.node_id();
    let (result_ciphertext, actual_input_tokens, actual_output_tokens) = match result {
        WorkerExecutionResult::Standard(value) => {
            let result_bytes = Zeroizing::new(
                serde_json::to_vec(&*value.response)
                    .map_err(|error| CliError::General(format!("无法编码推理结果：{error}")))?,
            );
            (
                BASE64_STANDARD.encode(&*result_bytes),
                usage_i32(&value.response, "prompt_tokens")?,
                usage_i32(&value.response, "completion_tokens")?,
            )
        }
        WorkerExecutionResult::Regulated(value) => (
            serde_json::to_string(&value.result_envelope).map_err(|error| {
                CliError::Attestation(format!("无法编码 TEE 结果 envelope：{error}"))
            })?,
            value.actual_input_tokens,
            value.actual_output_tokens,
        ),
    };
    let request = SensitiveJobResultRequest(JobResultRequest {
        node_id,
        idempotency_key: format!("result:{}:{}", job.job_id, job.attempt),
        result_ciphertext,
        actual_input_tokens,
        actual_output_tokens,
        execution_telemetry: execution_telemetry.clone(),
    });
    request
        .validate()
        .map_err(|error| CliError::General(error.to_string()))?;
    let refresh_lock = Arc::clone(&liveness.refresh_lock);
    submit_with_retry(
        &context.coordinator,
        session,
        node_id,
        job,
        lease_expires_at,
        JobSubmission::Result(&request),
        SubmissionRetryPolicy::PRODUCTION,
        move |failed_access_token| {
            let refresh_lock = Arc::clone(&refresh_lock);
            async move { refresh_worker_session(context, &refresh_lock, failed_access_token).await }
        },
        Some(liveness),
    )
    .await
}

async fn submit_result_or_terminal_failure(
    context: &AppContext,
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    result: &WorkerExecutionResult,
    execution_telemetry: &JobExecutionTelemetry,
    lease_expires_at: OffsetDateTime,
) -> bool {
    match submit_result(
        context,
        session,
        liveness,
        job,
        result,
        execution_telemetry,
        lease_expires_at,
    )
    .await
    {
        Ok(()) => true,
        Err(upload_error) => {
            warn_result_upload_failure(job.job_id, &upload_error);
            if result_submission_requires_terminal_failure(&upload_error) {
                // 协调器已经确定性拒绝结果结构或绑定；继续重试同一 result 不会
                // 成功，也不能把租约留到过期。只提交固定、无正文的模型校验失败，
                // 避免把服务端 message 写进任务审计。
                let rejection =
                    CliError::ModelValidation("推理结果未通过协调器的结构与绑定校验".to_owned());
                if let Err(failure_error) = submit_failure(
                    context,
                    session,
                    liveness,
                    job,
                    &rejection,
                    false,
                    lease_expires_at,
                )
                .await
                {
                    tracing::warn!(
                        job_id = %job.job_id,
                        error_type = failure_error.error_type(),
                        http_status = submission_http_status(&failure_error),
                        "结果被确定性拒绝后的失败状态未能确认"
                    );
                }
            }
            false
        }
    }
}

async fn submit_stream_event(
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    mut event: PendingStreamEvent,
    lease_expires_at: OffsetDateTime,
) -> CliResult<()> {
    let context = liveness.context;
    let node_id = liveness.node_id();
    let request = SensitiveJobStreamEventRequest(JobStreamEventRequest {
        node_id,
        attempt: job.attempt,
        sequence: event.sequence,
        idempotency_key: format!("stream:{}:{}:{}", job.job_id, job.attempt, event.sequence),
        kind: event.kind,
        event_data: event.event_data.take(),
    });
    request
        .validate()
        .map_err(|error| CliError::General(error.to_string()))?;
    let refresh_lock = Arc::clone(&liveness.refresh_lock);
    submit_with_retry(
        &context.coordinator,
        session,
        node_id,
        job,
        lease_expires_at,
        JobSubmission::StreamEvent(&request),
        SubmissionRetryPolicy::PRODUCTION,
        move |failed_access_token| {
            let refresh_lock = Arc::clone(&refresh_lock);
            async move { refresh_worker_session(context, &refresh_lock, failed_access_token).await }
        },
        Some(liveness),
    )
    .await
}

async fn submit_failure(
    context: &AppContext,
    session: &mut CredentialBundle,
    liveness: &mut ActiveJobLiveness<'_>,
    job: &ClaimJobResponse,
    error: &CliError,
    retryable: bool,
    lease_expires_at: OffsetDateTime,
) -> CliResult<()> {
    let node_id = liveness.node_id();
    let request = JobFailRequest {
        node_id,
        idempotency_key: format!("fail:{}:{}", job.job_id, job.attempt),
        error_class: match error {
            CliError::EngineOrSandbox(_) => JobErrorClass::Engine,
            CliError::ModelValidation(_) => JobErrorClass::Model,
            CliError::PolicyRejected(_) => JobErrorClass::Policy,
            CliError::Attestation(_) => JobErrorClass::Attestation,
            _ => JobErrorClass::Internal,
        },
        error_message: truncate_message(&error.to_string(), 1_000),
        retryable,
    };
    request
        .validate()
        .map_err(|validation| CliError::General(validation.to_string()))?;
    let refresh_lock = Arc::clone(&liveness.refresh_lock);
    submit_with_retry(
        &context.coordinator,
        session,
        node_id,
        job,
        lease_expires_at,
        JobSubmission::Failure(&request),
        SubmissionRetryPolicy::PRODUCTION,
        move |failed_access_token| {
            let refresh_lock = Arc::clone(&refresh_lock);
            async move { refresh_worker_session(context, &refresh_lock, failed_access_token).await }
        },
        Some(liveness),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn submit_with_retry<Refresh, RefreshFuture>(
    coordinator: &CoordinatorClient,
    session: &mut CredentialBundle,
    node_id: Uuid,
    job: &ClaimJobResponse,
    mut lease_expires_at: OffsetDateTime,
    submission: JobSubmission<'_>,
    policy: SubmissionRetryPolicy,
    mut refresh: Refresh,
    mut liveness: Option<&mut ActiveJobLiveness<'_>>,
) -> CliResult<()>
where
    Refresh: FnMut(String) -> RefreshFuture,
    RefreshFuture: Future<Output = CliResult<CredentialBundle>>,
{
    if policy.max_attempts == 0 {
        return Err(CliError::General(
            "任务结果提交重试次数必须大于零".to_owned(),
        ));
    }
    let mut last_error = None;
    for attempt in 1..=policy.max_attempts {
        let access_token = session.access_token.clone();
        let post = post_job_submission(coordinator, &access_token, job.job_id, submission);
        let submission_result = if let Some(active) = liveness.as_mut() {
            active.wait_with_heartbeat(session, post).await
        } else {
            post.await
        };
        match submission_result {
            Ok(()) => return Ok(()),
            Err(error) if submission_error_is_retryable(&error) => {
                let needs_refresh = matches!(error, CliError::Authentication(_));
                last_error = Some(error);
                if needs_refresh {
                    match refresh(session.access_token.clone()).await {
                        Ok(refreshed) => *session = refreshed,
                        Err(refresh_error) => last_error = Some(refresh_error),
                    }
                }
            }
            Err(error) => return Err(error),
        }

        if attempt == policy.max_attempts {
            break;
        }
        if lease_expires_at > OffsetDateTime::now_utc() {
            match renew_lease_for_submission(
                coordinator,
                session,
                node_id,
                job.job_id,
                &mut refresh,
            )
            .await
            {
                Ok(renewed_until) => lease_expires_at = renewed_until,
                Err(error) => tracing::warn!(
                    job_id = %job.job_id,
                    error_type = error.error_type(),
                    http_status = submission_http_status(&error),
                    "上传重试期间未能续租，将继续使用幂等键确认提交"
                ),
            }
        }
        let delay = submission_retry_delay(policy, attempt);
        let wait = async move {
            if delay.is_zero() {
                tokio::task::yield_now().await;
            } else {
                tokio::time::sleep(delay).await;
            }
        };
        if let Some(active) = liveness.as_mut() {
            active.wait_with_heartbeat(session, wait).await;
        } else {
            wait.await;
        }
    }

    let last_error = last_error.unwrap_or_else(|| CliError::General("未知提交错误".to_owned()));
    Err(CliError::General(format!(
        "任务结果在 {} 次幂等提交后仍未确认：{last_error}",
        policy.max_attempts
    )))
}

async fn post_job_submission(
    coordinator: &CoordinatorClient,
    access_token: &str,
    job_id: Uuid,
    submission: JobSubmission<'_>,
) -> CliResult<()> {
    match submission {
        JobSubmission::Result(request) => {
            let _: JobResultResponse = coordinator
                .post(
                    &mindone_protocol::job_result(job_id),
                    Some(access_token),
                    request,
                )
                .await?;
        }
        JobSubmission::Failure(request) => {
            let _: JobFailResponse = coordinator
                .post(
                    &mindone_protocol::job_fail(job_id),
                    Some(access_token),
                    request,
                )
                .await?;
        }
        JobSubmission::StreamEvent(request) => {
            let _: JobStreamEventResponse = coordinator
                .post(
                    &mindone_protocol::job_stream(job_id),
                    Some(access_token),
                    request,
                )
                .await?;
        }
    }
    Ok(())
}

async fn renew_lease_for_submission<Refresh, RefreshFuture>(
    coordinator: &CoordinatorClient,
    session: &mut CredentialBundle,
    node_id: Uuid,
    job_id: Uuid,
    refresh: &mut Refresh,
) -> CliResult<OffsetDateTime>
where
    Refresh: FnMut(String) -> RefreshFuture,
    RefreshFuture: Future<Output = CliResult<CredentialBundle>>,
{
    let request = RenewJobRequest { node_id };
    let path = mindone_protocol::job_renew(job_id);
    let first: CliResult<RenewJobResponse> = coordinator
        .post(&path, Some(&session.access_token), &request)
        .await;
    match first {
        Ok(response) => Ok(response.lease_expires_at),
        Err(CliError::Authentication(_)) => {
            *session = refresh(session.access_token.clone()).await?;
            let response: RenewJobResponse = coordinator
                .post(&path, Some(&session.access_token), &request)
                .await?;
            Ok(response.lease_expires_at)
        }
        Err(error) => Err(error),
    }
}

const fn submission_error_is_retryable(error: &CliError) -> bool {
    matches!(error, CliError::General(_) | CliError::Authentication(_))
}

fn submission_retry_delay(policy: SubmissionRetryPolicy, completed_attempt: usize) -> Duration {
    let exponent = completed_attempt.saturating_sub(1).min(16);
    let multiplier = 1_u32 << exponent;
    policy
        .initial_backoff
        .saturating_mul(multiplier)
        .min(policy.max_backoff)
}

async fn delete_model_instance(
    context: &AppContext,
    session: &mut CredentialBundle,
    model_instance_id: Uuid,
) -> CliResult<UnpublishModelResponse> {
    let path = mindone_protocol::model_instance(model_instance_id);
    let response = context
        .authorized_delete::<Value, UnpublishModelResponse>(&path, None)
        .await?;
    // worker 会继续复用内存中的会话；同步可能已被 authorized_delete 轮换的 token。
    *session = context.vault.load_session()?;
    Ok(response)
}

fn decode_job_payload(job: &ClaimJobResponse) -> CliResult<SensitiveStandardJobPayload> {
    let bytes = Zeroizing::new(
        match job.payload_encoding {
            PayloadEncoding::Base64 => BASE64_STANDARD.decode(&job.encrypted_payload),
            PayloadEncoding::Base64Url => URL_SAFE_NO_PAD.decode(&job.encrypted_payload),
            PayloadEncoding::RegulatedAeadV1 => {
                return Err(CliError::Attestation(
                    "Regulated 任务不能由 Standard worker 解码；必须交给 TEE runtime adapter"
                        .to_owned(),
                ));
            }
        }
        .map_err(|error| CliError::General(format!("任务载荷编码无效：{error}")))?,
    );
    let payload = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::General(format!("Standard 任务载荷 JSON 无效：{error}")))?;
    Ok(SensitiveStandardJobPayload(payload))
}

fn protocol_hardware_profile(
    applied_sandbox_mechanisms: &[mindone_sandbox::IsolationMechanism],
) -> CliResult<HardwareProfile> {
    let source = mindone_engine::detect_hardware();
    let profile = HardwareProfile {
        // 协议需要稳定的英文平台标识符（macos/linux/windows）。硬件探测返回的是
        // 面向用户展示的系统名称，在 macOS 上通常为 Darwin，不能直接用于信任判定。
        operating_system: std::env::consts::OS.to_owned(),
        operating_system_version: source.os_version,
        architecture: source.architecture,
        cpu_model: source.cpu_brand,
        cpu_logical_cores: u32::try_from(source.logical_cpu_count)
            .map_err(|_| CliError::General("逻辑 CPU 数量超出协议范围".to_owned()))?,
        ram_total_mib: source.total_memory_bytes / 1024 / 1024,
        gpus: source
            .gpus
            .into_iter()
            .map(|gpu| GpuProfile {
                name: gpu.name,
                vendor: None,
                vram_total_mib: gpu.memory_bytes.map(|bytes| bytes / 1024 / 1024),
                compute_capability: None,
            })
            .collect(),
        cuda_available: source.cuda_available,
        metal_available: source.metal_available,
        // 只发布监督进程为当前 llama-server 确认的 applied 集合。主机“可用/可应用”
        // 能力不能证明这次启动真正受其保护；多个 Linux 启动层映射到同一协议机制时去重。
        sandbox_mechanisms: protocol_sandbox_mechanisms(applied_sandbox_mechanisms),
        extra: BTreeMap::new(),
    };
    profile
        .validate()
        .map_err(|error| CliError::General(error.to_string()))?;
    Ok(profile)
}

fn protocol_sandbox_mechanisms(
    applied: &[mindone_sandbox::IsolationMechanism],
) -> Vec<SandboxMechanism> {
    applied
        .iter()
        .filter_map(map_sandbox_mechanism)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn map_sandbox_mechanism(
    mechanism: &mindone_sandbox::IsolationMechanism,
) -> Option<SandboxMechanism> {
    match mechanism {
        mindone_sandbox::IsolationMechanism::LinuxNamespaces
        | mindone_sandbox::IsolationMechanism::Bubblewrap => Some(SandboxMechanism::Namespaces),
        mindone_sandbox::IsolationMechanism::SeccompBpf => Some(SandboxMechanism::SeccompBpf),
        mindone_sandbox::IsolationMechanism::Landlock => Some(SandboxMechanism::Landlock),
        mindone_sandbox::IsolationMechanism::AppArmor => Some(SandboxMechanism::AppArmor),
        mindone_sandbox::IsolationMechanism::Seatbelt => Some(SandboxMechanism::Seatbelt),
        mindone_sandbox::IsolationMechanism::InheritedAppSandbox => {
            Some(SandboxMechanism::AppSandbox)
        }
        mindone_sandbox::IsolationMechanism::WindowsJobObject => Some(SandboxMechanism::JobObjects),
        mindone_sandbox::IsolationMechanism::WindowsAppContainer => {
            Some(SandboxMechanism::AppContainer)
        }
        mindone_sandbox::IsolationMechanism::HyperV => Some(SandboxMechanism::HyperV),
    }
}

fn heartbeat_request(
    metrics: &ShareMetrics,
    hardware: &HardwareMetrics,
    policy: &crate::node::NodePolicy,
    coordinator_rtt_ms: Option<i64>,
    current_concurrent: i32,
    draining: bool,
) -> CliResult<HeartbeatRequest> {
    let total = metrics.successes.saturating_add(metrics.failures);
    let error_rate_ppm = metrics
        .failures
        .saturating_mul(1_000_000)
        .checked_div(total)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(0);
    let metrics = HeartbeatRequest {
        tps_milli: metrics
            .tps
            .map(|value| (value * 1_000.0).round() as i64)
            .unwrap_or(0),
        ttft_ms: metrics
            .ttft_ms
            .map(|value| value.round() as i64)
            .unwrap_or(0),
        current_concurrent,
        gpu_temp_c: hardware.gpu_temperature_c.map(|value| value.round() as i32),
        vram_used_mib: hardware
            .vram_used_bytes
            .map(|value| i64::try_from(value / 1024 / 1024).unwrap_or(i64::MAX)),
        vram_total_mib: hardware
            .vram_total_bytes
            .map(|value| i64::try_from(value / 1024 / 1024).unwrap_or(i64::MAX)),
        error_rate_ppm,
        coordinator_rtt_ms,
        draining,
        policy: Some(NodePolicyDto {
            reject_tags: policy.reject_tags.clone(),
            max_concurrent: u32::from(policy.max_concurrent),
            gpu_temp_limit_c: policy.gpu_temp_limit_c,
            vram_reserve_mib: gib_to_mib_u64(policy.vram_reserve_gb)?,
        }),
    };
    metrics
        .validate()
        .map_err(|error| CliError::PolicyRejected(error.to_string()))?;
    Ok(metrics)
}

#[cfg(test)]
async fn post_heartbeat_request(
    context: &AppContext,
    session: &mut CredentialBundle,
    state: &mut ShareState,
    request: &HeartbeatRequest,
) -> CliResult<HeartbeatResponse> {
    post_heartbeat_request_with_refresh(context, session, state, request, |_| {
        refresh_session(context)
    })
    .await
}

async fn post_heartbeat_request_with_refresh<Refresh, RefreshFuture>(
    context: &AppContext,
    session: &mut CredentialBundle,
    state: &mut ShareState,
    request: &HeartbeatRequest,
    refresh: Refresh,
) -> CliResult<HeartbeatResponse>
where
    Refresh: FnOnce(String) -> RefreshFuture,
    RefreshFuture: Future<Output = CliResult<CredentialBundle>>,
{
    let path = mindone_protocol::node_heartbeat(state.node_id);
    let (response, measured_rtt_ms) =
        post_heartbeat_with_refresh(&context.coordinator, &path, session, request, refresh).await?;

    // 先原子持久化候选状态，再替换内存状态。这样本地写入失败也不会把
    // 未持久化样本带进下一次心跳。超过协议上限的真实成功请求只丢弃本次
    // 样本，不伪造 60000，也不覆盖上一条有效观测。
    let mut updated = state.clone();
    updated.last_heartbeat_at = Some(now_rfc3339()?);
    if let Some(measured_rtt_ms) = measured_rtt_ms {
        updated.last_coordinator_rtt_ms = Some(measured_rtt_ms);
    }
    write_json_atomic(&context.paths.runtime.join(STATE_FILE), &updated)?;
    *state = updated;
    Ok(response)
}

async fn post_heartbeat_with_refresh<Refresh, RefreshFuture>(
    coordinator: &CoordinatorClient,
    path: &str,
    session: &mut CredentialBundle,
    request: &HeartbeatRequest,
    refresh: Refresh,
) -> CliResult<(HeartbeatResponse, Option<i64>)>
where
    Refresh: FnOnce(String) -> RefreshFuture,
    RefreshFuture: Future<Output = CliResult<CredentialBundle>>,
{
    match timed_heartbeat_post(coordinator, path, &session.access_token, request).await {
        Ok(response) => Ok(response),
        Err(CliError::Authentication(_)) => {
            // refresh 自身不是节点到心跳 API 的网络 RTT，不能计入样本；401 的
            // 失败尝试也丢弃。新 token 的真正重试从零重新计时。
            *session = refresh(session.access_token.clone()).await?;
            timed_heartbeat_post(coordinator, path, &session.access_token, request).await
        }
        Err(error) => Err(error),
    }
}

async fn timed_heartbeat_post(
    coordinator: &CoordinatorClient,
    path: &str,
    access_token: &str,
    request: &HeartbeatRequest,
) -> CliResult<(HeartbeatResponse, Option<i64>)> {
    let started_at = Instant::now();
    // CoordinatorClient::post 只有在响应体完整读取且 HeartbeatResponse JSON
    // 成功解码后才返回 Ok，因此这里不会把连接成功或半截响应当作 RTT 样本。
    let response = coordinator.post(path, Some(access_token), request).await?;
    Ok((response, coordinator_rtt_sample(started_at.elapsed())))
}

fn coordinator_rtt_sample(elapsed: Duration) -> Option<i64> {
    if elapsed > Duration::from_secs(60) {
        return None;
    }
    i64::try_from(elapsed.as_millis().max(1)).ok()
}

#[cfg(test)]
async fn post_worker_heartbeat(
    context: &AppContext,
    session: &mut CredentialBundle,
    state: &mut ShareState,
    metrics: &ShareMetrics,
    current_concurrent: i32,
) -> CliResult<HeartbeatResponse> {
    let policy = load_persisted_policy(context)?;
    let hardware = hardware_metrics();
    let paused_for_temperature = update_temperature_pause(
        state.paused_for_temperature,
        policy.gpu_temp_limit_c,
        hardware.gpu_temperature_c,
    );
    if paused_for_temperature != state.paused_for_temperature {
        state.paused_for_temperature = paused_for_temperature;
        write_json_atomic(&context.paths.runtime.join(STATE_FILE), state)?;
    }
    let draining = context.paths.runtime.join(STOP_FILE).exists();
    let request = heartbeat_request(
        metrics,
        &hardware,
        &policy,
        state.last_coordinator_rtt_ms,
        current_concurrent,
        draining,
    )?;
    post_heartbeat_request(context, session, state, &request).await
}

async fn post_worker_heartbeat_serialized(
    context: &AppContext,
    session: &mut CredentialBundle,
    state: &mut ShareState,
    metrics: &ShareMetrics,
    current_concurrent: i32,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
) -> CliResult<HeartbeatResponse> {
    let policy = load_persisted_policy(context)?;
    let hardware = hardware_metrics();
    let paused_for_temperature = update_temperature_pause(
        state.paused_for_temperature,
        policy.gpu_temp_limit_c,
        hardware.gpu_temperature_c,
    );
    if paused_for_temperature != state.paused_for_temperature {
        state.paused_for_temperature = paused_for_temperature;
        write_json_atomic(&context.paths.runtime.join(STATE_FILE), state)?;
    }
    let draining = context.paths.runtime.join(STOP_FILE).exists();
    let request = heartbeat_request(
        metrics,
        &hardware,
        &policy,
        state.last_coordinator_rtt_ms,
        current_concurrent,
        draining,
    )?;
    post_heartbeat_request_with_refresh(
        context,
        session,
        state,
        &request,
        move |failed_access_token| async move {
            refresh_worker_session(context, &refresh_lock, failed_access_token).await
        },
    )
    .await
}

impl ActiveJobLiveness<'_> {
    #[cfg(test)]
    fn new<'a>(
        context: &'a AppContext,
        state: &'a mut ShareState,
        metrics: &'a ShareMetrics,
        heartbeat_interval: Duration,
    ) -> ActiveJobLiveness<'a> {
        ActiveJobLiveness {
            context,
            state,
            metrics,
            heartbeat_interval,
            next_heartbeat: tokio::time::Instant::now(),
            slot_id: managed_share_slot_id(0).unwrap_or(1),
            active_count: Arc::new(AtomicU16::new(1)),
            heartbeat_lock: Arc::new(tokio::sync::Mutex::new(())),
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn with_shared_runtime<'a>(
        context: &'a AppContext,
        state: &'a mut ShareState,
        metrics: &'a ShareMetrics,
        heartbeat_interval: Duration,
        slot_id: u32,
        runtime: SharedJobRuntime,
    ) -> CliResult<ActiveJobLiveness<'a>> {
        let mut liveness = ActiveJobLiveness {
            context,
            state,
            metrics,
            heartbeat_interval,
            next_heartbeat: tokio::time::Instant::now(),
            slot_id: managed_share_slot_id(0).unwrap_or(1),
            active_count: runtime.active_count,
            heartbeat_lock: runtime.heartbeat_lock,
            refresh_lock: runtime.refresh_lock,
        };
        liveness.set_slot_id(slot_id)?;
        Ok(liveness)
    }

    fn set_slot_id(&mut self, slot_id: u32) -> CliResult<()> {
        let valid = (0..MANAGED_SHARE_MAX_CONCURRENT)
            .filter_map(managed_share_slot_id)
            .any(|candidate| candidate == slot_id);
        if !valid {
            return Err(CliError::EngineOrSandbox(format!(
                "贡献任务 slot {slot_id} 超出受管范围"
            )));
        }
        self.slot_id = slot_id;
        Ok(())
    }

    fn node_id(&self) -> Uuid {
        self.state.node_id
    }

    fn local_port(&self) -> u16 {
        self.state.local_port
    }

    fn slot_id(&self) -> u32 {
        self.slot_id
    }

    async fn heartbeat_now(
        &mut self,
        session: &mut CredentialBundle,
    ) -> CliResult<HeartbeatResponse> {
        let current_concurrent = i32::from(self.active_count.load(Ordering::SeqCst));
        let _heartbeat_guard = self.heartbeat_lock.lock().await;
        let response = post_worker_heartbeat_serialized(
            self.context,
            session,
            self.state,
            self.metrics,
            current_concurrent,
            Arc::clone(&self.refresh_lock),
        )
        .await;
        self.next_heartbeat = tokio::time::Instant::now() + self.heartbeat_interval;
        response
    }

    async fn wait_with_heartbeat<F>(
        &mut self,
        session: &mut CredentialBundle,
        future: F,
    ) -> F::Output
    where
        F: Future,
    {
        tokio::pin!(future);
        loop {
            let heartbeat_due = tokio::time::sleep_until(self.next_heartbeat);
            tokio::pin!(heartbeat_due);
            tokio::select! {
                output = &mut future => return output,
                () = &mut heartbeat_due => {
                    if let Err(error) = self.heartbeat_now(session).await {
                        tracing::warn!(
                            error_type = error.error_type(),
                            "活动任务心跳失败，推理或上传继续并等待下次周期"
                        );
                    }
                }
            }
        }
    }
}

fn update_temperature_pause(
    was_paused: bool,
    limit: Option<u16>,
    temperature: Option<f64>,
) -> bool {
    let Some(limit) = limit else {
        return false;
    };
    let Some(temperature) = temperature else {
        return true;
    };
    if was_paused {
        temperature > f64::from(limit.saturating_sub(5))
    } else {
        temperature > f64::from(limit)
    }
}

fn initial_metrics(context: &AppContext, state: &ShareState) -> CliResult<ShareMetrics> {
    let path = context.paths.runtime.join("share-metrics.json");
    if let Ok(metrics) = read_json(&path) {
        if metrics_belong_to_state(&metrics, state) {
            return Ok(metrics);
        }
    }
    Ok(ShareMetrics {
        node_id: Some(state.node_id),
        model_instance_id: Some(state.model_instance_id),
        requests: 0,
        successes: 0,
        failures: 0,
        uptime_seconds: 0,
        ttft_ms: None,
        tps: None,
        tier: format!("{:?}", state.tier),
        trust_level: state.trust_level.clone(),
        quota_earned_micro: 0,
        contribution_points_micro: 0,
        best_tps: None,
        best_ttft_ms: None,
    })
}

fn metrics_belong_to_state(metrics: &ShareMetrics, state: &ShareState) -> bool {
    metrics.node_id == Some(state.node_id)
        && metrics.model_instance_id == Some(state.model_instance_id)
}

fn record_performance_observation(
    metrics: &mut ShareMetrics,
    measured_tps: Option<f64>,
    measured_ttft_ms: Option<f64>,
) {
    if let Some(tps) = positive_finite(measured_tps) {
        metrics.tps = Some(tps);
        metrics.best_tps = Some(positive_finite(metrics.best_tps).unwrap_or(tps).max(tps));
    }
    if let Some(ttft_ms) = positive_finite(measured_ttft_ms) {
        metrics.ttft_ms = Some(ttft_ms);
        metrics.best_ttft_ms = Some(
            positive_finite(metrics.best_ttft_ms)
                .unwrap_or(ttft_ms)
                .min(ttft_ms),
        );
    }
}

async fn local_context_length(port: u16) -> Option<i32> {
    let response = loopback_http_client(Some(Duration::from_secs(2)))
        .ok()?
        .get(format!("http://127.0.0.1:{port}/props"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    let value: Value = response.json().await.ok()?;
    value
        .pointer("/default_generation_settings/n_ctx")
        .or_else(|| value.get("n_ctx"))
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| *value > 0)
}

fn loopback_http_client(timeout: Option<Duration>) -> CliResult<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        // Prompt、/props 与评价请求只能直连 loopback，禁止环境代理转发明文。
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    builder
        .build()
        .map_err(|error| CliError::General(format!("无法初始化本地推理 HTTP 客户端：{error}")))
}

const fn model_instance_status_zh(status: ModelInstanceStatus) -> &'static str {
    match status {
        ModelInstanceStatus::Published => "已发布",
        ModelInstanceStatus::Draining => "排空中",
        ModelInstanceStatus::Unpublished => "已取消发布",
    }
}

fn format_local_issues(issues: &[String]) -> String {
    if issues.is_empty() {
        String::new()
    } else {
        format!("（另有本地问题：{}）", issues.join("；"))
    }
}

fn usage_i32(result: &Value, field: &str) -> CliResult<i32> {
    let value = result
        .get("usage")
        .and_then(|usage| usage.get(field))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    i32::try_from(value).map_err(|_| CliError::General(format!("{field} 超出协议范围")))
}

fn gib_to_mib_u64(value: f64) -> CliResult<u64> {
    let mib = value * 1024.0;
    if !mib.is_finite() || mib < 0.0 || mib > i64::MAX as f64 {
        return Err(CliError::PolicyRejected(
            "显存保留值超出协议范围".to_owned(),
        ));
    }
    Ok(mib.round() as u64)
}

fn stable_node_alias(session: &CredentialBundle) -> String {
    let suffix = session
        .uid
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>();
    if suffix.is_empty() {
        "mindone-node".to_owned()
    } else {
        format!("node-{suffix}")
    }
}

fn validate_alias(alias: &str) -> CliResult<()> {
    if alias.is_empty() || alias.len() > 64 || alias.chars().any(char::is_control) {
        return Err(CliError::General(
            "节点别名必须是 1 到 64 字节且不含控制字符".to_owned(),
        ));
    }
    Ok(())
}

fn normalize_tags(tags: &[String]) -> CliResult<Vec<String>> {
    let mut normalized = Vec::new();
    for tag in tags {
        let tag = tag.trim().to_ascii_lowercase();
        if tag.is_empty()
            || tag.len() > 64
            || !tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CliError::General(format!("无效共享标签：{tag}")));
        }
        if !normalized.contains(&tag) {
            normalized.push(tag);
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn truncate_message(message: &str, limit: usize) -> String {
    message.chars().take(limit).collect()
}

fn now_rfc3339() -> CliResult<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|error| CliError::General(format!("无法记录共享时间：{error}")))
}

fn elapsed_seconds(started_at: &str) -> Option<u64> {
    let started = OffsetDateTime::parse(started_at, &Rfc3339).ok()?;
    u64::try_from((OffsetDateTime::now_utc() - started).whole_seconds()).ok()
}

async fn wait_for_first_heartbeat(
    context: &AppContext,
    pid: u32,
    timeout: Duration,
) -> CliResult<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CliError::General("首次心跳等待时间超出平台范围".to_owned()))?;
    while Instant::now() < deadline {
        let state: ShareState = read_json(&context.paths.runtime.join(STATE_FILE))?;
        if state.pid != pid {
            return Err(CliError::General(
                "共享 worker 状态中的 PID 在首次心跳前发生变化，拒绝继续操作".to_owned(),
            ));
        }
        if !worker_process_is_running(&state)? {
            return Err(CliError::General(format!(
                "共享 worker 在首次心跳前退出，请查看 {}",
                context.paths.logs.join(LOG_FILE).display()
            )));
        }
        if state.last_heartbeat_at.is_some() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let state: ShareState = read_json(&context.paths.runtime.join(STATE_FILE))?;
    stop_verified_worker(&state, WORKER_FORCE_STOP_TIMEOUT).await?;
    Err(CliError::General(
        "共享 worker 未在 20 秒内建立首次真实心跳，已停止".to_owned(),
    ))
}

fn expected_worker_command() -> Vec<String> {
    WORKER_COMMAND
        .iter()
        .map(|value| (*value).to_owned())
        .collect()
}

fn clear_worker_identity(state: &mut ShareState) {
    state.pid = 0;
    state.process_start_marker = None;
    state.worker_executable = None;
    state.worker_command.clear();
}

fn merge_known_worker_identity(target: &mut ShareState, source: &ShareState) {
    if source.process_start_marker.is_some() {
        target.process_start_marker = source.process_start_marker.clone();
    }
    if source.worker_executable.is_some() {
        target.worker_executable = source.worker_executable.clone();
    }
    if !source.worker_command.is_empty() {
        target.worker_command = source.worker_command.clone();
    }
}

fn merge_observed_worker_identity(state: &mut ShareState) {
    let Some(observed) = observe_worker_identity(state.pid) else {
        return;
    };
    let expected_executable = state
        .worker_executable
        .clone()
        .or_else(|| std::env::current_exe().ok());
    let Some(expected_executable) = expected_executable else {
        return;
    };
    let expected_command = expected_worker_command();
    if observed_matches_expected_worker(&expected_executable, &expected_command, &observed) {
        state.process_start_marker = Some(observed.process_start_marker);
        state.worker_executable = Some(expected_executable);
        state.worker_command = expected_command;
    }
}

fn preserved_worker_identity_message(state: &ShareState) -> String {
    if state.process_start_marker.is_some()
        && state.worker_executable.is_some()
        && state.worker_command == expected_worker_command()
    {
        "worker 停止未确认，已保留 PID、启动标记、可执行文件和命令身份供安全重试".to_owned()
    } else {
        "worker 停止未确认；仅保留现有 PID/身份字段，因完整身份未建立而禁止自动发送信号".to_owned()
    }
}

async fn wait_for_worker_identity(
    pid: u32,
    executable: &Path,
    timeout: Duration,
) -> CliResult<ObservedWorkerIdentity> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CliError::General("worker 身份等待时间超出平台范围".to_owned()))?;
    while Instant::now() < deadline {
        if !raw_process_exists(pid)? {
            return Err(CliError::General(
                "共享 worker 在记录进程身份前退出".to_owned(),
            ));
        }
        if let Some(observed) = observe_worker_identity(pid) {
            if observed_matches_expected_worker(executable, &expected_worker_command(), &observed) {
                return Ok(observed);
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(CliError::General(
        "无法验证新共享 worker 的启动标记、可执行文件和命令身份".to_owned(),
    ))
}

fn worker_process_is_running(state: &ShareState) -> CliResult<bool> {
    if !raw_process_exists(state.pid)? {
        return Ok(false);
    }
    let observed = match observe_worker_identity(state.pid) {
        Some(observed) => observed,
        None if !raw_process_exists(state.pid)? => {
            // worker 可在首次存活探测与 sysinfo 身份读取之间自然退出。
            // 只有第二次权威探测也确认 PID 已消失时才认定停止；若 PID
            // 被复用且仍存活，下面的错误分支继续 fail closed。
            return Ok(false);
        }
        None => {
            return Err(CliError::General(format!(
                "无法读取 PID {} 的进程身份；为防止 PID 复用，拒绝把它视为共享 worker",
                state.pid
            )));
        }
    };
    validate_worker_identity(state, &observed)?;
    Ok(true)
}

fn validate_worker_identity(
    state: &ShareState,
    observed: &ObservedWorkerIdentity,
) -> CliResult<()> {
    let marker = state
        .process_start_marker
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::General(format!(
                "共享状态缺少 PID {} 的启动标记（旧版状态）；拒绝自动探测或终止该 PID",
                state.pid
            ))
        })?;
    let executable = state.worker_executable.as_deref().ok_or_else(|| {
        CliError::General(format!(
            "共享状态缺少 PID {} 的可执行文件身份（旧版状态）；拒绝自动探测或终止该 PID",
            state.pid
        ))
    })?;
    if state.worker_command != expected_worker_command() {
        return Err(CliError::General(format!(
            "共享状态缺少 PID {} 的稳定 worker 命令身份；拒绝自动探测或终止该 PID",
            state.pid
        )));
    }
    if marker != observed.process_start_marker
        || !observed_matches_expected_worker(executable, &state.worker_command, observed)
    {
        return Err(CliError::General(format!(
            "PID {} 的启动标记、可执行文件或命令与共享状态不匹配；可能发生 PID 复用，已拒绝发送信号",
            state.pid
        )));
    }
    Ok(())
}

fn observed_matches_expected_worker(
    executable: &Path,
    expected_command: &[String],
    observed: &ObservedWorkerIdentity,
) -> bool {
    paths_refer_to_same_file(executable, &observed.executable)
        && !expected_command.is_empty()
        && observed
            .command
            .windows(expected_command.len())
            .any(|window| window == expected_command)
}

fn paths_refer_to_same_file(expected: &Path, observed: &Path) -> bool {
    if expected == observed {
        return true;
    }
    match (
        std::fs::canonicalize(expected),
        std::fs::canonicalize(observed),
    ) {
        (Ok(expected), Ok(observed)) => expected == observed,
        _ => false,
    }
}

fn observe_worker_identity(pid: u32) -> Option<ObservedWorkerIdentity> {
    if pid == 0 {
        return None;
    }
    let target = Pid::from_u32(pid);
    let targets = [target];
    // macOS 上 `System::new()` 的最小刷新可能没有初始化进程可执行文件或命令行，
    // 导致一个真实运行的 worker 永远无法建立 PID 复用防护所需的身份绑定。
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::Some(&targets), true);
    let process = system.process(target)?;
    let start_time = process.start_time();
    if start_time == 0 {
        return None;
    }
    let executable = process.exe()?.to_path_buf();
    if executable.as_os_str().is_empty() {
        return None;
    }
    let command = process
        .cmd()
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if command.is_empty() {
        return None;
    }
    Some(ObservedWorkerIdentity {
        process_start_marker: start_time.to_string(),
        executable,
        command,
    })
}

async fn wait_for_verified_worker_stop(state: &ShareState, timeout: Duration) -> CliResult<bool> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| CliError::General("worker 停止等待时间超出平台范围".to_owned()))?;
    loop {
        if !worker_process_is_running(state)? {
            // 在认定停止前主动让出一次，并复核 PID+启动标记。
            // 若此时 PID 被复用，worker_process_is_running 会 fail closed。
            tokio::task::yield_now().await;
            if !worker_process_is_running(state)? {
                return Ok(true);
            }
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop_verified_worker(state: &ShareState, timeout: Duration) -> CliResult<()> {
    if wait_for_verified_worker_stop(state, Duration::ZERO).await? {
        return Ok(());
    }

    // 发 TERM 前已通过 worker_process_is_running 校验 PID、启动标记、
    // 可执行文件和固定命令；等待后再次校验才可升级到 KILL。
    terminate_process_raw(state.pid, false)?;
    if wait_for_verified_worker_stop(state, timeout).await? {
        return Ok(());
    }

    if !worker_process_is_running(state)? {
        return Ok(());
    }
    terminate_process_raw(state.pid, true)?;
    if wait_for_verified_worker_stop(state, WORKER_FORCE_STOP_TIMEOUT).await? {
        return Ok(());
    }

    // 最后一次身份校验：若 PID 被复用则返回身份错误；
    // 若仍是原 worker，则明确报告 TERM/KILL 未能停止。
    let _ = worker_process_is_running(state)?;
    Err(CliError::General(format!(
        "共享 worker PID {} 在 TERM/KILL 后仍存活；已保留 PID 与启动标记",
        state.pid
    )))
}

fn raw_process_exists(pid: u32) -> CliResult<bool> {
    if pid == 0 {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        let status = Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| CliError::General(format!("无法探测共享 worker：{error}")))?;
        if !status.success() {
            let target = Pid::from_u32(pid);
            let targets = [target];
            let mut system = System::new_all();
            system.refresh_processes(ProcessesToUpdate::Some(&targets), true);
            return match system.process(target) {
                Some(process) if matches!(process.status(), sysinfo::ProcessStatus::Zombie) => {
                    Ok(false)
                }
                Some(_) => Err(CliError::General(format!(
                    "PID {pid} 仍存活，但 kill -0 无法验证；拒绝当作已停止"
                ))),
                None => Ok(false),
            };
        }
        let target = Pid::from_u32(pid);
        let targets = [target];
        let mut system = System::new_all();
        system.refresh_processes(ProcessesToUpdate::Some(&targets), true);
        // `kill -0` 已经权威证明该 PID 存在且可被本进程发信号。sysinfo 只用于识别
        // zombie（已退出但未回收）这一种“对 kill -0 可见却实际已死”的情形。
        // 在 macOS 高负载或进程正在退出时，sysinfo 可能短暂枚举不到该 PID；此时
        // 无法证明它是 zombie，必须保守地按“仍存活”处理（返回 true），让上层继续
        // 发送 TERM/KILL 并重试，而不是错误地判定“无法读取进程状态”并失败关闭。
        // 只有明确读到 Zombie 状态才判定为已退出。
        match system.process(target) {
            Some(process) => Ok(!matches!(process.status(), sysinfo::ProcessStatus::Zombie)),
            None => Ok(true),
        }
    }
    #[cfg(windows)]
    {
        let output = Command::new("tasklist.exe")
            .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
            .output()
            .map_err(|error| CliError::General(format!("无法探测共享 worker：{error}")))?;
        if !output.status.success() {
            return Err(CliError::General(format!(
                "无法探测共享 worker：tasklist 退出码 {:?}",
                output.status.code()
            )));
        }
        let needle = format!("\",\"{pid}\",\"");
        Ok(String::from_utf8_lossy(&output.stdout).contains(&needle))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        Err(CliError::General(
            "当前平台不支持可验证的 worker PID 探测".to_owned(),
        ))
    }
}

fn terminate_process_raw(pid: u32, force: bool) -> CliResult<()> {
    #[cfg(unix)]
    let status = Command::new("/bin/kill")
        .args([if force { "-KILL" } else { "-TERM" }, &pid.to_string()])
        .status()
        .map_err(|error| CliError::General(format!("无法停止共享 worker：{error}")))?;
    #[cfg(windows)]
    let status = {
        let mut command = Command::new("taskkill.exe");
        command.args(["/PID", &pid.to_string(), "/T"]);
        if force {
            command.arg("/F");
        }
        command
            .status()
            .map_err(|error| CliError::General(format!("无法停止共享 worker：{error}")))?
    };
    #[cfg(not(any(unix, windows)))]
    return Err(CliError::General(
        "当前平台不支持停止共享 worker".to_owned(),
    ));
    #[cfg(any(unix, windows))]
    if !status.success() {
        if !raw_process_exists(pid)? {
            return Ok(());
        }
        return Err(CliError::General(format!("停止共享 worker {pid} 失败")));
    }
    #[cfg(any(unix, windows))]
    Ok(())
}

fn remove_if_exists(path: &std::path::Path) -> CliResult<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(CliError::General(format!(
            "无法清理 {}：{error}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use mindone_common::MindOnePaths;
    use mindone_protocol::{
        ClaimJobResponse, HeartbeatRequest, JobErrorClass, JobExecutionTelemetry, JobFailRequest,
        JobFailResponse, JobResultRequest, JobResultResponse, JobStreamEventKind,
        ModelInstanceStatus, NodeHonorStats, PayloadEncoding, PerformanceTier, RenewJobResponse,
        SandboxMechanism, StandardJobPayload, UnpublishModelResponse,
    };
    use mindone_sandbox::IsolationMechanism;
    use serde_json::Value;
    use tempfile::TempDir;
    use time::OffsetDateTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        contribution_progress_human, coordinator_rtt_sample, decode_job_payload,
        erase_managed_llama_slot, execute_local_inference,
        execute_local_inference_after_final_policy, expected_worker_command, file_identity,
        generation_path, heartbeat_request, honor_observation, job_execution_telemetry,
        local_context_length, merge_known_worker_identity, metrics_belong_to_state,
        normalize_standard_response_model, normalize_tags, observe_worker_identity,
        open_worker_log_file_io, post_heartbeat_request, post_heartbeat_with_refresh,
        post_worker_heartbeat, preserved_worker_identity_message, protocol_hardware_profile,
        protocol_sandbox_mechanisms, raw_process_exists, reconcile_local_unpublish_state,
        record_performance_observation, refresh_worker_session,
        result_submission_requires_terminal_failure, rotate_worker_log_if_needed,
        stable_node_alias, submission_http_status, submit_result,
        submit_result_or_terminal_failure, submit_with_retry, unpublish_command_output,
        update_temperature_pause, validate_standard_claim_identity,
        validate_standard_job_authorization, validate_standard_runtime_model_binding,
        validate_worker_identity, wait_for_inference_with_lease, wait_for_verified_worker_stop,
        warn_result_upload_failure, ActiveJobLiveness, FinalPolicyInference, JobSubmission,
        LocalOpenAiStreamKind, LogRotationConfig, ObservedWorkerIdentity, OpenAiStreamAccumulator,
        SensitiveJsonValue, ShareState, SpawnedWorker, StandardExecutionResult,
        StandardStreamForwarding, SubmissionRetryPolicy, VramPeakObservation,
        WorkerExecutionResult, WorkerLogMonitor, MAX_INFERENCE_RESPONSE_BYTES, STATE_FILE,
        STREAM_EVENT_CHANNEL_CAPACITY,
    };
    use crate::config::ConfigStore;
    use crate::context::AppContext;
    use crate::coordinator::CoordinatorClient;
    use crate::error::CliError;
    use crate::node::{HardwareMetrics, NodePolicy, ShareMetrics};
    use crate::storage::{read_json, write_json_atomic};
    use crate::vault::{CredentialBundle, SystemVault};

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    struct LogCaptureWriter(Arc<Mutex<Vec<u8>>>);

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogCapture {
        type Writer = LogCaptureWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            LogCaptureWriter(Arc::clone(&self.0))
        }
    }

    impl std::io::Write for LogCaptureWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("日志捕获锁损坏"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("日志捕获锁不应损坏").clone())
                .expect("tracing 输出应为 UTF-8")
        }
    }

    fn session(access_token: &str) -> CredentialBundle {
        CredentialBundle {
            access_token: access_token.to_owned(),
            refresh_token: "refresh-token".to_owned(),
            refresh_challenge: "ab".repeat(32),
            user: "alice".to_owned(),
            uid: "user-1".to_owned(),
            local_sandbox_trust_level: "standard".to_owned(),
            key_fingerprint: "fingerprint".to_owned(),
            login_at: "2026-07-17T00:00:00Z".to_owned(),
        }
    }

    fn execution_telemetry() -> JobExecutionTelemetry {
        JobExecutionTelemetry {
            ttft_ms: Some(100),
            tps_milli: Some(10_000),
            peak_vram_mib: Some(1_024),
            vram_sample_count: 4,
        }
    }

    #[test]
    fn node_registration_uses_only_applied_sandbox_mechanisms_and_deduplicates_layers() {
        let applied = vec![
            IsolationMechanism::LinuxNamespaces,
            IsolationMechanism::Bubblewrap,
            IsolationMechanism::SeccompBpf,
        ];
        assert_eq!(
            protocol_sandbox_mechanisms(&applied),
            vec![SandboxMechanism::Namespaces, SandboxMechanism::SeccompBpf]
        );
        assert!(protocol_sandbox_mechanisms(&[]).is_empty());

        let profile = protocol_hardware_profile(&applied).expect("协议硬件信息应有效");
        assert_eq!(profile.operating_system, std::env::consts::OS);
        assert_eq!(
            profile.sandbox_mechanisms,
            vec![SandboxMechanism::Namespaces, SandboxMechanism::SeccompBpf]
        );
    }

    #[test]
    fn standard_response_uses_authorized_virtual_model_name() {
        let mut response = serde_json::json!({
            "model": "qwen3-e2e",
            "choices": [{"message": {"content": "ok"}}]
        });
        normalize_standard_response_model(&mut response, "auto")
            .expect("本地模型展示名应归一化为已授权虚拟模型");
        assert_eq!(response["model"], "auto");

        let mut missing = serde_json::json!({"choices": []});
        assert!(normalize_standard_response_model(&mut missing, "auto").is_err());
    }

    #[test]
    fn standard_metrics_use_real_tps_and_only_measured_streaming_ttft() {
        let result = WorkerExecutionResult::Standard(StandardExecutionResult {
            response: SensitiveJsonValue(serde_json::json!({
                "timings": {"predicted_per_second": 109.95777621393384}
            })),
            measured_ttft_ms: Some(87),
        });
        let tps = result.inference_tps().expect("真实 llama.cpp TPS 应可读取");
        let ttft = result
            .measured_ttft_ms()
            .expect("流式首 Token TTFT 应可读取");
        assert!((tps - 109.957_776_213_933_84).abs() < 1e-9);
        assert_eq!(ttft, 87);

        let missing = WorkerExecutionResult::Standard(StandardExecutionResult {
            response: SensitiveJsonValue(serde_json::json!({"timings": {}})),
            measured_ttft_ms: None,
        });
        assert_eq!(missing.inference_tps(), None);
        assert_eq!(missing.measured_ttft_ms(), None);
        let zero = WorkerExecutionResult::Standard(StandardExecutionResult {
            response: SensitiveJsonValue(serde_json::json!({
                "timings": {"predicted_per_second": 0.0}
            })),
            measured_ttft_ms: None,
        });
        assert_eq!(zero.inference_tps(), None);
        assert_eq!(zero.measured_ttft_ms(), None);
    }

    #[test]
    fn chat_stream_accumulator_measures_first_generated_delta_and_rebuilds_response() {
        let mut accumulator = OpenAiStreamAccumulator::new(LocalOpenAiStreamKind::Chat, 1);
        let metadata = |choices: serde_json::Value| {
            serde_json::json!({
                "id": "chatcmpl-test",
                "object": "chat.completion.chunk",
                "created": 1_721_000_000,
                "model": "local-model",
                "system_fingerprint": "b10064",
                "choices": choices,
            })
        };
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {"role": "assistant", "content": null},
                    "finish_reason": null
                }])),
                Duration::from_millis(5),
            )
            .expect("role 事件应通过");
        assert_eq!(accumulator.measured_ttft_ms, None);
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {"content": "真实"},
                    "finish_reason": null
                }])),
                Duration::from_millis(37),
            )
            .expect("首 Token 事件应通过");
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {"content": "输出"},
                    "finish_reason": null
                }])),
                Duration::from_millis(51),
            )
            .expect("后续 Token 事件应通过");
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop"
                }])),
                Duration::from_millis(55),
            )
            .expect("结束事件应通过");
        let mut terminal = metadata(serde_json::json!([]));
        terminal["usage"] = serde_json::json!({
            "prompt_tokens": 3,
            "completion_tokens": 2,
            "total_tokens": 5
        });
        terminal["timings"] = serde_json::json!({"predicted_per_second": 25.0});
        accumulator
            .observe(&terminal, Duration::from_millis(56))
            .expect("终态统计应通过");
        let result = accumulator.finish(true).expect("完整 SSE 应可聚合");
        assert_eq!(result.measured_ttft_ms, Some(37));
        assert_eq!(result.response["object"], "chat.completion");
        assert_eq!(
            result.response["choices"][0]["message"]["content"],
            "真实输出"
        );
        assert_eq!(result.response["usage"]["completion_tokens"], 2);
    }

    #[test]
    fn chat_stream_accumulator_rejects_reasoning_without_visible_content() {
        let mut accumulator = OpenAiStreamAccumulator::new(LocalOpenAiStreamKind::Chat, 1);
        let metadata = |choices: serde_json::Value| {
            serde_json::json!({
                "id": "chatcmpl-reasoning-only",
                "object": "chat.completion.chunk",
                "created": 1_721_000_000,
                "model": "local-model",
                "system_fingerprint": "b10064",
                "choices": choices,
            })
        };
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {"role": "assistant", "content": null},
                    "finish_reason": null
                }])),
                Duration::from_millis(1),
            )
            .expect("role 事件应通过");
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {"reasoning_content": "只有推理过程"},
                    "finish_reason": null
                }])),
                Duration::from_millis(2),
            )
            .expect("reasoning 事件应先按协议聚合");
        accumulator
            .observe(
                &metadata(serde_json::json!([{
                    "index": 0,
                    "delta": {},
                    "finish_reason": "length"
                }])),
                Duration::from_millis(3),
            )
            .expect("结束事件应通过");
        let mut terminal = metadata(serde_json::json!([]));
        terminal["usage"] = serde_json::json!({
            "prompt_tokens": 3,
            "completion_tokens": 4,
            "total_tokens": 7
        });
        terminal["timings"] = serde_json::json!({"predicted_per_second": 25.0});
        accumulator
            .observe(&terminal, Duration::from_millis(4))
            .expect("终态统计应通过");

        let error = match accumulator.finish(true) {
            Ok(_) => panic!("只有 reasoning_content 的 chat 结果不得提交给协调器"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("非空可见 content"));
    }

    #[test]
    fn stream_accumulator_rejects_claimed_tokens_without_observed_first_token() {
        let mut accumulator = OpenAiStreamAccumulator::new(LocalOpenAiStreamKind::Chat, 1);
        let terminal = serde_json::json!({
            "id": "chatcmpl-test",
            "object": "chat.completion.chunk",
            "created": 1_721_000_000,
            "model": "local-model",
            "system_fingerprint": "b10064",
            "choices": [],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
            "timings": {"predicted_per_second": 25.0}
        });
        let error = accumulator
            .observe(&terminal, Duration::from_millis(50))
            .expect_err("没有首 Token 事件时必须拒绝正 completion_tokens");
        assert!(error.to_string().contains("没有可观测的首 Token"));
    }

    #[test]
    fn multi_choice_stream_aggregates_completion_usage_without_double_counting_prompt() {
        let mut accumulator = OpenAiStreamAccumulator::new(LocalOpenAiStreamKind::Completion, 2);
        let event = |index: u32, text: &str, finish_reason: Value, usage: Option<Value>| {
            let mut value = serde_json::json!({
                "id": "cmpl-multi",
                "object": "text_completion",
                "created": 1_721_000_000 + i64::from(index),
                "model": "local-model",
                "system_fingerprint": "b10064",
                "choices": [{
                    "index": index,
                    "text": text,
                    "finish_reason": finish_reason,
                    "logprobs": null
                }]
            });
            if let Some(usage) = usage {
                value["usage"] = usage;
                value["timings"] = serde_json::json!({"predicted_per_second": 20.0});
            }
            value
        };
        accumulator
            .observe(
                &event(0, "甲", Value::Null, None),
                Duration::from_millis(20),
            )
            .expect("choice 0 token 应通过");
        accumulator
            .observe(
                &event(1, "乙", Value::Null, None),
                Duration::from_millis(25),
            )
            .expect("choice 1 token 应通过");
        accumulator
            .observe(
                &event(
                    0,
                    "甲",
                    Value::String("stop".to_owned()),
                    Some(serde_json::json!({
                        "prompt_tokens": 3,
                        "completion_tokens": 2,
                        "total_tokens": 5
                    })),
                ),
                Duration::from_millis(30),
            )
            .expect("choice 0 终态应通过");
        accumulator
            .observe(
                &event(
                    1,
                    "乙",
                    Value::String("length".to_owned()),
                    Some(serde_json::json!({
                        "prompt_tokens": 3,
                        "completion_tokens": 4,
                        "total_tokens": 7
                    })),
                ),
                Duration::from_millis(35),
            )
            .expect("choice 1 终态应通过");
        let result = accumulator.finish(true).expect("多 choice SSE 应可聚合");
        assert_eq!(result.response["usage"]["prompt_tokens"], 3);
        assert_eq!(result.response["usage"]["completion_tokens"], 6);
        assert_eq!(result.response["usage"]["total_tokens"], 9);
        assert_eq!(result.response["choices"].as_array().map(Vec::len), Some(2));
        assert_eq!(result.measured_ttft_ms, Some(20));
    }

    #[tokio::test]
    async fn local_streaming_inference_measures_request_to_first_token_monotonically() {
        let delay = Duration::from_millis(80);
        let (port, server) = start_delayed_first_token_server(delay).await;
        let result = execute_local_inference(
            port,
            "/v1/chat/completions",
            SensitiveJsonValue(serde_json::json!({
                "model": "local-model",
                "messages": [{"role": "user", "content": "TTFT"}],
                "stream": false
            })),
            None,
            0,
        )
        .await
        .expect("完整 SSE 应返回聚合结果");
        server.await.expect("TTFT 测试服务应正常结束");
        let measured = result.measured_ttft_ms.expect("应实测首 Token TTFT");
        assert!(
            measured >= 70,
            "首 Token TTFT {measured}ms 不应早于 80ms 服务端延迟"
        );
        assert_eq!(result.response["choices"][0]["message"]["content"], "token");
        assert_eq!(result.response["usage"]["completion_tokens"], 1);
    }

    #[tokio::test]
    async fn consumer_stream_forwards_real_validated_events_and_one_done_in_order() {
        let (port, server) = start_delayed_first_token_server(Duration::from_millis(1)).await;
        let (sender, mut receiver) = tokio::sync::mpsc::channel(STREAM_EVENT_CHANNEL_CAPACITY);
        let result = execute_local_inference(
            port,
            "/v1/chat/completions",
            SensitiveJsonValue(serde_json::json!({
                "model": "virtual-model",
                "messages": [{"role": "user", "content": "stream"}],
                "stream": true
            })),
            Some(StandardStreamForwarding {
                sender,
                authorized_model: "virtual-model".to_owned(),
            }),
            0,
        )
        .await
        .expect("真实 llama SSE 应完成聚合与转发");
        server.await.expect("SSE 测试服务应正常结束");
        assert_eq!(result.response["choices"][0]["message"]["content"], "token");

        let mut observed = Vec::new();
        while let Some(event) = receiver.recv().await {
            observed.push(event);
        }
        assert!(observed.len() >= 2, "至少应包含 data 和 upstream_done");
        for (expected, event) in observed.iter().enumerate() {
            assert_eq!(
                event.sequence,
                i32::try_from(expected).expect("测试事件数很小")
            );
        }
        let done = observed.last().expect("应有完成标记");
        assert_eq!(done.kind, JobStreamEventKind::UpstreamDone);
        assert!(done.event_data.is_none());
        for event in &observed[..observed.len() - 1] {
            assert_eq!(event.kind, JobStreamEventKind::Data);
            let data: Value =
                serde_json::from_str(event.event_data.as_deref().expect("data 事件应有 JSON"))
                    .expect("转发事件应为 JSON");
            assert_eq!(data["model"], "virtual-model");
        }
    }

    #[test]
    fn task_window_vram_observation_keeps_device_level_peak_and_sample_count() {
        let mut observation = VramPeakObservation::default();
        observation.observe(&HardwareMetrics {
            vram_used_bytes: Some(2_048 * 1_048_576),
            ..HardwareMetrics::default()
        });
        observation.observe(&HardwareMetrics {
            vram_used_bytes: Some(3_072 * 1_048_576),
            ..HardwareMetrics::default()
        });
        observation.observe(&HardwareMetrics::default());
        assert_eq!(observation.peak_vram_mib, Some(3_072));
        assert_eq!(observation.sample_count, 2);
    }

    fn share_state() -> ShareState {
        ShareState {
            pid: 42,
            process_start_marker: Some("marker-1".to_owned()),
            worker_executable: Some(PathBuf::from("/opt/mindone/bin/mindone")),
            worker_command: super::expected_worker_command(),
            node_id: Uuid::from_u128(1),
            model_id: Uuid::from_u128(3),
            model_instance_id: Uuid::from_u128(2),
            model_name: "test-model".to_owned(),
            model_path: PathBuf::from("/tmp/test-model.gguf"),
            model_weights_hash: "a".repeat(64),
            alias: "test-node".to_owned(),
            tags: vec!["code".to_owned()],
            local_port: 8_080,
            tier: PerformanceTier::Medium,
            trust_level: "Standard".to_owned(),
            started_at: "2026-07-17T00:00:00Z".to_owned(),
            last_heartbeat_at: None,
            last_coordinator_rtt_ms: None,
            paused_for_temperature: false,
        }
    }

    fn heartbeat_test_metrics(state: &ShareState) -> ShareMetrics {
        ShareMetrics {
            node_id: Some(state.node_id),
            model_instance_id: Some(state.model_instance_id),
            requests: 0,
            successes: 0,
            failures: 0,
            uptime_seconds: 1,
            ttft_ms: None,
            tps: None,
            tier: "Medium".to_owned(),
            trust_level: "Standard".to_owned(),
            quota_earned_micro: 0,
            contribution_points_micro: 0,
            best_tps: None,
            best_ttft_ms: None,
        }
    }

    fn claimed_job() -> ClaimJobResponse {
        ClaimJobResponse {
            job_id: Uuid::from_u128(3),
            model_instance_id: Uuid::from_u128(2),
            model: "test-model".to_owned(),
            model_weights_hash: "a".repeat(64),
            encrypted_payload: "e30=".to_owned(),
            payload_encoding: PayloadEncoding::Base64,
            tags: vec![],
            estimated_input_tokens: 1,
            max_output_tokens: 1,
            attempt: 1,
            lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(120),
            policy_check_required_before_execution: true,
            confidentiality: mindone_protocol::ConfidentialityMode::Standard,
            regulated_route_id: None,
            attestation_report_id: None,
            attestation_provider: None,
            tee_public_key: None,
        }
    }

    #[test]
    fn standard_worker_rejects_unknown_payload_fields_and_under_authorization() {
        let mut job = claimed_job();
        let unknown_payload = serde_json::json!({
            "endpoint": "/v1/completions",
            "request": {"model": "auto", "prompt": "hello"},
            "unknown": true
        });
        job.encrypted_payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&unknown_payload).expect("测试载荷应可编码"));
        assert!(decode_job_payload(&job).is_err());

        let unknown_request_payload = StandardJobPayload {
            endpoint: "/v1/completions".to_owned(),
            request: serde_json::json!({
                "model": "auto",
                "prompt": "hello",
                "unsupported": true
            }),
        };
        job.encrypted_payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&unknown_request_payload).expect("测试载荷应可编码"));
        let decoded = decode_job_payload(&job).expect("外层结构仍应可解码");
        assert!(validate_standard_job_authorization(&job, &decoded).is_err());

        let payload = StandardJobPayload {
            endpoint: "/v1/chat/completions".to_owned(),
            request: serde_json::json!({
                "model": "auto",
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 32,
                "n": 2
            }),
        };
        let limits = payload.validated_limits().expect("规范载荷应可计算授权");
        job.estimated_input_tokens = limits.minimum_input_tokens - 1;
        job.max_output_tokens = limits.maximum_output_tokens;
        assert!(validate_standard_job_authorization(&job, &payload).is_err());

        job.estimated_input_tokens = limits.minimum_input_tokens;
        job.max_output_tokens = limits.maximum_output_tokens - 1;
        assert!(validate_standard_job_authorization(&job, &payload).is_err());

        job.max_output_tokens = limits.maximum_output_tokens;
        assert!(validate_standard_job_authorization(&job, &payload).is_ok());
    }

    #[test]
    fn standard_worker_rejects_claim_for_a_different_model_instance_before_inference() {
        let state = share_state();
        let mut job = claimed_job();
        job.model_instance_id = Uuid::from_u128(999);

        let error = validate_standard_claim_identity(&state, &job)
            .expect_err("不同模型实例的已领取任务绝不能交给本地 llama.cpp");
        assert!(error.to_string().contains("模型实例"));
        assert!(matches!(error, CliError::ModelValidation(_)));
    }

    #[test]
    fn standard_worker_rejects_claim_with_different_weights_before_inference() {
        let state = share_state();
        let mut job = claimed_job();
        job.model_weights_hash = "b".repeat(64);

        let error = validate_standard_claim_identity(&state, &job)
            .expect_err("不同权重的已领取任务绝不能交给本地 llama.cpp");
        assert!(error.to_string().contains("权重哈希"));
        assert!(matches!(error, CliError::ModelValidation(_)));
    }

    #[test]
    fn standard_worker_rejects_model_file_or_registry_change_before_inference() {
        let state = share_state();
        let error = validate_standard_runtime_model_binding(
            &state,
            &state.model_name,
            &state.model_path,
            state.local_port,
            &state.model_path,
            &state.model_weights_hash,
            &"b".repeat(64),
        )
        .expect_err("活动模型文件的实时哈希变化必须阻止本地推理");
        assert!(error.to_string().contains("模型文件"));
        assert!(matches!(error, CliError::ModelValidation(_)));
    }

    #[tokio::test]
    async fn policy_changed_during_binding_blocks_inference_and_success_settlement() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &server);
        let policy_path = context.paths.runtime.join("node-policy.json");
        let task_tag = "blocked-after-rehash".to_owned();

        // 领取后、重新哈希开始时的策略仍允许该任务。
        write_json_atomic(&policy_path, &NodePolicy::default()).expect("应写入初始策略");

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(valid_chat_sse(), "text/event-stream"),
            )
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_slot": 0,
                "n_erased": 1
            })))
            .expect(0)
            .mount(&server)
            .await;
        let job_id = Uuid::from_u128(0x504f4c494359);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_result(job_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(result_response(job_id)))
            .expect(0)
            .mount(&server)
            .await;

        // 模拟节点主在进程/模型登记/文件哈希复验窗口内更新
        // 磁盘策略。生产调用顺序会在 binding 返回后才进入下面的闸门。
        write_json_atomic(
            &policy_path,
            &NodePolicy {
                reject_tags: vec![task_tag.clone()],
                ..NodePolicy::default()
            },
        )
        .expect("应写入领取后拒绝策略");

        let error = execute_local_inference_after_final_policy(
            &context,
            std::slice::from_ref(&task_tag),
            0,
            FinalPolicyInference {
                local_port: server.address().port(),
                endpoint: "/v1/chat/completions",
                request: SensitiveJsonValue(serde_json::json!({
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "must-not-run"}],
                    "stream": false
                })),
                stream_forwarding: None,
                slot_id: 0,
            },
        )
        .await
        .err()
        .expect("重新哈希期间新增的拒绝策略必须在本地推理前生效");

        assert!(matches!(error, CliError::PolicyRejected(_)));
        assert_eq!(error.exit_code(), 50);
        assert_eq!(error.error_type(), "node_policy_rejected");
        assert_eq!(
            error.to_string(),
            "执行前最终策略复核拒绝任务：任务标签 blocked-after-rehash 被节点路由否决策略拒绝；未调用本地模型，拒绝提交和结算"
        );
        server.verify().await;
    }

    fn result_response(job_id: Uuid) -> JobResultResponse {
        JobResultResponse {
            job_id,
            status: mindone_protocol::JobStatus::Succeeded,
            idempotent_replay: false,
        }
    }

    fn failure_response(job_id: Uuid) -> JobFailResponse {
        JobFailResponse {
            job_id,
            accepted: true,
            idempotent_replay: false,
        }
    }

    fn retry_policy(max_attempts: usize) -> SubmissionRetryPolicy {
        SubmissionRetryPolicy {
            max_attempts,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        }
    }

    #[test]
    fn result_upload_log_redacts_untrusted_remote_message() {
        let canary = "REMOTE_PROMPT_RESPONSE_CANARY_MUST_NOT_ENTER_LOG";
        let error = CliError::General(format!(
            "任务结果在 3 次幂等提交后仍未确认：协调服务器请求失败（HTTP 503）：{canary}"
        ));
        assert_eq!(submission_http_status(&error), 503);
        assert_eq!(
            submission_http_status(&CliError::General("transport closed".to_owned())),
            0
        );

        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(capture.clone())
            .finish();
        let job_id = Uuid::from_u128(0x1234);
        tracing::subscriber::with_default(subscriber, || {
            warn_result_upload_failure(job_id, &error);
        });

        let log = capture.text();
        assert!(log.contains(&job_id.to_string()));
        assert!(log.contains("error_type"));
        assert!(log.contains("generic_error"));
        assert!(log.contains("http_status=503"));
        assert!(!log.contains(canary));
        assert!(!log.contains("协调服务器请求失败"));
    }

    #[test]
    fn definitive_result_rejection_requires_a_sanitized_terminal_failure() {
        let rejected = CliError::ModelValidation(
            "协调服务器请求失败（HTTP 400）：聊天任务结果必须包含非空文本".to_owned(),
        );
        assert!(result_submission_requires_terminal_failure(&rejected));
        assert!(!result_submission_requires_terminal_failure(
            &CliError::General("协调服务器请求失败（HTTP 503）：暂时不可用".to_owned())
        ));
        assert!(!result_submission_requires_terminal_failure(
            &CliError::General("协调服务器请求失败（HTTP 409）：租约已过期".to_owned())
        ));
    }

    #[tokio::test]
    async fn definitive_result_rejection_submits_one_sanitized_failure() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &server);
        let mut state = share_state();
        let metrics = heartbeat_test_metrics(&state);
        let job = claimed_job();
        let remote_canary = "REMOTE_RESULT_REJECTION_MUST_NOT_ENTER_FAILURE";
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_result(job.job_id)))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": {
                    "type": "invalid_job_result",
                    "message": remote_canary
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_fail(job.job_id)))
            .and(body_json(serde_json::json!({
                "node_id": state.node_id,
                "idempotency_key": format!("fail:{}:{}", job.job_id, job.attempt),
                "error_class": "model",
                "error_message": "推理结果未通过协调器的结构与绑定校验",
                "retryable": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(failure_response(job.job_id)))
            .expect(1)
            .mount(&server)
            .await;

        let result = WorkerExecutionResult::Standard(StandardExecutionResult {
            response: SensitiveJsonValue(serde_json::json!({
                "id": "chatcmpl-terminal-failure",
                "object": "chat.completion",
                "created": 1_721_000_000,
                "model": job.model,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "可见输出"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
            })),
            measured_ttft_ms: Some(1),
        });
        let mut active_session = session("token");
        let mut liveness =
            ActiveJobLiveness::new(&context, &mut state, &metrics, Duration::from_secs(60));
        liveness.next_heartbeat = tokio::time::Instant::now() + Duration::from_secs(60);
        let accepted = submit_result_or_terminal_failure(
            &context,
            &mut active_session,
            &mut liveness,
            &job,
            &result,
            &JobExecutionTelemetry::default(),
            job.lease_expires_at,
        )
        .await;
        assert!(!accepted);
    }

    fn test_context(home: &TempDir, server: &MockServer) -> AppContext {
        let canonical_home = std::fs::canonicalize(home.path()).expect("应规范化测试临时目录");
        let paths = MindOnePaths::from_home(canonical_home).expect("临时目录应可作为 MindOne home");
        paths.ensure_directories().expect("应创建测试目录");
        let config = mindone_common::Config {
            server_url: server.uri(),
            ..mindone_common::Config::default()
        };
        AppContext {
            config_store: ConfigStore::new(paths.config.clone()),
            coordinator: CoordinatorClient::new(&config.server_url).expect("mock 地址应有效"),
            vault: SystemVault::in_memory_for_home(&paths.home)
                .expect("应创建测试内存凭证命名空间"),
            paths,
            config,
        }
    }

    async fn read_test_http_request(socket: &mut tokio::net::TcpStream) -> (String, Vec<u8>) {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4 * 1024];
        let (header_end, content_length) = loop {
            let count = socket.read(&mut buffer).await.expect("应读取 HTTP 请求");
            assert!(count > 0, "请求头完成前连接不应关闭");
            request.extend_from_slice(&buffer[..count]);
            if let Some(offset) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let header_end = offset + 4;
                let headers =
                    std::str::from_utf8(&request[..header_end]).expect("请求头应为 UTF-8");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                break (header_end, content_length);
            }
        };
        while request.len() < header_end + content_length {
            let count = socket.read(&mut buffer).await.expect("应读取完整请求体");
            assert!(count > 0, "请求体完成前连接不应关闭");
            request.extend_from_slice(&buffer[..count]);
        }
        let headers = std::str::from_utf8(&request[..header_end]).expect("请求头应为 UTF-8");
        let request_line = headers.lines().next().expect("请求应包含首行").to_owned();
        (
            request_line,
            request[header_end..header_end + content_length].to_vec(),
        )
    }

    async fn serve_slot_erase(listener: &TcpListener, n_erased: u64) {
        let (mut socket, _) = listener.accept().await.expect("应接受 slot erase 请求");
        let (request_line, body) = read_test_http_request(&mut socket).await;
        assert_eq!(request_line, "POST /slots/0?action=erase HTTP/1.1");
        assert_eq!(body, b"{}");
        let response_body = serde_json::json!({
            "id_slot": 0,
            "n_erased": n_erased
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("应写入 slot erase 回执");
    }

    fn valid_chat_sse() -> &'static str {
        concat!(
            "data: {\"id\":\"chatcmpl-cleanup\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-cleanup\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-cleanup\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3},\"timings\":{\"predicted_per_second\":20.0}}\n\n",
            "data: [DONE]\n\n"
        )
    }

    async fn slot_erase_error_from(template: ResponseTemplate) -> String {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        erase_managed_llama_slot(server.address().port(), 0)
            .await
            .expect_err("无效 slot erase 回执必须失败")
            .to_string()
    }

    async fn start_slow_sse_server(
        body: Vec<u8>,
        body_delay: Duration,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应绑定慢响应测试端口");
        let port = listener.local_addr().expect("应读取测试地址").port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("应接受推理请求");
            let (_, request) = read_test_http_request(&mut socket).await;
            let request: Value = serde_json::from_slice(&request).expect("推理请求应为 JSON");
            assert_eq!(request["id_slot"], 0);
            assert_eq!(request["cache_prompt"], false);
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("应写入响应头");
            let split = body.len().max(2) / 2;
            let (first, second) = body.split_at(split.min(body.len()));
            socket
                .write_all(format!("{:X}\r\n", first.len()).as_bytes())
                .await
                .expect("应写入首块长度");
            socket.write_all(first).await.expect("应写入首块");
            socket.write_all(b"\r\n").await.expect("应结束首块");
            socket.flush().await.expect("应发送首块");
            tokio::time::sleep(body_delay).await;
            socket
                .write_all(format!("{:X}\r\n", second.len()).as_bytes())
                .await
                .expect("应写入末块长度");
            socket.write_all(second).await.expect("应写入末块");
            socket
                .write_all(b"\r\n0\r\n\r\n")
                .await
                .expect("应结束分块响应");
            drop(socket);
            serve_slot_erase(&listener, 8).await;
        });
        (port, task)
    }

    async fn start_delayed_first_token_server(
        token_delay: Duration,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应绑定 TTFT 测试端口");
        let port = listener.local_addr().expect("应读取测试地址").port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("应接受推理请求");
            let (_, request) = read_test_http_request(&mut socket).await;
            let body: Value = serde_json::from_slice(&request).expect("内部推理请求应为 JSON");
            assert_eq!(body["stream"], true);
            assert_eq!(body["stream_options"]["include_usage"], true);
            assert_eq!(body["id_slot"], 0);
            assert_eq!(body["cache_prompt"], false);
            assert!(body.get("timings_per_token").is_none());

            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("应写入 TTFT 响应头");
            let initial = b"data: {\"id\":\"chatcmpl-ttft\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":null},\"finish_reason\":null}]}\n\n";
            socket
                .write_all(format!("{:X}\r\n", initial.len()).as_bytes())
                .await
                .expect("应写入首块长度");
            socket.write_all(initial).await.expect("应写入 role 事件");
            socket.write_all(b"\r\n").await.expect("应结束 role 块");
            socket.flush().await.expect("应立即发送 role 事件");
            tokio::time::sleep(token_delay).await;
            let remainder = b"data: {\"id\":\"chatcmpl-ttft\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token\"},\"finish_reason\":null}]}\n\ndata: {\"id\":\"chatcmpl-ttft\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: {\"id\":\"chatcmpl-ttft\",\"object\":\"chat.completion.chunk\",\"created\":1721000000,\"model\":\"local-model\",\"system_fingerprint\":\"b10064\",\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3},\"timings\":{\"predicted_per_second\":20.0}}\n\ndata: [DONE]\n\n";
            socket
                .write_all(format!("{:X}\r\n", remainder.len()).as_bytes())
                .await
                .expect("应写入末块长度");
            socket.write_all(remainder).await.expect("应写入末块");
            socket
                .write_all(b"\r\n0\r\n\r\n")
                .await
                .expect("应结束 TTFT 分块响应");
            drop(socket);
            serve_slot_erase(&listener, 3).await;
        });
        (port, task)
    }

    #[test]
    fn tags_are_normalized_deterministically() {
        let tags = normalize_tags(&["Math".to_owned(), "code".to_owned(), "math".to_owned()])
            .expect("标签应有效");
        assert_eq!(tags, vec!["code", "math"]);
    }

    #[test]
    fn default_alias_is_stable_and_secret_free() {
        let session = CredentialBundle {
            access_token: "secret-a".to_owned(),
            refresh_token: "secret-r".to_owned(),
            refresh_challenge: "ab".repeat(32),
            user: "user".to_owned(),
            uid: "019f6fc8-c62d".to_owned(),
            local_sandbox_trust_level: "standard".to_owned(),
            key_fingerprint: "fingerprint".to_owned(),
            login_at: "time".to_owned(),
        };
        let alias = stable_node_alias(&session);
        assert_eq!(alias, "node-019f6fc8c62d");
        assert!(!alias.contains("secret"));
    }

    #[test]
    fn temperature_pause_uses_five_degree_hysteresis_and_fails_closed() {
        assert!(!update_temperature_pause(false, None, None));
        assert!(update_temperature_pause(false, Some(80), None));
        assert!(!update_temperature_pause(false, Some(80), Some(79.9)));
        assert!(!update_temperature_pause(false, Some(80), Some(80.0)));
        assert!(update_temperature_pause(false, Some(80), Some(80.1)));
        assert!(update_temperature_pause(true, Some(80), Some(79.0)));
        assert!(update_temperature_pause(true, Some(80), Some(75.1)));
        assert!(!update_temperature_pause(true, Some(80), Some(75.0)));
    }

    #[test]
    fn performance_baseline_uses_only_positive_engine_observations() {
        let mut metrics = ShareMetrics {
            node_id: Some(Uuid::from_u128(1)),
            model_instance_id: Some(Uuid::from_u128(2)),
            requests: 3,
            successes: 2,
            failures: 1,
            uptime_seconds: 10,
            ttft_ms: Some(500.0),
            tps: Some(8.0),
            tier: "Medium".to_owned(),
            trust_level: "Standard".to_owned(),
            quota_earned_micro: 0,
            contribution_points_micro: 0,
            best_tps: Some(10.0),
            best_ttft_ms: Some(400.0),
        };

        record_performance_observation(&mut metrics, Some(12.0), Some(450.0));
        assert_eq!(metrics.tps, Some(12.0));
        assert_eq!(metrics.best_tps, Some(12.0));
        assert_eq!(metrics.ttft_ms, Some(450.0));
        assert_eq!(metrics.best_ttft_ms, Some(400.0));

        record_performance_observation(&mut metrics, Some(0.0), Some(f64::NAN));
        assert_eq!(metrics.tps, Some(12.0));
        assert_eq!(metrics.best_tps, Some(12.0));
        assert_eq!(metrics.ttft_ms, Some(450.0));
        assert_eq!(metrics.best_ttft_ms, Some(400.0));

        let state = share_state();
        assert!(metrics_belong_to_state(&metrics, &state));
        metrics.model_instance_id = Some(Uuid::from_u128(3));
        assert!(!metrics_belong_to_state(&metrics, &state));
    }

    #[test]
    fn honor_observation_uses_only_valid_server_aggregates() {
        let unavailable = NodeHonorStats::default();
        let zero_failure = honor_observation(25, 0, Some(0), &unavailable).expect("非负统计应有效");
        assert_eq!(zero_failure.observed_zero_failures, Some(true));
        assert!(zero_failure.contribution_rank_percentile.is_none());
        assert!(zero_failure.zero_failure_streak_days.is_none());
        assert!(zero_failure.next_contribution_milestone_micro.is_none());
        assert!(zero_failure.contribution_progress.is_none());

        let published = NodeHonorStats {
            aggregation_version: "node-honor-v2".to_owned(),
            contribution_rank_percentile: Some(0.75),
            contribution_rank_cohort_nodes: 5,
            contribution_rank_privacy_threshold: 5,
            previous_contribution_milestone_micro: Some(1_000_000),
            next_contribution_milestone_micro: Some(10_000_000),
            zero_failure_streak_days: Some(3),
            network_leaderboard: Default::default(),
        };
        let observed =
            honor_observation(25, 0, Some(4_000_000), &published).expect("服务端聚合应可展示");
        assert_eq!(observed.contribution_rank_percentile, Some(0.75));
        assert_eq!(observed.zero_failure_streak_days, Some(3));
        assert_eq!(observed.next_contribution_milestone_micro, Some(10_000_000));
        assert_eq!(
            observed
                .contribution_progress
                .as_ref()
                .map(|value| value.progress_ppm),
            Some(333_333)
        );
        let progress_human = contribution_progress_human(observed.contribution_progress.as_ref());
        let bar = progress_human
            .split_once('[')
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(bar, _)| bar)
            .expect("人类输出应包含进度条");
        assert_eq!(bar.chars().count(), 24);
        assert!(bar.chars().all(|value| matches!(value, '#' | '-')));
        let progress_json =
            serde_json::to_value(&observed.contribution_progress).expect("进度应可序列化");
        assert_eq!(progress_json["progress_ppm"], 333_333);
        assert!(
            progress_json.as_str().is_none(),
            "JSON 不得输出 ANSI 进度文本"
        );

        let no_samples = honor_observation(0, 0, None, &unavailable).expect("零样本应有效");
        assert_eq!(no_samples.observed_zero_failures, None);
        assert!(honor_observation(-1, 0, None, &unavailable).is_err());
        assert!(honor_observation(1, -1, None, &unavailable).is_err());
        let invalid = NodeHonorStats {
            contribution_rank_percentile: Some(f64::NAN),
            ..NodeHonorStats::default()
        };
        assert!(honor_observation(1, 0, None, &invalid).is_err());
        assert!(honor_observation(
            1,
            0,
            Some(4_000_000),
            &NodeHonorStats {
                previous_contribution_milestone_micro: Some(5_000_000),
                next_contribution_milestone_micro: Some(10_000_000),
                ..NodeHonorStats::default()
            }
        )
        .is_err());
    }

    #[test]
    fn heartbeat_contains_dynamic_policy_without_claiming_draining() {
        let metrics = ShareMetrics {
            node_id: Some(Uuid::from_u128(1)),
            model_instance_id: Some(Uuid::from_u128(2)),
            requests: 2,
            successes: 1,
            failures: 1,
            uptime_seconds: 10,
            ttft_ms: Some(25.0),
            tps: Some(3.5),
            tier: "Low".to_owned(),
            trust_level: "Experimental".to_owned(),
            quota_earned_micro: 0,
            contribution_points_micro: 0,
            best_tps: Some(3.5),
            best_ttft_ms: Some(25.0),
        };
        let hardware = HardwareMetrics {
            gpu_temperature_c: Some(70.0),
            vram_total_bytes: Some(8 * 1024 * 1024 * 1024),
            vram_used_bytes: Some(2 * 1024 * 1024 * 1024),
        };
        let policy = NodePolicy {
            reject_tags: vec!["nsfw".to_owned()],
            max_concurrent: 2,
            gpu_temp_limit_c: Some(80),
            vram_reserve_gb: 1.0,
        };
        let value = serde_json::to_value(
            heartbeat_request(&metrics, &hardware, &policy, None, 0, false).expect("心跳应可构造"),
        )
        .expect("心跳应可序列化");
        assert_eq!(value["draining"], false);
        assert_eq!(value["policy"]["reject_tags"], serde_json::json!(["nsfw"]));
        assert_eq!(value["policy"]["max_concurrent"], 2);
        assert_eq!(value["policy"]["gpu_temp_limit_c"], 80);
        assert_eq!(value["policy"]["vram_reserve_mib"], 1024);
        assert!(value.get("coordinator_rtt_ms").is_none());

        let next = heartbeat_request(&metrics, &hardware, &policy, Some(37), 0, false)
            .expect("下一次心跳应携带上一成功 RTT");
        assert_eq!(next.coordinator_rtt_ms, Some(37));
    }

    #[test]
    fn coordinator_rtt_conversion_never_fabricates_zero_or_caps_overflow() {
        assert_eq!(coordinator_rtt_sample(Duration::ZERO), Some(1));
        assert_eq!(
            coordinator_rtt_sample(Duration::from_secs(60)),
            Some(60_000)
        );
        assert_eq!(
            coordinator_rtt_sample(Duration::from_secs(60) + Duration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn legacy_share_state_without_rtt_deserializes_as_no_sample() {
        let mut encoded = serde_json::to_value(share_state()).expect("状态应可序列化");
        encoded["last_coordinator_rtt_ms"] = serde_json::json!(41);
        encoded
            .as_object_mut()
            .expect("状态 JSON 应为对象")
            .remove("last_coordinator_rtt_ms");

        let decoded: ShareState = serde_json::from_value(encoded).expect("旧版状态应继续可读");
        assert_eq!(decoded.last_coordinator_rtt_ms, None);
        assert!(
            serde_json::to_value(decoded)
                .expect("状态应可重新序列化")
                .get("last_coordinator_rtt_ms")
                .is_none(),
            "无样本时不得伪造 0 或 null 字段"
        );
    }

    #[tokio::test]
    async fn successful_heartbeat_sample_is_carried_only_by_the_next_request() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &server);
        let mut state = share_state();
        let node_id = state.node_id;
        let observed = Arc::new(Mutex::new(Vec::<Option<i64>>::new()));
        let captured = Arc::clone(&observed);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::node_heartbeat(state.node_id)))
            .respond_with(move |request: &wiremock::Request| {
                let request: HeartbeatRequest = request.body_json().expect("心跳请求应为协议 JSON");
                captured
                    .lock()
                    .expect("心跳捕获锁不应损坏")
                    .push(request.coordinator_rtt_ms);
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(2))
                    .set_body_json(serde_json::json!({
                        "node_id": node_id,
                        "status": "online",
                        "accepting_jobs": true,
                        "pause_reason": null
                    }))
            })
            .expect(2)
            .mount(&server)
            .await;
        let metrics = heartbeat_test_metrics(&state);
        let hardware = HardwareMetrics::default();
        let policy = NodePolicy::default();
        let mut active_session = session("token");

        let first = heartbeat_request(
            &metrics,
            &hardware,
            &policy,
            state.last_coordinator_rtt_ms,
            0,
            false,
        )
        .expect("首次心跳应可构造");
        post_heartbeat_request(&context, &mut active_session, &mut state, &first)
            .await
            .expect("首次心跳应成功");
        let first_sample = state
            .last_coordinator_rtt_ms
            .expect("完整成功后应保存正 RTT");
        assert!((1..=60_000).contains(&first_sample));

        let second = heartbeat_request(
            &metrics,
            &hardware,
            &policy,
            state.last_coordinator_rtt_ms,
            0,
            false,
        )
        .expect("第二次心跳应可构造");
        post_heartbeat_request(&context, &mut active_session, &mut state, &second)
            .await
            .expect("第二次心跳应成功");

        assert_eq!(
            observed.lock().expect("心跳捕获锁不应损坏").as_slice(),
            &[None, Some(first_sample)]
        );
    }

    #[tokio::test]
    async fn concurrent_refresh_uses_the_already_rotated_vault_session() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &server);
        context
            .vault
            .store_session(&session("fresh-access"))
            .expect("应写入已轮换会话");
        let refresh_lock = Arc::new(tokio::sync::Mutex::new(()));
        let first = refresh_worker_session(&context, &refresh_lock, "expired-access".to_owned());
        let second = refresh_worker_session(&context, &refresh_lock, "expired-access".to_owned());
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            first.expect("第一个任务应复用新会话").access_token,
            "fresh-access"
        );
        assert_eq!(
            second.expect("第二个任务应复用同一新会话").access_token,
            "fresh-access"
        );
        assert!(server
            .received_requests()
            .await
            .expect("应读取请求")
            .is_empty());
    }

    #[tokio::test]
    async fn authentication_refresh_times_only_the_successful_retry() {
        let server = MockServer::start().await;
        let node_id = Uuid::from_u128(1);
        let heartbeat_path = mindone_protocol::node_heartbeat(node_id);
        Mock::given(method("POST"))
            .and(path(heartbeat_path.clone()))
            .and(header("authorization", "Bearer expired"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_delay(Duration::from_millis(500))
                    .set_body_json(serde_json::json!({"message": "expired"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(heartbeat_path.clone()))
            .and(header("authorization", "Bearer refreshed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "node_id": node_id,
                "status": "online",
                "accepting_jobs": true,
                "pause_reason": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let coordinator = CoordinatorClient::new(&server.uri()).expect("mock 地址应有效");
        let mut active_session = session("expired");
        let started_at = Instant::now();

        let (_, sample) = post_heartbeat_with_refresh(
            &coordinator,
            &heartbeat_path,
            &mut active_session,
            &HeartbeatRequest::default(),
            |_| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok(session("refreshed"))
            },
        )
        .await
        .expect("401 后刷新并重试应成功");
        let total = started_at.elapsed();
        let sample = sample.expect("成功重试应产生 RTT 样本");

        assert!(total >= Duration::from_millis(1_000));
        assert!(
            sample < 450,
            "RTT 只能覆盖第二次 POST，不得包含 401 或 refresh 耗时；实际 {sample}ms"
        );
        assert_eq!(active_session.access_token, "refreshed");
    }

    #[tokio::test]
    async fn malformed_success_response_does_not_update_rtt_state() {
        let server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &server);
        let mut state = share_state();
        state.last_heartbeat_at = Some("2026-07-17T00:00:00Z".to_owned());
        state.last_coordinator_rtt_ms = Some(73);
        write_json_atomic(&context.paths.runtime.join(STATE_FILE), &state).expect("应写入原始状态");
        Mock::given(method("POST"))
            .and(path(mindone_protocol::node_heartbeat(state.node_id)))
            .respond_with(ResponseTemplate::new(200).set_body_raw("{", "application/json"))
            .expect(1)
            .mount(&server)
            .await;
        let mut active_session = session("token");
        let request = HeartbeatRequest {
            coordinator_rtt_ms: state.last_coordinator_rtt_ms,
            ..HeartbeatRequest::default()
        };

        post_heartbeat_request(&context, &mut active_session, &mut state, &request)
            .await
            .expect_err("完整 JSON 解码失败不得产生 RTT 样本");

        assert_eq!(state.last_coordinator_rtt_ms, Some(73));
        assert_eq!(
            state.last_heartbeat_at.as_deref(),
            Some("2026-07-17T00:00:00Z")
        );
        let persisted: ShareState =
            read_json(&context.paths.runtime.join(STATE_FILE)).expect("原状态应保留");
        assert_eq!(persisted.last_coordinator_rtt_ms, Some(73));
        assert_eq!(persisted.last_heartbeat_at, state.last_heartbeat_at);
    }

    #[tokio::test]
    async fn result_submission_retries_transient_failure_and_renews_lease() {
        let server = MockServer::start().await;
        let state = share_state();
        let job = claimed_job();
        let request = JobResultRequest {
            node_id: state.node_id,
            idempotency_key: format!("result:{}:{}", job.job_id, job.attempt),
            result_ciphertext: "e30=".to_owned(),
            actual_input_tokens: 1,
            actual_output_tokens: 1,
            execution_telemetry: execution_telemetry(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        let success = result_response(job.job_id);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_result(job.job_id)))
            .respond_with(move |_request: &wiremock::Request| {
                if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(503).set_body_json(serde_json::json!({
                        "message": "暂时不可用"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(&success)
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_renew(job.job_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(RenewJobResponse {
                job_id: job.job_id,
                lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(120),
            }))
            .expect(1)
            .mount(&server)
            .await;

        let coordinator = CoordinatorClient::new(&server.uri()).expect("mock 地址应有效");
        let mut active_session = session("old-token");
        submit_with_retry(
            &coordinator,
            &mut active_session,
            state.node_id,
            &job,
            job.lease_expires_at,
            JobSubmission::Result(&request),
            retry_policy(3),
            |_| std::future::ready(Err(CliError::Authentication("不应刷新".to_owned()))),
            None,
        )
        .await
        .expect("瞬时失败后应使用同一幂等请求成功");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failure_submission_refreshes_once_after_unauthorized() {
        let server = MockServer::start().await;
        let state = share_state();
        let job = claimed_job();
        let request = JobFailRequest {
            node_id: state.node_id,
            idempotency_key: format!("fail:{}:{}", job.job_id, job.attempt),
            error_class: JobErrorClass::Engine,
            error_message: "本地推理失败".to_owned(),
            retryable: true,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        let success = failure_response(job.job_id);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_fail(job.job_id)))
            .respond_with(move |request: &wiremock::Request| {
                let attempt = response_calls.fetch_add(1, Ordering::SeqCst);
                let token = request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok());
                if attempt == 0 || token != Some("Bearer new-token") {
                    ResponseTemplate::new(401).set_body_json(serde_json::json!({
                        "ok": false,
                        "code": 10,
                        "error": {"type": "authentication_failed", "message": "令牌过期"}
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_json(&success)
                }
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_renew(job.job_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(RenewJobResponse {
                job_id: job.job_id,
                lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(120),
            }))
            .expect(1)
            .mount(&server)
            .await;
        let refresh_calls = Arc::new(AtomicUsize::new(0));
        let observed_refresh_calls = Arc::clone(&refresh_calls);
        let coordinator = CoordinatorClient::new(&server.uri()).expect("mock 地址应有效");
        let mut active_session = session("old-token");

        submit_with_retry(
            &coordinator,
            &mut active_session,
            state.node_id,
            &job,
            job.lease_expires_at,
            JobSubmission::Failure(&request),
            retry_policy(3),
            move |_| {
                observed_refresh_calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Ok(session("new-token")))
            },
            None,
        )
        .await
        .expect("401 后刷新会话应成功提交");

        assert_eq!(refresh_calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(active_session.access_token, "new-token");
    }

    #[tokio::test]
    async fn submission_retry_is_bounded() {
        let server = MockServer::start().await;
        let state = share_state();
        let job = claimed_job();
        let request = JobResultRequest {
            node_id: state.node_id,
            idempotency_key: format!("result:{}:{}", job.job_id, job.attempt),
            result_ciphertext: "e30=".to_owned(),
            actual_input_tokens: 1,
            actual_output_tokens: 1,
            execution_telemetry: execution_telemetry(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let response_calls = Arc::clone(&calls);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_result(job.job_id)))
            .respond_with(move |_request: &wiremock::Request| {
                response_calls.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"message": "暂时不可用"}))
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_renew(job.job_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(RenewJobResponse {
                job_id: job.job_id,
                lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(120),
            }))
            .expect(2)
            .mount(&server)
            .await;
        let coordinator = CoordinatorClient::new(&server.uri()).expect("mock 地址应有效");
        let mut active_session = session("token");

        let error = submit_with_retry(
            &coordinator,
            &mut active_session,
            state.node_id,
            &job,
            job.lease_expires_at,
            JobSubmission::Result(&request),
            retry_policy(3),
            |_| std::future::ready(Err(CliError::Authentication("不应刷新".to_owned()))),
            None,
        )
        .await
        .expect_err("持续失败必须在上限处返回");
        assert!(error.to_string().contains("3 次幂等提交"));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn slow_inference_and_upload_keep_heartbeat_lease_and_concurrency_truthful() {
        let coordinator_server = MockServer::start().await;
        let home = TempDir::new().expect("应创建临时目录");
        let context = test_context(&home, &coordinator_server);
        crate::node::save_policy(&context, &NodePolicy::default())
            .expect("活动 worker 测试应先持久化节点策略");
        let node_id = Uuid::from_u128(1);
        let heartbeats = Arc::new(Mutex::new(Vec::<i32>::new()));
        let observed_heartbeats = Arc::clone(&heartbeats);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::node_heartbeat(node_id)))
            .respond_with(move |request: &wiremock::Request| {
                let heartbeat: HeartbeatRequest =
                    request.body_json().expect("心跳请求必须是协议 JSON");
                observed_heartbeats
                    .lock()
                    .expect("心跳记录锁不应损坏")
                    .push(heartbeat.current_concurrent);
                let status = if heartbeat.draining {
                    "draining"
                } else if heartbeat.current_concurrent > 0 {
                    "paused"
                } else {
                    "online"
                };
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "node_id": node_id,
                    "status": status,
                    "accepting_jobs": heartbeat.current_concurrent == 0 && !heartbeat.draining,
                    "pause_reason": if heartbeat.current_concurrent > 0 {
                        Some("max_concurrent")
                    } else {
                        None::<&str>
                    }
                }))
            })
            .mount(&coordinator_server)
            .await;
        let renew_calls = Arc::new(AtomicUsize::new(0));
        let observed_renew_calls = Arc::clone(&renew_calls);
        let job_id = Uuid::from_u128(3);
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_renew(job_id)))
            .respond_with(move |_request: &wiremock::Request| {
                observed_renew_calls.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(RenewJobResponse {
                    job_id,
                    lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(3),
                })
            })
            .mount(&coordinator_server)
            .await;
        Mock::given(method("POST"))
            .and(path(mindone_protocol::job_result(job_id)))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(180))
                    .set_body_json(result_response(job_id)),
            )
            .expect(1)
            .mount(&coordinator_server)
            .await;

        let stream_metadata = |choices: serde_json::Value| {
            serde_json::json!({
                "id": "slow-result",
                "object": "chat.completion.chunk",
                "created": 1_721_000_000,
                "model": "test-model",
                "system_fingerprint": "b10064",
                "choices": choices,
            })
        };
        let mut terminal = stream_metadata(serde_json::json!([]));
        terminal["usage"] = serde_json::json!({
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "total_tokens": 2
        });
        terminal["timings"] = serde_json::json!({"predicted_per_second": 25.0});
        let inference_sse = format!(
            "data: {}\n\ndata: {}\n\ndata: {}\n\ndata: {}\n\n",
            stream_metadata(serde_json::json!([{
                "index": 0,
                "delta": {"role": "assistant", "content": null},
                "finish_reason": null
            }])),
            stream_metadata(serde_json::json!([{
                "index": 0,
                "delta": {"content": "真实慢响应"},
                "finish_reason": null
            }])),
            stream_metadata(serde_json::json!([{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }])),
            terminal,
        );
        let mut inference_sse = inference_sse.into_bytes();
        inference_sse.extend_from_slice(b"data: [DONE]\n\n");
        let (inference_port, inference_task) =
            start_slow_sse_server(inference_sse, Duration::from_millis(1_200)).await;
        let mut state = share_state();
        state.local_port = inference_port;
        let metrics = ShareMetrics {
            node_id: Some(state.node_id),
            model_instance_id: Some(state.model_instance_id),
            requests: 1,
            successes: 0,
            failures: 0,
            uptime_seconds: 1,
            ttft_ms: None,
            tps: None,
            tier: "Medium".to_owned(),
            trust_level: "Standard".to_owned(),
            quota_earned_micro: 0,
            contribution_points_micro: 0,
            best_tps: None,
            best_ttft_ms: None,
        };
        let request_payload = serde_json::json!({
            "endpoint": "/v1/chat/completions",
            "request": {
                "model": "test-model",
                "messages": [{"role": "user", "content": "慢响应测试"}],
                "stream": false
            }
        });
        let standard_payload: StandardJobPayload =
            serde_json::from_value(request_payload.clone()).expect("任务载荷应符合协议");
        let limits = standard_payload
            .validated_limits()
            .expect("任务载荷限制应可计算");
        let job = ClaimJobResponse {
            job_id,
            model_instance_id: state.model_instance_id,
            model: state.model_name.clone(),
            model_weights_hash: state.model_weights_hash.clone(),
            encrypted_payload: base64::engine::general_purpose::STANDARD
                .encode(serde_json::to_vec(&request_payload).expect("应编码任务载荷")),
            payload_encoding: PayloadEncoding::Base64,
            tags: Vec::new(),
            estimated_input_tokens: limits.minimum_input_tokens,
            max_output_tokens: limits.maximum_output_tokens,
            attempt: 1,
            lease_expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(2),
            policy_check_required_before_execution: true,
            confidentiality: mindone_protocol::ConfidentialityMode::Standard,
            regulated_route_id: None,
            attestation_report_id: None,
            attestation_provider: None,
            tee_public_key: None,
        };
        let mut active_session = session("token");
        post_worker_heartbeat(&context, &mut active_session, &mut state, &metrics, 0)
            .await
            .expect("领取前应上报空闲");
        {
            let mut liveness =
                ActiveJobLiveness::new(&context, &mut state, &metrics, Duration::from_millis(40));
            liveness
                .heartbeat_now(&mut active_session)
                .await
                .expect("领取后应立即上报活动并发");
            let mut lease_expires_at = job.lease_expires_at;
            let inference = async move {
                execute_local_inference(
                    inference_port,
                    "/v1/chat/completions",
                    SensitiveJsonValue(request_payload["request"].clone()),
                    None,
                    0,
                )
                .await
                .map(WorkerExecutionResult::Standard)
            };
            let result = wait_for_inference_with_lease(
                &mut active_session,
                &mut liveness,
                &job,
                &mut lease_expires_at,
                None,
                inference,
            )
            .await
            .expect("慢响应应完成并保持租约");
            let execution_telemetry =
                job_execution_telemetry(&result, VramPeakObservation::default());
            let heartbeats_after_inference = heartbeats.lock().expect("心跳记录锁不应损坏").len();
            submit_result(
                &context,
                &mut active_session,
                &mut liveness,
                &job,
                &result,
                &execution_telemetry,
                lease_expires_at,
            )
            .await
            .expect("慢上传期间应持续心跳并提交成功");
            let heartbeats_after_upload = heartbeats.lock().expect("心跳记录锁不应损坏").len();
            assert!(heartbeats_after_upload > heartbeats_after_inference);
        }
        post_worker_heartbeat(&context, &mut active_session, &mut state, &metrics, 0)
            .await
            .expect("任务完成后应立即恢复空闲并发");
        inference_task.await.expect("慢响应服务应正常结束");

        let captured = heartbeats.lock().expect("心跳记录锁不应损坏");
        assert_eq!(captured.first(), Some(&0));
        assert_eq!(captured.last(), Some(&0));
        assert!(captured[1..captured.len() - 1]
            .iter()
            .all(|current| *current == 1));
        assert!(captured.len() >= 6, "慢推理和上传期间应有多个周期心跳");
        assert!(renew_calls.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn concurrent_managed_inference_binds_and_erases_distinct_share_slots() {
        let server = MockServer::start().await;
        for (slot_id, prompt) in [(1_u32, "slow-a"), (2_u32, "slow-b")] {
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .and(body_json(serde_json::json!({
                    "model": "local-model",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": true,
                    "id_slot": slot_id,
                    "cache_prompt": false,
                    "stream_options": {"include_usage": true}
                })))
                .respond_with(
                    ResponseTemplate::new(200).set_body_raw(valid_chat_sse(), "text/event-stream"),
                )
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(format!("/slots/{slot_id}")))
                .and(query_param("action", "erase"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id_slot": slot_id,
                    "n_erased": 3
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        let run = |slot_id, prompt| {
            execute_local_inference(
                server.address().port(),
                "/v1/chat/completions",
                SensitiveJsonValue(serde_json::json!({
                    "model": "local-model",
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": false
                })),
                None,
                slot_id,
            )
        };
        let (first, second) = tokio::join!(run(1, "slow-a"), run(2, "slow-b"));
        first.expect("第一个贡献 slot 应独立完成并清理");
        second.expect("第二个贡献 slot 应独立完成并清理");
    }

    #[tokio::test]
    async fn inference_response_body_is_hard_limited_before_json_or_settlement() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_bytes(vec![b'x'; MAX_INFERENCE_RESPONSE_BYTES + 1]),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_slot": 0,
                "n_erased": 1
            })))
            .expect(1)
            .mount(&server)
            .await;
        let error = execute_local_inference(
            server.address().port(),
            "/v1/chat/completions",
            SensitiveJsonValue(serde_json::json!({"stream": false})),
            None,
            0,
        )
        .await
        .err()
        .expect("超出协议传输预算的响应必须拒绝");
        assert!(error.to_string().contains("安全上限"));
        assert!(error.to_string().contains("拒绝提交和结算"));
    }

    #[tokio::test]
    async fn managed_inference_rejects_zero_erased_slot_receipt() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(valid_chat_sse(), "text/event-stream"),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_slot": 0,
                "n_erased": 0
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = execute_local_inference(
            server.address().port(),
            "/v1/chat/completions",
            SensitiveJsonValue(serde_json::json!({
                "model": "local-model",
                "messages": [{"role": "user", "content": "cleanup"}],
                "stream": false
            })),
            None,
            0,
        )
        .await
        .err()
        .expect("未清除任何 KV token 时必须拒绝结果");
        let rendered = error.to_string();
        assert!(
            rendered.contains("没有确认清除任何 KV token"),
            "实际错误：{rendered}"
        );
        assert!(rendered.contains("拒绝提交和结算"));
    }

    #[tokio::test]
    async fn slot_erase_receipt_is_bounded_bound_and_fail_closed() {
        let http_error = slot_erase_error_from(ResponseTemplate::new(503)).await;
        assert!(http_error.contains("返回 HTTP 503"));

        let wrong_slot = slot_erase_error_from(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"id_slot": 1, "n_erased": 3})),
        )
        .await;
        assert!(wrong_slot.contains("slot 绑定不一致"));

        let invalid_json =
            slot_erase_error_from(ResponseTemplate::new(200).set_body_string("not-json")).await;
        assert!(invalid_json.contains("不是有效 JSON"));

        let oversized = slot_erase_error_from(
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 4 * 1024 + 1]),
        )
        .await;
        assert!(oversized.contains("回执超过安全上限"));
    }

    #[test]
    fn draining_state_is_preserved_and_unpublished_state_is_removed() {
        let directory = TempDir::new().expect("应创建临时目录");
        let state_path = directory.path().join("share.json");
        let stop_path = directory.path().join("share.stop");
        let state = share_state();
        write_json_atomic(&state_path, &state).expect("应写入测试状态");
        std::fs::write(&stop_path, b"drain\n").expect("应写入停止标记");
        let draining = UnpublishModelResponse {
            model_instance_id: state.model_instance_id,
            status: ModelInstanceStatus::Draining,
            active_jobs: 2,
        };

        assert!(
            reconcile_local_unpublish_state(&state_path, &stop_path, &state, &draining)
                .expect("排空状态应可保存")
        );
        let stopped: ShareState = read_json(&state_path).expect("排空状态必须保留");
        assert_eq!(stopped.pid, 0);
        assert_eq!(stopped.process_start_marker, None);
        assert_eq!(stopped.worker_executable, None);
        assert!(stopped.worker_command.is_empty());
        assert!(!stop_path.exists());
        let output =
            unpublish_command_output(&state, true, &draining, true).expect("应生成排空输出");
        assert_eq!(output.data["unpublished"], false);
        assert_eq!(output.data["status"], "draining");
        assert_eq!(output.data["active_jobs"], 2);
        assert_eq!(output.exit_code, 1);
        assert!(output.human.contains("请稍后再次运行"));

        std::fs::write(&stop_path, b"drain\n").expect("应再次写入停止标记");
        let unpublished = UnpublishModelResponse {
            model_instance_id: state.model_instance_id,
            status: ModelInstanceStatus::Unpublished,
            active_jobs: 0,
        };
        assert!(
            !reconcile_local_unpublish_state(&state_path, &stop_path, &state, &unpublished)
                .expect("终态应可清理")
        );
        assert!(!state_path.exists());
        assert!(!stop_path.exists());
        let output = unpublish_command_output(&state, false, &unpublished, false)
            .expect("应生成取消发布终态输出");
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.data["unpublished"], true);
    }

    #[tokio::test]
    async fn loopback_http_client_never_follows_redirects() {
        let redirect_target = MockServer::start().await;
        let target_calls = Arc::new(AtomicUsize::new(0));
        let observed_target_calls = Arc::clone(&target_calls);
        Mock::given(method("GET"))
            .respond_with(move |_request: &wiremock::Request| {
                observed_target_calls.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"n_ctx": 4096}))
            })
            .mount(&redirect_target)
            .await;
        let source = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/props"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/stolen", redirect_target.uri())),
            )
            .mount(&source)
            .await;

        let context_length = local_context_length(source.address().port()).await;
        assert_eq!(context_length, None);
        assert_eq!(target_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn zero_pid_is_never_treated_as_a_live_worker() {
        assert!(!raw_process_exists(0).expect("PID 0 应直接判定为未运行"));
    }

    #[test]
    fn current_process_identity_is_observable() {
        let observed = observe_worker_identity(std::process::id())
            .expect("当前测试进程必须能读取启动标记、可执行文件和命令行");
        assert!(!observed.process_start_marker.is_empty());
        assert!(observed.executable.is_file());
        assert!(!observed.command.is_empty());
    }

    #[test]
    fn worker_identity_requires_matching_marker_executable_and_command() {
        let state = share_state();
        let observed = ObservedWorkerIdentity {
            process_start_marker: "marker-1".to_owned(),
            executable: PathBuf::from("/opt/mindone/bin/mindone"),
            command: vec![
                "/opt/mindone/bin/mindone".to_owned(),
                "__worker".to_owned(),
                "share".to_owned(),
                "--quiet".to_owned(),
            ],
        };
        validate_worker_identity(&state, &observed).expect("完整身份应匹配");

        let mut reused = observed.clone();
        reused.process_start_marker = "marker-2".to_owned();
        assert!(validate_worker_identity(&state, &reused)
            .expect_err("启动标记变化必须拒绝")
            .to_string()
            .contains("PID 复用"));

        let mut wrong_command = observed.clone();
        wrong_command.command = vec!["/usr/bin/sleep".to_owned(), "60".to_owned()];
        assert!(validate_worker_identity(&state, &wrong_command).is_err());

        let mut wrong_executable = observed;
        wrong_executable.executable = PathBuf::from("/usr/bin/sleep");
        assert!(validate_worker_identity(&state, &wrong_executable).is_err());
    }

    #[test]
    fn legacy_share_state_never_authorizes_an_automatic_signal() {
        let mut legacy = share_state();
        legacy.process_start_marker = None;
        legacy.worker_executable = None;
        legacy.worker_command.clear();
        let observed = ObservedWorkerIdentity {
            process_start_marker: "marker-1".to_owned(),
            executable: PathBuf::from("/opt/mindone/bin/mindone"),
            command: vec![
                "/opt/mindone/bin/mindone".to_owned(),
                "__worker".to_owned(),
                "share".to_owned(),
                "--quiet".to_owned(),
            ],
        };
        let error = validate_worker_identity(&legacy, &observed)
            .expect_err("旧状态缺少身份时必须拒绝自动信号");
        assert!(error.to_string().contains("旧版状态"));
        assert!(error.to_string().contains("拒绝自动探测或终止"));
    }

    #[tokio::test]
    async fn stop_identity_failure_preserves_pid_and_marker_state() {
        let directory = TempDir::new().expect("应创建临时目录");
        let state_path = directory.path().join("share.json");
        let mut state = share_state();
        state.pid = std::process::id();
        state.process_start_marker = Some("definitely-not-current-marker".to_owned());
        state.worker_executable = std::env::current_exe().ok();
        state.worker_command = expected_worker_command();
        write_json_atomic(&state_path, &state).expect("应写入 worker 身份状态");

        let error = wait_for_verified_worker_stop(&state, Duration::ZERO)
            .await
            .expect_err("PID 身份错误必须 fail closed");
        assert!(error.to_string().contains("PID 复用"));
        let preserved: ShareState = read_json(&state_path).expect("失败时必须保留状态");
        assert_eq!(preserved.pid, state.pid);
        assert_eq!(preserved.process_start_marker, state.process_start_marker);
        assert_eq!(preserved.worker_executable, state.worker_executable);
        assert_eq!(preserved.worker_command, state.worker_command);
    }

    #[test]
    #[ignore = "由进程句柄回收测试作为长驻子进程显式启动"]
    fn spawned_worker_cleanup_test_helper() {
        std::thread::sleep(Duration::from_secs(60));
    }

    fn spawn_cleanup_test_worker() -> SpawnedWorker {
        let child = Command::new(std::env::current_exe().expect("应定位当前测试程序"))
            .args([
                "--exact",
                "share::tests::spawned_worker_cleanup_test_helper",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动长驻测试子进程");
        SpawnedWorker::new(child)
    }

    #[test]
    fn newly_spawned_worker_is_stopped_and_reaped_through_its_owned_handle() {
        let mut worker = spawn_cleanup_test_worker();
        let pid = worker.id().expect("进程句柄应包含 PID");
        worker
            .stop_and_reap()
            .expect("应精确停止并回收刚创建的子进程");
        assert!(!raw_process_exists(pid).expect("应确认测试子进程已经消失"));
    }

    #[test]
    fn early_error_drop_guard_does_not_leave_a_spawned_worker_orphan() {
        let pid = {
            let worker = spawn_cleanup_test_worker();
            worker.id().expect("进程句柄应包含 PID")
        };
        assert!(!raw_process_exists(pid).expect("错误分支析构后不应残留子进程"));
    }

    #[test]
    fn release_refuses_to_report_success_after_the_spawned_worker_has_exited() {
        let mut child = Command::new(std::env::current_exe().expect("应定位当前测试程序"))
            .args(["--exact", "share::tests::nonexistent_test_name"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动立即退出的测试子进程");
        let status = child.wait().expect("应回收立即退出的测试子进程");
        assert!(status.success(), "测试子进程应正常退出");
        let mut worker = SpawnedWorker::new(child);
        let error = worker
            .release_if_running()
            .expect_err("已退出的 worker 不得被报告为成功运行");
        assert!(error.to_string().contains("启动确认完成前已退出"));
    }

    #[test]
    fn incomplete_parent_identity_never_erases_a_worker_identity_written_to_disk() {
        let mut latest = share_state();
        let mut incomplete = latest.clone();
        incomplete.process_start_marker = None;
        incomplete.worker_executable = None;
        incomplete.worker_command.clear();

        merge_known_worker_identity(&mut latest, &incomplete);
        assert_eq!(latest.process_start_marker.as_deref(), Some("marker-1"));
        assert_eq!(
            latest.worker_executable.as_deref(),
            Some(std::path::Path::new("/opt/mindone/bin/mindone"))
        );
        assert_eq!(latest.worker_command, expected_worker_command());
        assert!(preserved_worker_identity_message(&latest).contains("已保留 PID、启动标记"));

        latest.process_start_marker = None;
        assert!(preserved_worker_identity_message(&latest).contains("完整身份未建立"));
    }

    fn tiny_log_config() -> LogRotationConfig {
        LogRotationConfig {
            max_bytes: 32,
            generations: 2,
            poll_interval: Duration::from_millis(10),
        }
    }

    #[test]
    fn worker_log_rotation_keeps_stdout_inode_and_bounds_every_generation() {
        let directory = TempDir::new().expect("应创建日志测试目录");
        let path = directory.path().join("share-worker.log");
        let mut controlled = open_worker_log_file_io(&path).expect("应安全创建受控日志");
        let mut stdout = controlled.try_clone().expect("应复制 stdout 日志句柄");
        let original_identity = file_identity(&controlled).expect("应读取原始日志身份");

        stdout.write_all(&[b'a'; 80]).expect("应写入第一批日志");
        stdout.flush().expect("应刷新第一批日志");
        assert!(
            rotate_worker_log_if_needed(&path, &mut controlled, tiny_log_config())
                .expect("应执行首次轮转")
        );
        assert_eq!(
            original_identity,
            file_identity(&controlled).expect("轮转后应读取日志身份")
        );
        assert_eq!(std::fs::metadata(&path).expect("当前日志应存在").len(), 0);
        assert_eq!(
            std::fs::metadata(generation_path(&path, 1))
                .expect("第一代日志应存在")
                .len(),
            32
        );

        stdout
            .write_all(b"same-inode-after-truncate")
            .expect("stdout 应继续写入原 inode");
        stdout.flush().expect("应刷新轮转后日志");
        assert_eq!(
            std::fs::read(&path).expect("应读取当前日志"),
            b"same-inode-after-truncate"
        );

        stdout.write_all(&[b'b'; 80]).expect("应写入第二批日志");
        stdout.flush().expect("应刷新第二批日志");
        assert!(
            rotate_worker_log_if_needed(&path, &mut controlled, tiny_log_config())
                .expect("应执行第二次轮转")
        );
        assert!(generation_path(&path, 1).is_file());
        assert!(generation_path(&path, 2).is_file());
        assert!(!generation_path(&path, 3).exists());
        for generation in 1..=2 {
            assert!(
                std::fs::metadata(generation_path(&path, generation))
                    .expect("日志代文件应存在")
                    .len()
                    <= 32
            );
        }
    }

    #[tokio::test]
    async fn background_log_monitor_rotates_continuously_and_reports_path_replacement() {
        let directory = TempDir::new().expect("应创建日志监控目录");
        let path = directory.path().join("share-worker.log");
        let mut stdout = open_worker_log_file_io(&path).expect("应创建日志文件");
        let original_identity = file_identity(&stdout).expect("应读取日志身份");
        let monitor = WorkerLogMonitor::start(path.clone(), tiny_log_config(), false)
            .expect("应启动日志监控");

        stdout.write_all(&[b'x'; 96]).expect("应持续写入日志");
        stdout.flush().expect("应刷新持续日志");
        let rotation_deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !generation_path(&path, 1).is_file() {
            assert!(
                std::time::Instant::now() < rotation_deadline,
                "后台 monitor 应及时轮转"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        monitor.ensure_healthy().expect("正常轮转后 monitor 应健康");
        assert_eq!(
            original_identity,
            file_identity(&stdout).expect("stdout 仍应指向原 inode")
        );

        let displaced = directory.path().join("displaced.log");
        std::fs::rename(&path, &displaced).expect("应替换当前日志路径");
        std::fs::write(&path, b"replacement").expect("应创建替换文件");
        let error = tokio::time::timeout(Duration::from_secs(2), monitor.wait_for_failure())
            .await
            .expect("路径被替换后 monitor 必须及时通知 worker");
        assert!(error.to_string().contains("日志路径已被替换"));
        assert!(monitor.ensure_healthy().is_err());
    }

    #[test]
    fn worker_log_open_rejects_non_regular_target() {
        let directory = TempDir::new().expect("应创建日志测试目录");
        let path = directory.path().join("share-worker.log");
        std::fs::create_dir(&path).expect("应创建同名目录");
        let error = open_worker_log_file_io(&path).expect_err("目录不得冒充日志文件");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn worker_log_and_generation_never_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("应创建日志测试目录");
        let path = directory.path().join("share-worker.log");
        let protected = directory.path().join("protected.txt");
        std::fs::write(&protected, b"protected").expect("应写入受保护文件");
        symlink(&protected, &path).expect("应创建当前日志符号链接");
        assert!(open_worker_log_file_io(&path).is_err());
        assert_eq!(
            std::fs::read(&protected).expect("应读取受保护文件"),
            b"protected"
        );

        std::fs::remove_file(&path).expect("应移除测试符号链接");
        let mut log = open_worker_log_file_io(&path).expect("应创建普通日志");
        log.write_all(&[b'z'; 80]).expect("应写入待轮转日志");
        log.flush().expect("应刷新待轮转日志");
        symlink(&protected, generation_path(&path, 1)).expect("应创建日志代符号链接");
        assert!(rotate_worker_log_if_needed(&path, &mut log, tiny_log_config()).is_err());
        assert_eq!(
            std::fs::read(&protected).expect("日志轮转不得覆盖符号链接目标"),
            b"protected"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("拒绝轮转时当前日志应保留")
                .len(),
            80
        );
    }

    #[cfg(windows)]
    #[test]
    fn worker_log_and_generation_never_follow_reparse_points() {
        use std::os::windows::fs::symlink_file;

        let directory = TempDir::new().expect("应创建日志测试目录");
        let path = directory.path().join("share-worker.log");
        let protected = directory.path().join("protected.txt");
        std::fs::write(&protected, b"protected").expect("应写入受保护文件");
        match symlink_file(&protected, &path) {
            Ok(()) => {
                assert!(open_worker_log_file_io(&path).is_err());
                assert_eq!(
                    std::fs::read(&protected).expect("应读取受保护文件"),
                    b"protected"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Windows runner 未授予创建 symlink 的能力时，非普通目标测试仍覆盖拒绝分支。
            }
            Err(error) => panic!("创建测试 reparse point 失败：{error}"),
        }
    }
}
