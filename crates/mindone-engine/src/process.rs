use crate::install::{EngineName, InstalledEngine};
use crate::logging::{
    clear_managed_log_history, consume_log_monitor_ready, open_log_append_no_follow,
    read_process_start_marker, LogMonitorError,
};
use crate::validation::{validate_model, ModelFormat};
use mindone_sandbox::{
    build_launch_plan_with_supervisor, IsolationMechanism, SandboxAccess, SandboxError, TrustLevel,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};
use tempfile::NamedTempFile;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::time::{sleep, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

/// v1 对 llama.cpp 受管日志、slot 与请求后清理语义做过源码和真实 E2E 审计的
/// 唯一发行版。
///
/// 新发行版即使继续暴露同名参数，也必须先完成独立审计再替换该值；仅凭参数名
/// 猜测语义会让上游行为漂移，并可能泄露 Prompt/Response 或残留请求 KV。
pub const AUDITED_MANAGED_LLAMA_CPP_RELEASE: &str = "b10064";
/// slot 0 专供本机公开回环代理使用。贡献 worker 只使用后续独立 slot，避免本机
/// 调用与远程贡献任务互相擦除 KV sequence。
pub const MANAGED_LLAMA_SLOT_ID: u32 = 0;
/// 官方贡献 worker 可同时占用的独立 llama.cpp slot 数。服务端发布容量、本地策略、
/// worker 调度和受管启动参数必须共同复用这个上限，不能靠节点自报扩张。
pub const MANAGED_SHARE_MAX_CONCURRENT: u16 = 3;
/// 一个本机公开 slot 加三个贡献 slot。
pub const MANAGED_LLAMA_PARALLEL_SLOTS: u16 = MANAGED_SHARE_MAX_CONCURRENT + 1;
/// 将贡献任务的零基序号映射到与本机 slot 0 隔离的真实 llama.cpp slot。
#[must_use]
pub const fn managed_share_slot_id(index: u16) -> Option<u32> {
    if index < MANAGED_SHARE_MAX_CONCURRENT {
        Some(index as u32 + 1)
    } else {
        None
    }
}
const LLAMA_LOG_DISABLE_ARG: &str = "--log-disable";
// 官方 b10064 macOS arm64 包在当前机器的首次动态库装载与完整 help 生成实测约
// 7.5 秒；15 秒仍是有界 fail-closed 探测，同时避免把受审计发行版本身误判为不兼容。
const LLAMA_CAPABILITY_TIMEOUT: Duration = Duration::from_secs(15);
const LLAMA_CAPABILITY_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const LLAMA_MANAGED_ENV_OVERRIDES: &[&str] = &[
    "LLAMA_ARG_LOG_DISABLE",
    "LLAMA_ARG_LOG_FILE",
    "LLAMA_ARG_LOG_COLORS",
    "LLAMA_ARG_LOG_VERBOSITY",
    "LLAMA_ARG_LOG_PREFIX",
    "LLAMA_ARG_LOG_TIMESTAMPS",
    "LLAMA_ARG_VERBOSE",
    "LLAMA_LOG_DISABLE",
    "LLAMA_LOG_FILE",
    "LLAMA_LOG_COLORS",
    "LLAMA_LOG_VERBOSITY",
    "LLAMA_LOG_PREFIX",
    "LLAMA_LOG_TIMESTAMPS",
    // 这些值属于 MindOne 的请求后清理、回环绑定与模型绑定合同；用户环境不得
    // 在命令行固定参数之外重新打开缓存、增加 slot 或替换 host/model/port。
    "LLAMA_ARG_N_PARALLEL",
    "LLAMA_ARG_ENDPOINT_SLOTS",
    "LLAMA_ARG_CACHE_PROMPT",
    "LLAMA_ARG_KV_UNIFIED",
    "LLAMA_ARG_NO_KV_UNIFIED",
    "LLAMA_ARG_SLOT_SAVE_PATH",
    "LLAMA_ARG_HOST",
    "LLAMA_ARG_PORT",
    "LLAMA_ARG_MODEL",
    // 设备选择与 CPU-only 策略由类型化的 ServeRequest 生成，不得由
    // 父进程环境重新开启 GPU/KV/算子卸载。
    "LLAMA_ARG_DEVICE",
    "LLAMA_ARG_N_GPU_LAYERS",
    "LLAMA_ARG_KV_OFFLOAD",
    "LLAMA_ARG_NO_KV_OFFLOAD",
    "LLAMA_ARG_NO_OP_OFFLOAD",
];

/// 判断一个实际安装登记是否属于 v1 唯一受审计的受管运行时发行版。
///
/// CLI 默认引擎选择与 `serve` 启动必须复用这里的同一判断，避免“可以安装”被
/// 误当成“已经审计过日志、slot 与请求后清理语义”。新增上游发行版必须先完成
/// 独立审计，再显式更新这个唯一版本。
#[must_use]
pub fn is_audited_managed_serve_release(name: EngineName, version: &str) -> bool {
    name == EngineName::LlamaCpp && version == AUDITED_MANAGED_LLAMA_CPP_RELEASE
}

#[derive(Debug, Clone)]
pub struct ServeRequest {
    pub engine: InstalledEngine,
    pub model_path: PathBuf,
    /// 单文件模型只包含 `model_path`；分片 GGUF 必须按 00001..000NN
    /// 提供完整路径，使结构验证与沙盒授权覆盖 llama.cpp 将自动打开的每一片。
    pub model_artifact_paths: Vec<PathBuf>,
    pub port: u16,
    pub runtime_directory: PathBuf,
    pub log_path: PathBuf,
    pub health_timeout: Duration,
    /// 由受管启动路径生成的 CPU-only 策略；不将设备选择降级为任意字符串参数。
    pub cpu_only: bool,
    pub additional_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServeRuntimeState {
    pub pid: u32,
    pub process_start_marker: String,
    #[serde(default)]
    pub log_monitor_pid: u32,
    #[serde(default)]
    pub log_monitor_start_marker: String,
    /// 对本机应用开放的受管代理进程。旧状态没有代理时保持 0，并被视为不健康。
    #[serde(default)]
    pub proxy_pid: u32,
    #[serde(default)]
    pub proxy_start_marker: String,
    pub engine: EngineName,
    pub engine_executable: PathBuf,
    pub model_path: PathBuf,
    pub port: u16,
    /// llama.cpp 实际监听的随机回环端口；只有受管代理和 share worker 使用。
    #[serde(default)]
    pub backend_port: u16,
    #[serde(default)]
    pub cleanup_status_path: PathBuf,
    pub started_at_unix: i64,
    pub log_path: PathBuf,
    pub sandbox_mechanisms: Vec<IsolationMechanism>,
    pub trust_level: TrustLevel,
    pub sandbox_note: String,
    #[serde(default)]
    pub sandbox_policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServeStatus {
    pub running: bool,
    pub process_verified: bool,
    pub log_monitor_verified: bool,
    pub proxy_verified: bool,
    pub healthy: bool,
    pub state: ServeRuntimeState,
    pub resident_memory_bytes: Option<u64>,
    pub tokens_per_second: Option<f64>,
    pub cleanup: Option<ServeCleanupStatus>,
}

/// 受管代理持久化的无正文逐请求清理状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeCleanupStatus {
    pub version: u32,
    pub proxy_pid: u32,
    pub proxy_start_marker: String,
    pub requests_completed: u64,
    pub cleanup_attempts: u64,
    pub cleanup_successes: u64,
    pub cleanup_failures: u64,
    pub tokens_erased: u64,
    pub owned_host_buffer_bytes_zeroed: u64,
    pub cleanup_required: bool,
    pub last_error_code: Option<String>,
    pub updated_at_unix: i64,
}

impl ServeCleanupStatus {
    #[must_use]
    pub fn new(proxy_pid: u32, proxy_start_marker: String) -> Self {
        Self {
            version: 1,
            proxy_pid,
            proxy_start_marker,
            requests_completed: 0,
            cleanup_attempts: 0,
            cleanup_successes: 0,
            cleanup_failures: 0,
            tokens_erased: 0,
            owned_host_buffer_bytes_zeroed: 0,
            cleanup_required: false,
            last_error_code: None,
            updated_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupReport {
    pub process_memory_released: bool,
    pub owned_host_buffer_bytes_zeroed: u64,
    pub kv_cache_cleanup_confirmed: bool,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct ServeManager {
    state_path: PathBuf,
    client: Client,
}

/// 启动阶段必须一直持有精确的 OS child handle。`std::process::Child` 自身在
/// Drop 时不会终止进程，因此这里用 fail-closed guard 保证 marker、状态落盘或
/// 健康检查任一步骤失败时，都不会留下没有可管理状态的孤儿进程。
struct SpawnedChildGuard {
    child: Option<Child>,
}

impl SpawnedChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> Result<u32, ServeError> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| ServeError::Spawn("启动进程 handle 已释放".to_owned()))
    }

    fn terminate_and_reap(&mut self) -> Result<(), ServeError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| ServeError::Spawn("启动进程 handle 已释放".to_owned()))?;
        if child.try_wait()?.is_none() {
            if let Err(kill_error) = child.kill() {
                // try_wait 与 kill 之间进程可能自然退出；只有再次确认仍在运行时，
                // kill 错误才代表补偿失败，不能把正常退出误报成孤儿。
                if child.try_wait()?.is_none() {
                    return Err(ServeError::Io(kill_error));
                }
            }
        }
        child.wait()?;
        self.child.take();
        Ok(())
    }

    fn ensure_running(&mut self) -> Result<(), ServeError> {
        let child = self
            .child
            .as_mut()
            .ok_or_else(|| ServeError::Spawn("启动进程 handle 已释放".to_owned()))?;
        if child.try_wait()?.is_some() {
            return Err(ServeError::Spawn(
                "受管子进程在启动交权前已经退出".to_owned(),
            ));
        }
        Ok(())
    }

    fn release_after_preflight(&mut self) {
        // 健康、身份和状态都已验证后，服务必须继续长驻；关闭本进程中的
        // Child handle 不会向已启动的服务发送信号。
        self.child.take();
    }
}

/// 三个长驻子进程必须作为一个整体交权。第一轮只检查，任一失败时所有 guard
/// 仍持有精确 Child handle 并会在 Drop 时回收；只有全部存活才进入不失败的 take。
fn handoff_spawned_children(children: &mut [&mut SpawnedChildGuard]) -> Result<(), ServeError> {
    for child in children.iter_mut() {
        child.ensure_running()?;
    }
    for child in children.iter_mut() {
        child.release_after_preflight();
    }
    Ok(())
}

impl Drop for SpawnedChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // 这是精确的 Child handle，不根据未验证或可能复用的裸 PID 操作。
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

#[derive(Debug, Error)]
pub enum ServeError {
    #[error("本地推理服务已经运行，PID={0}")]
    AlreadyRunning(u32),
    #[error("本地推理服务未运行")]
    NotRunning,
    #[error("端口 {0} 已被占用")]
    PortInUse(u16),
    #[error("端口必须大于 0")]
    InvalidPort,
    #[error("模型与引擎不兼容：{0}")]
    Incompatible(String),
    #[error("沙盒初始化失败：{0}")]
    Sandbox(#[from] SandboxError),
    #[error("推理服务启动失败：{0}")]
    Spawn(String),
    #[error("推理服务未在限定时间内通过健康检查")]
    HealthTimeout,
    #[error("运行状态文件损坏：{0}")]
    CorruptState(String),
    #[error("PID 身份不匹配，拒绝操作可能已复用的进程")]
    ProcessIdentityMismatch,
    #[error("停止本地推理服务失败，PID={0} 在 TERM/KILL 后仍存活；已保留运行状态")]
    StopFailed(u32),
    #[error("日志监控进程 PID={0} 未在推理服务退出后同步结束；已保留运行状态")]
    LogMonitorStopFailed(u32),
    #[error("受管回环代理 PID={0} 未能安全停止；已保留运行状态")]
    ProxyStopFailed(u32),
    #[error("模型安全校验失败：{0}")]
    Validation(#[from] crate::validation::ValidationError),
    #[error("本地推理服务 HTTP 检查失败：{0}")]
    Http(#[from] reqwest::Error),
    #[error("本地推理服务日志监控失败：{0}")]
    LogMonitor(#[from] LogMonitorError),
    #[error("本地推理服务文件操作失败：{0}")]
    Io(#[from] std::io::Error),
}

impl ServeManager {
    pub fn new(state_path: impl Into<PathBuf>) -> Result<Self, ServeError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            // 回环健康与指标请求不得被 HTTP_PROXY/ALL_PROXY 接管。
            .no_proxy()
            // 健康检查只能由本机受管进程回答；跟随 30x 会让外部网站
            // 冒充健康的 llama-server，也会把本地运行信息带出 loopback。
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            state_path: state_path.into(),
            client,
        })
    }

    pub async fn start(&self, request: ServeRequest) -> Result<ServeStatus, ServeError> {
        if request.port == 0 {
            return Err(ServeError::InvalidPort);
        }
        ensure_managed_engine(request.engine.name)?;
        match fs::symlink_metadata(&self.state_path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() {
                    return Err(ServeError::CorruptState(
                        "状态路径不是普通文件，拒绝自动覆盖".to_owned(),
                    ));
                }
                let status = self.status().await?;
                if status.running && status.process_verified {
                    return Err(ServeError::AlreadyRunning(status.state.pid));
                }
                if status.running {
                    return Err(ServeError::ProcessIdentityMismatch);
                }
                if status.log_monitor_verified {
                    return Err(ServeError::LogMonitorStopFailed(
                        status.state.log_monitor_pid,
                    ));
                }
                if status.proxy_verified {
                    return Err(ServeError::ProxyStopFailed(status.state.proxy_pid));
                }
                if status.state.proxy_pid != 0 && process_alive(status.state.proxy_pid)? {
                    return Err(ServeError::ProcessIdentityMismatch);
                }
                // 只有成功解析状态且操作系统明确证明 PID 不存在时，
                // 才能清理 stale state。损坏状态、无权探测或身份错误均向上返回。
                fs::remove_file(&self.state_path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ServeError::Io(error)),
        }
        ensure_port_available(request.port)?;
        let backend_port = allocate_backend_port(request.port)?;
        if request.model_artifact_paths.first() != Some(&request.model_path) {
            return Err(ServeError::Incompatible(
                "模型文件集合必须以受管主模型路径开头".to_owned(),
            ));
        }
        let model_reports = request
            .model_artifact_paths
            .iter()
            .map(|path| validate_model(path, None))
            .collect::<Result<Vec<_>, _>>()?;
        if model_reports.len() > 1 {
            crate::validation::validate_gguf_split_reports(&model_reports)?;
        }
        let model_report = model_reports
            .first()
            .ok_or_else(|| ServeError::Incompatible("模型文件集合不能为空".to_owned()))?;
        if model_report.format != ModelFormat::Gguf {
            return Err(ServeError::Incompatible(
                "llama.cpp 仅执行已验证的 GGUF".to_owned(),
            ));
        }
        ensure_safe_llama_logging_contract(&request.engine).await?;
        // slot 动作端点（请求后 KV erase）在 b10064 需要 `--slot-save-path`。这个托管
        // 子目录只用于启用该端点，位于沙盒已授予 read_write 的 runtime 目录内；worker
        // 只调用 erase、从不 save，因此该目录不会保存 KV/Prompt 数据。
        let slot_save_directory = request.runtime_directory.join("llama-slot-cache");
        let engine_args = build_managed_llama_args(
            &model_report.path,
            backend_port,
            &slot_save_directory,
            request.cpu_only,
            &request.additional_args,
        )?;
        fs::create_dir_all(&request.runtime_directory)?;
        fs::create_dir_all(&slot_save_directory)?;
        if let Some(parent) = request.log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        // 旧版本可能已把正文写入活动或轮转日志。受审计参数生效前先安全截断
        // 整个受管历史，避免升级后仍保留先前泄漏的数据。
        clear_managed_log_history(&request.log_path)?;
        let access = SandboxAccess {
            read_execute: vec![request.engine.directory.clone()],
            read_only: model_reports
                .iter()
                .map(|report| report.path.clone())
                .collect(),
            read_write: vec![request.runtime_directory.clone()],
            allow_loopback_network: true,
        };
        let supervisor = std::env::current_exe()
            .map_err(|error| ServeError::Spawn(format!("无法解析 MindOne 监督进程：{error}")))?;
        let launch = build_launch_plan_with_supervisor(
            &request.engine.executable,
            &engine_args,
            &access,
            Some(&supervisor),
        )?;
        let launch_policy = serde_json::to_vec(&launch)
            .map_err(|error| ServeError::Spawn(format!("无法编码实际沙盒策略：{error}")))?;
        let sandbox_policy_hash = hex::encode(Sha256::digest(launch_policy));
        let stdout = open_log_append_no_follow(&request.log_path)?;
        let stderr = stdout.try_clone()?;
        let mut command = Command::new(&launch.program);
        command
            .args(&launch.args)
            .current_dir(&request.engine.directory)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .env_remove("LD_PRELOAD")
            .env_remove("DYLD_INSERT_LIBRARIES")
            .env_remove("PYTHONPATH");
        for key in LLAMA_MANAGED_ENV_OVERRIDES {
            command.env_remove(key);
        }
        let child = command
            .spawn()
            .map_err(|error| ServeError::Spawn(error.to_string()))?;
        let mut child = SpawnedChildGuard::new(child);
        let pid = child.id()?;
        let marker = wait_for_process_marker(pid, Duration::from_secs(2)).await?;
        let ready_path = request.runtime_directory.join(format!(
            ".serve-log-monitor-{}.ready",
            Uuid::new_v4().simple()
        ));
        let ready_token = Uuid::new_v4().simple().to_string();
        let engine_identity = request
            .engine
            .executable
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ServeError::Spawn("推理引擎文件名不是有效 UTF-8".to_owned()))?
            .to_owned();
        let expected_command_parts = [
            engine_identity,
            model_report.path.to_string_lossy().into_owned(),
            backend_port.to_string(),
        ];
        let mut monitor_command = Command::new(&supervisor);
        monitor_command
            .arg("__worker")
            .arg("log-monitor")
            .arg("--path")
            .arg(&request.log_path)
            .arg("--pid")
            .arg(pid.to_string())
            .arg("--marker")
            .arg(&marker)
            .arg("--ready-path")
            .arg(&ready_path)
            .arg("--ready-token")
            .arg(&ready_token);
        for expected in &expected_command_parts {
            monitor_command.arg("--expected-command").arg(expected);
        }
        monitor_command
            .arg("--quiet")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("LD_PRELOAD")
            .env_remove("DYLD_INSERT_LIBRARIES")
            .env_remove("PYTHONPATH");
        let monitor = monitor_command
            .spawn()
            .map_err(|error| ServeError::Spawn(format!("无法启动日志监控进程：{error}")))?;
        let mut monitor = SpawnedChildGuard::new(monitor);
        let monitor_pid = monitor.id()?;
        let monitor_marker =
            match wait_for_process_marker(monitor_pid, Duration::from_secs(2)).await {
                Ok(marker) => marker,
                Err(error) => {
                    let _ = monitor.terminate_and_reap();
                    let _ = consume_log_monitor_ready(&ready_path, &ready_token);
                    return Err(error);
                }
            };
        if let Err(error) = wait_for_log_monitor_ready(
            &mut monitor,
            &ready_path,
            &ready_token,
            Duration::from_secs(5),
        )
        .await
        {
            let _ = monitor.terminate_and_reap();
            let _ = consume_log_monitor_ready(&ready_path, &ready_token);
            return Err(error);
        }
        let cleanup_status_path = request
            .runtime_directory
            .join(format!(".serve-cleanup-{}.json", Uuid::new_v4().simple()));
        let mut proxy_command = Command::new(&supervisor);
        proxy_command
            .arg("__worker")
            .arg("serve-proxy")
            .arg("--listen-port")
            .arg(request.port.to_string())
            .arg("--backend-port")
            .arg(backend_port.to_string())
            .arg("--target-pid")
            .arg(pid.to_string())
            .arg("--target-marker")
            .arg(&marker);
        for expected in &expected_command_parts {
            proxy_command.arg("--expected-command").arg(expected);
        }
        let proxy = proxy_command
            .arg("--status-path")
            .arg(&cleanup_status_path)
            .arg("--quiet")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_remove("LD_PRELOAD")
            .env_remove("DYLD_INSERT_LIBRARIES")
            .env_remove("PYTHONPATH")
            .spawn()
            .map_err(|error| ServeError::Spawn(format!("无法启动受管回环代理：{error}")))?;
        let mut proxy = SpawnedChildGuard::new(proxy);
        let proxy_pid = proxy.id()?;
        let proxy_marker = wait_for_process_marker(proxy_pid, Duration::from_secs(2)).await?;
        let state = ServeRuntimeState {
            pid,
            process_start_marker: marker,
            log_monitor_pid: monitor_pid,
            log_monitor_start_marker: monitor_marker,
            proxy_pid,
            proxy_start_marker: proxy_marker,
            engine: request.engine.name,
            engine_executable: request.engine.executable,
            model_path: model_report.path.clone(),
            port: request.port,
            backend_port,
            cleanup_status_path,
            started_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            log_path: request.log_path,
            sandbox_mechanisms: launch.applied,
            trust_level: launch.trust_level,
            sandbox_note: launch.note,
            sandbox_policy_hash,
        };
        if let Err(error) = self.write_state(&state) {
            return Err(self.compensate_failed_start(&state, &mut child, error));
        }
        if let Err(error) = self.wait_healthy(state.port, request.health_timeout).await {
            return Err(self.compensate_failed_start(&state, &mut child, error));
        }
        match self.status().await {
            Ok(status)
                if status.running
                    && status.process_verified
                    && status.log_monitor_verified
                    && status.proxy_verified
                    && status.healthy =>
            {
                if let Err(error) =
                    handoff_spawned_children(&mut [&mut proxy, &mut monitor, &mut child])
                {
                    Err(self.compensate_failed_start(&state, &mut child, error))
                } else {
                    Ok(status)
                }
            }
            Ok(_) => Err(self.compensate_failed_start(
                &state,
                &mut child,
                ServeError::Spawn(
                    "推理服务、受管代理或日志监控在交权前未通过最终身份与健康复核".to_owned(),
                ),
            )),
            Err(error) => Err(self.compensate_failed_start(&state, &mut child, error)),
        }
    }

    pub async fn status(&self) -> Result<ServeStatus, ServeError> {
        let state = self.read_state()?;
        let running = process_alive(state.pid)?;
        if !running {
            let log_monitor_verified = verify_log_monitor_identity(&state)?;
            let proxy_verified = verify_proxy_identity(&state)?;
            let cleanup = self.read_cleanup_status(&state)?;
            return Ok(ServeStatus {
                running: false,
                process_verified: false,
                log_monitor_verified,
                proxy_verified,
                healthy: false,
                resident_memory_bytes: None,
                tokens_per_second: None,
                cleanup,
                state,
            });
        }
        verify_process_identity(&state)?;
        let log_monitor_verified = verify_log_monitor_identity(&state)?;
        let proxy_verified = verify_proxy_identity(&state)?;
        let cleanup = self.read_cleanup_status(&state)?;
        let cleanup_healthy = cleanup
            .as_ref()
            .is_some_and(|value| !value.cleanup_required);
        let healthy = log_monitor_verified
            && proxy_verified
            && cleanup_healthy
            && self.health(state.port).await;
        let tokens_per_second = if healthy {
            self.metrics_tokens_per_second(state.port).await
        } else {
            None
        };
        Ok(ServeStatus {
            running,
            process_verified: true,
            log_monitor_verified,
            proxy_verified,
            healthy,
            resident_memory_bytes: process_resident_memory(state.pid),
            tokens_per_second,
            cleanup,
            state,
        })
    }

    pub async fn stop(&self, timeout: Duration) -> Result<CleanupReport, ServeError> {
        let status = self.status().await?;
        if !status.running {
            if status.log_monitor_verified {
                stop_verified_log_monitor(&status.state).await?;
            } else if status.state.log_monitor_pid != 0
                && process_alive(status.state.log_monitor_pid)?
            {
                return Err(ServeError::LogMonitorStopFailed(
                    status.state.log_monitor_pid,
                ));
            }
            if status.proxy_verified {
                stop_verified_proxy(&status.state).await?;
            } else if status.state.proxy_pid != 0 && process_alive(status.state.proxy_pid)? {
                return Err(ServeError::ProxyStopFailed(status.state.proxy_pid));
            }
            return self.finish_stop(&status, true);
        }
        if !status.process_verified {
            return Err(ServeError::ProcessIdentityMismatch);
        }
        if status.proxy_verified {
            stop_verified_proxy(&status.state).await?;
        } else if status.state.proxy_pid == 0 || process_alive(status.state.proxy_pid)? {
            return Err(ServeError::ProxyStopFailed(status.state.proxy_pid));
        }
        // 将完整身份复核尽量贴近首次 TERM，收窄状态读取与信号发送之间的
        // PID 复用窗口；KILL 前还会再做一次同样的 marker + argv 复核。
        verify_process_identity(&status.state)?;
        terminate_pid(status.state.pid, false)?;
        if !wait_until_dead(status.state.pid, timeout).await? {
            // TERM 之后再次核对启动标记与命令，防止向已复用的 PID 发 KILL。
            verify_process_identity(&status.state)?;
            terminate_pid(status.state.pid, true)?;
        }
        let released = wait_until_dead(status.state.pid, Duration::from_secs(2)).await?;
        if !released {
            // 若 PID 被复用，身份校验也会失败并保留状态。
            verify_process_identity(&status.state)?;
        }
        if released
            && status.state.log_monitor_pid != 0
            && !wait_until_log_monitor_gone(&status.state, Duration::from_secs(3)).await?
        {
            stop_verified_log_monitor(&status.state).await?;
        }
        self.finish_stop(&status, released)
    }

    fn finish_stop(
        &self,
        status: &ServeStatus,
        released: bool,
    ) -> Result<CleanupReport, ServeError> {
        if !released {
            return Err(ServeError::StopFailed(status.state.pid));
        }
        if !status.state.cleanup_status_path.as_os_str().is_empty() {
            match fs::remove_file(&status.state.cleanup_status_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(ServeError::Io(error)),
            }
        }
        fs::remove_file(&self.state_path)?;
        let cleanup = status.cleanup.as_ref();
        let all_terminal_requests_cleaned = cleanup.is_some_and(|value| {
            value.requests_completed > 0
                && !value.cleanup_required
                && value.cleanup_failures == 0
                && value.cleanup_successes == value.requests_completed
        });
        Ok(CleanupReport {
            process_memory_released: released,
            owned_host_buffer_bytes_zeroed: cleanup
                .map(|value| value.owned_host_buffer_bytes_zeroed)
                .unwrap_or(0),
            kv_cache_cleanup_confirmed: all_terminal_requests_cleaned,
            note: if all_terminal_requests_cleaned && status.running {
                "本机公开代理的全部已终态请求均取得 b10064 slot 0 逻辑 erase 回执；贡献 worker 对 slot 1..=3 独立清理；进程退出同时释放其余引擎内存，不声称驱动内存池物理页逐字节覆写"
                    .to_owned()
            } else if all_terminal_requests_cleaned {
                "引擎已在 stop 前退出；残留受管进程已按精确身份回收，本机公开代理的已终态请求均有 b10064 slot 0 逻辑 erase 回执；贡献 worker 使用独立 slot 1..=3；不声称物理页逐字节覆写".to_owned()
            } else if status.running {
                "引擎进程内存已释放，但逐请求 KV 清理回执不完整；未声称物理页覆写".to_owned()
            } else {
                "引擎已在 stop 前退出，残留受管进程已按精确身份回收；逐请求 KV 清理回执不完整，未声称物理页覆写".to_owned()
            },
        })
    }

    fn compensate_failed_start(
        &self,
        state: &ServeRuntimeState,
        child: &mut SpawnedChildGuard,
        original: ServeError,
    ) -> ServeError {
        // 先核验 marker + executable/model/port 命令身份；无论核验是否成功，
        // 都通过仍持有的精确 Child handle 回收，绝不按裸 PID 猜测终止对象。
        let identity = verify_process_identity(state);
        let cleanup = child.terminate_and_reap();
        if cleanup.is_ok() {
            let _ = self.remove_state_if_matches(state);
        } else if !self.state_path.exists() {
            // 极端情况下回收失败且第一次状态写入也失败，尽力重新落下带启动
            // marker 的权威状态，避免把仍可能存活的进程变成无状态孤儿。
            let _ = self.write_state(state);
        }
        match (identity, cleanup) {
            (Ok(()), Ok(())) => original,
            (Err(identity_error), Ok(())) => identity_error,
            (_, Err(cleanup_error)) => ServeError::Spawn(format!(
                "{original}；启动失败补偿回收也失败：{cleanup_error}"
            )),
        }
    }

    fn remove_state_if_matches(&self, expected: &ServeRuntimeState) -> Result<(), ServeError> {
        match self.read_state() {
            Ok(actual) if actual == *expected => {
                fs::remove_file(&self.state_path)?;
                Ok(())
            }
            Ok(_) => Err(ServeError::CorruptState(
                "启动补偿时状态已被其他进程替换，拒绝删除".to_owned(),
            )),
            Err(ServeError::NotRunning) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn wait_healthy(&self, port: u16, timeout: Duration) -> Result<(), ServeError> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.health(port).await {
                return Ok(());
            }
            sleep(Duration::from_millis(250)).await;
        }
        Err(ServeError::HealthTimeout)
    }

    async fn health(&self, port: u16) -> bool {
        let url = format!("http://127.0.0.1:{port}/health");
        self.client
            .get(url)
            .send()
            .await
            .map(|response| response.status().is_success())
            .unwrap_or(false)
    }

    async fn metrics_tokens_per_second(&self, port: u16) -> Option<f64> {
        let url = format!("http://127.0.0.1:{port}/metrics");
        let text = self.client.get(url).send().await.ok()?.text().await.ok()?;
        let tokens = metric_value(&text, "llamacpp:tokens_predicted_total")?;
        let seconds = metric_value(&text, "llamacpp:tokens_predicted_seconds_total")?;
        if seconds > 0.0 {
            Some(tokens / seconds)
        } else {
            None
        }
    }

    fn read_state(&self) -> Result<ServeRuntimeState, ServeError> {
        if !self.state_path.is_file() {
            return Err(ServeError::NotRunning);
        }
        let bytes = fs::read(&self.state_path)?;
        serde_json::from_slice(&bytes).map_err(|error| ServeError::CorruptState(error.to_string()))
    }

    fn write_state(&self, state: &ServeRuntimeState) -> Result<(), ServeError> {
        let parent = self
            .state_path
            .parent()
            .ok_or_else(|| ServeError::CorruptState("状态文件缺少父目录".to_owned()))?;
        fs::create_dir_all(parent)?;
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| ServeError::CorruptState(error.to_string()))?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.state_path)
            .map_err(|error| ServeError::Io(error.error))?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn read_cleanup_status(
        &self,
        state: &ServeRuntimeState,
    ) -> Result<Option<ServeCleanupStatus>, ServeError> {
        if state.cleanup_status_path.as_os_str().is_empty() {
            return Ok(None);
        }
        let metadata = match fs::symlink_metadata(&state.cleanup_status_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(ServeError::Io(error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 16 * 1024
        {
            return Err(ServeError::CorruptState(
                "请求后清理状态不是安全的有界普通文件".to_owned(),
            ));
        }
        let bytes = fs::read(&state.cleanup_status_path)?;
        let status: ServeCleanupStatus = serde_json::from_slice(&bytes)
            .map_err(|error| ServeError::CorruptState(format!("请求后清理状态损坏：{error}")))?;
        if status.version != 1
            || status.proxy_pid != state.proxy_pid
            || status.proxy_start_marker != state.proxy_start_marker
            || status
                .cleanup_successes
                .saturating_add(status.cleanup_failures)
                != status.cleanup_attempts
            || status.cleanup_successes > status.cleanup_attempts
            || status.requests_completed > status.cleanup_attempts
            || status.cleanup_required != status.last_error_code.is_some()
        {
            return Err(ServeError::CorruptState(
                "请求后清理状态身份或计数不一致".to_owned(),
            ));
        }
        Ok(Some(status))
    }
}

fn ensure_managed_engine(name: EngineName) -> Result<(), ServeError> {
    if name == EngineName::LlamaCpp {
        Ok(())
    } else {
        Err(ServeError::Incompatible(format!(
            "v1 受管服务仅支持已验证的 llama.cpp 适配器；{name} 未实现完整安装与运行时验证"
        )))
    }
}

async fn ensure_safe_llama_logging_contract(engine: &InstalledEngine) -> Result<(), ServeError> {
    if !is_audited_managed_serve_release(engine.name, &engine.version) {
        return Err(ServeError::Incompatible(format!(
            "llama.cpp {} 尚未完成受管运行时审计；当前唯一允许 {}，拒绝在日志、slot 或请求后清理语义可能漂移的情况下启动",
            engine.version,
            AUDITED_MANAGED_LLAMA_CPP_RELEASE
        )));
    }

    let mut command = tokio::process::Command::new(&engine.executable);
    command
        .arg("--help")
        .current_dir(&engine.directory)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_remove("LD_PRELOAD")
        .env_remove("DYLD_INSERT_LIBRARIES")
        .env_remove("PYTHONPATH");
    for key in LLAMA_MANAGED_ENV_OVERRIDES {
        command.env_remove(key);
    }
    let mut child = command.spawn().map_err(|error| {
        ServeError::Incompatible(format!(
            "无法启动 llama.cpp 日志安全参数能力探测，拒绝启动：{error}"
        ))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        ServeError::Incompatible("无法捕获 llama.cpp 能力探测 stdout，拒绝启动".to_owned())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        ServeError::Incompatible("无法捕获 llama.cpp 能力探测 stderr，拒绝启动".to_owned())
    })?;
    let probe = async {
        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut limited_stdout = stdout.take((LLAMA_CAPABILITY_OUTPUT_MAX_BYTES + 1) as u64);
        let mut limited_stderr = stderr.take((LLAMA_CAPABILITY_OUTPUT_MAX_BYTES + 1) as u64);
        let stdout_read = limited_stdout.read_to_end(&mut stdout_bytes);
        let stderr_read = limited_stderr.read_to_end(&mut stderr_bytes);
        let (stdout_len, stderr_len, status) =
            tokio::try_join!(stdout_read, stderr_read, child.wait())?;
        Ok::<_, std::io::Error>((status, stdout_len, stderr_len, stdout_bytes, stderr_bytes))
    };
    let (status, stdout_len, stderr_len, stdout_bytes, stderr_bytes) =
        match tokio::time::timeout(LLAMA_CAPABILITY_TIMEOUT, probe).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(ServeError::Incompatible(format!(
                    "无法读取 llama.cpp 日志安全参数能力，拒绝启动：{error}"
                )));
            }
            Err(_) => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(ServeError::Incompatible(
                    "llama.cpp 日志安全参数能力探测超时或输出超限，拒绝启动".to_owned(),
                ));
            }
        };
    if !status.success()
        || stdout_len > LLAMA_CAPABILITY_OUTPUT_MAX_BYTES
        || stderr_len > LLAMA_CAPABILITY_OUTPUT_MAX_BYTES
        || (!help_advertises_managed_contract(&stdout_bytes)
            && !help_advertises_managed_contract(&stderr_bytes))
    {
        return Err(ServeError::Incompatible(
            "llama.cpp 未明确声明支持 --log-disable、--parallel、--kv-unified、--slots、--slot-save-path 与 --no-cache-prompt 的完整受管合同，拒绝启动"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn help_advertises_log_disable(help: &[u8]) -> bool {
    help_advertises_exact_flag(help, LLAMA_LOG_DISABLE_ARG)
}

fn help_advertises_managed_contract(help: &[u8]) -> bool {
    [
        "--log-disable",
        "--parallel",
        "--kv-unified",
        "--slots",
        "--slot-save-path",
        "--no-cache-prompt",
    ]
    .iter()
    .all(|flag| help_advertises_exact_flag(help, flag))
}

fn help_advertises_exact_flag(help: &[u8], expected: &str) -> bool {
    String::from_utf8_lossy(help)
        .split_whitespace()
        .any(|word| {
            word.trim_matches(|character: char| {
                matches!(character, '`' | ',' | '|' | '[' | ']' | '(' | ')')
            }) == expected
        })
}

fn build_managed_llama_args(
    model_path: &Path,
    port: u16,
    slot_save_path: &Path,
    cpu_only: bool,
    additional_args: &[String],
) -> Result<Vec<String>, ServeError> {
    // macOS 受管进程始终受 Seatbelt CPU-only 策略约束；显式 CPU-only 请求在
    // 其他平台采用同一套覆盖拒绝和参数注入，避免两条策略随时间漂移。
    let effective_cpu_only = cpu_only || cfg!(target_os = "macos");
    if let Some(argument) = additional_args.iter().find(|argument| {
        is_llama_managed_runtime_override(argument)
            || (effective_cpu_only && is_llama_cpu_policy_override(argument))
    }) {
        return Err(ServeError::Incompatible(format!(
            "高级配置不得覆盖受管 llama.cpp 日志、请求后 KV 清理或 CPU-only 参数：{argument}"
        )));
    }
    let mut engine_args = vec![
        "--model".to_owned(),
        model_path.to_string_lossy().into_owned(),
        "--host".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--metrics".to_owned(),
        "--parallel".to_owned(),
        MANAGED_LLAMA_PARALLEL_SLOTS.to_string(),
        // llama.cpp 的固定多 slot 默认会把总 KV 容量静态分摊；显式统一 KV 缓存
        // 允许空闲 slot 的容量被活动 sequence 使用，避免只运行 standard/fast 或
        // 本机请求时把单请求上下文无条件缩小为四分之一。
        "--kv-unified".to_owned(),
        "--slots".to_owned(),
        // b10064 把 `/slots/{id}?action=erase` 等 slot 动作端点门禁在 `--slot-save-path`
        // 之后；只启用 `--slots` 监控端点不足以执行请求后 KV 逻辑清理。受管服务提供
        // 一个只用于启用该动作端点的托管目录，本机代理和 worker 只调用各自 slot 的
        // erase、从不 save，因此不会向磁盘写入任何 KV/Prompt 数据。
        "--slot-save-path".to_owned(),
        slot_save_path.to_string_lossy().into_owned(),
        "--no-cache-prompt".to_owned(),
    ];
    engine_args.extend(additional_args.iter().cloned());
    if effective_cpu_only {
        // macOS 上受管 llama.cpp 运行在 Seatbelt 沙盒内，沙盒会拒绝 Metal/GPU
        // 设备访问；其他平台仅在用户显式请求 CPU-only 时采用相同策略。
        engine_args.push("--device".to_owned());
        engine_args.push("none".to_owned());
        engine_args.extend([
            "--n-gpu-layers".to_owned(),
            "0".to_owned(),
            "--no-kv-offload".to_owned(),
            "--no-op-offload".to_owned(),
        ]);
    }
    // 固定安全参数最后加入，调用方既不能删除，也不能通过高级配置提供第二份。
    engine_args.push(LLAMA_LOG_DISABLE_ARG.to_owned());
    Ok(engine_args)
}

fn is_llama_logging_override(argument: &str) -> bool {
    let name = argument.split('=').next().unwrap_or(argument);
    let normalized = name.replace('_', "-");
    normalized == "-v"
        || normalized == "-lv"
        || normalized.starts_with("--log-")
        || normalized.starts_with("--no-log-")
        || normalized.starts_with("--verbose")
        || normalized.starts_with("--verbosity")
}

fn is_llama_managed_runtime_override(argument: &str) -> bool {
    if is_llama_logging_override(argument) {
        return true;
    }
    let name = argument.split('=').next().unwrap_or(argument);
    let normalized = name.replace('_', "-");
    matches!(
        normalized.as_str(),
        "-np"
            | "--parallel"
            | "-kvu"
            | "--kv-unified"
            | "-no-kvu"
            | "--no-kv-unified"
            | "--slots"
            | "--no-slots"
            | "--cache-prompt"
            | "--no-cache-prompt"
            | "--slot-save-path"
            // 设备选择由受管路径固定：macOS Seatbelt 下强制纯 CPU（--device none），
            // 不允许高级配置重新启用 GPU/Metal 而使沙盒内进程初始化失败。
            | "-dev"
            | "--device"
    )
}

fn is_llama_cpu_policy_override(argument: &str) -> bool {
    let name = argument.split('=').next().unwrap_or(argument);
    let normalized = name.replace('_', "-");
    matches!(
        normalized.as_str(),
        "-ngl"
            | "--gpu-layers"
            | "--n-gpu-layers"
            | "-kvo"
            | "-nkvo"
            | "--kv-offload"
            | "--no-kv-offload"
            | "--op-offload"
            | "--no-op-offload"
    )
}

/// 对 MindOne 自己持有的 Prompt/Response 缓冲执行同步覆写，并返回实际覆写字节数。
pub fn zeroize_owned_buffer(buffer: &mut [u8]) -> u64 {
    let length = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
    buffer.zeroize();
    length
}

fn ensure_port_available(port: u16) -> Result<(), ServeError> {
    if port == 0 {
        return Err(ServeError::InvalidPort);
    }
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    TcpListener::bind(address)
        .map(drop)
        .map_err(|_| ServeError::PortInUse(port))
}

fn allocate_backend_port(public_port: u16) -> Result<u16, ServeError> {
    for _ in 0..16 {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port != public_port {
            return Ok(port);
        }
    }
    Err(ServeError::Spawn(
        "无法分配独立的 llama.cpp 内部回环端口".to_owned(),
    ))
}

async fn wait_for_process_marker(pid: u32, timeout: Duration) -> Result<String, ServeError> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(marker) = process_start_marker(pid) {
            return Ok(marker);
        }
        sleep(Duration::from_millis(50)).await;
    }
    Err(ServeError::Spawn("无法读取新进程身份".to_owned()))
}

async fn wait_for_log_monitor_ready(
    monitor: &mut SpawnedChildGuard,
    ready_path: &Path,
    ready_token: &str,
    timeout: Duration,
) -> Result<(), ServeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ServeError::Spawn("日志监控就绪等待时间超出平台范围".to_owned()))?;
    loop {
        monitor.ensure_running()?;
        if consume_log_monitor_ready(ready_path, ready_token)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ServeError::Spawn(
                "日志监控未在限定时间内完成身份校验与首轮轮转".to_owned(),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_until_dead(pid: u32, timeout: Duration) -> Result<bool, ServeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ServeError::Spawn("进程停止等待时间超出平台范围".to_owned()))?;
    loop {
        if !process_alive(pid)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_until_log_monitor_gone(
    state: &ServeRuntimeState,
    timeout: Duration,
) -> Result<bool, ServeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ServeError::Spawn("日志监控停止等待时间超出平台范围".to_owned()))?;
    loop {
        // PID 已退出或已被复用时，保存的 monitor 身份都已消失；绝不等待、
        // 更不会操作复用该 PID 的无关进程。
        if !verify_log_monitor_identity(state)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn verify_process_identity(state: &ServeRuntimeState) -> Result<(), ServeError> {
    let marker = process_start_marker(state.pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let command = process_command(state.pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let executable_name = state
        .engine_executable
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let backend_port = if state.backend_port == 0 {
        state.port
    } else {
        state.backend_port
    };
    let identity_matches = marker == state.process_start_marker
        && !executable_name.is_empty()
        && command.contains(executable_name)
        && command.contains(&state.model_path.to_string_lossy().into_owned())
        && command.contains(&backend_port.to_string());
    if identity_matches {
        Ok(())
    } else {
        Err(ServeError::ProcessIdentityMismatch)
    }
}

fn verify_proxy_identity(state: &ServeRuntimeState) -> Result<bool, ServeError> {
    if state.proxy_pid == 0 || state.proxy_start_marker.is_empty() || state.backend_port == 0 {
        return Ok(false);
    }
    if !process_alive(state.proxy_pid)? {
        return Ok(false);
    }
    Ok(verify_proxy_identity_exact(state).is_ok())
}

fn verify_proxy_identity_exact(state: &ServeRuntimeState) -> Result<(), ServeError> {
    let marker =
        process_start_marker(state.proxy_pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let command = process_arguments(state.proxy_pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let matches = marker == state.proxy_start_marker
        && command_has_pair(&command, "__worker", "serve-proxy")
        && command_has_pair(&command, "--listen-port", &state.port.to_string())
        && command_has_pair(&command, "--backend-port", &state.backend_port.to_string())
        && command_has_pair(&command, "--target-pid", &state.pid.to_string())
        && command_has_pair(&command, "--target-marker", &state.process_start_marker)
        && command_has_pair(
            &command,
            "--status-path",
            &state.cleanup_status_path.to_string_lossy(),
        );
    if matches {
        Ok(())
    } else {
        Err(ServeError::ProcessIdentityMismatch)
    }
}

fn command_has_pair(command: &[String], key: &str, value: &str) -> bool {
    command
        .windows(2)
        .any(|pair| pair[0] == key && pair[1] == value)
}

fn process_arguments(pid: u32) -> Option<Vec<String>> {
    let target = Pid::from_u32(pid);
    // macOS 上 sysinfo 对刚 spawn 的子进程用 `ProcessesToUpdate::Some` 定位不稳定
    // （有时找不到进程）。这里刷新全部进程后再取目标，保证能可靠读取到含空格
    // 参数（如 "Application Support" 路径）的完整 argv，避免 ps 空白切分破坏
    // `--status-path` 等键值对匹配。
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let process = system.process(target)?;
    if matches!(
        process.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        return None;
    }
    let arguments = process
        .cmd()
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    (!arguments.is_empty()).then_some(arguments)
}

fn verify_log_monitor_identity(state: &ServeRuntimeState) -> Result<bool, ServeError> {
    if state.log_monitor_pid == 0 || state.log_monitor_start_marker.is_empty() {
        return Ok(false);
    }
    if !process_alive(state.log_monitor_pid)? {
        return Ok(false);
    }
    Ok(verify_log_monitor_identity_exact(state).is_ok())
}

fn verify_log_monitor_identity_exact(state: &ServeRuntimeState) -> Result<(), ServeError> {
    let marker =
        process_start_marker(state.log_monitor_pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let command =
        process_command(state.log_monitor_pid).ok_or(ServeError::ProcessIdentityMismatch)?;
    let identity_matches = marker == state.log_monitor_start_marker
        && command.contains("__worker")
        && command.contains("log-monitor")
        && command.contains(&state.log_path.to_string_lossy().into_owned())
        && command.contains(&state.pid.to_string())
        && command.contains(&state.process_start_marker);
    if identity_matches {
        Ok(())
    } else {
        Err(ServeError::ProcessIdentityMismatch)
    }
}

async fn stop_verified_proxy(state: &ServeRuntimeState) -> Result<(), ServeError> {
    verify_proxy_identity_exact(state)?;
    terminate_pid(state.proxy_pid, false)?;
    if !wait_until_dead(state.proxy_pid, Duration::from_secs(3)).await? {
        verify_proxy_identity_exact(state)?;
        terminate_pid(state.proxy_pid, true)?;
    }
    if wait_until_dead(state.proxy_pid, Duration::from_secs(2)).await? {
        Ok(())
    } else {
        Err(ServeError::ProxyStopFailed(state.proxy_pid))
    }
}

async fn stop_verified_log_monitor(state: &ServeRuntimeState) -> Result<(), ServeError> {
    verify_log_monitor_identity_exact(state)?;
    terminate_pid(state.log_monitor_pid, false)?;
    if !wait_until_dead(state.log_monitor_pid, Duration::from_secs(3)).await? {
        verify_log_monitor_identity_exact(state)?;
        terminate_pid(state.log_monitor_pid, true)?;
    }
    if wait_until_dead(state.log_monitor_pid, Duration::from_secs(2)).await? {
        Ok(())
    } else {
        Err(ServeError::LogMonitorStopFailed(state.log_monitor_pid))
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> Result<bool, ServeError> {
    let raw_pid = i32::try_from(pid)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| ServeError::CorruptState("状态文件中的 PID 无效".to_owned()))?;
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), None) {
        Ok(()) => Ok(true),
        Err(nix::errno::Errno::ESRCH) => Ok(false),
        Err(error) => Err(ServeError::Spawn(format!(
            "无法确认 PID {pid} 是否存活：{error}"
        ))),
    }
}

#[cfg(windows)]
fn process_alive(pid: u32) -> Result<bool, ServeError> {
    if pid == 0 {
        return Err(ServeError::CorruptState("状态文件中的 PID 无效".to_owned()));
    }
    let output = Command::new("tasklist.exe")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map_err(ServeError::Io)?;
    if !output.status.success() {
        return Err(ServeError::Spawn(format!(
            "无法确认 PID {pid} 是否存活：tasklist 退出码 {:?}",
            output.status.code()
        )));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| ServeError::Spawn("tasklist 返回了无效文本".to_owned()))?;
    let pid_text = pid.to_string();
    Ok(text.split_whitespace().any(|field| field == pid_text))
}

#[cfg(unix)]
fn terminate_pid(pid: u32, force: bool) -> Result<(), ServeError> {
    let raw_pid =
        i32::try_from(pid).map_err(|_| ServeError::Spawn("PID 超出平台范围".to_owned()))?;
    let signal = if force {
        nix::sys::signal::Signal::SIGKILL
    } else {
        nix::sys::signal::Signal::SIGTERM
    };
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), signal) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(error) => Err(ServeError::Spawn(error.to_string())),
    }
}

#[cfg(windows)]
fn terminate_pid(pid: u32, force: bool) -> Result<(), ServeError> {
    let mut command = Command::new("taskkill.exe");
    command.args(["/PID", &pid.to_string(), "/T"]);
    if force {
        command.arg("/F");
    }
    let status = command.status()?;
    if status.success() || !process_alive(pid)? {
        Ok(())
    } else {
        Err(ServeError::Spawn(format!(
            "taskkill 退出码 {:?}",
            status.code()
        )))
    }
}

fn process_start_marker(pid: u32) -> Option<String> {
    read_process_start_marker(pid).ok().flatten()
}

fn process_command(pid: u32) -> Option<String> {
    process_field(pid, "command")
}

#[cfg(unix)]
fn process_resident_memory(pid: u32) -> Option<u64> {
    process_field(pid, "rss")?
        .trim()
        .parse::<u64>()
        .ok()?
        .checked_mul(1024)
}

#[cfg(windows)]
fn process_resident_memory(pid: u32) -> Option<u64> {
    // Win32_Process.WorkingSetSize 已经以字节为单位返回。
    process_field(pid, "rss")?.trim().parse::<u64>().ok()
}

#[cfg(unix)]
fn process_field(pid: u32, field: &str) -> Option<String> {
    // 无控制终端时（如从守护进程调用），`ps` 会把 command 等字段截断到默认宽度，
    // 导致长命令行（含 model 路径、端口）被截掉而身份校验失败。`-ww` 强制不限宽度，
    // 并显式给一个大 COLUMNS 兜底，确保读取到完整命令行。
    let output = Command::new("/bin/ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", &format!("{field}=")])
        .env("COLUMNS", "1048576")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

#[cfg(windows)]
fn process_field(pid: u32, field: &str) -> Option<String> {
    let property = match field {
        "lstart" => "CreationDate",
        "command" => "CommandLine",
        "rss" => "WorkingSetSize",
        _ => return None,
    };
    let script = format!(
        "$p = Get-CimInstance Win32_Process -Filter 'ProcessId = {pid}'; \
         if ($null -eq $p) {{ exit 3 }}; \
         $value = $p.{property}; \
         if ($null -eq $value) {{ exit 4 }}; \
         [Console]::Out.Write($value.ToString())"
    );
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn metric_value(text: &str, name: &str) -> Option<f64> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let metric = parts.next()?;
            if metric == name || metric.starts_with(&format!("{name}{{")) {
                parts.next()?.parse::<f64>().ok()
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(unix)]
    fn write_fake_llama_engine(directory: &Path, advertises_log_disable: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let executable = directory.join(if advertises_log_disable {
            "fake-llama-safe"
        } else {
            "fake-llama-unsafe"
        });
        let help = if advertises_log_disable {
            "printf '%s\\n' '--log-disable Log disable' '--parallel N' '--kv-unified' '--slots' '--slot-save-path PATH' '--no-cache-prompt'"
        } else {
            "printf '%s\\n' '--log-file FNAME'"
        };
        let script = format!(
            "#!/bin/sh\nset -eu\nif [ \"${{1-}}\" = \"--help\" ]; then\n  {help}\n  exit 0\nfi\nsafe=0\nfor argument in \"$@\"; do\n  if [ \"$argument\" = \"--log-disable\" ]; then safe=1; fi\ndone\nif [ \"$safe\" = 1 ]; then\n  printf '%s\\n' 'SAFE_MANAGED_STARTUP'\nelse\n  printf '%s\\n' 'PROMPT_RESPONSE_CANARY_DO_NOT_LOG'\n  printf '%s\\n' 'PROMPT_RESPONSE_CANARY_DO_NOT_LOG' >&2\nfi\n"
        );
        fs::write(&executable, script).expect("应写入 fake llama engine");
        let mut permissions = fs::metadata(&executable)
            .expect("应读取 fake engine 权限")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&executable, permissions).expect("应设置 fake engine 可执行权限");
        executable
    }

    fn test_state(directory: &Path, pid: u32) -> ServeRuntimeState {
        ServeRuntimeState {
            pid,
            process_start_marker: "test-marker".to_owned(),
            log_monitor_pid: 0,
            log_monitor_start_marker: String::new(),
            proxy_pid: 0,
            proxy_start_marker: String::new(),
            engine: EngineName::LlamaCpp,
            engine_executable: directory.join("llama-server"),
            model_path: directory.join("model.gguf"),
            port: 19_999,
            backend_port: 19_998,
            cleanup_status_path: directory.join("cleanup.json"),
            started_at_unix: 0,
            log_path: directory.join("llama-server.log"),
            sandbox_mechanisms: Vec::new(),
            trust_level: TrustLevel::Unverified,
            sandbox_note: "test".to_owned(),
            sandbox_policy_hash: "test-policy".to_owned(),
        }
    }

    fn test_request(directory: &Path, port: u16) -> ServeRequest {
        ServeRequest {
            engine: InstalledEngine {
                id: uuid::Uuid::nil(),
                name: EngineName::LlamaCpp,
                version: "test".to_owned(),
                target: "test".to_owned(),
                directory: directory.to_path_buf(),
                executable: directory.join("llama-server"),
                sha256: "00".repeat(32),
                files: Vec::new(),
                installed_at_unix: 0,
                source: "test".to_owned(),
            },
            model_path: directory.join("missing.gguf"),
            model_artifact_paths: vec![directory.join("missing.gguf")],
            port,
            runtime_directory: directory.join("runtime"),
            log_path: directory.join("llama-server.log"),
            health_timeout: Duration::from_millis(10),
            cpu_only: false,
            additional_args: Vec::new(),
        }
    }

    #[test]
    fn owned_buffers_are_actually_zeroized() {
        let mut buffer = b"secret prompt".to_vec();
        let bytes = zeroize_owned_buffer(&mut buffer);
        assert_eq!(bytes, 13);
        assert!(buffer.iter().all(|value| *value == 0));
    }

    #[test]
    fn cleanup_status_is_bound_to_proxy_identity_and_consistent_counters() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let manager =
            ServeManager::new(temporary.path().join("serve.json")).expect("应创建服务管理器");
        let mut state = test_state(temporary.path(), 42);
        state.proxy_pid = 77;
        state.proxy_start_marker = "proxy-marker".to_owned();
        let mut cleanup = ServeCleanupStatus::new(77, "proxy-marker".to_owned());
        cleanup.requests_completed = 1;
        cleanup.cleanup_attempts = 1;
        cleanup.cleanup_successes = 1;
        cleanup.tokens_erased = 3;
        fs::write(
            &state.cleanup_status_path,
            serde_json::to_vec(&cleanup).expect("应编码清理状态"),
        )
        .expect("应写入清理状态");
        assert_eq!(
            manager.read_cleanup_status(&state).expect("有效状态应通过"),
            Some(cleanup.clone())
        );

        cleanup.proxy_pid = 78;
        fs::write(
            &state.cleanup_status_path,
            serde_json::to_vec(&cleanup).expect("应编码错绑状态"),
        )
        .expect("应写入错绑状态");
        assert!(matches!(
            manager.read_cleanup_status(&state),
            Err(ServeError::CorruptState(_))
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_identity_requires_marker_command_ports_target_and_status_path() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let mut state = test_state(temporary.path(), 123);
        let child = Command::new("/bin/sh")
            .args([
                "-c",
                "while :; do /bin/sleep 1; done",
                "mindone-proxy-test",
                "__worker",
                "serve-proxy",
                "--listen-port",
                &state.port.to_string(),
                "--backend-port",
                &state.backend_port.to_string(),
                "--target-pid",
                &state.pid.to_string(),
                "--target-marker",
                &state.process_start_marker,
                "--status-path",
                &state.cleanup_status_path.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动代理身份测试进程");
        let mut child = SpawnedChildGuard::new(child);
        state.proxy_pid = child.id().expect("应读取代理 PID");
        state.proxy_start_marker = wait_for_process_marker(state.proxy_pid, Duration::from_secs(2))
            .await
            .expect("应读取代理启动标记");
        assert!(verify_proxy_identity(&state).is_ok_and(|verified| verified));
        state.backend_port = state.backend_port.saturating_add(1);
        assert!(verify_proxy_identity_exact(&state).is_err());
        child.terminate_and_reap().expect("应回收测试进程");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_recovers_verified_proxy_after_engine_already_exited() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");
        let mut engine = Command::new("/usr/bin/true")
            .spawn()
            .expect("应启动短命引擎替身");
        let engine_pid = engine.id();
        engine.wait().expect("短命引擎替身应退出");
        let mut state = test_state(temporary.path(), engine_pid);
        let mut proxy = Command::new("/bin/sh")
            .args([
                "-c",
                "while :; do /bin/sleep 1; done",
                "mindone-proxy-test",
                "__worker",
                "serve-proxy",
                "--listen-port",
                &state.port.to_string(),
                "--backend-port",
                &state.backend_port.to_string(),
                "--target-pid",
                &state.pid.to_string(),
                "--target-marker",
                &state.process_start_marker,
                "--status-path",
                &state.cleanup_status_path.to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动残留代理替身");
        state.proxy_pid = proxy.id();
        state.proxy_start_marker = wait_for_process_marker(state.proxy_pid, Duration::from_secs(2))
            .await
            .expect("应读取残留代理标记");
        let proxy_waiter = std::thread::spawn(move || proxy.wait());
        let cleanup = ServeCleanupStatus::new(state.proxy_pid, state.proxy_start_marker.clone());
        fs::write(
            &state.cleanup_status_path,
            serde_json::to_vec(&cleanup).expect("应编码清理状态"),
        )
        .expect("应写入清理状态");
        manager.write_state(&state).expect("应写入运行状态");

        let report = manager
            .stop(Duration::from_millis(100))
            .await
            .expect("应回收已验证的残留代理并完成清理");
        assert!(report.process_memory_released);
        assert!(!report.kv_cache_cleanup_confirmed);
        assert!(report.note.contains("已在 stop 前退出"));
        assert!(!state_path.exists());
        assert!(!state.cleanup_status_path.exists());
        assert!(proxy_waiter.join().expect("等待线程不应 panic").is_ok());
    }

    #[test]
    fn managed_serve_release_audit_is_unique_and_engine_bound() {
        assert!(is_audited_managed_serve_release(
            EngineName::LlamaCpp,
            AUDITED_MANAGED_LLAMA_CPP_RELEASE
        ));
        assert!(!is_audited_managed_serve_release(
            EngineName::LlamaCpp,
            "b10065"
        ));
        for name in [
            EngineName::Vllm,
            EngineName::Ollama,
            EngineName::TensorrtLlm,
        ] {
            assert!(!is_audited_managed_serve_release(
                name,
                AUDITED_MANAGED_LLAMA_CPP_RELEASE
            ));
        }
    }

    #[test]
    fn parses_llama_metrics() {
        let text = "# HELP x\nllamacpp:tokens_predicted_total 90\n\
                    llamacpp:tokens_predicted_seconds_total 3\n";
        assert_eq!(
            metric_value(text, "llamacpp:tokens_predicted_total"),
            Some(90.0)
        );
        assert_eq!(
            metric_value(text, "llamacpp:tokens_predicted_seconds_total"),
            Some(3.0)
        );
    }

    #[test]
    fn refuses_zero_port() {
        assert!(matches!(
            ensure_port_available(0),
            Err(ServeError::InvalidPort)
        ));
    }

    #[test]
    fn serve_rejects_unmanaged_engine_names_before_launch() {
        for name in [
            EngineName::Vllm,
            EngineName::Ollama,
            EngineName::TensorrtLlm,
        ] {
            assert!(matches!(
                ensure_managed_engine(name),
                Err(ServeError::Incompatible(message))
                    if message.contains("未实现完整安装与运行时验证")
            ));
        }
        assert!(ensure_managed_engine(EngineName::LlamaCpp).is_ok());
    }

    #[test]
    fn managed_llama_args_force_safe_logging_and_reject_overrides() {
        let additional = vec!["--ctx-size".to_owned(), "4096".to_owned()];
        let args = build_managed_llama_args(
            Path::new("/models/safe.gguf"),
            18_080,
            Path::new("/runtime/llama-slot-cache"),
            false,
            &additional,
        )
        .expect("普通性能参数应被接受");
        assert_eq!(args.last().map(String::as_str), Some("--log-disable"));
        let expected_parallel = MANAGED_LLAMA_PARALLEL_SLOTS.to_string();
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--parallel", expected_parallel.as_str()]));
        assert_eq!(managed_share_slot_id(0), Some(1));
        assert_eq!(managed_share_slot_id(1), Some(2));
        assert_eq!(managed_share_slot_id(2), Some(3));
        assert_eq!(managed_share_slot_id(3), None);
        assert!(args.iter().any(|argument| argument == "--kv-unified"));
        assert!(args.iter().any(|argument| argument == "--slots"));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["--slot-save-path", "/runtime/llama-slot-cache"]));
        assert!(args.iter().any(|argument| argument == "--no-cache-prompt"));
        assert_eq!(
            args.iter()
                .filter(|argument| argument.as_str() == "--log-disable")
                .count(),
            1
        );
        // macOS 受管路径固定纯 CPU（Seatbelt 拒绝 Metal/GPU），必须注入 --device none。
        #[cfg(target_os = "macos")]
        assert!(
            args.windows(2).any(|pair| pair == ["--device", "none"]),
            "macOS 受管 llama 必须固定 --device none 以在 Seatbelt 沙盒内纯 CPU 运行"
        );

        for override_arg in [
            "--log-disable",
            "--log_disable=false",
            "--log-file=/tmp/leak.log",
            "--log-verbosity",
            "--no-log-prefix",
            "--verbose",
            "--verbose-prompt",
            "--verbosity=5",
            "-v",
            "-lv",
            "-np",
            "--parallel=4",
            "--kv-unified",
            "--no-kv-unified",
            "--no-slots",
            "--cache-prompt",
            "--slot-save-path=/tmp/cache",
            "--device=metal",
            "-dev",
        ] {
            let error = build_managed_llama_args(
                Path::new("/models/safe.gguf"),
                18_080,
                Path::new("/runtime/llama-slot-cache"),
                false,
                &[override_arg.to_owned()],
            )
            .expect_err("高级配置不得覆盖日志策略");
            assert!(matches!(error, ServeError::Incompatible(_)));
        }

        let cpu_args = build_managed_llama_args(
            Path::new("/models/safe.gguf"),
            18_080,
            Path::new("/runtime/llama-slot-cache"),
            true,
            &[],
        )
        .expect("CPU-only 应由受管路径注入设备与卸载参数");
        assert!(cpu_args.windows(2).any(|pair| pair == ["--device", "none"]));
        assert!(cpu_args
            .windows(2)
            .any(|pair| pair == ["--n-gpu-layers", "0"]));
        assert!(cpu_args
            .iter()
            .any(|argument| argument == "--no-kv-offload"));
        assert!(cpu_args
            .iter()
            .any(|argument| argument == "--no-op-offload"));
        assert_eq!(
            cpu_args
                .iter()
                .filter(|argument| argument.as_str() == "--device")
                .count(),
            1
        );
        for override_arg in [
            "-ngl",
            "--gpu-layers=4",
            "--n-gpu-layers=4",
            "-kvo",
            "-nkvo",
            "--kv-offload",
            "--no-kv-offload",
            "--op-offload",
            "--no-op-offload",
        ] {
            let error = build_managed_llama_args(
                Path::new("/models/safe.gguf"),
                18_080,
                Path::new("/runtime/llama-slot-cache"),
                true,
                &[override_arg.to_owned()],
            )
            .expect_err("CPU-only 时不得用高级参数重新开启或重复设备卸载");
            assert!(matches!(error, ServeError::Incompatible(_)));
        }
        for variable in [
            "LLAMA_ARG_DEVICE",
            "LLAMA_ARG_N_GPU_LAYERS",
            "LLAMA_ARG_KV_OFFLOAD",
            "LLAMA_ARG_NO_KV_OFFLOAD",
            "LLAMA_ARG_NO_OP_OFFLOAD",
        ] {
            assert!(LLAMA_MANAGED_ENV_OVERRIDES.contains(&variable));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_seatbelt_uses_the_complete_cpu_only_policy_without_explicit_request() {
        let args = build_managed_llama_args(
            Path::new("/models/safe.gguf"),
            18_080,
            Path::new("/runtime/llama-slot-cache"),
            false,
            &[],
        )
        .expect("macOS Seatbelt 应自动应用完整 CPU-only 策略");
        assert!(args.windows(2).any(|pair| pair == ["--device", "none"]));
        assert!(args.windows(2).any(|pair| pair == ["--n-gpu-layers", "0"]));
        assert!(args.iter().any(|argument| argument == "--no-kv-offload"));
        assert!(args.iter().any(|argument| argument == "--no-op-offload"));

        let error = build_managed_llama_args(
            Path::new("/models/safe.gguf"),
            18_080,
            Path::new("/runtime/llama-slot-cache"),
            false,
            &["--n-gpu-layers=4".to_owned()],
        )
        .expect_err("macOS Seatbelt 下不得用高级参数重新开启 GPU");
        assert!(matches!(error, ServeError::Incompatible(_)));
    }

    #[test]
    fn log_disable_capability_detection_requires_the_exact_flag() {
        assert!(help_advertises_log_disable(
            b"options: `--log-disable` Log disable"
        ));
        assert!(!help_advertises_log_disable(
            b"options: --log-disable-not-really"
        ));
        assert!(help_advertises_managed_contract(
            b"options: --log-disable --parallel --kv-unified --slots --slot-save-path --no-cache-prompt"
        ));
        // 缺少 slot 动作端点所需的 --slot-save-path 必须失败关闭。
        assert!(!help_advertises_managed_contract(
            b"options: --log-disable --parallel --kv-unified --slots --no-cache-prompt"
        ));
        // 固定多 slot 缺少统一 KV 时会静态切小每个请求的上下文，必须失败关闭。
        assert!(!help_advertises_managed_contract(
            b"options: --log-disable --parallel --slots --slot-save-path --no-cache-prompt"
        ));
        assert!(!help_advertises_managed_contract(
            b"options: --log-disable --parallel --slots"
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fake_engine_capability_and_release_are_both_fail_closed() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let safe = write_fake_llama_engine(temporary.path(), true);
        let unsafe_engine = write_fake_llama_engine(temporary.path(), false);
        let mut engine = test_request(temporary.path(), 18_080).engine;
        engine.version = "b10064".to_owned();
        engine.executable = safe;
        ensure_safe_llama_logging_contract(&engine)
            .await
            .expect("受审计版本和明确能力应通过");

        engine.executable = unsafe_engine;
        assert!(matches!(
            ensure_safe_llama_logging_contract(&engine).await,
            Err(ServeError::Incompatible(_))
        ));

        engine.version = "b10065".to_owned();
        assert!(matches!(
            ensure_safe_llama_logging_contract(&engine).await,
            Err(ServeError::Incompatible(message)) if message.contains("尚未完成受管运行时审计")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn fixed_fake_engine_args_keep_prompt_canary_out_of_active_and_rotated_logs() {
        use std::ffi::OsString;

        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let root = fs::canonicalize(temporary.path()).expect("应规范化临时目录");
        let executable = write_fake_llama_engine(&root, true);
        let canary = b"PROMPT_RESPONSE_CANARY_DO_NOT_LOG";

        let unsafe_path = root.join("unsafe.log");
        let unsafe_stdout = crate::logging::open_log_append_no_follow(&unsafe_path)
            .expect("应创建 counterfactual 日志");
        let unsafe_stderr = unsafe_stdout.try_clone().expect("应复制日志句柄");
        let status = Command::new(&executable)
            .arg("--metrics")
            .stdout(Stdio::from(unsafe_stdout))
            .stderr(Stdio::from(unsafe_stderr))
            .status()
            .expect("fake engine 应运行");
        assert!(status.success());
        assert!(fs::read(&unsafe_path)
            .expect("应读取 counterfactual 日志")
            .windows(canary.len())
            .any(|window| window == canary));

        let safe_path = root.join("safe.log");
        let safe_stdout =
            crate::logging::open_log_append_no_follow(&safe_path).expect("应创建受管日志");
        let safe_stderr = safe_stdout.try_clone().expect("应复制受管日志句柄");
        let args = build_managed_llama_args(
            &root.join("model.gguf"),
            18_080,
            &root.join("llama-slot-cache"),
            false,
            &["--ctx-size".to_owned(), "4096".to_owned()],
        )
        .expect("应构建受管参数");
        let status = Command::new(&executable)
            .args(args)
            .stdout(Stdio::from(safe_stdout))
            .stderr(Stdio::from(safe_stderr))
            .status()
            .expect("受管 fake engine 应运行");
        assert!(status.success());
        crate::logging::rotate_log_if_needed(&safe_path, 4).expect("应轮转受管日志");

        let mut generation_name = OsString::from(safe_path.as_os_str());
        generation_name.push(".1");
        for candidate in [safe_path, PathBuf::from(generation_name)] {
            let contents = fs::read(candidate).expect("应读取活动/轮转日志");
            assert!(!contents
                .windows(canary.len())
                .any(|window| window == canary));
        }
    }

    #[tokio::test]
    async fn start_preserves_corrupt_state_and_fails_closed() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        fs::write(&state_path, b"not-json").expect("应写入损坏状态");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");

        let error = manager
            .start(test_request(temporary.path(), 19_998))
            .await
            .expect_err("损坏状态必须拒绝启动");
        assert!(matches!(error, ServeError::CorruptState(_)));
        assert_eq!(
            fs::read(&state_path).expect("损坏状态必须保留"),
            b"not-json"
        );
    }

    #[tokio::test]
    async fn start_preserves_live_pid_when_identity_cannot_be_proved() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");
        manager
            .write_state(&test_state(temporary.path(), std::process::id()))
            .expect("应写入测试状态");

        let error = manager
            .start(test_request(temporary.path(), 19_997))
            .await
            .expect_err("活 PID 身份不匹配必须拒绝启动");
        assert!(matches!(error, ServeError::ProcessIdentityMismatch));
        assert!(state_path.is_file(), "身份错误时必须保留状态");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn start_only_removes_state_after_pid_is_proven_dead() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");
        let mut child = Command::new("/usr/bin/true")
            .spawn()
            .expect("应启动短命进程");
        let pid = child.id();
        child.wait().expect("短命进程应退出");
        manager
            .write_state(&test_state(temporary.path(), pid))
            .expect("应写入 stale state");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("应分配端口");
        let port = listener.local_addr().expect("应读取端口").port();
        drop(listener);

        let error = manager
            .start(test_request(temporary.path(), port))
            .await
            .expect_err("模型不存在应在 stale state 清理后失败");
        assert!(matches!(error, ServeError::Validation(_)));
        assert!(!state_path.exists(), "已证明死亡的 stale state 应被清理");
    }

    #[test]
    fn failed_stop_preserves_state_and_returns_error() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        fs::write(&state_path, b"state-must-survive").expect("应写入状态");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");

        let status = ServeStatus {
            running: true,
            process_verified: true,
            log_monitor_verified: false,
            proxy_verified: false,
            healthy: false,
            state: test_state(temporary.path(), 42),
            resident_memory_bytes: None,
            tokens_per_second: None,
            cleanup: None,
        };
        let error = manager
            .finish_stop(&status, false)
            .expect_err("进程仍存活时不得假成功");
        assert!(matches!(error, ServeError::StopFailed(42)));
        assert_eq!(
            fs::read(&state_path).expect("停止失败必须保留状态"),
            b"state-must-survive"
        );
    }

    #[cfg(unix)]
    #[test]
    fn spawned_child_guard_drop_kills_and_reaps_exact_child() {
        let child = Command::new("/usr/bin/yes")
            .arg("guard-test")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动测试进程");
        let pid = child.id();
        {
            let guard = SpawnedChildGuard::new(child);
            assert_eq!(guard.id().ok(), Some(pid));
            assert!(process_alive(pid).is_ok_and(|alive| alive));
        }
        assert!(process_alive(pid).is_ok_and(|alive| !alive));
    }

    #[cfg(unix)]
    #[test]
    fn spawned_child_guard_refuses_release_after_child_exited() {
        let child = Command::new("/usr/bin/true")
            .spawn()
            .expect("应启动短命测试进程");
        let mut guard = SpawnedChildGuard::new(child);
        std::thread::sleep(Duration::from_millis(50));
        assert!(matches!(
            handoff_spawned_children(&mut [&mut guard]),
            Err(ServeError::Spawn(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn multi_child_handoff_keeps_every_handle_when_any_preflight_fails() {
        let long_lived = Command::new("/usr/bin/yes")
            .arg("handoff-long-lived")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动长驻测试进程");
        let long_pid = long_lived.id();
        let short_lived = Command::new("/usr/bin/true")
            .spawn()
            .expect("应启动短命测试进程");
        let mut first = SpawnedChildGuard::new(long_lived);
        let mut second = SpawnedChildGuard::new(short_lived);
        std::thread::sleep(Duration::from_millis(50));

        let error = handoff_spawned_children(&mut [&mut first, &mut second])
            .expect_err("任一子进程已退出时必须整体拒绝交权");
        assert!(matches!(error, ServeError::Spawn(_)));
        assert_eq!(first.id().ok(), Some(long_pid), "首个 handle 不得提前释放");
        drop(first);
        assert!(process_alive(long_pid).is_ok_and(|alive| !alive));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_start_verifies_identity_then_reaps_child_and_matching_state() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let state_path = temporary.path().join("serve.json");
        let manager = ServeManager::new(&state_path).expect("应创建服务管理器");
        let model_fragment = "mindone-lifecycle-model";
        let port = 19_996;
        let child = Command::new("/usr/bin/yes")
            .args([model_fragment, &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动测试进程");
        let pid = child.id();
        let mut child = SpawnedChildGuard::new(child);
        let marker = wait_for_process_marker(pid, Duration::from_secs(2))
            .await
            .expect("应读取测试进程 marker");
        let mut state = test_state(temporary.path(), pid);
        state.process_start_marker = marker;
        state.engine_executable = PathBuf::from("/usr/bin/yes");
        state.model_path = PathBuf::from(model_fragment);
        state.port = port;
        state.backend_port = port;
        manager.write_state(&state).expect("应写入匹配状态");

        let error = manager.compensate_failed_start(&state, &mut child, ServeError::HealthTimeout);
        assert!(matches!(error, ServeError::HealthTimeout));
        assert!(process_alive(pid).is_ok_and(|alive| !alive));
        assert!(!state_path.exists(), "精确回收后必须删除匹配状态");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn failed_start_identity_mismatch_still_reaps_exact_child_handle() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let manager =
            ServeManager::new(temporary.path().join("serve.json")).expect("应创建服务管理器");
        let child = Command::new("/usr/bin/yes")
            .arg("identity-mismatch")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动测试进程");
        let pid = child.id();
        let mut child = SpawnedChildGuard::new(child);
        let mut state = test_state(temporary.path(), pid);
        state.process_start_marker = "wrong-marker".to_owned();

        let error = manager.compensate_failed_start(&state, &mut child, ServeError::HealthTimeout);
        assert!(matches!(error, ServeError::ProcessIdentityMismatch));
        assert!(process_alive(pid).is_ok_and(|alive| !alive));
    }

    #[tokio::test]
    async fn health_check_never_follows_redirects_out_of_loopback_endpoint() {
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应启动跳转目标服务");
        let destination_port = destination.local_addr().expect("应读取跳转目标端口").port();
        let (visited_tx, visited_rx) = tokio::sync::oneshot::channel();
        let destination_task = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.expect("应接收连接");
            let _ = visited_tx.send(());
            let mut buffer = [0_u8; 1_024];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .expect("应返回响应");
        });

        let redirect = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("应启动跳转服务");
        let redirect_port = redirect.local_addr().expect("应读取跳转端口").port();
        let redirect_task = tokio::spawn(async move {
            let (mut stream, _) = redirect.accept().await.expect("应接收连接");
            let mut buffer = [0_u8; 1_024];
            let _ = stream.read(&mut buffer).await;
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{destination_port}/healthy\r\nContent-Length: 0\r\n\r\n"
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("应返回跳转");
        });

        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let manager =
            ServeManager::new(temporary.path().join("serve.json")).expect("应创建服务管理器");
        assert!(!manager.health(redirect_port).await);
        redirect_task.await.expect("跳转服务应正常结束");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), visited_rx)
                .await
                .is_err(),
            "健康检查不得访问跳转目标"
        );
        destination_task.abort();
    }
}
