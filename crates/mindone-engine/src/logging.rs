//! 长驻推理进程的安全日志轮转监控。
//!
//! 活动日志绝不改名或替换：推理进程持有的 stdout/stderr 文件描述符必须继续
//! 指向同一文件。轮转会先把活动文件的快照复制到同目录临时文件并原子替换归档，
//! 成功后再通过同一个已验证文件句柄截断活动文件。

use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use fs2::FileExt;
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;

pub const DEFAULT_LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
pub const DEFAULT_LOG_CHECK_INTERVAL: Duration = Duration::from_secs(1);
pub const LOG_GENERATIONS: u8 = 5;

#[derive(Debug, Clone)]
pub struct LogMonitorConfig {
    log_path: PathBuf,
    target_pid: u32,
    process_start_marker: String,
    rotate_bytes: u64,
    check_interval: Duration,
    expected_command_parts: Vec<String>,
    ready_signal: Option<ReadySignal>,
}

#[derive(Debug, Clone)]
struct ReadySignal {
    path: PathBuf,
    token: String,
}

impl LogMonitorConfig {
    pub fn new(
        log_path: impl Into<PathBuf>,
        target_pid: u32,
        process_start_marker: impl Into<String>,
    ) -> Result<Self, LogMonitorError> {
        let config = Self {
            log_path: log_path.into(),
            target_pid,
            process_start_marker: process_start_marker.into(),
            rotate_bytes: DEFAULT_LOG_ROTATE_BYTES,
            check_interval: DEFAULT_LOG_CHECK_INTERVAL,
            expected_command_parts: Vec::new(),
            ready_signal: None,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn with_rotation_threshold(mut self, rotate_bytes: u64) -> Result<Self, LogMonitorError> {
        self.rotate_bytes = rotate_bytes;
        self.validate()?;
        Ok(self)
    }

    pub fn with_check_interval(
        mut self,
        check_interval: Duration,
    ) -> Result<Self, LogMonitorError> {
        self.check_interval = check_interval;
        self.validate()?;
        Ok(self)
    }

    pub fn with_expected_command_parts(
        mut self,
        expected_command_parts: Vec<String>,
    ) -> Result<Self, LogMonitorError> {
        self.expected_command_parts = expected_command_parts;
        self.validate()?;
        Ok(self)
    }

    pub fn with_ready_signal(
        mut self,
        path: impl Into<PathBuf>,
        token: impl Into<String>,
    ) -> Result<Self, LogMonitorError> {
        self.ready_signal = Some(ReadySignal {
            path: path.into(),
            token: token.into(),
        });
        self.validate()?;
        Ok(self)
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    pub fn process_start_marker(&self) -> &str {
        &self.process_start_marker
    }

    fn validate(&self) -> Result<(), LogMonitorError> {
        if self.target_pid == 0 {
            return Err(LogMonitorError::InvalidConfiguration(
                "日志监控目标 PID 必须大于 0".to_owned(),
            ));
        }
        if self.process_start_marker.trim().is_empty() || self.process_start_marker.len() > 256 {
            return Err(LogMonitorError::InvalidConfiguration(
                "日志监控目标启动标记无效".to_owned(),
            ));
        }
        if self.rotate_bytes == 0 {
            return Err(LogMonitorError::InvalidConfiguration(
                "日志轮转阈值必须大于 0".to_owned(),
            ));
        }
        if self.check_interval.is_zero() {
            return Err(LogMonitorError::InvalidConfiguration(
                "日志检查间隔必须大于 0".to_owned(),
            ));
        }
        if self
            .expected_command_parts
            .iter()
            .any(|part| part.is_empty() || part.len() > 4_096 || part.chars().any(char::is_control))
        {
            return Err(LogMonitorError::InvalidConfiguration(
                "日志监控目标命令身份无效".to_owned(),
            ));
        }
        if let Some(ready) = &self.ready_signal {
            validate_absolute_normal_path(&ready.path)?;
            validate_ready_token(&ready.token)?;
        }
        validate_absolute_normal_path(&self.log_path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogMonitorExit {
    TargetExited,
}

#[derive(Debug, Error)]
pub enum LogMonitorError {
    #[error("日志监控配置无效：{0}")]
    InvalidConfiguration(String),
    #[error("日志路径不是安全的普通文件：{0}")]
    UnsafePath(PathBuf),
    #[error("日志监控无法读取 PID {0} 的进程身份")]
    ProcessProbe(u32),
    #[error("日志监控发现 PID {0} 已被复用，拒绝继续操作")]
    ProcessIdentityMismatch(u32),
    #[error("日志监控缺少目标命令身份，拒绝在故障时发送终止信号")]
    MissingCommandIdentity,
    #[error("日志文件在轮转期间被替换，拒绝截断：{0}")]
    FileIdentityChanged(PathBuf),
    #[error("日志监控失败：{cause}；目标处置：{containment}")]
    Fatal { cause: String, containment: String },
    #[error("日志文件操作失败（{operation}，{path}）：{source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// 持续监控日志，直到目标进程退出或出现无法安全恢复的错误。
pub fn run_log_monitor(config: &LogMonitorConfig) -> Result<LogMonitorExit, LogMonitorError> {
    config.validate()?;
    if config.expected_command_parts.is_empty() {
        return Err(LogMonitorError::MissingCommandIdentity);
    }
    ensure_safe_parent(&config.log_path)?;
    let mut active = open_regular_no_follow(&config.log_path, true)?;
    let active_identity = FileIdentity::from_file(&active, &config.log_path)?;
    match observe_target(config)? {
        TargetState::Exited => return Ok(LogMonitorExit::TargetExited),
        TargetState::Mismatch => {
            return Err(LogMonitorError::ProcessIdentityMismatch(config.target_pid));
        }
        TargetState::Running => {}
    }
    rotate_open_log_if_needed(
        &config.log_path,
        &mut active,
        &active_identity,
        config.rotate_bytes,
    )?;
    if let Some(ready) = &config.ready_signal {
        emit_ready_signal(ready)?;
    }

    loop {
        thread::sleep(config.check_interval);
        match observe_target(config) {
            Ok(TargetState::Exited) => return Ok(LogMonitorExit::TargetExited),
            Ok(TargetState::Mismatch) => {
                return Err(runtime_failure_with_containment(
                    config,
                    LogMonitorError::ProcessIdentityMismatch(config.target_pid),
                ));
            }
            Ok(TargetState::Running) => {}
            Err(error) => return Err(runtime_failure_with_containment(config, error)),
        }
        if let Err(error) = rotate_open_log_if_needed(
            &config.log_path,
            &mut active,
            &active_identity,
            config.rotate_bytes,
        ) {
            return Err(runtime_failure_with_containment(config, error));
        }
    }
}

/// 返回与 monitor 使用相同口径的启动标记；进程不存在或已成为 zombie 时返回 `None`。
pub fn read_process_start_marker(pid: u32) -> Result<Option<String>, LogMonitorError> {
    if pid == 0 {
        return Err(LogMonitorError::InvalidConfiguration(
            "日志监控目标 PID 必须大于 0".to_owned(),
        ));
    }
    observe_process_start_marker(pid)
}

/// 安全读取并消费 monitor ready 回执。
pub fn consume_log_monitor_ready(
    path: &Path,
    expected_token: &str,
) -> Result<bool, LogMonitorError> {
    validate_absolute_normal_path(path)?;
    validate_ready_token(expected_token)?;
    ensure_safe_parent(path)?;
    let mut ready = match open_optional_regular_no_follow(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(false),
        Err(LogMonitorError::UnsafePath(_)) if ready_link_is_still_publishing(path) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let metadata = ready
        .metadata()
        .map_err(|source| io_error("读取日志监控回执元数据", path, source))?;
    if metadata.len() > 256 {
        return Err(LogMonitorError::UnsafePath(path.to_path_buf()));
    }
    let identity = FileIdentity::from_file(&ready, path)?;
    let mut content = Vec::new();
    ready
        .read_to_end(&mut content)
        .map_err(|source| io_error("读取日志监控回执", path, source))?;
    if content != expected_token.as_bytes() {
        return Err(LogMonitorError::InvalidConfiguration(
            "日志监控 ready token 不匹配".to_owned(),
        ));
    }
    ensure_path_matches_open_file(path, &identity)?;
    let consumed = consumed_ready_path(path)?;
    fs::rename(path, &consumed).map_err(|source| io_error("原子领取日志监控回执", path, source))?;
    ensure_path_matches_open_file(&consumed, &identity)?;
    fs::remove_file(&consumed)
        .map_err(|source| io_error("删除已消费日志监控回执", &consumed, source))?;
    Ok(true)
}

#[cfg(unix)]
fn ready_link_is_still_publishing(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    // ready 文件通过同目录 hard link 无覆盖发布。发布方释放临时路径之前会有一个
    // 极短的双链接窗口；此时继续等待，绝不把双链接文件当作已完成回执消费。
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        metadata.file_type().is_file()
            && !metadata.file_type().is_symlink()
            && metadata.nlink() == 2
    })
}

#[cfg(not(unix))]
fn ready_link_is_still_publishing(_path: &Path) -> bool {
    false
}

/// 安全创建或打开活动日志，供推理进程 stdout/stderr 以 append 模式长期持有。
///
/// 该函数拒绝相对/非规范路径、symlink、Windows reparse point、非普通文件和
/// 打开期间发生的路径替换；Unix 上将最终文件权限收紧为 `0600`。
pub fn open_log_append_no_follow(path: &Path) -> Result<File, LogMonitorError> {
    ensure_safe_parent(path)?;
    validate_optional_regular_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).append(true).create(true);
    configure_secure_log_create(&mut options);
    let file = options
        .open(path)
        .map_err(|source| io_error("安全打开活动日志", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("读取活动日志元数据", path, source))?;
    validate_regular_metadata(path, &metadata)?;
    let identity = FileIdentity::from_file(&file, path)?;
    ensure_path_matches_open_file(path, &identity)?;
    tighten_log_permissions(&file, path)?;
    ensure_path_matches_open_file(path, &identity)?;
    Ok(file)
}

/// 在应用受审计的引擎日志关闭参数前，安全截断活动日志及全部轮转代。
///
/// 旧版本可能已经留下 Prompt/Response；仅阻止后续写入并不能清除这些历史。
/// 此操作坚持 no-follow、单硬链接和打开后身份复核，任何可疑路径都会令启动
/// fail closed，而不会跟随链接去改写其他文件。
pub(crate) fn clear_managed_log_history(path: &Path) -> Result<(), LogMonitorError> {
    ensure_safe_parent(path)?;
    truncate_managed_log_if_present(path)?;
    for generation in 1..=LOG_GENERATIONS {
        truncate_managed_log_if_present(&generation_path(path, generation))?;
    }
    Ok(())
}

fn truncate_managed_log_if_present(path: &Path) -> Result<(), LogMonitorError> {
    let mut file = match fs::symlink_metadata(path) {
        Ok(_) => open_regular_no_follow(path, true)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(io_error("检查待清理日志", path, source)),
    };
    let identity = FileIdentity::from_file(&file, path)?;
    FileExt::lock_exclusive(&file).map_err(|source| io_error("锁定待清理日志", path, source))?;
    let truncation = (|| {
        ensure_path_matches_open_file(path, &identity)?;
        file.set_len(0)
            .map_err(|source| io_error("截断历史日志", path, source))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|source| io_error("复位历史日志游标", path, source))?;
        file.sync_data()
            .map_err(|source| io_error("同步历史日志清理", path, source))?;
        ensure_path_matches_open_file(path, &identity)
    })();
    let unlock =
        FileExt::unlock(&file).map_err(|source| io_error("释放历史日志清理锁", path, source));
    match (truncation, unlock) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// 读取进程启动标记（进程创建时刻），用于跨调用识别 PID 是否被复用。
///
/// macOS 上 sysinfo 的 `refresh_processes(ProcessesToUpdate::Some(..))` 对刚 spawn 的
/// 子进程定位不稳定（有时找不到进程），因此在 Unix 平台优先用 `/bin/ps -o lstart=`
/// 读取稳定且可复现的启动时间字符串；仅在 ps 不可用时回退到 sysinfo。
#[cfg(unix)]
fn observe_process_start_marker(pid: u32) -> Result<Option<String>, LogMonitorError> {
    if let Some(marker) = ps_process_start_marker(pid) {
        return Ok(Some(marker));
    }
    // ps 读不到（进程已退出或平台异常）时回退到 sysinfo，保持既有 zombie 过滤语义。
    observe_process_start_marker_sysinfo(pid)
}

#[cfg(not(unix))]
fn observe_process_start_marker(pid: u32) -> Result<Option<String>, LogMonitorError> {
    observe_process_start_marker_sysinfo(pid)
}

/// 用 `/bin/ps -o lstart=` 读取进程启动时刻。返回归一化的启动时间字符串。
/// 进程不存在或已退出时返回 None。
#[cfg(unix)]
fn ps_process_start_marker(pid: u32) -> Option<String> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let marker = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if marker.is_empty() {
        None
    } else {
        Some(marker)
    }
}

fn observe_process_start_marker_sysinfo(pid: u32) -> Result<Option<String>, LogMonitorError> {
    let target = Pid::from_u32(pid);
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let Some(process) = system.process(target) else {
        return Ok(None);
    };
    if matches!(
        process.status(),
        ProcessStatus::Zombie | ProcessStatus::Dead
    ) {
        return Ok(None);
    }
    let started_at = process.start_time();
    if started_at == 0 {
        return Err(LogMonitorError::ProcessProbe(pid));
    }
    Ok(Some(started_at.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetState {
    Running,
    Exited,
    Mismatch,
}

fn observe_target(config: &LogMonitorConfig) -> Result<TargetState, LogMonitorError> {
    // marker 的记录与比较必须使用同一来源（见 observe_process_start_marker）：
    // Unix 上用 /bin/ps -o lstart=，避免 sysinfo 在 macOS 上对子进程定位不稳定。
    let marker = match observe_process_start_marker(config.target_pid)? {
        Some(marker) => marker,
        None => return Ok(TargetState::Exited),
    };
    if marker != config.process_start_marker {
        return Ok(TargetState::Mismatch);
    }
    // 命令行仍用 sysinfo 读取 argv 做精确匹配；读不到时回退为退出，
    // 避免对已消失或不可见的进程误判为运行中。
    let target = Pid::from_u32(config.target_pid);
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let command = match system.process(target) {
        Some(process)
            if !matches!(
                process.status(),
                ProcessStatus::Zombie | ProcessStatus::Dead
            ) =>
        {
            process
                .cmd()
                .iter()
                .map(|part| part.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        }
        // sysinfo 读不到 argv 时用 ps 兜底读取完整命令行。
        _ => ps_process_command_parts(config.target_pid),
    };
    let command_matches = config.expected_command_parts.iter().all(|expected| {
        command.iter().any(|actual| {
            actual == expected
                || Path::new(actual)
                    .file_name()
                    .is_some_and(|name| name == expected.as_str())
        })
    });
    Ok(if command_matches {
        TargetState::Running
    } else {
        TargetState::Mismatch
    })
}

/// 用 `/bin/ps -o command=` 读取进程完整命令行并按空白切分为参数，作为 sysinfo 的兜底。
#[cfg(unix)]
fn ps_process_command_parts(pid: u32) -> Vec<String> {
    // `-ww` + 大 COLUMNS 强制不截断，确保无控制终端时也能读到完整命令行。
    let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .env("COLUMNS", "1048576")
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8(output.stdout)
        .map(|text| text.split_whitespace().map(str::to_owned).collect())
        .unwrap_or_default()
}

#[cfg(not(unix))]
fn ps_process_command_parts(_pid: u32) -> Vec<String> {
    Vec::new()
}

fn runtime_failure_with_containment(
    config: &LogMonitorConfig,
    cause: LogMonitorError,
) -> LogMonitorError {
    let containment = contain_target_after_failure(config);
    LogMonitorError::Fatal {
        cause: cause.to_string(),
        containment,
    }
}

fn contain_target_after_failure(config: &LogMonitorConfig) -> String {
    match observe_target(config) {
        Ok(TargetState::Exited) => "目标已退出，未发送信号".to_owned(),
        Ok(TargetState::Mismatch) => "目标身份不匹配，未发送信号".to_owned(),
        Err(error) => format!("无法重新验证目标身份，未发送信号：{error}"),
        Ok(TargetState::Running) => match force_terminate_target(config.target_pid) {
            Ok(()) => "已在完整身份复核后强制终止目标".to_owned(),
            Err(error) => format!("目标身份匹配但强制终止失败：{error}"),
        },
    }
}

#[cfg(unix)]
fn force_terminate_target(pid: u32) -> Result<(), LogMonitorError> {
    let raw_pid = i32::try_from(pid).map_err(|_| {
        LogMonitorError::InvalidConfiguration("日志监控目标 PID 超出平台范围".to_owned())
    })?;
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(raw_pid),
        nix::sys::signal::Signal::SIGKILL,
    )
    .map_err(|error| LogMonitorError::Io {
        operation: "强制终止失去日志保护的目标",
        path: PathBuf::from(format!("pid:{pid}")),
        source: io::Error::other(error),
    })
}

#[cfg(windows)]
fn force_terminate_target(pid: u32) -> Result<(), LogMonitorError> {
    let status = Command::new("taskkill.exe")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|source| {
            io_error(
                "强制终止失去日志保护的目标",
                Path::new("taskkill.exe"),
                source,
            )
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(LogMonitorError::Io {
            operation: "强制终止失去日志保护的目标",
            path: PathBuf::from(format!("pid:{pid}")),
            source: io::Error::other(format!("taskkill 退出码 {:?}", status.code())),
        })
    }
}

#[cfg(not(any(unix, windows)))]
fn force_terminate_target(pid: u32) -> Result<(), LogMonitorError> {
    Err(LogMonitorError::InvalidConfiguration(format!(
        "当前平台不支持强制终止日志监控目标 PID {pid}"
    )))
}

fn emit_ready_signal(ready: &ReadySignal) -> Result<(), LogMonitorError> {
    validate_ready_token(&ready.token)?;
    ensure_safe_parent(&ready.path)?;
    validate_optional_regular_path(&ready.path)?;
    if ready.path.exists() {
        return Err(LogMonitorError::InvalidConfiguration(
            "日志监控 ready 路径已存在".to_owned(),
        ));
    }
    let parent = ready
        .path
        .parent()
        .ok_or_else(|| LogMonitorError::UnsafePath(ready.path.clone()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| io_error("创建日志监控 ready 临时文件", &ready.path, source))?;
    temporary
        .as_file_mut()
        .write_all(ready.token.as_bytes())
        .map_err(|source| io_error("写入日志监控 ready token", &ready.path, source))?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|source| io_error("刷新日志监控 ready token", &ready.path, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error("同步日志监控 ready token", &ready.path, source))?;
    let temporary_identity = FileIdentity::from_file(temporary.as_file(), temporary.path())?;
    ensure_path_matches_open_file(temporary.path(), &temporary_identity)?;
    fs::hard_link(temporary.path(), &ready.path)
        .map_err(|source| io_error("原子创建日志监控 ready 回执", &ready.path, source))?;
    // hard_link 成功即表示完整且已同步的同一文件已发布。不要在这里重新打开 ready
    // 路径；父进程可能立刻原子消费该路径，这不应反过来令 monitor 启动失败。
    Ok(())
}

fn validate_ready_token(token: &str) -> Result<(), LogMonitorError> {
    if !(16..=128).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LogMonitorError::InvalidConfiguration(
            "日志监控 ready token 无效".to_owned(),
        ));
    }
    Ok(())
}

fn consumed_ready_path(path: &Path) -> Result<PathBuf, LogMonitorError> {
    let parent = path
        .parent()
        .ok_or_else(|| LogMonitorError::UnsafePath(path.to_path_buf()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| LogMonitorError::UnsafePath(path.to_path_buf()))?;
    Ok(parent.join(format!(".{file_name}.consumed-{}", Uuid::new_v4())))
}

#[cfg(test)]
pub(crate) fn rotate_log_if_needed(path: &Path, rotate_bytes: u64) -> Result<(), LogMonitorError> {
    ensure_safe_parent(path)?;
    let mut active = open_regular_no_follow(path, true)?;
    let active_identity = FileIdentity::from_file(&active, path)?;
    rotate_open_log_if_needed(path, &mut active, &active_identity, rotate_bytes)
}

fn rotate_open_log_if_needed(
    path: &Path,
    active: &mut File,
    active_identity: &FileIdentity,
    rotate_bytes: u64,
) -> Result<(), LogMonitorError> {
    FileExt::lock_exclusive(active).map_err(|source| io_error("锁定活动日志轮转", path, source))?;
    let rotation = (|| {
        ensure_path_matches_open_file(path, active_identity)?;
        let snapshot_len = active
            .metadata()
            .map_err(|source| io_error("读取活动日志元数据", path, source))?
            .len();
        if snapshot_len <= rotate_bytes {
            return Ok(());
        }

        for generation in (2..=LOG_GENERATIONS).rev() {
            let source_path = generation_path(path, generation - 1);
            let destination_path = generation_path(path, generation);
            match open_optional_regular_no_follow(&source_path)? {
                Some(mut source) => {
                    let source_len = source
                        .metadata()
                        .map_err(|error| io_error("读取历史日志元数据", &source_path, error))?
                        .len();
                    atomic_copy_to_path(&mut source, source_len, rotate_bytes, &destination_path)?;
                }
                None => validate_optional_regular_path(&destination_path)?,
            }
        }

        let first_generation = generation_path(path, 1);
        atomic_copy_to_path(active, snapshot_len, rotate_bytes, &first_generation)?;
        ensure_path_matches_open_file(path, active_identity)?;
        active
            .set_len(0)
            .map_err(|source| io_error("截断活动日志", path, source))?;
        active
            .seek(SeekFrom::Start(0))
            .map_err(|source| io_error("复位活动日志游标", path, source))?;
        active
            .sync_data()
            .map_err(|source| io_error("同步活动日志", path, source))?;
        Ok(())
    })();
    let unlock =
        FileExt::unlock(active).map_err(|source| io_error("释放活动日志轮转锁", path, source));
    match (rotation, unlock) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn atomic_copy_to_path(
    source: &mut File,
    snapshot_len: u64,
    max_bytes: u64,
    destination: &Path,
) -> Result<(), LogMonitorError> {
    ensure_safe_parent(destination)?;
    validate_optional_regular_path(destination)?;
    let parent = destination
        .parent()
        .ok_or_else(|| LogMonitorError::UnsafePath(destination.to_path_buf()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| io_error("创建日志轮转临时文件", destination, source))?;
    let copy_bytes = snapshot_len.min(max_bytes);
    let copy_start = snapshot_len.saturating_sub(copy_bytes);
    source
        .seek(SeekFrom::Start(copy_start))
        .map_err(|source| io_error("定位日志快照", destination, source))?;
    let mut snapshot = source.take(copy_bytes);
    let copied = io::copy(&mut snapshot, temporary.as_file_mut())
        .map_err(|source| io_error("复制日志快照", destination, source))?;
    if copied != copy_bytes {
        return Err(LogMonitorError::Io {
            operation: "复制完整日志快照",
            path: destination.to_path_buf(),
            source: io::Error::new(io::ErrorKind::UnexpectedEof, "日志快照在复制时缩短"),
        });
    }
    temporary
        .as_file_mut()
        .flush()
        .map_err(|source| io_error("刷新日志轮转临时文件", destination, source))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| io_error("同步日志轮转临时文件", destination, source))?;
    validate_optional_regular_path(destination)?;
    temporary
        .persist(destination)
        .map_err(|error| io_error("原子替换日志归档", destination, error.error))?;
    validate_existing_regular_path(destination)?;
    let archived_len = fs::metadata(destination)
        .map_err(|source| io_error("复核日志归档大小", destination, source))?
        .len();
    if archived_len > max_bytes {
        return Err(LogMonitorError::UnsafePath(destination.to_path_buf()));
    }
    Ok(())
}

fn open_optional_regular_no_follow(path: &Path) -> Result<Option<File>, LogMonitorError> {
    match fs::symlink_metadata(path) {
        Ok(_) => open_regular_no_follow(path, false).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error("检查历史日志", path, source)),
    }
}

fn open_regular_no_follow(path: &Path, writable: bool) -> Result<File, LogMonitorError> {
    validate_existing_regular_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    configure_no_follow(&mut options);
    let file = options
        .open(path)
        .map_err(|source| io_error("以 no-follow 打开日志", path, source))?;
    validate_regular_metadata(
        path,
        &file
            .metadata()
            .map_err(|source| io_error("读取已打开日志的元数据", path, source))?,
    )?;
    Ok(file)
}

#[cfg(unix)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
}

#[cfg(unix)]
fn configure_secure_log_create(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
}

#[cfg(windows)]
fn configure_secure_log_create(options: &mut OpenOptions) {
    configure_no_follow(options);
}

#[cfg(not(any(unix, windows)))]
fn configure_secure_log_create(options: &mut OpenOptions) {
    configure_no_follow(options);
}

#[cfg(unix)]
fn tighten_log_permissions(file: &File, path: &Path) -> Result<(), LogMonitorError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| io_error("收紧活动日志权限", path, source))
}

#[cfg(not(unix))]
fn tighten_log_permissions(_file: &File, _path: &Path) -> Result<(), LogMonitorError> {
    Ok(())
}

#[cfg(windows)]
fn configure_no_follow(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow(_options: &mut OpenOptions) {}

fn validate_absolute_normal_path(path: &Path) -> Result<(), LogMonitorError> {
    let normalized = path.components().collect::<PathBuf>();
    if !path.is_absolute()
        || path.file_name().is_none()
        || normalized.as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(LogMonitorError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_safe_parent(path: &Path) -> Result<(), LogMonitorError> {
    validate_absolute_normal_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| LogMonitorError::UnsafePath(path.to_path_buf()))?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|source| io_error("检查日志目录父链", &current, source))?;
        if !metadata.file_type().is_dir() || metadata_is_reparse_point(&metadata) {
            return Err(LogMonitorError::UnsafePath(current));
        }
    }
    Ok(())
}

fn validate_optional_regular_path(path: &Path) -> Result<(), LogMonitorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_regular_metadata(path, &metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("检查日志归档", path, source)),
    }
}

fn validate_existing_regular_path(path: &Path) -> Result<(), LogMonitorError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("检查日志文件", path, source))?;
    validate_regular_metadata(path, &metadata)
}

fn validate_regular_metadata(path: &Path, metadata: &Metadata) -> Result<(), LogMonitorError> {
    if !metadata.file_type().is_file() || metadata_is_reparse_point(metadata) {
        return Err(LogMonitorError::UnsafePath(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.nlink() != 1 {
            return Err(LogMonitorError::UnsafePath(path.to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn ensure_path_matches_open_file(
    path: &Path,
    expected: &FileIdentity,
) -> Result<(), LogMonitorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("轮转后复核活动日志", path, source))?;
    validate_regular_metadata(path, &metadata)?;
    if !expected.matches_path(path)? {
        return Err(LogMonitorError::FileIdentityChanged(path.to_path_buf()));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    handle: same_file::Handle,
    #[cfg(not(any(unix, windows)))]
    created: Option<std::time::SystemTime>,
}

impl FileIdentity {
    fn from_file(file: &File, path: &Path) -> Result<Self, LogMonitorError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = file
                .metadata()
                .map_err(|source| io_error("读取文件身份", path, source))?;
            Ok(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(windows)]
        {
            let clone = file
                .try_clone()
                .map_err(|source| io_error("复制文件身份句柄", path, source))?;
            let handle = same_file::Handle::from_file(clone)
                .map_err(|source| io_error("读取 Windows 文件身份", path, source))?;
            Ok(Self { handle })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let metadata = file
                .metadata()
                .map_err(|source| io_error("读取文件身份", path, source))?;
            Ok(Self {
                created: metadata.created().ok(),
            })
        }
    }

    fn matches_path(&self, path: &Path) -> Result<bool, LogMonitorError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("复核 Unix 文件身份", path, source))?;
            Ok(metadata.dev() == self.device && metadata.ino() == self.inode)
        }
        #[cfg(windows)]
        {
            let handle = same_file::Handle::from_path(path)
                .map_err(|source| io_error("复核 Windows 文件身份", path, source))?;
            validate_existing_regular_path(path)?;
            Ok(handle == self.handle)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("复核文件身份", path, source))?;
            Ok(metadata.created().ok() == self.created)
        }
    }
}

fn generation_path(path: &Path, generation: u8) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{generation}"));
    PathBuf::from(value)
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> LogMonitorError {
    LogMonitorError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use super::{
        clear_managed_log_history, consume_log_monitor_ready, generation_path,
        open_log_append_no_follow, open_regular_no_follow, read_process_start_marker,
        rotate_log_if_needed, rotate_open_log_if_needed, run_log_monitor, FileIdentity,
        LogMonitorConfig, LogMonitorError, LogMonitorExit, LOG_GENERATIONS,
    };

    fn test_root(directory: &TempDir) -> std::path::PathBuf {
        std::fs::canonicalize(directory.path()).expect("应规范化临时日志目录")
    }

    #[test]
    fn small_threshold_rotates_five_generations_and_keeps_active_inode() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let active_contents = b"abcdefghijkl";
        std::fs::write(&log_path, active_contents).expect("应写入活动日志");
        for generation in 1..=LOG_GENERATIONS {
            let contents = format!("old-generation-{generation}");
            std::fs::write(generation_path(&log_path, generation), contents)
                .expect("应写入历史日志");
        }
        let mut inherited_stdout = OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("应模拟推理进程持有的 stdout 文件描述符");
        #[cfg(unix)]
        let inode_before = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&log_path).expect("应读取 inode").ino()
        };

        rotate_log_if_needed(&log_path, 4).expect("小阈值轮转应成功");
        assert_eq!(std::fs::read(&log_path).expect("应读取活动日志"), b"");
        assert_eq!(
            std::fs::read(generation_path(&log_path, 1)).expect("应读取第一代日志"),
            &active_contents[active_contents.len() - 4..]
        );
        for generation in 2..=LOG_GENERATIONS {
            let previous = format!("old-generation-{}", generation - 1);
            assert_eq!(
                std::fs::read(generation_path(&log_path, generation)).expect("应读取轮转日志"),
                &previous.as_bytes()[previous.len() - 4..]
            );
        }
        for generation in 1..=LOG_GENERATIONS {
            assert!(
                std::fs::metadata(generation_path(&log_path, generation))
                    .expect("应读取归档大小")
                    .len()
                    <= 4
            );
        }
        assert!(!generation_path(&log_path, LOG_GENERATIONS + 1).exists());

        inherited_stdout
            .write_all(b"continued")
            .expect("原 stdout 文件描述符应继续写入活动 inode");
        inherited_stdout.flush().expect("应刷新模拟 stdout");
        assert_eq!(
            std::fs::read(&log_path).expect("应读取截断后的新日志"),
            b"continued"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                std::fs::metadata(&log_path).expect("应复核 inode").ino(),
                inode_before
            );
        }
    }

    #[test]
    fn safe_start_clears_canary_from_active_and_rotated_logs() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let canary = b"PROMPT_RESPONSE_CANARY_MUST_NOT_SURVIVE";
        std::fs::write(&log_path, canary).expect("应写入旧活动日志 canary");
        for generation in 1..=LOG_GENERATIONS {
            std::fs::write(generation_path(&log_path, generation), canary)
                .expect("应写入旧轮转日志 canary");
        }

        clear_managed_log_history(&log_path).expect("安全启动应清理旧日志正文");

        for candidate in std::iter::once(log_path.clone())
            .chain((1..=LOG_GENERATIONS).map(|generation| generation_path(&log_path, generation)))
        {
            let contents = std::fs::read(&candidate).expect("受管日志应继续存在");
            assert!(contents.is_empty());
            assert!(!contents
                .windows(canary.len())
                .any(|window| window == canary));
        }
    }

    #[test]
    fn held_active_file_rejects_regular_path_replacement_without_truncating_it() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let displaced_path = test_root(&directory).join("serve.displaced.log");
        std::fs::write(&log_path, b"original-active-log").expect("应写入原活动日志");
        let mut held = open_regular_no_follow(&log_path, true).expect("应安全打开活动日志");
        let identity = FileIdentity::from_file(&held, &log_path).expect("应读取活动日志身份");
        std::fs::rename(&log_path, &displaced_path).expect("应替换活动日志路径");
        let replacement = b"replacement-must-not-be-truncated";
        std::fs::write(&log_path, replacement).expect("应写入替换文件");

        assert!(matches!(
            rotate_open_log_if_needed(&log_path, &mut held, &identity, 4),
            Err(LogMonitorError::FileIdentityChanged(_))
        ));
        assert_eq!(
            std::fs::read(&log_path).expect("应读取替换文件"),
            replacement
        );
    }

    #[cfg(unix)]
    #[test]
    fn safe_append_open_is_private_and_rejects_symlink() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let mut log = open_log_append_no_follow(&log_path).expect("应安全创建活动日志");
        log.write_all(b"private").expect("应写入活动日志");
        log.flush().expect("应刷新活动日志");
        let metadata = std::fs::metadata(&log_path).expect("应读取活动日志元数据");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let linked_path = test_root(&directory).join("linked.log");
        symlink(&log_path, &linked_path).expect("应创建日志 symlink");
        assert!(matches!(
            open_log_append_no_follow(&linked_path),
            Err(LogMonitorError::UnsafePath(_))
        ));

        let real_parent = test_root(&directory).join("real-parent");
        std::fs::create_dir(&real_parent).expect("应创建真实日志父目录");
        let linked_parent = test_root(&directory).join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("应创建父目录 symlink");
        assert!(matches!(
            open_log_append_no_follow(&linked_parent.join("serve.log")),
            Err(LogMonitorError::UnsafePath(_))
        ));
    }

    #[test]
    fn non_normalized_log_path_is_rejected() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path =
            std::path::PathBuf::from(format!("{}/./serve.log", test_root(&directory).display()));
        assert!(matches!(
            LogMonitorConfig::new(log_path, std::process::id(), "1"),
            Err(LogMonitorError::UnsafePath(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn ready_consumer_waits_for_atomic_link_publication_to_finish() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let root = test_root(&directory);
        let temporary_path = root.join("publishing.tmp");
        let ready_path = root.join("monitor.ready");
        let token = "ready-token-0123456789abcdef";
        std::fs::write(&temporary_path, token).expect("应写入完整 ready 临时文件");
        std::fs::hard_link(&temporary_path, &ready_path).expect("应原子发布 ready 链接");

        assert!(!consume_log_monitor_ready(&ready_path, token).expect("双链接发布窗口应继续等待"));
        assert!(ready_path.exists());
        std::fs::remove_file(&temporary_path).expect("应结束 ready 发布窗口");
        assert!(consume_log_monitor_ready(&ready_path, token).expect("单链接 ready 应可消费"));
        assert!(!ready_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_log_and_generation_are_rejected() {
        use std::os::unix::fs::symlink;

        let directory = TempDir::new().expect("应创建临时日志目录");
        let target = test_root(&directory).join("target.log");
        std::fs::write(&target, b"oversized").expect("应写入 symlink 目标");
        let linked_log = test_root(&directory).join("linked.log");
        symlink(&target, &linked_log).expect("应创建日志 symlink");
        assert!(matches!(
            rotate_log_if_needed(&linked_log, 1),
            Err(LogMonitorError::UnsafePath(_))
        ));

        let active = test_root(&directory).join("active.log");
        std::fs::write(&active, b"oversized").expect("应写入活动日志");
        symlink(&target, generation_path(&active, 1)).expect("应创建历史日志 symlink");
        assert!(matches!(
            rotate_log_if_needed(&active, 1),
            Err(LogMonitorError::UnsafePath(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_log_and_generation_are_rejected() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let directory = TempDir::new().expect("应创建临时日志目录");
        let target = test_root(&directory).join("target.log");
        std::fs::write(&target, b"oversized").expect("应写入 reparse 目标");
        let linked_log = test_root(&directory).join("linked.log");
        symlink_file(&target, &linked_log).expect("应创建日志 reparse point");
        assert!(matches!(
            rotate_log_if_needed(&linked_log, 1),
            Err(LogMonitorError::UnsafePath(_))
        ));

        let active = test_root(&directory).join("active.log");
        std::fs::write(&active, b"oversized").expect("应写入活动日志");
        symlink_file(&target, generation_path(&active, 1)).expect("应创建历史日志 reparse point");
        assert!(matches!(
            rotate_log_if_needed(&active, 1),
            Err(LogMonitorError::UnsafePath(_))
        ));

        let real_parent = test_root(&directory).join("real-parent");
        std::fs::create_dir(&real_parent).expect("应创建真实日志父目录");
        let linked_parent = test_root(&directory).join("linked-parent");
        symlink_dir(&real_parent, &linked_parent).expect("应创建父目录 reparse point");
        assert!(matches!(
            open_log_append_no_follow(&linked_parent.join("serve.log")),
            Err(LogMonitorError::UnsafePath(_))
        ));
    }

    #[test]
    #[ignore = "由日志 monitor 生命周期测试显式启动"]
    fn log_monitor_target_helper() {
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn monitor_exits_after_verified_target_exits() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        std::fs::write(&log_path, b"log").expect("应写入测试日志");
        let mut child = Command::new(std::env::current_exe().expect("应定位当前测试程序"))
            .args([
                "--exact",
                "logging::tests::log_monitor_target_helper",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动 monitor 目标子进程");
        let deadline = Instant::now() + Duration::from_secs(2);
        let marker = loop {
            if let Some(marker) =
                read_process_start_marker(child.id()).expect("应能探测 monitor 目标")
            {
                break marker;
            }
            assert!(Instant::now() < deadline, "应在超时前取得目标启动标记");
            std::thread::sleep(Duration::from_millis(10));
        };
        let config = LogMonitorConfig::new(&log_path, child.id(), marker)
            .expect("应构造 monitor 配置")
            .with_expected_command_parts(vec![
                "logging::tests::log_monitor_target_helper".to_owned()
            ])
            .expect("应设置目标命令身份")
            .with_rotation_threshold(64)
            .expect("应设置测试阈值")
            .with_check_interval(Duration::from_millis(10))
            .expect("应设置测试间隔");
        let (sender, receiver) = mpsc::channel();
        let monitor = std::thread::spawn(move || {
            let _ = sender.send(run_log_monitor(&config));
        });

        child.kill().expect("应停止 monitor 目标");
        child.wait().expect("应回收 monitor 目标");
        let result = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("目标退出后 monitor 应自行结束")
            .expect("目标正常退出不应成为 monitor 错误");
        assert_eq!(result, LogMonitorExit::TargetExited);
        monitor.join().expect("monitor 线程应正常结束");
    }

    #[test]
    fn identity_mismatch_emits_no_ready_signal_and_never_kills_target() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let ready_path = test_root(&directory).join("monitor.ready");
        std::fs::write(&log_path, b"log").expect("应写入测试日志");
        let mut child = Command::new(std::env::current_exe().expect("应定位当前测试程序"))
            .args([
                "--exact",
                "logging::tests::log_monitor_target_helper",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动 monitor 目标子进程");
        let config = LogMonitorConfig::new(&log_path, child.id(), "wrong-marker")
            .expect("应构造错误身份配置")
            .with_expected_command_parts(vec![
                "logging::tests::log_monitor_target_helper".to_owned()
            ])
            .expect("应设置目标命令身份")
            .with_ready_signal(&ready_path, "ready-token-0123456789abcdef")
            .expect("应设置 ready 回执");

        assert!(matches!(
            run_log_monitor(&config),
            Err(LogMonitorError::ProcessIdentityMismatch(_))
        ));
        assert!(!ready_path.exists(), "身份校验失败前不得创建 ready 回执");
        assert!(child.try_wait().expect("应查询目标状态").is_none());
        child.kill().expect("应清理测试目标");
        child.wait().expect("应回收测试目标");
    }

    #[test]
    fn runtime_path_replacement_kills_only_verified_target() {
        let directory = TempDir::new().expect("应创建临时日志目录");
        let log_path = test_root(&directory).join("serve.log");
        let displaced_path = test_root(&directory).join("serve.displaced.log");
        let ready_path = test_root(&directory).join("monitor.ready");
        let ready_token = "ready-token-0123456789abcdef";
        std::fs::write(&log_path, b"initial").expect("应写入测试日志");
        let mut child = Command::new(std::env::current_exe().expect("应定位当前测试程序"))
            .args([
                "--exact",
                "logging::tests::log_monitor_target_helper",
                "--ignored",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("应启动 monitor 目标子进程");
        let deadline = Instant::now() + Duration::from_secs(2);
        let marker = loop {
            if let Some(marker) =
                read_process_start_marker(child.id()).expect("应能探测 monitor 目标")
            {
                break marker;
            }
            assert!(Instant::now() < deadline, "应在超时前取得目标启动标记");
            std::thread::sleep(Duration::from_millis(10));
        };
        let config = LogMonitorConfig::new(&log_path, child.id(), marker)
            .expect("应构造 monitor 配置")
            .with_expected_command_parts(vec![
                "logging::tests::log_monitor_target_helper".to_owned()
            ])
            .expect("应设置目标命令身份")
            .with_ready_signal(&ready_path, ready_token)
            .expect("应设置 ready 回执")
            .with_rotation_threshold(64)
            .expect("应设置测试阈值")
            .with_check_interval(Duration::from_millis(10))
            .expect("应设置测试间隔");
        let (sender, receiver) = mpsc::channel();
        let monitor = std::thread::spawn(move || {
            let _ = sender.send(run_log_monitor(&config));
        });
        let ready_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if consume_log_monitor_ready(&ready_path, ready_token).expect("应安全读取 ready 回执")
            {
                break;
            }
            assert!(Instant::now() < ready_deadline, "monitor 应在超时前 ready");
            std::thread::sleep(Duration::from_millis(10));
        }

        std::fs::rename(&log_path, &displaced_path).expect("应替换活动日志路径");
        let replacement = b"replacement-must-survive";
        std::fs::write(&log_path, replacement).expect("应写入替换日志");
        let result = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("路径替换后 monitor 应结束");
        assert!(matches!(result, Err(LogMonitorError::Fatal { .. })));
        let exit_deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if child.try_wait().expect("应查询目标状态").is_some() {
                break;
            }
            if Instant::now() >= exit_deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("日志保护失效后应终止已验证目标");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(&log_path).expect("应读取替换日志"),
            replacement
        );
        monitor.join().expect("monitor 线程应正常结束");
    }
}
