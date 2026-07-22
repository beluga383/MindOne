use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WindowsSupervisorError {
    #[error("Windows Job Object 监督进程只在 Windows 目标上可用")]
    Unsupported,
    #[error("推理引擎路径无效：{0}")]
    InvalidExecutable(PathBuf),
    #[error("无法创建带 KILL_ON_JOB_CLOSE 的 Windows Job Object：{0}")]
    CreateJob(String),
    #[error("无法把 Windows 监督进程加入 Job Object：{0}")]
    AssignSupervisor(String),
    #[error("Windows Job Object 未确认监督进程 PID")]
    SupervisorNotInJob,
    #[error("无法启动 Windows Job Object 内的推理引擎：{0}")]
    Spawn(String),
    #[error("无法查询 Windows Job Object 的进程列表：{0}")]
    QueryProcesses(String),
    #[error("Windows Job Object 未确认推理引擎 PID")]
    EngineNotInJob,
    #[error("等待 Windows Job Object 内的推理引擎失败：{0}")]
    Wait(String),
    #[error("Windows 推理引擎没有可传递的退出码")]
    MissingExitCode,
}

/// 在长期持有的 Job Object 中运行推理引擎，并原样传递其 Windows 退出码。
///
/// 监督进程先把自身加入带 `KILL_ON_JOB_CLOSE` 的 Job Object，再创建子进程，
/// 因而子进程从创建时即继承 Job Object，不存在先启动、后分配的逃逸窗口。成功
/// 路径不会返回，而是在 Job handle 仍打开时退出当前进程；Windows 随后关闭
/// handle。错误路径也保留 handle 到 CLI 输出完错误并退出，避免提前关闭 Job
/// Object 直接终止当前监督进程。
#[cfg(target_os = "windows")]
pub fn run_windows_job_supervisor(
    executable: &Path,
    args: &[String],
    emit_proof: bool,
) -> Result<(), WindowsSupervisorError> {
    use std::process::Command;
    use win32job::{ExtendedLimitInfo, Job};

    let executable = validated_executable(executable)?;
    let mut limits = ExtendedLimitInfo::new();
    limits.limit_kill_on_job_close();
    let job = Job::create_with_limit_info(&limits)
        .map_err(|error| WindowsSupervisorError::CreateJob(error.to_string()))?;

    if let Err(error) = job.assign_current_process() {
        return keep_job_until_process_exit(
            job,
            WindowsSupervisorError::AssignSupervisor(error.to_string()),
        );
    }
    let supervisor_pid = std::process::id() as usize;
    match job.query_process_id_list() {
        Ok(processes) if processes.contains(&supervisor_pid) => {}
        Ok(_) => {
            return keep_job_until_process_exit(job, WindowsSupervisorError::SupervisorNotInJob);
        }
        Err(error) => {
            return keep_job_until_process_exit(
                job,
                WindowsSupervisorError::QueryProcesses(error.to_string()),
            );
        }
    }

    let mut command = Command::new(&executable);
    command.args(args).env_clear().env("LC_ALL", "C");
    for name in ["SystemRoot", "WINDIR", "TEMP", "TMP"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return keep_job_until_process_exit(
                job,
                WindowsSupervisorError::Spawn(error.to_string()),
            );
        }
    };
    let engine_pid = child.id() as usize;
    match job.query_process_id_list() {
        Ok(processes) if processes.contains(&engine_pid) => {}
        Ok(_) => {
            terminate_child(&mut child);
            return keep_job_until_process_exit(job, WindowsSupervisorError::EngineNotInJob);
        }
        Err(error) => {
            terminate_child(&mut child);
            return keep_job_until_process_exit(
                job,
                WindowsSupervisorError::QueryProcesses(error.to_string()),
            );
        }
    }

    if emit_proof {
        eprintln!(
            "{{\"event\":\"windows_job_object_verified\",\"supervisor_pid\":{supervisor_pid},\"engine_pid\":{engine_pid}}}"
        );
    }
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            terminate_child(&mut child);
            return keep_job_until_process_exit(
                job,
                WindowsSupervisorError::Wait(error.to_string()),
            );
        }
    };
    let Some(exit_code) = status.code() else {
        return keep_job_until_process_exit(job, WindowsSupervisorError::MissingExitCode);
    };

    // `process::exit` 不运行析构；Job handle 会由 Windows 在进程终止时关闭。
    // 此时子进程已退出，同时满足“保持 handle 到进程退出”的安全边界。
    std::mem::forget(job);
    std::process::exit(exit_code);
}

#[cfg(target_os = "windows")]
fn validated_executable(executable: &Path) -> Result<PathBuf, WindowsSupervisorError> {
    if !executable.is_absolute() {
        return Err(WindowsSupervisorError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    let metadata = std::fs::symlink_metadata(executable)
        .map_err(|_| WindowsSupervisorError::InvalidExecutable(executable.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(WindowsSupervisorError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    let canonical = std::fs::canonicalize(executable)
        .map_err(|_| WindowsSupervisorError::InvalidExecutable(executable.to_path_buf()))?;
    if canonical != executable {
        return Err(WindowsSupervisorError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "windows")]
fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "windows")]
fn keep_job_until_process_exit<T>(
    job: win32job::Job,
    error: WindowsSupervisorError,
) -> Result<T, WindowsSupervisorError> {
    // 当前进程已经属于带 KILL_ON_JOB_CLOSE 的 Job。提前 drop 会让 Windows
    // 立即终止监督进程，来不及通过普通 Result 输出中文错误。交由进程退出时
    // 的内核 handle 清理，既保持 fail-closed，也不会产生跨进程资源泄漏。
    std::mem::forget(job);
    Err(error)
}

#[cfg(not(target_os = "windows"))]
pub fn run_windows_job_supervisor(
    _executable: &Path,
    _args: &[String],
    _emit_proof: bool,
) -> Result<(), WindowsSupervisorError> {
    Err(WindowsSupervisorError::Unsupported)
}
