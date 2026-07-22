use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LinuxSupervisorError {
    #[error("Linux 完整隔离只在 Linux 目标上可用")]
    Unsupported,
    #[error("Landlock 规则无法完整应用：{0}")]
    Landlock(String),
    #[error("Landlock 未报告 FullyEnforced")]
    LandlockNotEnforced,
    #[error("seccomp-bpf profile 无法应用：{0}")]
    Seccomp(String),
    #[error("推理引擎路径无效：{0}")]
    InvalidExecutable(PathBuf),
    #[error("无法 exec 已隔离的推理引擎：{0}")]
    Exec(String),
}

#[cfg(target_os = "linux")]
pub fn probe_linux_security_layers() -> Result<(), LinuxSupervisorError> {
    let current =
        std::env::current_exe().map_err(|error| LinuxSupervisorError::Exec(error.to_string()))?;
    let read_only = system_read_paths();
    apply_landlock(&current, &[], &read_only, &[])?;
    apply_seccomp()
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_security_layers() -> Result<(), LinuxSupervisorError> {
    Err(LinuxSupervisorError::Unsupported)
}

/// 独立验证 seccomp-bpf 能否真实安装。该探针不依赖 Landlock，供较旧内核在
/// Landlock 不可用时构建 namespace + bubblewrap + seccomp 的受限降级路径。
#[cfg(target_os = "linux")]
pub fn probe_linux_seccomp() -> Result<(), LinuxSupervisorError> {
    apply_seccomp()
}

#[cfg(not(target_os = "linux"))]
pub fn probe_linux_seccomp() -> Result<(), LinuxSupervisorError> {
    Err(LinuxSupervisorError::Unsupported)
}

#[cfg(target_os = "linux")]
pub fn run_linux_supervisor(
    executable: &Path,
    read_execute: &[PathBuf],
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    args: &[String],
) -> Result<(), LinuxSupervisorError> {
    run_linux_supervisor_profile(executable, read_execute, read_only, read_write, args, true)
}

#[cfg(not(target_os = "linux"))]
pub fn run_linux_supervisor(
    _executable: &Path,
    _read_execute: &[PathBuf],
    _read_only: &[PathBuf],
    _read_write: &[PathBuf],
    _args: &[String],
) -> Result<(), LinuxSupervisorError> {
    Err(LinuxSupervisorError::Unsupported)
}

/// 在外层 namespace + bubblewrap 文件系统中独立安装 seccomp-bpf 后执行引擎。
/// 此路径绝不应用或声明 Landlock，只用于完整 Landlock 探针失败后的明确降级。
#[cfg(target_os = "linux")]
pub fn run_linux_seccomp_supervisor(
    executable: &Path,
    read_execute: &[PathBuf],
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    args: &[String],
) -> Result<(), LinuxSupervisorError> {
    run_linux_supervisor_profile(executable, read_execute, read_only, read_write, args, false)
}

#[cfg(not(target_os = "linux"))]
pub fn run_linux_seccomp_supervisor(
    _executable: &Path,
    _read_execute: &[PathBuf],
    _read_only: &[PathBuf],
    _read_write: &[PathBuf],
    _args: &[String],
) -> Result<(), LinuxSupervisorError> {
    Err(LinuxSupervisorError::Unsupported)
}

#[cfg(target_os = "linux")]
fn run_linux_supervisor_profile(
    executable: &Path,
    read_execute: &[PathBuf],
    read_only: &[PathBuf],
    read_write: &[PathBuf],
    args: &[String],
    require_landlock: bool,
) -> Result<(), LinuxSupervisorError> {
    use std::os::unix::process::CommandExt;

    validate_executable(executable)?;
    if require_landlock {
        let mut system_read = system_read_paths();
        system_read.extend(read_only.iter().cloned());
        apply_landlock(executable, read_execute, &system_read, read_write)?;
    }
    apply_seccomp()?;

    let mut command = std::process::Command::new(executable);
    command.args(args).env_clear().env("LC_ALL", "C");
    if let Some(runtime_directory) = read_write.first() {
        command.env("TMPDIR", runtime_directory);
    }
    let error = command.exec();
    Err(LinuxSupervisorError::Exec(error.to_string()))
}

#[cfg(target_os = "linux")]
fn validate_executable(executable: &Path) -> Result<(), LinuxSupervisorError> {
    let metadata = std::fs::symlink_metadata(executable)
        .map_err(|_| LinuxSupervisorError::InvalidExecutable(executable.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !executable.is_absolute() {
        return Err(LinuxSupervisorError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    let canonical = std::fs::canonicalize(executable)
        .map_err(|_| LinuxSupervisorError::InvalidExecutable(executable.to_path_buf()))?;
    if canonical != executable {
        return Err(LinuxSupervisorError::InvalidExecutable(
            executable.to_path_buf(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_landlock(
    executable: &Path,
    read_execute: &[PathBuf],
    read_only: &[PathBuf],
    read_write: &[PathBuf],
) -> Result<(), LinuxSupervisorError> {
    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    let abi = ABI::V1;
    let handled = AccessFs::from_all(abi);
    let directory_read = AccessFs::ReadFile | AccessFs::ReadDir;
    let writable = directory_read | AccessFs::from_write(abi);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(handled)
        .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?
        .create()
        .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;

    for path in read_only {
        if !path.exists() {
            continue;
        }
        let file =
            PathFd::new(path).map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
        let access = if path.is_file() {
            AccessFs::ReadFile.into()
        } else {
            directory_read
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, access))
            .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    }
    for path in read_execute {
        let file =
            PathFd::new(path).map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
        let access = if path.is_file() {
            AccessFs::ReadFile.into()
        } else {
            directory_read
        };
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, access))
            .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    }
    for path in read_write {
        let file =
            PathFd::new(path).map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
        ruleset = ruleset
            .add_rule(PathBeneath::new(file, writable))
            .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    }
    let engine = PathFd::new(executable)
        .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(
            engine,
            AccessFs::ReadFile | AccessFs::Execute,
        ))
        .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    for loader_directory in ["/lib", "/lib64"] {
        let loader_directory = Path::new(loader_directory);
        if loader_directory.exists() {
            let loader = PathFd::new(loader_directory)
                .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(loader, directory_read | AccessFs::Execute))
                .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
        }
    }
    let status = ruleset
        .restrict_self()
        .map_err(|error| LinuxSupervisorError::Landlock(error.to_string()))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(LinuxSupervisorError::LandlockNotEnforced);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_seccomp() -> Result<(), LinuxSupervisorError> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule,
    };
    use std::collections::BTreeMap;

    let mut rules = blocked_syscalls()
        .into_iter()
        .map(|syscall| (syscall, Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let namespace_flags = [
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWUTS,
    ];
    let clone_rules = namespace_flags
        .into_iter()
        .map(|flag| {
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::MaskedEq(flag as u64),
                flag as u64,
            )
            .map_err(|error| LinuxSupervisorError::Seccomp(error.to_string()))
            .and_then(|condition| {
                SeccompRule::new(vec![condition])
                    .map_err(|error| LinuxSupervisorError::Seccomp(error.to_string()))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.insert(libc::SYS_clone, clone_rules);
    let architecture =
        std::env::consts::ARCH
            .try_into()
            .map_err(|error: seccompiler::BackendError| {
                LinuxSupervisorError::Seccomp(error.to_string())
            })?;
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        // clone3 无法安全检查其指针参数。返回 ENOSYS 可让 glibc 的线程
        // 创建路径回退到受参数过滤的 clone，同时对其他危险 syscall 仍
        // 是确定性的拒绝。
        SeccompAction::Errno(libc::ENOSYS as u32),
        architecture,
    )
    .map_err(|error| LinuxSupervisorError::Seccomp(error.to_string()))?
    .try_into()
    .map_err(|error: seccompiler::BackendError| LinuxSupervisorError::Seccomp(error.to_string()))?;
    seccompiler::apply_filter(&filter)
        .map_err(|error| LinuxSupervisorError::Seccomp(error.to_string()))
}

#[cfg(target_os = "linux")]
fn blocked_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_open_by_handle_at,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_fanotify_init,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_connect,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_clone3,
    ]
}

#[cfg(target_os = "linux")]
fn system_read_paths() -> Vec<PathBuf> {
    [
        "/usr",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/proc",
        "/dev",
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|path| path.exists())
    .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_profile_blocks_high_risk_and_outbound_syscalls() {
        let blocked = super::blocked_syscalls();
        assert!(blocked.contains(&libc::SYS_ptrace));
        assert!(blocked.contains(&libc::SYS_mount));
        assert!(blocked.contains(&libc::SYS_bpf));
        assert!(blocked.contains(&libc::SYS_connect));
    }
}
