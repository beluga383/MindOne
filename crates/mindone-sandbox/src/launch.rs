use crate::capability::{detect_capabilities, IsolationMechanism, Platform, TrustLevel};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxAccess {
    /// 允许读取并映射动态库的可信引擎目录。
    pub read_execute: Vec<PathBuf>,
    /// 只允许作为数据读取，禁止映射为可执行代码的目录。
    pub read_only: Vec<PathBuf>,
    pub read_write: Vec<PathBuf>,
    pub allow_loopback_network: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub applied: Vec<IsolationMechanism>,
    pub trust_level: TrustLevel,
    pub note: String,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("推理引擎路径不存在或不是普通文件：{0}")]
    InvalidExecutable(PathBuf),
    #[error("沙盒访问路径无效：{0}")]
    InvalidAccessPath(PathBuf),
    #[error("当前平台无法应用要求的推理沙盒：{0}")]
    Unavailable(String),
}

/// 构建真实可执行的沙盒启动计划。返回值中的 `applied` 仅包含该计划会应用的机制。
pub fn build_launch_plan(
    executable: &Path,
    args: &[String],
    access: &SandboxAccess,
) -> Result<LaunchPlan, SandboxError> {
    build_launch_plan_with_supervisor(executable, args, access, None)
}

/// 构建沙盒启动计划，并在 Linux 上使用当前 MindOne 可执行文件作为
/// Landlock/seccomp 监督进程。监督进程必须是已经解析过的绝对普通文件；
/// 任何探针失败都会保留显式降级，不会把仅“可用”的能力写成已应用。
pub fn build_launch_plan_with_supervisor(
    executable: &Path,
    args: &[String],
    access: &SandboxAccess,
    supervisor: Option<&Path>,
) -> Result<LaunchPlan, SandboxError> {
    let executable = validated_executable(executable)?;
    let access = validated_access(access)?;
    let supervisor = supervisor.map(validated_executable).transpose()?;
    let report = detect_capabilities();
    match report.platform {
        Platform::MacOs => macos_plan(&executable, args, &access),
        Platform::Linux => linux_plan(&executable, args, &access, supervisor.as_deref()),
        Platform::Windows => windows_plan(&executable, args, supervisor.as_deref()),
        Platform::Other => Err(SandboxError::Unavailable(
            "没有该平台的隔离适配器".to_owned(),
        )),
    }
}

fn validated_executable(executable: &Path) -> Result<PathBuf, SandboxError> {
    if !executable.is_absolute() {
        return Err(SandboxError::InvalidExecutable(executable.to_path_buf()));
    }
    let metadata = fs::symlink_metadata(executable)
        .map_err(|_| SandboxError::InvalidExecutable(executable.to_path_buf()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SandboxError::InvalidExecutable(executable.to_path_buf()));
    }
    let canonical = fs::canonicalize(executable)
        .map_err(|_| SandboxError::InvalidExecutable(executable.to_path_buf()))?;
    let canonical_metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| SandboxError::InvalidExecutable(executable.to_path_buf()))?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_file() {
        return Err(SandboxError::InvalidExecutable(executable.to_path_buf()));
    }
    Ok(canonical)
}

fn validated_access(access: &SandboxAccess) -> Result<SandboxAccess, SandboxError> {
    Ok(SandboxAccess {
        read_execute: access
            .read_execute
            .iter()
            .map(|path| canonical_access_path(path))
            .collect::<Result<Vec<_>, _>>()?,
        read_only: access
            .read_only
            .iter()
            .map(|path| canonical_access_path(path))
            .collect::<Result<Vec<_>, _>>()?,
        read_write: access
            .read_write
            .iter()
            .map(|path| canonical_access_path(path))
            .collect::<Result<Vec<_>, _>>()?,
        allow_loopback_network: access.allow_loopback_network,
    })
}

fn canonical_access_path(path: &Path) -> Result<PathBuf, SandboxError> {
    if !path.is_absolute() {
        return Err(SandboxError::InvalidAccessPath(path.to_path_buf()));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| SandboxError::InvalidAccessPath(path.to_path_buf()))?;
    if metadata.file_type().is_symlink() {
        return Err(SandboxError::InvalidAccessPath(path.to_path_buf()));
    }
    fs::canonicalize(path).map_err(|_| SandboxError::InvalidAccessPath(path.to_path_buf()))
}

#[cfg(target_os = "macos")]
fn macos_plan(
    executable: &Path,
    args: &[String],
    access: &SandboxAccess,
) -> Result<LaunchPlan, SandboxError> {
    if crate::capability::inherited_macos_sandbox() {
        return Ok(LaunchPlan {
            program: executable.to_path_buf(),
            args: args.to_vec(),
            applied: vec![IsolationMechanism::InheritedAppSandbox],
            trust_level: TrustLevel::StandardLimited,
            note: "子进程继承当前 App Sandbox/Seatbelt 约束".to_owned(),
        });
    }

    let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
    if !sandbox_exec.is_file() || !seatbelt_probe() {
        return Err(SandboxError::Unavailable(
            "Seatbelt profile 无法在当前进程中应用".to_owned(),
        ));
    }
    let profile = seatbelt_profile(executable, access)?;
    let mut launch_args = vec!["-p".to_owned(), profile, "--".to_owned()];
    launch_args.push(executable.to_string_lossy().into_owned());
    launch_args.extend(args.iter().cloned());
    Ok(LaunchPlan {
        program: sandbox_exec.to_path_buf(),
        args: launch_args,
        applied: vec![IsolationMechanism::Seatbelt],
        trust_level: TrustLevel::StandardLimited,
        note: "已生成并应用最小文件访问 Seatbelt profile".to_owned(),
    })
}

#[cfg(not(target_os = "macos"))]
fn macos_plan(
    _executable: &Path,
    _args: &[String],
    _access: &SandboxAccess,
) -> Result<LaunchPlan, SandboxError> {
    Err(SandboxError::Unavailable("当前并非 macOS".to_owned()))
}

#[cfg(target_os = "macos")]
fn seatbelt_probe() -> bool {
    Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn seatbelt_profile(executable: &Path, access: &SandboxAccess) -> Result<String, SandboxError> {
    let mut profile = String::from("(version 1)\n(deny default)\n");
    if Path::new("/System/Library/Sandbox/Profiles/dyld-support.sb").is_file()
        || Path::new("/usr/share/sandbox/dyld-support.sb").is_file()
    {
        // macOS 13+ 的 dyld/libignition 启动还需要受限 openat、fstatat、
        // map_with_linking_np 与签名校验规则。导入系统随 OS 更新的最小规则，
        // 不复制易漂移的私有 syscall 编号，也不导入更宽的 system.sb。
        profile.push_str("(import \"dyld-support.sb\")\n");
    }
    profile.push_str(
        "(allow process-info*)\n(allow sysctl-read)\n(allow mach-lookup)\n\
         (allow file-read-metadata)\n\
         (allow file-read* file-test-existence (subpath \"/System\") (subpath \"/usr/lib\") \
         (subpath \"/usr/share\") (subpath \"/Library/Apple\") \
         (subpath \"/private/var/db/dyld\") (subpath \"/private/var/db/timezone\"))\n\
         (allow file-map-executable (subpath \"/System/Library\") (subpath \"/usr/lib\") \
         (subpath \"/Library/Apple\"))\n",
    );
    profile.push_str(&format!(
        "(allow process-exec (literal \"{}\"))\n",
        escape_seatbelt(executable)?
    ));
    profile.push_str(&format!(
        "(allow file-read* file-map-executable (literal \"{}\"))\n",
        escape_seatbelt(executable)?
    ));
    for path in &access.read_execute {
        profile.push_str(&format!(
            "(allow file-read* file-map-executable {})\n",
            seatbelt_path_filter(path)?
        ));
    }
    for path in &access.read_only {
        profile.push_str(&format!(
            "(allow file-read* {})\n",
            seatbelt_path_filter(path)?
        ));
    }
    for path in &access.read_write {
        profile.push_str(&format!(
            "(allow file-read* file-write* {})\n",
            seatbelt_path_filter(path)?
        ));
    }
    if access.allow_loopback_network {
        profile.push_str("(allow network-inbound (local ip \"localhost:*\"))\n");
        profile.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
    }
    Ok(profile)
}

#[cfg(target_os = "macos")]
fn escape_seatbelt(path: &Path) -> Result<String, SandboxError> {
    let value = path.to_string_lossy();
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '"' | '\\'))
    {
        return Err(SandboxError::InvalidAccessPath(path.to_path_buf()));
    }
    Ok(value.into_owned())
}

#[cfg(target_os = "macos")]
fn seatbelt_path_filter(path: &Path) -> Result<String, SandboxError> {
    let operator = if path.is_file() { "literal" } else { "subpath" };
    Ok(format!("({operator} \"{}\")", escape_seatbelt(path)?))
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxSupervisorProfile {
    Full,
    SeccompOnly,
    None,
}

#[cfg(any(target_os = "linux", test))]
const fn select_linux_supervisor_profile(
    full_probe_passed: bool,
    seccomp_probe_passed: bool,
) -> LinuxSupervisorProfile {
    if full_probe_passed {
        LinuxSupervisorProfile::Full
    } else if seccomp_probe_passed {
        LinuxSupervisorProfile::SeccompOnly
    } else {
        LinuxSupervisorProfile::None
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_applied_mechanisms(
    profile: LinuxSupervisorProfile,
    restricted_apparmor: bool,
) -> Vec<IsolationMechanism> {
    let mut applied = vec![
        IsolationMechanism::LinuxNamespaces,
        IsolationMechanism::Bubblewrap,
    ];
    match profile {
        LinuxSupervisorProfile::Full => {
            applied.push(IsolationMechanism::SeccompBpf);
            applied.push(IsolationMechanism::Landlock);
        }
        LinuxSupervisorProfile::SeccompOnly => {
            applied.push(IsolationMechanism::SeccompBpf);
        }
        LinuxSupervisorProfile::None => {}
    }
    if restricted_apparmor {
        applied.push(IsolationMechanism::AppArmor);
    }
    applied
}

#[cfg(any(target_os = "linux", test))]
fn parse_restricted_apparmor_profile(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    let profile = trimmed.strip_suffix(" (enforce)")?.trim();
    if profile.is_empty() || profile == "unconfined" {
        return None;
    }
    Some(profile)
}

#[cfg(target_os = "linux")]
fn restricted_apparmor_profile() -> Option<String> {
    let enabled = fs::read_to_string("/sys/module/apparmor/parameters/enabled").ok()?;
    if enabled.trim() != "Y" {
        return None;
    }
    let current = fs::read_to_string("/proc/self/attr/current").ok()?;
    if current.len() > 4096 {
        return None;
    }
    parse_restricted_apparmor_profile(&current).map(str::to_owned)
}

#[cfg(target_os = "linux")]
fn linux_plan(
    executable: &Path,
    args: &[String],
    access: &SandboxAccess,
    supervisor: Option<&Path>,
) -> Result<LaunchPlan, SandboxError> {
    let bwrap = trusted_bwrap().ok_or_else(|| {
        SandboxError::Unavailable(
            "缺少固定路径、root 所有且不可被普通用户改写的 bubblewrap；不会在未隔离状态下启动推理引擎"
                .to_owned(),
        )
    })?;
    if !bubblewrap_probe(&bwrap) {
        return Err(SandboxError::Unavailable(
            "bubblewrap 存在，但当前内核/权限无法建立 user、mount、PID 等 namespace".to_owned(),
        ));
    }

    let mut launch_args = vec![
        "--new-session".to_owned(),
        "--unshare-all".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--ro-bind".to_owned(),
        "/usr".to_owned(),
        "/usr".to_owned(),
        "--ro-bind".to_owned(),
        "/lib".to_owned(),
        "/lib".to_owned(),
    ];
    // `--unshare-all` 默认隔离网络。受管服务需要让宿主访问 127.0.0.1，
    // 此时共享 network namespace，但完整方案会用 seccomp 拒绝主动连接类
    // syscall；不需要本地服务时继续使用独立 network namespace。
    if access.allow_loopback_network {
        launch_args.push("--share-net".to_owned());
    }
    if Path::new("/lib64").exists() {
        launch_args.extend([
            "--ro-bind".to_owned(),
            "/lib64".to_owned(),
            "/lib64".to_owned(),
        ]);
    }
    if Path::new("/etc/ld.so.cache").is_file() {
        launch_args.extend([
            "--ro-bind".to_owned(),
            "/etc/ld.so.cache".to_owned(),
            "/etc/ld.so.cache".to_owned(),
        ]);
    }
    for path in access.read_execute.iter().chain(&access.read_only) {
        let value = path.to_string_lossy().into_owned();
        launch_args.extend(["--ro-bind".to_owned(), value.clone(), value]);
    }
    for path in &access.read_write {
        let value = path.to_string_lossy().into_owned();
        launch_args.extend(["--bind".to_owned(), value.clone(), value]);
    }

    let full_probe_passed = supervisor
        .map(|program| supervisor_security_probe(program, "sandbox-probe"))
        .unwrap_or(false);
    let seccomp_probe_passed = !full_probe_passed
        && supervisor
            .map(|program| supervisor_security_probe(program, "sandbox-seccomp-probe"))
            .unwrap_or(false);
    let supervisor_profile =
        select_linux_supervisor_profile(full_probe_passed, seccomp_probe_passed);
    let active_supervisor = match supervisor_profile {
        LinuxSupervisorProfile::Full | LinuxSupervisorProfile::SeccompOnly => supervisor,
        LinuxSupervisorProfile::None => None,
    };
    if let Some(supervisor) = active_supervisor {
        let value = supervisor.to_string_lossy().into_owned();
        launch_args.extend(["--ro-bind".to_owned(), value.clone(), value]);
    }

    launch_args.extend([
        "--clearenv".to_owned(),
        "--setenv".to_owned(),
        "LC_ALL".to_owned(),
        "C".to_owned(),
    ]);
    launch_args.push("--".to_owned());
    if let Some(supervisor) = active_supervisor {
        launch_args.push(supervisor.to_string_lossy().into_owned());
        launch_args.extend([
            "__worker".to_owned(),
            match supervisor_profile {
                LinuxSupervisorProfile::Full => "sandbox-exec",
                LinuxSupervisorProfile::SeccompOnly => "sandbox-seccomp-exec",
                LinuxSupervisorProfile::None => {
                    return Err(SandboxError::Unavailable(
                        "Linux 监督进程状态不一致，拒绝启动推理引擎".to_owned(),
                    ));
                }
            }
            .to_owned(),
            "--executable".to_owned(),
            executable.to_string_lossy().into_owned(),
        ]);
        append_path_options(&mut launch_args, "--read-execute", &access.read_execute);
        append_path_options(&mut launch_args, "--read-only", &access.read_only);
        append_path_options(&mut launch_args, "--read-write", &access.read_write);
        launch_args.push("--".to_owned());
        launch_args.extend(args.iter().cloned());
        let apparmor_profile = restricted_apparmor_profile();
        let applied = linux_applied_mechanisms(supervisor_profile, apparmor_profile.is_some());
        let (trust_level, note) = match supervisor_profile {
            LinuxSupervisorProfile::Full => (
                TrustLevel::Standard,
                if let Some(profile) = apparmor_profile {
                    format!(
                        "已通过运行时探针并组合应用 namespace、bubblewrap、Landlock 与 seccomp-bpf，并继承受限 AppArmor profile {profile}；主动网络连接 syscall 被拒绝"
                    )
                } else {
                    "已通过运行时探针并组合应用 namespace、bubblewrap、Landlock 与 seccomp-bpf；主动网络连接 syscall 被拒绝".to_owned()
                },
            ),
            LinuxSupervisorProfile::SeccompOnly => (
                TrustLevel::StandardLimited,
                if let Some(profile) = apparmor_profile {
                    format!(
                        "Landlock 完整探针失败；已实际应用 namespace、bubblewrap 与独立 seccomp-bpf，并继承受限 AppArmor profile {profile}；明确降级为 Standard-Limited"
                    )
                } else {
                    "Landlock 完整探针失败；已实际应用 namespace、bubblewrap 与独立 seccomp-bpf，明确降级为 Standard-Limited".to_owned()
                },
            ),
            LinuxSupervisorProfile::None => {
                return Err(SandboxError::Unavailable(
                    "Linux 监督进程状态不一致，拒绝启动推理引擎".to_owned(),
                ));
            }
        };
        Ok(LaunchPlan {
            program: bwrap,
            args: launch_args,
            applied,
            trust_level,
            note,
        })
    } else {
        launch_args.push(executable.to_string_lossy().into_owned());
        launch_args.extend(args.iter().cloned());
        let apparmor_profile = restricted_apparmor_profile();
        let applied =
            linux_applied_mechanisms(LinuxSupervisorProfile::None, apparmor_profile.is_some());
        Ok(LaunchPlan {
            program: bwrap,
            args: launch_args,
            applied,
            trust_level: TrustLevel::StandardLimited,
            note: if let Some(profile) = apparmor_profile {
                format!(
                    "已应用 namespace 与 bubblewrap 只读文件系统，并继承受限 AppArmor profile {profile}；监督进程 seccomp/Landlock 探针未通过"
                )
            } else {
                "已应用 namespace 与 bubblewrap 只读文件系统；监督进程探针未通过，未声称已应用 seccomp/Landlock".to_owned()
            },
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn linux_plan(
    _executable: &Path,
    _args: &[String],
    _access: &SandboxAccess,
    _supervisor: Option<&Path>,
) -> Result<LaunchPlan, SandboxError> {
    Err(SandboxError::Unavailable("当前并非 Linux".to_owned()))
}

#[cfg(target_os = "windows")]
fn windows_plan(
    executable: &Path,
    args: &[String],
    supervisor: Option<&Path>,
) -> Result<LaunchPlan, SandboxError> {
    if let Some(supervisor) = supervisor {
        let mut launch_args = vec![
            "__worker".to_owned(),
            "windows-job-exec".to_owned(),
            "--executable".to_owned(),
            executable.to_string_lossy().into_owned(),
            "--emit-proof".to_owned(),
            "--".to_owned(),
        ];
        launch_args.extend(args.iter().cloned());
        return Ok(LaunchPlan {
            program: supervisor.to_path_buf(),
            args: launch_args,
            applied: vec![IsolationMechanism::WindowsJobObject],
            trust_level: TrustLevel::Experimental,
            note: "通过 MindOne 监督进程创建并长期持有 KILL_ON_JOB_CLOSE Job Object；未建立真实 AppContainer，信任等级保持 Experimental"
                .to_owned(),
        });
    }

    Ok(LaunchPlan {
        program: executable.to_path_buf(),
        args: args.to_vec(),
        applied: Vec::new(),
        trust_level: TrustLevel::Experimental,
        note: "未提供 MindOne Job Object 监督进程；明确降级为 Experimental，未声明已应用机制"
            .to_owned(),
    })
}

#[cfg(not(target_os = "windows"))]
fn windows_plan(
    _executable: &Path,
    _args: &[String],
    _supervisor: Option<&Path>,
) -> Result<LaunchPlan, SandboxError> {
    Err(SandboxError::Unavailable("当前并非 Windows".to_owned()))
}

#[cfg(target_os = "linux")]
fn append_path_options(args: &mut Vec<String>, option: &str, paths: &[PathBuf]) {
    for path in paths {
        args.push(option.to_owned());
        args.push(path.to_string_lossy().into_owned());
    }
}

#[cfg(target_os = "linux")]
fn trusted_bwrap() -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;

    [
        "/usr/bin/bwrap",
        "/bin/bwrap",
        "/usr/local/bin/bwrap",
        "/run/current-system/sw/bin/bwrap",
    ]
    .into_iter()
    .map(Path::new)
    .find_map(|candidate| {
        let metadata = fs::symlink_metadata(candidate).ok()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return None;
        }
        fs::canonicalize(candidate).ok()
    })
}

#[cfg(target_os = "linux")]
fn bubblewrap_probe(program: &Path) -> bool {
    let probe = if Path::new("/usr/bin/true").is_file() {
        "/usr/bin/true"
    } else {
        "/bin/true"
    };
    Command::new(program)
        .args([
            "--new-session",
            "--unshare-all",
            "--share-net",
            "--ro-bind",
            "/",
            "/",
            "--",
            probe,
        ])
        .env_clear()
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn supervisor_security_probe(program: &Path, probe_command: &str) -> bool {
    Command::new(program)
        .args(["__worker", probe_command])
        .env_clear()
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;

    #[test]
    fn linux_profile_selection_preserves_full_gate_and_seccomp_fallback() {
        assert_eq!(
            select_linux_supervisor_profile(true, true),
            LinuxSupervisorProfile::Full
        );
        assert_eq!(
            select_linux_supervisor_profile(true, false),
            LinuxSupervisorProfile::Full
        );
        assert_eq!(
            select_linux_supervisor_profile(false, true),
            LinuxSupervisorProfile::SeccompOnly
        );
        assert_eq!(
            select_linux_supervisor_profile(false, false),
            LinuxSupervisorProfile::None
        );
    }

    #[test]
    fn linux_fallback_claims_only_mechanisms_that_are_actually_applied() {
        let fallback = linux_applied_mechanisms(LinuxSupervisorProfile::SeccompOnly, false);
        assert!(fallback.contains(&IsolationMechanism::LinuxNamespaces));
        assert!(fallback.contains(&IsolationMechanism::Bubblewrap));
        assert!(fallback.contains(&IsolationMechanism::SeccompBpf));
        assert!(!fallback.contains(&IsolationMechanism::Landlock));
        assert!(!fallback.contains(&IsolationMechanism::AppArmor));

        let fallback_with_apparmor =
            linux_applied_mechanisms(LinuxSupervisorProfile::SeccompOnly, true);
        assert!(fallback_with_apparmor.contains(&IsolationMechanism::AppArmor));
    }

    #[test]
    fn apparmor_requires_a_real_enforcing_non_unconfined_profile() {
        assert_eq!(
            parse_restricted_apparmor_profile("mindone-engine (enforce)\n"),
            Some("mindone-engine")
        );
        assert_eq!(
            parse_restricted_apparmor_profile("docker-default (enforce)"),
            Some("docker-default")
        );
        assert_eq!(parse_restricted_apparmor_profile("unconfined\n"), None);
        assert_eq!(
            parse_restricted_apparmor_profile("mindone-engine (complain)\n"),
            None
        );
        assert_eq!(
            parse_restricted_apparmor_profile("mindone\nforged (enforce)"),
            None
        );
    }

    #[test]
    fn rejects_relative_access_paths() {
        let temp = tempfile_path();
        let access = SandboxAccess {
            read_execute: Vec::new(),
            read_only: vec![PathBuf::from("relative")],
            read_write: Vec::new(),
            allow_loopback_network: true,
        };
        let result = build_launch_plan(&temp, &[], &access);
        assert!(matches!(result, Err(SandboxError::InvalidAccessPath(_))));
        let _ = fs::remove_file(temp);
    }

    #[test]
    fn rejects_relative_and_symlink_executables() {
        assert!(matches!(
            validated_executable(Path::new("relative-engine")),
            Err(SandboxError::InvalidExecutable(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let directory = tempfile::tempdir();
            assert!(directory.is_ok());
            let Ok(directory) = directory else { return };
            let target = directory.path().join("target");
            let link = directory.path().join("link");
            assert!(fs::write(&target, b"test").is_ok());
            assert!(symlink(&target, &link).is_ok());
            assert!(matches!(
                validated_executable(&link),
                Err(SandboxError::InvalidExecutable(_))
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn access_paths_are_canonicalized_before_policy_generation() {
        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let access = SandboxAccess {
            read_execute: Vec::new(),
            read_only: vec![directory.path().to_path_buf()],
            read_write: Vec::new(),
            allow_loopback_network: false,
        };
        let validated = validated_access(&access);
        assert!(validated.is_ok());
        let Ok(validated) = validated else { return };
        let expected = fs::canonicalize(directory.path());
        assert!(expected.is_ok());
        let Ok(expected) = expected else { return };
        assert_eq!(validated.read_only, vec![expected]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_profile_allows_only_canonical_target_execution() {
        let executable = Path::new("/usr/bin/true");
        let canonical = fs::canonicalize(executable);
        assert!(canonical.is_ok());
        let Ok(canonical) = canonical else { return };
        let access = SandboxAccess {
            read_execute: Vec::new(),
            read_only: Vec::new(),
            read_write: Vec::new(),
            allow_loopback_network: false,
        };
        let profile = seatbelt_profile(&canonical, &access);
        assert!(profile.is_ok());
        let Ok(profile) = profile else { return };
        assert!(profile.contains(&format!(
            "(allow process-exec (literal \"{}\"))",
            canonical.display()
        )));
        assert!(!profile.contains("CODEX_SANDBOX"));
        assert!(!profile.contains("APP_SANDBOX_CONTAINER_ID"));
    }

    fn tempfile_path() -> PathBuf {
        let path = env::temp_dir().join(format!("mindone-sandbox-test-{}", std::process::id()));
        let _ = fs::write(&path, b"test");
        path
    }
}
