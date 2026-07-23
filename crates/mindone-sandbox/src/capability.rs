use serde::{Deserialize, Serialize};
use std::env;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::process::Command;

/// MindOne 支持的平台标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Linux,
    MacOs,
    Windows,
    Other,
}

/// 执行环境的实际能力等级。结算信任桶由服务端另行映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustLevel {
    Enhanced,
    Standard,
    StandardLimited,
    Experimental,
    Unverified,
}

/// 能够被真实探测或应用的隔离机制。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolationMechanism {
    LinuxNamespaces,
    SeccompBpf,
    Landlock,
    AppArmor,
    Bubblewrap,
    Seatbelt,
    InheritedAppSandbox,
    WindowsJobObject,
    WindowsAppContainer,
    HyperV,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReport {
    pub platform: Platform,
    pub os_version: String,
    pub kernel_version: String,
    pub available: Vec<IsolationMechanism>,
    pub applicable: Vec<IsolationMechanism>,
    pub trust_level: TrustLevel,
    pub warnings: Vec<String>,
}

/// 探测当前进程能够实际使用的隔离能力。
pub fn detect_capabilities() -> CapabilityReport {
    #[cfg(target_os = "macos")]
    {
        return detect_macos();
    }
    #[cfg(target_os = "linux")]
    {
        return detect_linux(None);
    }
    #[cfg(target_os = "windows")]
    {
        return detect_windows();
    }
    #[allow(unreachable_code)]
    CapabilityReport {
        platform: Platform::Other,
        os_version: env::consts::OS.to_owned(),
        kernel_version: String::new(),
        available: Vec::new(),
        applicable: Vec::new(),
        trust_level: TrustLevel::Unverified,
        warnings: vec!["当前平台没有可用的 MindOne 沙盒适配器".to_owned()],
    }
}

/// 在 Linux 上通过指定 MindOne 监督进程执行破坏性能力探针；探针运行在
/// 独立子进程中，因此不会给调用方自身安装不可逆的 Landlock/seccomp 规则。
/// 其他平台与 [`detect_capabilities`] 等价。
pub fn detect_capabilities_with_supervisor(supervisor: &Path) -> CapabilityReport {
    #[cfg(target_os = "linux")]
    {
        detect_linux(Some(supervisor))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = supervisor;
        detect_capabilities()
    }
}

#[cfg(target_os = "macos")]
fn detect_macos() -> CapabilityReport {
    let os_version = command_text("/usr/bin/sw_vers", &["-productVersion"]);
    let kernel_version = command_text("/usr/bin/uname", &["-r"]);
    let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
    let inherited = inherited_macos_sandbox();
    // 已处于 App Sandbox 时再次调用 sandbox-exec 会被内核拒绝；只有未继承
    // App Sandbox 时才执行独立 profile 探针，避免把正常的嵌套拒绝写到 stderr。
    let sandbox_probe = !inherited
        && sandbox_exec.is_file()
        && Command::new(sandbox_exec)
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);

    let mut available = Vec::new();
    let mut applicable = Vec::new();
    let mut warnings = Vec::new();
    if sandbox_exec.is_file() {
        available.push(IsolationMechanism::Seatbelt);
    }
    if inherited {
        available.push(IsolationMechanism::InheritedAppSandbox);
        applicable.push(IsolationMechanism::InheritedAppSandbox);
    }
    if sandbox_probe {
        applicable.push(IsolationMechanism::Seatbelt);
    } else if sandbox_exec.is_file() && !inherited {
        warnings.push("检测到 sandbox-exec，但当前进程无法应用 Seatbelt profile".to_owned());
    }

    let trust_level = if applicable.is_empty() {
        warnings.push("未检测到可实际应用的 macOS 沙盒；执行等级降为 Experimental".to_owned());
        TrustLevel::Experimental
    } else {
        warnings.push("macOS 无法提供目标 TEE 数据机密性，最高为 Standard-Limited".to_owned());
        TrustLevel::StandardLimited
    };

    CapabilityReport {
        platform: Platform::MacOs,
        os_version,
        kernel_version,
        available,
        applicable,
        trust_level,
        warnings,
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn inherited_macos_sandbox() -> bool {
    // APP_SANDBOX_CONTAINER_ID 与 CODEX_SANDBOX 都能由普通子进程伪造，不能
    // 作为安全证据。codesign 的 +PID 形式查询当前正在运行的内核代码对象，
    // 只有签名中真实携带 App Sandbox entitlement 时才走继承分支。
    let pid = format!("+{}", std::process::id());
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--entitlements", "-", &pid])
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    entitlement_is_true(&text, "com.apple.security.app-sandbox")
}

#[cfg(target_os = "macos")]
fn entitlement_is_true(text: &str, wanted: &str) -> bool {
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let wanted_key = format!("[Key] {wanted}");
    while let Some(line) = lines.next() {
        if line != wanted_key {
            continue;
        }
        return matches!(
            (lines.next(), lines.next()),
            (Some("[Value]"), Some("[Bool] true"))
        );
    }
    false
}

#[cfg(target_os = "linux")]
fn detect_linux(supervisor: Option<&Path>) -> CapabilityReport {
    let kernel_version = command_text("/usr/bin/uname", &["-r"]);
    let os_version = read_os_release();
    let mut available = Vec::new();
    let mut applicable = Vec::new();
    let mut warnings = Vec::new();

    if Path::new("/proc/self/ns/user").exists() && Path::new("/proc/self/ns/mnt").exists() {
        available.push(IsolationMechanism::LinuxNamespaces);
    }
    if Path::new("/proc/sys/kernel/seccomp").exists()
        || Path::new("/proc/self/status").is_file()
            && std::fs::read_to_string("/proc/self/status")
                .map(|text| text.contains("Seccomp:"))
                .unwrap_or(false)
    {
        available.push(IsolationMechanism::SeccompBpf);
    }
    let apparmor_profile = restricted_apparmor_profile();
    if apparmor_enabled() {
        available.push(IsolationMechanism::AppArmor);
    }
    let bwrap = trusted_bwrap();
    if bwrap.is_some() {
        available.push(IsolationMechanism::Bubblewrap);
    }
    if bwrap.as_deref().map(bubblewrap_probe).unwrap_or(false) {
        applicable.push(IsolationMechanism::LinuxNamespaces);
        applicable.push(IsolationMechanism::Bubblewrap);
    } else if bwrap.is_some() {
        warnings.push(
            "检测到固定路径 bubblewrap，但实际 namespace 探针失败；不会标记为可应用".to_owned(),
        );
    }

    let trusted_supervisor = supervisor.filter(|path| trusted_supervisor_path(path));
    let full_security_probe = trusted_supervisor
        .map(|program| supervisor_security_probe(program, "sandbox-probe"))
        .unwrap_or(false);
    let seccomp_probe = if full_security_probe {
        true
    } else {
        trusted_supervisor
            .map(|program| supervisor_security_probe(program, "sandbox-seccomp-probe"))
            .unwrap_or(false)
    };
    if full_security_probe {
        if !available.contains(&IsolationMechanism::SeccompBpf) {
            available.push(IsolationMechanism::SeccompBpf);
        }
        available.push(IsolationMechanism::Landlock);
        if applicable.contains(&IsolationMechanism::LinuxNamespaces) {
            applicable.push(IsolationMechanism::SeccompBpf);
            applicable.push(IsolationMechanism::Landlock);
        }
    } else if seccomp_probe {
        if !available.contains(&IsolationMechanism::SeccompBpf) {
            available.push(IsolationMechanism::SeccompBpf);
        }
        if applicable.contains(&IsolationMechanism::LinuxNamespaces) {
            applicable.push(IsolationMechanism::SeccompBpf);
        }
        warnings.push(
            "Landlock 完整探针失败，但独立 seccomp-bpf 探针已实际通过；能力降级为 Standard-Limited"
                .to_owned(),
        );
    } else if supervisor.is_some() {
        warnings.push(
            "MindOne 监督进程未能应用 Landlock 或独立 seccomp-bpf；不会把内核版本推断当作安全证明"
                .to_owned(),
        );
    } else {
        warnings.push(
            "未提供监督进程，Landlock/seccomp-bpf 仅作静态能力显示，不计入已应用机制".to_owned(),
        );
    }
    if apparmor_profile.is_some() && applicable.contains(&IsolationMechanism::LinuxNamespaces) {
        applicable.push(IsolationMechanism::AppArmor);
    }

    let full = applicable.contains(&IsolationMechanism::LinuxNamespaces)
        && applicable.contains(&IsolationMechanism::Bubblewrap)
        && applicable.contains(&IsolationMechanism::SeccompBpf)
        && applicable.contains(&IsolationMechanism::Landlock);
    let trust_level = if full {
        warnings.push("四层 Linux 隔离探针均已通过；最终状态仍以实际启动计划为准".to_owned());
        TrustLevel::Standard
    } else if applicable.contains(&IsolationMechanism::LinuxNamespaces) {
        warnings.push("Linux 隔离能力不完整，当前为 Standard-Limited".to_owned());
        TrustLevel::StandardLimited
    } else {
        warnings.push("缺少可用的隔离启动器，当前为 Unverified".to_owned());
        TrustLevel::Unverified
    };

    CapabilityReport {
        platform: Platform::Linux,
        os_version,
        kernel_version,
        available,
        applicable,
        trust_level,
        warnings,
    }
}

#[cfg(target_os = "linux")]
fn apparmor_enabled() -> bool {
    std::fs::read_to_string("/sys/module/apparmor/parameters/enabled")
        .map(|value| value.trim() == "Y")
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn restricted_apparmor_profile() -> Option<String> {
    if !apparmor_enabled() {
        return None;
    }
    let current = std::fs::read_to_string("/proc/self/attr/current").ok()?;
    if current.len() > 4096 {
        return None;
    }
    let trimmed = current.trim();
    if trimmed.chars().any(char::is_control) {
        return None;
    }
    let profile = trimmed.strip_suffix(" (enforce)")?.trim();
    if profile.is_empty() || profile == "unconfined" {
        return None;
    }
    Some(profile.to_owned())
}

#[cfg(target_os = "linux")]
fn trusted_supervisor_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    std::fs::symlink_metadata(path)
        .map(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn read_os_release() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("PRETTY_NAME="))
                .map(|value| value.trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| "Linux".to_owned())
}

#[cfg(target_os = "windows")]
fn detect_windows() -> CapabilityReport {
    let available = vec![IsolationMechanism::WindowsJobObject];
    let warnings = vec![
        "Windows GPU 隔离仍为实验性".to_owned(),
        "未验证当前进程拥有 AppContainer token；不会把容器环境变量当作 AppContainer 证明"
            .to_owned(),
    ];
    CapabilityReport {
        platform: Platform::Windows,
        os_version: env::var("OS").unwrap_or_else(|_| "Windows".to_owned()),
        kernel_version: String::new(),
        available,
        // 能力探测不能冒充启动器已经应用了限制。当前版本在无法建立
        // AppContainer/Job Object supervisor 时允许以 Experimental 明确降级运行。
        applicable: Vec::new(),
        trust_level: TrustLevel::Experimental,
        warnings,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_text(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .unwrap_or_default()
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
        let metadata = std::fs::symlink_metadata(candidate).ok()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return None;
        }
        std::fs::canonicalize(candidate).ok()
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

    #[test]
    fn report_never_claims_enhanced_without_provider() {
        let report = detect_capabilities();
        assert_ne!(report.trust_level, TrustLevel::Enhanced);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_report_is_experimental_until_appcontainer_supervisor_exists() {
        let report = detect_capabilities();
        assert_eq!(report.platform, Platform::Windows);
        assert_eq!(report.trust_level, TrustLevel::Experimental);
        assert!(report.applicable.is_empty());
        assert!(report
            .available
            .contains(&IsolationMechanism::WindowsJobObject));
        assert!(!report
            .available
            .contains(&IsolationMechanism::WindowsAppContainer));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_is_never_standard_or_enhanced() {
        let report = detect_capabilities();
        assert!(matches!(
            report.trust_level,
            TrustLevel::StandardLimited | TrustLevel::Experimental
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn app_sandbox_detection_requires_structured_true_entitlement() {
        let valid = "[Dict]\n  [Key] com.apple.security.app-sandbox\n  [Value]\n    [Bool] true\n";
        assert!(entitlement_is_true(valid, "com.apple.security.app-sandbox"));
        assert!(!entitlement_is_true(
            "CODEX_SANDBOX=seatbelt\nAPP_SANDBOX_CONTAINER_ID=fake\n",
            "com.apple.security.app-sandbox"
        ));
        assert!(!entitlement_is_true(
            "[Key] com.apple.security.app-sandbox\n[Value]\n[Bool] false\n",
            "com.apple.security.app-sandbox"
        ));
    }
}
