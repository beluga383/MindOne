#![cfg(target_os = "linux")]

use mindone_sandbox::{
    build_launch_plan_with_supervisor, IsolationMechanism, SandboxAccess, TrustLevel,
};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

/// 该测试必须在真实 Linux runner 上显式启用。它执行发行版同一条隐藏
/// supervisor 路径，不以 `/proc` 文件或内核版本推断“已应用”。
#[test]
#[ignore = "需要安装可信 bubblewrap 且启用 unprivileged user namespaces 的真实 Linux 主机"]
fn real_linux_sandbox_applies_four_layers_and_rejects_sibling_model() {
    if std::env::var("MINDONE_REAL_LINUX_SANDBOX_TEST").as_deref() != Ok("1") {
        eprintln!("跳过：未设置 MINDONE_REAL_LINUX_SANDBOX_TEST=1");
        return;
    }

    let supervisor = Path::new(env!("CARGO_BIN_EXE_mindone"));
    let executable = fs::canonicalize("/usr/bin/cat").expect("Linux runner 必须提供 /usr/bin/cat");
    let directory = tempfile::tempdir().expect("应创建测试目录");
    let allowed = directory.path().join("allowed.gguf");
    let denied = directory.path().join("denied.gguf");
    fs::write(&allowed, b"allowed\n").expect("应写入允许文件");
    fs::write(&denied, b"denied\n").expect("应写入拒绝文件");
    let runtime = directory.path().join("runtime");
    fs::create_dir(&runtime).expect("应创建运行目录");
    let access = SandboxAccess {
        read_execute: vec![executable.parent().expect("cat 必须有父目录").to_path_buf()],
        read_only: vec![allowed.clone()],
        read_write: vec![runtime],
        allow_loopback_network: false,
    };

    let allowed_plan = build_launch_plan_with_supervisor(
        &executable,
        &[allowed.to_string_lossy().into_owned()],
        &access,
        Some(supervisor),
    )
    .expect("四层隔离启动计划应可构建");
    assert_eq!(allowed_plan.trust_level, TrustLevel::Standard);
    for mechanism in [
        IsolationMechanism::LinuxNamespaces,
        IsolationMechanism::Bubblewrap,
        IsolationMechanism::Landlock,
        IsolationMechanism::SeccompBpf,
    ] {
        assert!(allowed_plan.applied.contains(&mechanism));
    }
    let allowed_output = Command::new(&allowed_plan.program)
        .args(&allowed_plan.args)
        .stderr(Stdio::piped())
        .output()
        .expect("应执行允许读取测试");
    assert!(
        allowed_output.status.success(),
        "允许的模型文件应可读取：{}",
        String::from_utf8_lossy(&allowed_output.stderr)
    );
    assert_eq!(allowed_output.stdout, b"allowed\n");

    let denied_plan = build_launch_plan_with_supervisor(
        &executable,
        &[denied.to_string_lossy().into_owned()],
        &access,
        Some(supervisor),
    )
    .expect("拒绝路径仍应生成相同沙盒计划");
    let denied_output = Command::new(&denied_plan.program)
        .args(&denied_plan.args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("应执行拒绝读取测试");
    assert!(
        !denied_output.status.success(),
        "未授权的同目录模型文件不得被读取"
    );
}
