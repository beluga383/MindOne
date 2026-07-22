#![cfg(target_os = "windows")]

use std::path::Path;
use std::process::Command;

/// 在真实 Windows 上穿过和发行版一致的隐藏 supervisor 路径：监督进程须先
/// 进入 KILL_ON_JOB_CLOSE Job Object，确认自身及引擎 PID，再将引擎的退出码
/// 原样传回。JSON 证明事件只含 PID，不含模型路径、参数或推理内容。
#[test]
fn real_windows_job_supervisor_confirms_pids_and_propagates_exit_code() {
    let executable = std::fs::canonicalize(Path::new(env!("CARGO_BIN_EXE_mindone")))
        .expect("Windows CI 必须提供已构建的 mindone.exe");
    let expected_exit_code = 37;
    let output = Command::new(&executable)
        .args([
            "__worker",
            "windows-job-exec",
            "--executable",
            executable
                .to_str()
                .expect("Windows CI 可执行路径必须是有效 Unicode"),
            "--emit-proof",
            "--",
            "__worker",
            "windows-job-smoke-exit",
            "--code",
            "37",
        ])
        .output()
        .expect("应启动 Windows Job Object 监督进程");

    assert_eq!(output.status.code(), Some(expected_exit_code));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let proof_line = stderr
        .lines()
        .find(|line| line.contains("\"event\":\"windows_job_object_verified\""))
        .expect("监督进程必须输出已确认 PID 的 Job Object 证明事件");
    let proof: serde_json::Value =
        serde_json::from_str(proof_line).expect("Job Object 证明事件必须是 JSON");
    assert_eq!(proof["event"], "windows_job_object_verified");
    let supervisor_pid = proof["supervisor_pid"]
        .as_u64()
        .expect("证明事件必须包含 supervisor PID");
    let engine_pid = proof["engine_pid"]
        .as_u64()
        .expect("证明事件必须包含 engine PID");
    assert!(supervisor_pid > 0);
    assert!(engine_pid > 0);
    assert_ne!(supervisor_pid, engine_pid);
}
