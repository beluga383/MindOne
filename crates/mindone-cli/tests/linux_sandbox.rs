#![cfg(target_os = "linux")]

use mindone_sandbox::{
    build_launch_plan_with_supervisor, IsolationMechanism, SandboxAccess, TrustLevel,
};
use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// 该测试必须在真实 Linux runner 上显式启用。它执行发行版同一条隐藏
/// supervisor 路径，不以 `/proc` 文件或内核版本推断“已应用”。
#[test]
#[ignore = "需要安装可信 bubblewrap 且启用 unprivileged user namespaces 的真实 Linux 主机"]
fn real_linux_sandbox_applies_four_layers_serves_loopback_and_rejects_outbound() {
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

    let python = fs::canonicalize("/usr/bin/python3")
        .expect("Linux runner 必须提供可规范化的 /usr/bin/python3");
    let loopback_access = SandboxAccess {
        read_execute: vec![python.parent().expect("python3 必须有父目录").to_path_buf()],
        read_only: Vec::new(),
        read_write: vec![access.read_write[0].clone()],
        allow_loopback_network: true,
    };
    let reservation = TcpListener::bind("127.0.0.1:0").expect("应预留回环测试端口");
    let serve_port = reservation.local_addr().expect("应读取回环地址").port();
    drop(reservation);
    let server_script = format!(
        "import socket\n\
         server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         server.bind(('127.0.0.1', {serve_port}))\n\
         server.listen(1)\n\
         client, _ = server.accept()\n\
         client.sendall(b'ok')\n\
         client.close()\n\
         server.close()\n"
    );
    let server_plan = build_launch_plan_with_supervisor(
        &python,
        &["-c".to_owned(), server_script],
        &loopback_access,
        Some(supervisor),
    )
    .expect("回环服务沙盒计划应可构建");
    let mut server = Command::new(&server_plan.program)
        .args(&server_plan.args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("应启动受管回环服务");
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = None;
    while Instant::now() < deadline {
        match TcpStream::connect(("127.0.0.1", serve_port)) {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("应设置读取时限");
                let mut body = [0_u8; 2];
                received = Some(stream.read_exact(&mut body).map(|()| body));
                break;
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
    if received.is_none() {
        let _ = server.kill();
    }
    let server_output = server.wait_with_output().expect("应回收回环服务");
    assert!(
        server_output.status.success(),
        "沙盒内回环服务应能向已接受的 TCP 连接响应：{}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    assert_eq!(
        received
            .expect("沙盒内回环服务应在时限内监听")
            .expect("沙盒内回环服务应发回完整响应"),
        *b"ok"
    );

    let outbound_listener = TcpListener::bind("127.0.0.1:0").expect("应创建主动连接拒绝目标");
    let outbound_port = outbound_listener
        .local_addr()
        .expect("应读取主动连接目标")
        .port();
    let outbound_script = format!(
        "import socket, sys\n\
         try:\n\
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
         except OSError:\n\
             pass\n\
         else:\n\
             sys.exit(11)\n\
         stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         try:\n\
             stream.connect(('127.0.0.1', {outbound_port}))\n\
         except OSError:\n\
             sys.exit(0)\n\
         sys.exit(12)\n"
    );
    let outbound_plan = build_launch_plan_with_supervisor(
        &python,
        &["-c".to_owned(), outbound_script],
        &loopback_access,
        Some(supervisor),
    )
    .expect("主动连接拒绝沙盒计划应可构建");
    let outbound_output = Command::new(&outbound_plan.program)
        .args(&outbound_plan.args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("应执行主动连接拒绝测试");
    assert!(
        outbound_output.status.success(),
        "沙盒必须拒绝 UDP socket 和主动 TCP connect：{}",
        String::from_utf8_lossy(&outbound_output.stderr)
    );
}
