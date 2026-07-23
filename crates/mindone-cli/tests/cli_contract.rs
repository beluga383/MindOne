use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::net::TcpListener;

#[test]
fn root_help_is_chinese_and_complete() {
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    command.arg("--help").assert().success().stdout(
        predicate::str::contains("用法")
            .and(predicate::str::contains("auth"))
            .and(predicate::str::contains("model"))
            .and(predicate::str::contains("engine"))
            .and(predicate::str::contains("serve"))
            .and(predicate::str::contains("share"))
            .and(predicate::str::contains("quota"))
            .and(predicate::str::contains("node"))
            .and(predicate::str::contains("config"))
            .and(predicate::str::contains("doctor"))
            .and(predicate::str::contains("--json"))
            .and(predicate::str::contains("--quiet"))
            .and(predicate::str::contains("--verbose"))
            .and(predicate::str::contains("__worker").not()),
    );
}

#[test]
fn bare_non_interactive_invocation_falls_back_to_successful_chinese_help() {
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    command.assert().success().stdout(
        predicate::str::contains("用法")
            .and(predicate::str::contains(
                "MindOne AI 算力与模型共享网络客户端",
            ))
            .and(predicate::str::contains("终端图形界面")),
    );
}

#[test]
fn version_is_exact_release_version() {
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    command
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::eq(format!(
            "mindone {}\n",
            env!("CARGO_PKG_VERSION")
        )));
}

#[test]
fn json_model_validation_error_has_required_exit_code() {
    let temp = tempfile::TempDir::new().expect("应创建临时目录");
    let home = std::fs::canonicalize(temp.path()).expect("临时目录应可解析为物理路径");
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    command
        .env("MINDONE_HOME", &home)
        .args(["--json", "model", "verify", "missing"])
        .assert()
        .code(21)
        .stderr(
            predicate::str::contains("\"ok\":false")
                .and(predicate::str::contains("\"code\":21"))
                .and(predicate::str::contains("model_validation_failed")),
        );
}

#[test]
fn dangerous_config_key_is_rejected_without_writing_secret() {
    let temp = tempfile::TempDir::new().expect("应创建临时目录");
    let home = std::fs::canonicalize(temp.path()).expect("临时目录应可解析为物理路径");
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    command
        .env("MINDONE_HOME", &home)
        .args(["config", "set", "auth.token", "should-not-be-written"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("禁止写入 config.toml"));
    let config = home.join("config.toml");
    if let Ok(raw) = std::fs::read_to_string(config) {
        assert!(!raw.contains("should-not-be-written"));
    }
}

#[test]
fn installed_engine_without_serve_adapter_cannot_become_default() {
    for command_args in [
        vec!["engine", "set-default", "ollama"],
        vec!["config", "set", "engine.default", "ollama"],
    ] {
        let temp = tempfile::TempDir::new().expect("应创建临时目录");
        let home = std::fs::canonicalize(temp.path()).expect("临时目录应可解析为物理路径");
        seed_installed_ollama(&home);

        let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
        command
            .env("MINDONE_HOME", &home)
            .args(&command_args)
            .assert()
            .code(20)
            .stderr(
                predicate::str::contains("当前 v1 受管 serve 仅支持真实 llama.cpp")
                    .and(predicate::str::contains("尚未实现可运行的 serve adapter")),
            );

        let registry: Value = serde_json::from_slice(
            &std::fs::read(home.join("engines/index.json")).expect("应读取测试登记"),
        )
        .expect("测试登记应保持为合法 JSON");
        assert!(
            registry["default"].is_null(),
            "失败命令不得修改 registry 默认值"
        );
        if let Ok(config) = std::fs::read_to_string(home.join("config.toml")) {
            assert!(!config.contains("ollama"), "失败命令不得写入不可运行默认值");
        }
    }
}

fn seed_installed_ollama(home: &std::path::Path) {
    let target = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let directory = home.join("engines/ollama/test-version").join(&target);
    std::fs::create_dir_all(&directory).expect("应创建测试引擎目录");
    let executable_name = if cfg!(windows) {
        "ollama.exe"
    } else {
        "ollama"
    };
    let executable = directory.join(executable_name);
    let contents = b"managed-test-ollama";
    std::fs::write(&executable, contents).expect("应写入测试引擎入口");
    let engines_root = std::fs::canonicalize(home.join("engines")).expect("应规范化引擎根目录");
    let directory = std::fs::canonicalize(directory).expect("应规范化测试引擎目录");
    let executable = std::fs::canonicalize(executable).expect("应规范化测试引擎入口");
    let sha256 = hex::encode(Sha256::digest(contents));
    let registry = serde_json::json!({
        "version": 1,
        "default": null,
        "engines": [{
            "id": "018f0000-0000-7000-8000-000000000001",
            "name": "ollama",
            "version": "test-version",
            "target": target,
            "directory": directory,
            "executable": executable,
            "sha256": sha256,
            "files": [{
                "relative_path": executable_name,
                "size_bytes": contents.len(),
                "sha256": sha256,
            }],
            "installed_at_unix": 1,
            "source": "unit-test",
        }],
    });
    std::fs::write(
        engines_root.join("index.json"),
        serde_json::to_vec_pretty(&registry).expect("应序列化测试登记"),
    )
    .expect("应写入测试登记");
}

#[test]
fn json_parse_error_uses_stable_contract_and_chinese_message() {
    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    let assertion = command
        .args(["--json", "definitely-not-a-command"])
        .assert()
        .code(1)
        .stdout(predicate::str::is_empty());
    let output = assertion.get_output();
    let parsed: Value = serde_json::from_slice(&output.stderr).expect("错误应为单行合法 JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["code"], 1);
    assert_eq!(parsed["error"]["type"], "cli_parse_failed");
    assert!(parsed["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("子命令无法识别")));
}

#[cfg(target_os = "macos")]
#[test]
fn doctor_real_macos_standard_limited_path_returns_31_with_complete_json() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("应启动 loopback 健康检查服务");
    let address = listener.local_addr().expect("应读取 loopback 地址");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("应接收 doctor 健康检查");
        let mut request = [0_u8; 4096];
        let read = stream.read(&mut request).expect("应读取 HTTP 请求");
        let request = String::from_utf8_lossy(&request[..read]);
        assert!(request.starts_with("GET /health HTTP/1.1"));
        let body = r#"{"status":"ok"}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("应返回健康响应");
    });

    let temp = tempfile::TempDir::new().expect("应创建临时目录");
    let home = std::fs::canonicalize(temp.path()).expect("临时目录应可解析为物理路径");
    std::fs::write(
        home.join("config.toml"),
        format!("server_url = \"http://{address}\"\n"),
    )
    .expect("应写入隔离 doctor 配置");

    let mut command = Command::cargo_bin("mindone").expect("应构建 mindone 二进制");
    let output = command
        .env("MINDONE_HOME", &home)
        .args(["--json", "doctor"])
        .output()
        .expect("应运行 doctor");
    server.join().expect("健康检查服务不应失败");

    assert_eq!(
        output.status.code(),
        Some(31),
        "doctor stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let parsed: Value = serde_json::from_slice(&output.stdout).expect("doctor 应输出合法 JSON");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["code"], 31);
    assert_eq!(parsed["data"]["summary"]["failures"], 0);
    assert_eq!(parsed["data"]["summary"]["trust_downgrades"], 1);
    let checks = parsed["data"]["checks"]
        .as_array()
        .expect("doctor 应保留完整 checks");
    let sandbox = checks
        .iter()
        .find(|check| check["name"] == "沙盒能力")
        .expect("doctor 应包含沙盒能力检查");
    assert_eq!(sandbox["status"], "warning");
    assert!(sandbox["message"]
        .as_str()
        .is_some_and(|message| message.contains("StandardLimited")));
}
