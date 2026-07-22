#![cfg(target_os = "macos")]

use mindone_sandbox::{build_launch_plan, IsolationMechanism, SandboxAccess, TrustLevel};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
#[ignore = "需要在未继承其他 Seatbelt profile 的 macOS 进程中显式运行"]
fn real_seatbelt_executes_target_and_denies_unauthorized_write() -> Result<(), Box<dyn Error>> {
    if std::env::var("MINDONE_REAL_SEATBELT_TEST").as_deref() != Ok("1") {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    let allowed = directory.path().join("allowed");
    let denied = directory.path().join("denied");
    fs::create_dir_all(&allowed)?;
    fs::create_dir_all(&denied)?;
    let allowed = fs::canonicalize(allowed)?;
    let denied = fs::canonicalize(denied)?;
    let touch = fs::canonicalize(Path::new("/usr/bin/touch"))?;
    let access = SandboxAccess {
        read_execute: Vec::new(),
        read_only: Vec::new(),
        read_write: vec![allowed.clone()],
        allow_loopback_network: false,
    };

    let allowed_file = allowed.join("created");
    let allowed_plan = build_launch_plan(
        &touch,
        &[allowed_file.to_string_lossy().into_owned()],
        &access,
    )?;
    assert_eq!(allowed_plan.trust_level, TrustLevel::StandardLimited);
    assert_eq!(allowed_plan.applied, vec![IsolationMechanism::Seatbelt]);
    let allowed_output = Command::new(&allowed_plan.program)
        .args(&allowed_plan.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    assert!(
        allowed_output.status.success(),
        "授权写入失败，status={:?}，stderr={}，plan={allowed_plan:?}",
        allowed_output.status.code(),
        String::from_utf8_lossy(&allowed_output.stderr),
    );
    assert!(allowed_file.is_file());

    let denied_file = denied.join("must-not-exist");
    let denied_plan = build_launch_plan(
        &touch,
        &[denied_file.to_string_lossy().into_owned()],
        &access,
    )?;
    let denied_output = Command::new(&denied_plan.program)
        .args(&denied_plan.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    assert!(!denied_output.status.success());
    assert!(!denied_file.exists());

    let allowed_model = directory.path().join("allowed-model.gguf");
    let sibling_model = directory.path().join("sibling-model.gguf");
    fs::write(&allowed_model, b"allowed-model")?;
    fs::write(&sibling_model, b"sibling-model")?;
    let allowed_model = fs::canonicalize(allowed_model)?;
    let sibling_model = fs::canonicalize(sibling_model)?;
    let cat = fs::canonicalize(Path::new("/bin/cat"))?;
    let model_access = SandboxAccess {
        read_execute: Vec::new(),
        read_only: vec![allowed_model.clone()],
        read_write: Vec::new(),
        allow_loopback_network: false,
    };
    let allowed_read = build_launch_plan(
        &cat,
        &[allowed_model.to_string_lossy().into_owned()],
        &model_access,
    )?;
    let output = Command::new(&allowed_read.program)
        .args(&allowed_read.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"allowed-model");

    let sibling_read = build_launch_plan(
        &cat,
        &[sibling_model.to_string_lossy().into_owned()],
        &model_access,
    )?;
    let output = Command::new(&sibling_read.program)
        .args(&sibling_read.args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .output()?;
    assert!(!output.status.success());
    Ok(())
}
