use mindone_engine::{EngineInstaller, EngineName};
use std::error::Error;
use std::process::Command;

#[tokio::test]
#[ignore = "需要访问官方 GitHub release，显式设置 MINDONE_REAL_ENGINE_INSTALL=1 后运行"]
async fn installs_and_executes_official_llama_cpp() -> Result<(), Box<dyn Error>> {
    if std::env::var("MINDONE_REAL_ENGINE_INSTALL").as_deref() != Ok("1") {
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let installer = EngineInstaller::new(
        temp.path().join("engines"),
        temp.path().join("cache"),
        temp.path().join("engines.json"),
    )?;
    let installed = installer.install(EngineName::LlamaCpp, "latest").await?;
    assert!(installed.executable.is_file());
    let output = Command::new(&installed.executable)
        .arg("--version")
        .output()?;
    assert!(output.status.success());
    assert!(!output.stdout.is_empty() || !output.stderr.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore = "需要访问 Ollama 官方 GitHub release，显式设置 MINDONE_REAL_OLLAMA_INSTALL=1 后运行"]
async fn installs_verifies_and_executes_official_ollama() -> Result<(), Box<dyn Error>> {
    if std::env::var("MINDONE_REAL_OLLAMA_INSTALL").as_deref() != Ok("1") {
        return Ok(());
    }
    let temp = tempfile::tempdir()?;
    let engines = temp.path().join("engines");
    let installer = EngineInstaller::new(
        &engines,
        temp.path().join("cache"),
        engines.join("index.json"),
    )?;
    let installed = installer.install(EngineName::Ollama, "latest").await?;
    assert!(installed.executable.is_file());
    assert!(installed
        .source
        .starts_with("https://github.com/ollama/ollama/"));
    installed.verify_integrity_in(&engines)?;
    let output = Command::new(&installed.executable)
        .arg("--version")
        .env_remove("OLLAMA_HOST")
        .env_remove("OLLAMA_MODELS")
        .output()?;
    assert!(output.status.success());
    let mut version = String::from_utf8_lossy(&output.stdout).into_owned();
    version.push_str(&String::from_utf8_lossy(&output.stderr));
    assert!(version.contains(installed.version.trim_start_matches('v')));
    assert_eq!(installer.registry().latest(EngineName::Ollama)?, installed);
    let managed_bytes = installed
        .files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.size_bytes))
        .ok_or("受管 Ollama 目录大小溢出")?;
    eprintln!(
        "OLLAMA_REAL_SMOKE version={} executable_sha256={} managed_files={} managed_bytes={} directory={}",
        installed.version,
        installed.sha256,
        installed.files.len(),
        managed_bytes,
        installed.directory.display()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "需要 Linux x86_64、NVIDIA CUDA 与本机可信 Docker；设置 MINDONE_REAL_CONTAINER_ENGINE=vllm 或 tensorrt-llm"]
async fn installs_and_verifies_official_cuda_container_engine() -> Result<(), Box<dyn Error>> {
    let name = match std::env::var("MINDONE_REAL_CONTAINER_ENGINE").as_deref() {
        Ok("vllm") => EngineName::Vllm,
        Ok("tensorrt-llm") => EngineName::TensorrtLlm,
        _ => return Ok(()),
    };
    let temp = tempfile::tempdir()?;
    let engines = temp.path().join("engines");
    let installer = EngineInstaller::new(
        &engines,
        temp.path().join("cache"),
        engines.join("index.json"),
    )?;
    let installed = installer.install(name, "latest").await?;
    assert!(installed.source.starts_with("oci://"));
    assert!(installed.directory.join("engine-image.tar").is_file());
    assert!(installed.directory.join("engine.json").is_file());
    installed.verify_integrity_in(&engines)?;
    assert_eq!(installer.registry().latest(name)?, installed);
    Ok(())
}
