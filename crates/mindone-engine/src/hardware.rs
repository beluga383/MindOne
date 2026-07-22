use serde::{Deserialize, Serialize};
use std::env;
#[cfg(not(target_os = "macos"))]
use std::path::PathBuf;
use std::process::Command;
use sysinfo::System;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuProfile {
    pub name: String,
    pub memory_bytes: Option<u64>,
    pub temperature_celsius: Option<i32>,
    pub unified_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub os: String,
    pub os_version: String,
    pub kernel_version: String,
    pub architecture: String,
    pub cpu_brand: String,
    pub logical_cpu_count: usize,
    pub total_memory_bytes: u64,
    pub gpus: Vec<GpuProfile>,
    pub metal_available: bool,
    pub cuda_available: bool,
    #[serde(default)]
    pub nvidia_driver_version: Option<String>,
    #[serde(default)]
    pub cuda_driver_version: Option<String>,
    pub recommended_backend: String,
}

pub fn detect_hardware() -> HardwareProfile {
    let mut system = System::new_all();
    system.refresh_all();
    let os = System::name().unwrap_or_else(|| env::consts::OS.to_owned());
    let os_version = System::os_version().unwrap_or_default();
    let kernel_version = System::kernel_version().unwrap_or_default();
    let cpu_brand = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "未知 CPU".to_owned());
    let metal_available = detect_metal();
    let (gpus, cuda_available, nvidia_driver_version, cuda_driver_version) =
        detect_gpus(system.total_memory());
    let recommended_backend = if cuda_available {
        "cuda"
    } else if metal_available {
        "metal"
    } else {
        "cpu"
    }
    .to_owned();
    HardwareProfile {
        os,
        os_version,
        kernel_version,
        architecture: env::consts::ARCH.to_owned(),
        cpu_brand,
        logical_cpu_count: system.cpus().len(),
        total_memory_bytes: system.total_memory(),
        gpus,
        metal_available,
        cuda_available,
        nvidia_driver_version,
        cuda_driver_version,
        recommended_backend,
    }
}

#[cfg(target_os = "macos")]
fn detect_metal() -> bool {
    Command::new("/usr/sbin/system_profiler")
        .arg("SPDisplaysDataType")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.contains("Metal: Supported"))
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn detect_metal() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn detect_gpus(_total_memory: u64) -> (Vec<GpuProfile>, bool, Option<String>, Option<String>) {
    let output = Command::new("/usr/sbin/system_profiler")
        .args(["-json", "SPDisplaysDataType"])
        .output();
    let Ok(output) = output else {
        return (Vec::new(), false, None, None);
    };
    if !output.status.success() {
        return (Vec::new(), false, None, None);
    }
    let value: serde_json::Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => return (Vec::new(), false, None, None),
    };
    let gpus = value
        .get("SPDisplaysDataType")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let name = item
                        .get("sppci_model")
                        .or_else(|| item.get("_name"))
                        .and_then(serde_json::Value::as_str)?;
                    Some(GpuProfile {
                        name: name.to_owned(),
                        // Apple Silicon 使用统一内存，不能把系统 RAM 伪装成独立 VRAM。
                        memory_bytes: None,
                        temperature_celsius: None,
                        unified_memory: name.to_ascii_lowercase().contains("apple"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    (gpus, false, None, None)
}

#[cfg(not(target_os = "macos"))]
fn detect_gpus(_total_memory: u64) -> (Vec<GpuProfile>, bool, Option<String>, Option<String>) {
    let Some(nvidia_smi) = find_executable("nvidia-smi") else {
        return (Vec::new(), false, None, None);
    };
    let output = Command::new(&nvidia_smi)
        .args([
            "--query-gpu=name,memory.total,temperature.gpu,driver_version",
            "--format=csv,noheader,nounits",
        ])
        .output();
    let Ok(output) = output else {
        return (Vec::new(), false, None, None);
    };
    if !output.status.success() {
        return (Vec::new(), false, None, None);
    }
    let text = String::from_utf8(output.stdout).unwrap_or_default();
    let mut detected_driver = None;
    let gpus = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split(',').map(str::trim);
            let name = parts.next()?.to_owned();
            let memory_mib = parts.next().and_then(|value| value.parse::<u64>().ok());
            let temperature = parts.next().and_then(|value| value.parse::<i32>().ok());
            let driver = parts.next().filter(|value| !value.is_empty());
            if detected_driver.is_none() {
                detected_driver = driver.map(str::to_owned);
            }
            Some(GpuProfile {
                name,
                memory_bytes: memory_mib.and_then(|value| value.checked_mul(1024 * 1024)),
                temperature_celsius: temperature,
                unified_memory: false,
            })
        })
        .collect::<Vec<_>>();
    let available = !gpus.is_empty();
    let cuda_driver_version = Command::new(nvidia_smi)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| parse_cuda_version(&output));
    (gpus, available, detected_driver, cuda_driver_version)
}

#[cfg(not(target_os = "macos"))]
fn parse_cuda_version(output: &str) -> Option<String> {
    let marker = "CUDA Version:";
    let remainder = output.split_once(marker)?.1.trim_start();
    let version = remainder
        .split(|character: char| character.is_ascii_whitespace() || character == '|')
        .next()?
        .trim();
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        None
    } else {
        Some(version.to_owned())
    }
}

#[cfg(not(target_os = "macos"))]
fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_real_nonzero_host_resources() {
        let profile = detect_hardware();
        assert!(!profile.os.is_empty());
        assert!(!profile.architecture.is_empty());
        assert!(profile.logical_cpu_count > 0);
        assert!(profile.total_memory_bytes > 0);
        assert!(matches!(
            profile.recommended_backend.as_str(),
            "metal" | "cuda" | "cpu"
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn parses_nvidia_cuda_driver_version_without_trusting_free_text() {
        let output = "| NVIDIA-SMI 575.57.08  Driver Version: 575.57.08  CUDA Version: 12.9 |";
        assert_eq!(parse_cuda_version(output).as_deref(), Some("12.9"));
        assert!(parse_cuda_version("CUDA Version: ../../bad |").is_none());
        assert!(parse_cuda_version("CUDA unavailable").is_none());
    }
}
