use std::path::Path;
use std::time::Duration;

use mindone_engine::{ServeManager, ServeRequest};
use mindone_sandbox::IsolationMechanism;
use serde::{Deserialize, Serialize};

use crate::cli::{EngineName, ServeRunArgs, ServeStatusArgs, ServeStopArgs};
use crate::context::AppContext;
use crate::engine::{default_engine, resolve_engine};
use crate::error::{CliError, CliResult};
use crate::model::find_verified_model;
use crate::node::hardware_probe_output;
use crate::output::CommandOutput;

const DEFAULT_PORT: u16 = 8080;

#[derive(Debug, Clone, Serialize)]
pub struct ActiveServeState {
    pub pid: u32,
    /// 本机应用访问的受管代理端口。
    pub port: u16,
    /// 仅供受管 share worker 直连的 llama.cpp 内部回环端口。
    pub backend_port: u16,
    pub model_name: String,
    pub model_path: std::path::PathBuf,
    pub engine_name: String,
    pub engine_path: std::path::PathBuf,
    pub log_path: std::path::PathBuf,
    /// 监督进程确认实际应用到当前 llama-server 的机制；不是主机能力探测结果。
    pub sandbox_mechanisms: Vec<IsolationMechanism>,
    pub trust_level: String,
    pub sandbox_policy_hash: String,
    pub healthy: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AdvancedConfig {
    context_size: Option<u32>,
    gpu_layers: Option<i32>,
    threads: Option<u16>,
    batch_size: Option<u32>,
    /// 禁用所有设备与 KV/算子卸载，用于 GPU 不可用或沙盒不授予 GPU 设备访问的主机。
    cpu_only: bool,
}

pub async fn run(context: &AppContext, args: &ServeRunArgs) -> CliResult<CommandOutput> {
    let model = find_verified_model(context, &args.model)?;
    let engine_name = args.engine.unwrap_or(default_engine(context)?);
    if engine_name != EngineName::LlamaCpp {
        return Err(CliError::EngineOrSandbox(format!(
            "当前受管服务仅支持真实 llama.cpp；{} 不兼容此启动路径",
            engine_name.as_str()
        )));
    }
    let engine = resolve_engine(context, engine_name)?;
    let advanced = load_advanced_config(args.config.as_deref())?;
    let manager = manager(context, args.port)?;
    let runtime_directory = service_runtime_directory(context, args.port);
    let log_path = service_log_path(context, args.port);
    let status = manager
        .start(ServeRequest {
            engine,
            model_path: model.path.clone(),
            model_artifact_paths: model.artifact_paths(),
            port: args.port,
            runtime_directory,
            log_path,
            health_timeout: Duration::from_secs(30),
            cpu_only: advanced.cpu_only,
            additional_args: advanced_args(&advanced),
        })
        .await
        .map_err(serve_error)?;
    let state = active_state(&model.name, status);
    CommandOutput::new(
        format!(
            "本地推理服务已启动并通过真实健康检查\n受管地址：http://127.0.0.1:{}\nPID：{}\n模型：{}\n引擎：{}\n请求后清理：本机 slot 0 与三个贡献 slot 均按请求精确同步 erase\n沙盒：{}\n信任等级：{}\n日志：{}",
            state.port,
            state.pid,
            state.model_name,
            state.engine_name,
            state
                .sandbox_mechanisms
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            state.trust_level,
            state.log_path.display()
        ),
        state,
    )
}

pub async fn stop(context: &AppContext, args: &ServeStopArgs) -> CliResult<CommandOutput> {
    let report = manager(context, args.port)?
        .stop(Duration::from_secs(args.timeout))
        .await
        .map_err(serve_error)?;
    CommandOutput::new(
        format!(
            "推理服务已停止\n进程内存已释放：{}\n已覆写受控主机缓冲区：{} bytes\nKV Cache 覆写已确认：{}\n说明：{}",
            report.process_memory_released,
            report.owned_host_buffer_bytes_zeroed,
            report.kv_cache_cleanup_confirmed,
            report.note
        ),
        report,
    )
}

pub async fn status(context: &AppContext, args: &ServeStatusArgs) -> CliResult<CommandOutput> {
    let status = manager(context, args.port)?
        .status()
        .await
        .map_err(serve_error)?;
    let model = find_model_name_by_path(context, &status.state.model_path);
    let vram = process_vram_bytes(status.state.pid);
    CommandOutput::new(
        format!(
            "进程：{}（PID {}，身份校验={}）\n日志监督身份校验：{}\n受管代理身份校验：{}\n请求后清理：{}\n健康：{}\n模型：{}\n引擎：{}\n端口：http://127.0.0.1:{}\nTPS：{}\n内存：{}\n显存：{}\n沙盒：{}\n信任等级：{:?}\n说明：{}\n日志：{}",
            if status.running { "运行" } else { "停止" },
            status.state.pid,
            status.process_verified,
            status.log_monitor_verified,
            status.proxy_verified,
            status
                .cleanup
                .as_ref()
                .map(|cleanup| format!(
                    "已终态={}，成功={}，失败={}，待清理={}",
                    cleanup.requests_completed,
                    cleanup.cleanup_successes,
                    cleanup.cleanup_failures,
                    cleanup.cleanup_required
                ))
                .unwrap_or_else(|| "状态不可用".to_owned()),
            if status.healthy { "通过" } else { "失败" },
            model,
            status.state.engine,
            status.state.port,
            status
                .tokens_per_second
                .map(|value| format!("{value:.2}"))
                .unwrap_or_else(|| "引擎未提供可计算指标".to_owned()),
            status
                .resident_memory_bytes
                .map(|value| format!("{value} bytes"))
                .unwrap_or_else(|| "平台不可用".to_owned()),
            vram
                .map(|value| format!("{value} bytes"))
                .unwrap_or_else(|| "平台未提供进程级指标".to_owned()),
            status
                .state
                .sandbox_mechanisms
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            status.state.trust_level,
            status.state.sandbox_note,
            status.state.log_path.display()
        ),
        serde_json::json!({
            "status": status,
            "model_name": model,
            "vram_bytes": vram,
        }),
    )
}

pub async fn load_state(context: &AppContext) -> CliResult<ActiveServeState> {
    let status = manager(context, DEFAULT_PORT)?
        .status()
        .await
        .map_err(serve_error)?;
    if !status.running || !status.process_verified || !status.proxy_verified || !status.healthy {
        return Err(CliError::EngineOrSandbox(
            "本地推理服务未通过进程身份与健康检查".to_owned(),
        ));
    }
    let model_name = find_model_name_by_path(context, &status.state.model_path);
    Ok(active_state(&model_name, status))
}

fn active_state(model_name: &str, status: mindone_engine::ServeStatus) -> ActiveServeState {
    ActiveServeState {
        pid: status.state.pid,
        port: status.state.port,
        backend_port: status.state.backend_port,
        model_name: model_name.to_owned(),
        model_path: status.state.model_path,
        engine_name: status.state.engine.as_str().to_owned(),
        engine_path: status.state.engine_executable,
        log_path: status.state.log_path,
        sandbox_mechanisms: status.state.sandbox_mechanisms.clone(),
        trust_level: format!("{:?}", status.state.trust_level),
        sandbox_policy_hash: status.state.sandbox_policy_hash,
        healthy: status.healthy,
    }
}

fn manager(context: &AppContext, port: u16) -> CliResult<ServeManager> {
    ServeManager::new(state_path(context, port)).map_err(serve_error)
}

pub(crate) fn state_path(context: &AppContext, port: u16) -> std::path::PathBuf {
    context.paths.runtime.join(state_file_name(port))
}

fn state_file_name(port: u16) -> String {
    if port == DEFAULT_PORT {
        "serve.json".to_owned()
    } else {
        format!("serve-{port}.json")
    }
}

fn service_runtime_directory(context: &AppContext, port: u16) -> std::path::PathBuf {
    if port == DEFAULT_PORT {
        context.paths.runtime.clone()
    } else {
        context.paths.runtime.join(format!("serve-{port}"))
    }
}

fn service_log_path(context: &AppContext, port: u16) -> std::path::PathBuf {
    if port == DEFAULT_PORT {
        context.paths.logs.join("llama-server.log")
    } else {
        context.paths.logs.join(format!("llama-server-{port}.log"))
    }
}

fn load_advanced_config(path: Option<&Path>) -> CliResult<AdvancedConfig> {
    let Some(path) = path else {
        return Ok(AdvancedConfig::default());
    };
    let raw = std::fs::read_to_string(path).map_err(|error| {
        CliError::EngineOrSandbox(format!("无法读取高级配置 {}：{error}", path.display()))
    })?;
    serde_yaml::from_str(&raw).map_err(|error| {
        CliError::EngineOrSandbox(format!("高级 YAML 配置无效 {}：{error}", path.display()))
    })
}

fn advanced_args(config: &AdvancedConfig) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(value) = config.context_size {
        args.extend(["--ctx-size".to_owned(), value.to_string()]);
    }
    // CPU-only 是 ServeRequest 的类型化受管策略，不编码进未受信的
    // additional_args，否则 manager 会正确地把 `--device` 视为覆盖并失败关闭。
    if !config.cpu_only {
        if let Some(value) = config.gpu_layers {
            args.extend(["--n-gpu-layers".to_owned(), value.to_string()]);
        }
    }
    if let Some(value) = config.threads {
        args.extend(["--threads".to_owned(), value.to_string()]);
    }
    if let Some(value) = config.batch_size {
        args.extend(["--batch-size".to_owned(), value.to_string()]);
    }
    args
}

fn find_model_name_by_path(context: &AppContext, path: &Path) -> String {
    mindone_engine::ModelRegistry::new(context.paths.models.join("index.json"))
        .list()
        .ok()
        .and_then(|models| {
            models
                .into_iter()
                .find(|model| model.path == path)
                .map(|model| model.name)
        })
        .unwrap_or_else(|| path.display().to_string())
}

fn process_vram_bytes(pid: u32) -> Option<u64> {
    let mut command = std::process::Command::new("nvidia-smi");
    command.args([
        "--query-compute-apps=pid,used_memory",
        "--format=csv,noheader,nounits",
    ]);
    let output = hardware_probe_output(&mut command)?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
            if fields.first()?.parse::<u32>().ok()? != pid {
                return None;
            }
            fields.get(1)?.parse::<u64>().ok()?.checked_mul(1024 * 1024)
        })
}

fn serve_error(error: impl std::fmt::Display) -> CliError {
    let message = error.to_string();
    if message.contains("模型安全校验") {
        CliError::ModelValidation(message)
    } else {
        CliError::EngineOrSandbox(message)
    }
}

#[cfg(test)]
mod tests {
    use super::{advanced_args, state_file_name, AdvancedConfig};

    #[test]
    fn advanced_config_rejects_network_override() {
        assert!(serde_yaml::from_str::<AdvancedConfig>("host: 0.0.0.0\n").is_err());
    }

    #[test]
    fn advanced_config_rejects_every_logging_override() {
        for yaml in [
            "log_disable: false\n",
            "log_file: /tmp/prompt.log\n",
            "log_verbosity: 5\n",
            "verbose: true\n",
            "verbose_prompt: true\n",
        ] {
            assert!(
                serde_yaml::from_str::<AdvancedConfig>(yaml).is_err(),
                "日志参数不得进入高级配置：{yaml}"
            );
        }
    }

    #[test]
    fn advanced_args_are_bounded_to_known_engine_flags() {
        let config = AdvancedConfig {
            context_size: Some(4096),
            ..AdvancedConfig::default()
        };
        assert_eq!(advanced_args(&config), vec!["--ctx-size", "4096"]);
    }

    #[test]
    fn cpu_only_remains_typed_and_never_becomes_an_untrusted_device_override() {
        let config = AdvancedConfig {
            cpu_only: true,
            gpu_layers: Some(99),
            ..AdvancedConfig::default()
        };
        assert!(config.cpu_only);
        assert!(advanced_args(&config).is_empty());
    }

    #[test]
    fn every_non_default_port_gets_an_independent_managed_state_file() {
        assert_eq!(state_file_name(8080), "serve.json");
        assert_eq!(state_file_name(8081), "serve-8081.json");
        assert_eq!(state_file_name(65_535), "serve-65535.json");
        assert_ne!(state_file_name(8081), state_file_name(8082));
    }
}
