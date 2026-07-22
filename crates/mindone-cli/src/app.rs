use std::fs;
use std::path::{Path, PathBuf};

use mindone_common::{ConfigKey, MindOnePaths};

use crate::api;
use crate::auth;
use crate::cli::{
    ApiCommand, AuthCommand, Cli, Command, ConfigCommand, EngineCommand, EngineName, ModelCommand,
    NodeCommand, NodePolicyCommand, NodeThresholdCommand, QuotaCommand, ServeCommand, ShareCommand,
    WorkerCommand,
};
use crate::config::{
    canonical_config_key, config_get, config_list, config_set as set_config_value,
};
use crate::context::AppContext;
use crate::doctor;
use crate::engine;
use crate::error::{CliError, CliResult};
use crate::model;
use crate::node;
use crate::output::{CommandOutput, OutputMode};
use crate::quota;
use crate::serve;
use crate::share;
use crate::vault::SystemVault;

pub async fn execute(cli: Cli) -> CliResult<(OutputMode, CommandOutput)> {
    let output_mode = OutputMode {
        json: cli.json,
        quiet: cli.quiet,
        verbose: cli.verbose,
    };
    // Linux 沙盒监督进程运行在最小 bubblewrap 文件系统中，不能也不需要
    // 读取用户配置或系统凭证库。必须在 AppContext::load 前处理，避免扩大
    // 监督进程的文件访问面。
    if let Command::Worker(args) = &cli.command {
        match &args.command {
            WorkerCommand::SandboxProbe => {
                mindone_sandbox::probe_linux_security_layers()
                    .map_err(|error| CliError::General(format!("Linux 沙盒探针失败：{error}")))?;
                let output = CommandOutput::new(
                    "Landlock 与 seccomp-bpf 探针已完整应用",
                    serde_json::json!({
                        "landlock": "fully_enforced",
                        "seccomp_bpf": "applied",
                    }),
                )?;
                return Ok((output_mode, output));
            }
            WorkerCommand::SandboxSeccompProbe => {
                mindone_sandbox::probe_linux_seccomp().map_err(|error| {
                    CliError::General(format!("Linux seccomp-bpf 探针失败：{error}"))
                })?;
                let output = CommandOutput::new(
                    "seccomp-bpf 探针已实际应用",
                    serde_json::json!({
                        "seccomp_bpf": "applied",
                        "landlock": "not_requested",
                    }),
                )?;
                return Ok((output_mode, output));
            }
            WorkerCommand::SandboxExec(args) => {
                mindone_sandbox::run_linux_supervisor(
                    &args.executable,
                    &args.read_execute,
                    &args.read_only,
                    &args.read_write,
                    &args.engine_args,
                )
                .map_err(|error| {
                    CliError::General(format!("Linux 推理监督进程启动失败：{error}"))
                })?;
                return Err(CliError::General(
                    "Linux 推理监督进程意外返回，未执行推理引擎".to_owned(),
                ));
            }
            WorkerCommand::SandboxSeccompExec(args) => {
                mindone_sandbox::run_linux_seccomp_supervisor(
                    &args.executable,
                    &args.read_execute,
                    &args.read_only,
                    &args.read_write,
                    &args.engine_args,
                )
                .map_err(|error| {
                    CliError::General(format!("Linux seccomp-bpf 监督进程启动失败：{error}"))
                })?;
                return Err(CliError::General(
                    "Linux seccomp-bpf 监督进程意外返回，未执行推理引擎".to_owned(),
                ));
            }
            WorkerCommand::WindowsJobExec(args) => {
                mindone_sandbox::run_windows_job_supervisor(
                    &args.executable,
                    &args.engine_args,
                    args.emit_proof,
                )
                .map_err(|error| {
                    CliError::General(format!("Windows Job Object 监督进程启动失败：{error}"))
                })?;
                return Err(CliError::General(
                    "Windows Job Object 监督进程意外返回，未执行推理引擎".to_owned(),
                ));
            }
            WorkerCommand::WindowsJobSmokeExit(args) => {
                #[cfg(target_os = "windows")]
                std::process::exit(i32::from(args.code));
                #[cfg(not(target_os = "windows"))]
                return Err(CliError::General(format!(
                    "Windows Job Object 测试子进程不支持当前平台（退出码 {}）",
                    args.code
                )));
            }
            WorkerCommand::LogMonitor(args) => {
                let mut config = mindone_engine::LogMonitorConfig::new(
                    args.path.clone(),
                    args.pid,
                    args.marker.clone(),
                )
                .and_then(|config| {
                    config.with_expected_command_parts(args.expected_command.clone())
                })
                .map_err(|error| CliError::General(format!("无法启动推理日志监控：{error}")))?;
                if let (Some(path), Some(token)) = (&args.ready_path, &args.ready_token) {
                    config = config
                        .with_ready_signal(path.clone(), token.clone())
                        .map_err(|error| {
                            CliError::General(format!("无法配置推理日志监控回执：{error}"))
                        })?;
                }
                let exit = mindone_engine::run_log_monitor(&config)
                    .map_err(|error| CliError::General(format!("推理日志监控失败：{error}")))?;
                let reason = match exit {
                    mindone_engine::LogMonitorExit::TargetExited => "target_exited",
                };
                let output = CommandOutput::new(
                    "受管推理进程已退出，日志监控同步结束",
                    serde_json::json!({
                        "target_pid": args.pid,
                        "log_path": args.path,
                        "reason": reason,
                    }),
                )?;
                return Ok((output_mode, output));
            }
            WorkerCommand::ServeProxy(args) => {
                crate::serve_proxy::run_serve_proxy(crate::serve_proxy::ServeProxyConfig {
                    listen_port: args.listen_port,
                    backend_port: args.backend_port,
                    target_pid: args.target_pid,
                    target_marker: args.target_marker.clone(),
                    expected_command_parts: args.expected_command.clone(),
                    status_path: args.status_path.clone(),
                })
                .await?;
                return Err(CliError::General("受管回环代理意外返回".to_owned()));
            }
            WorkerCommand::Share
            | WorkerCommand::ResolveDataDir
            | WorkerCommand::ResolveConfigHome => {}
        }
    }
    let context = AppContext::load()?;
    let output = match cli.command {
        Command::Auth(args) => match args.command {
            AuthCommand::Login(args) => auth::login(&context, &args, output_mode).await?,
            AuthCommand::Logout => auth::logout(&context).await?,
            AuthCommand::Status => auth::status(&context).await?,
            AuthCommand::Attest => auth::attest(&context).await?,
        },
        Command::Api(args) => match args.command {
            ApiCommand::Info => api::info(&context)?,
            ApiCommand::Create(args) => api::create(&context, &args).await?,
            ApiCommand::List => api::list(&context).await?,
            ApiCommand::Revoke(args) => api::revoke(&context, &args).await?,
            ApiCommand::Models => api::models(&context).await?,
        },
        Command::Model(args) => match args.command {
            ModelCommand::List => model::list(&context)?,
            ModelCommand::Catalog(args) => model::catalog(&args)?,
            ModelCommand::Recommend(args) => model::recommend(&args)?,
            ModelCommand::Probe(args) => model::probe(&args).await?,
            ModelCommand::Deploy(args) => model::deploy(&context, &args, output_mode).await?,
            ModelCommand::Download(args) => model::download(&context, &args, output_mode).await?,
            ModelCommand::Delete(args) => model::delete(&context, &args, output_mode)?,
            ModelCommand::Verify(args) => model::verify(&context, &args)?,
        },
        Command::Engine(args) => match args.command {
            EngineCommand::List => engine::list(&context)?,
            EngineCommand::Install(args) => engine::install(&context, &args).await?,
            EngineCommand::Detect => engine::detect()?,
            EngineCommand::SetDefault(args) => engine::set_default(&context, &args)?,
        },
        Command::Serve(args) => match args.command {
            ServeCommand::Run(args) => serve::run(&context, &args).await?,
            ServeCommand::Stop(args) => serve::stop(&context, &args).await?,
            ServeCommand::Status(args) => serve::status(&context, &args).await?,
        },
        Command::Share(args) => match args.command {
            ShareCommand::Publish(args) => share::publish(&context, &args).await?,
            ShareCommand::Unpublish(args) => share::unpublish(&context, &args).await?,
            ShareCommand::Stats => share::stats(&context).await?,
        },
        Command::Quota(args) => match args.command {
            QuotaCommand::Balance => quota::balance(&context).await?,
            QuotaCommand::History(args) => quota::history(&context, &args).await?,
            QuotaCommand::Receipt(args) => quota::receipt(&context, &args).await?,
            QuotaCommand::Use(args) => quota::use_proxy(&context, &args, output_mode).await?,
        },
        Command::Node(args) => match args.command {
            NodeCommand::Policy(args) => match args.command {
                NodePolicyCommand::Show => node::policy_show(&context)?,
                NodePolicyCommand::Set(args) => node::policy_set(&context, &args)?,
            },
            NodeCommand::Threshold(args) => match args.command {
                NodeThresholdCommand::Show => node::threshold_show(&context)?,
                NodeThresholdCommand::Set(args) => node::threshold_set(&context, &args)?,
            },
            NodeCommand::Optimize => node::optimize(&context).await?,
        },
        Command::Config(args) => match args.command {
            ConfigCommand::Set(args) => config_set(&context, &args.key, &args.value)?,
            ConfigCommand::Get(args) => {
                let value = config_get(&context.config, &args.key)?;
                CommandOutput::new(
                    format!("{} = {}", args.key, value),
                    serde_json::json!({ "key": args.key, "value": value }),
                )?
            }
            ConfigCommand::List => {
                let values = config_list(&context.config);
                let human = values
                    .iter()
                    .map(|(key, value)| format!("{key} = {value}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                CommandOutput::new(human, values)?
            }
        },
        Command::Doctor(args) => doctor::run(&context, args.server_mode).await?,
        Command::Worker(args) => match args.command {
            WorkerCommand::Share => share::run_worker(&context).await?,
            WorkerCommand::ResolveDataDir => resolved_path_output("data_dir", &context.paths.home)?,
            WorkerCommand::ResolveConfigHome => {
                let home = context.config_store.path().parent().ok_or_else(|| {
                    CliError::General("配置文件缺少父目录，无法解析控制目录".to_owned())
                })?;
                resolved_path_output("config_home", home)?
            }
            WorkerCommand::SandboxProbe
            | WorkerCommand::SandboxSeccompProbe
            | WorkerCommand::SandboxExec(_)
            | WorkerCommand::SandboxSeccompExec(_)
            | WorkerCommand::WindowsJobExec(_)
            | WorkerCommand::WindowsJobSmokeExit(_)
            | WorkerCommand::LogMonitor(_)
            | WorkerCommand::ServeProxy(_) => {
                return Err(CliError::General(
                    "内部沙盒命令未在安全初始化阶段处理".to_owned(),
                ));
            }
        },
    };
    Ok((output_mode, output))
}

fn resolved_path_output(key: &str, path: &Path) -> CliResult<CommandOutput> {
    let rendered = path.display().to_string();
    CommandOutput::new(
        rendered.clone(),
        serde_json::json!({ "key": key, "path": rendered }),
    )
}

fn config_set(context: &AppContext, key: &str, value: &str) -> CliResult<CommandOutput> {
    let mut config = context.config.clone();
    set_config_value(&mut config, key, value)?;
    let canonical_key = canonical_config_key(key)?;
    if canonical_key == ConfigKey::DataDir {
        prepare_data_dir_change(context, value)?;
    }
    if canonical_key == ConfigKey::DefaultEngine && !value.trim().is_empty() {
        let engine_name = match value {
            "llama.cpp" => EngineName::LlamaCpp,
            "vllm" => EngineName::Vllm,
            "ollama" => EngineName::Ollama,
            "tensorrt-llm" => EngineName::TensorRtLlm,
            other => {
                return Err(CliError::General(format!("不支持的默认引擎：{other}")));
            }
        };
        engine::validate_default_engine_candidate(context, engine_name)?;
    }
    context.config_store.save(&config)?;
    let stored = config_get(&config, canonical_key.as_str())?;
    CommandOutput::new(
        format!("配置已原子更新：{} = {stored}", canonical_key.as_str()),
        serde_json::json!({ "key": canonical_key.as_str(), "value": stored }),
    )
}

fn prepare_data_dir_change(context: &AppContext, value: &str) -> CliResult<()> {
    if std::env::var_os("MINDONE_HOME").is_some() {
        return Err(CliError::General(
            "当前由 MINDONE_HOME 覆盖数据目录，拒绝写入不会生效的 data.dir；请先删除该环境变量再切换"
                .to_owned(),
        ));
    }

    let target_home = if value.trim().is_empty() {
        context
            .config_store
            .path()
            .parent()
            .ok_or_else(|| {
                CliError::General("配置文件缺少父目录，无法恢复默认 data.dir".to_owned())
            })?
            .to_path_buf()
    } else {
        PathBuf::from(value.trim())
    };
    let target_paths = MindOnePaths::from_home(target_home)
        .map_err(|error| CliError::General(error.to_string()))?;

    if equivalent_paths(&context.paths.home, &target_paths.home) {
        target_paths
            .ensure_directories()
            .map_err(|error| CliError::General(error.to_string()))?;
        return Ok(());
    }

    let control_config = context.config_store.path();
    if let Some(state) = first_managed_state(&context.paths, control_config)? {
        return Err(data_dir_state_error("当前", &context.paths.home, &state));
    }
    if let Some(state) = first_managed_state(&target_paths, control_config)? {
        return Err(data_dir_state_error("目标", &target_paths.home, &state));
    }
    if context.vault.has_any_credentials()? {
        return Err(CliError::General(format!(
            "拒绝切换 data.dir：当前数据目录 {} 的系统凭证命名空间仍包含 session、设备密钥或证明密钥。请先停止 serve/share 并执行 auth logout；MindOne 不会让现有身份静默失联",
            context.paths.home.display()
        )));
    }
    let target_vault = SystemVault::for_home(&target_paths.home)?;
    if target_vault.has_any_credentials()? {
        return Err(CliError::General(format!(
            "拒绝切换 data.dir：目标数据目录 {} 已绑定系统凭证。请先在该目录完成 auth logout 或改用全新空目录",
            target_paths.home.display()
        )));
    }

    target_paths
        .ensure_directories()
        .map_err(|error| CliError::General(error.to_string()))?;
    if let Some(state) = first_managed_state(&target_paths, control_config)? {
        return Err(data_dir_state_error("目标", &target_paths.home, &state));
    }
    Ok(())
}

fn first_managed_state(paths: &MindOnePaths, control_config: &Path) -> CliResult<Option<PathBuf>> {
    if !paths.home.exists() {
        return Ok(None);
    }
    let entries = fs::read_dir(&paths.home).map_err(|error| {
        CliError::General(format!(
            "无法检查数据目录 {} 的现有状态：{error}",
            paths.home.display()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|error| {
            CliError::General(format!(
                "无法枚举数据目录 {} 的现有状态：{error}",
                paths.home.display()
            ))
        })?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            CliError::General(format!("无法检查受管路径 {}：{error}", path.display()))
        })?;

        if equivalent_paths(&path, control_config) {
            if metadata.is_file() && !metadata.file_type().is_symlink() {
                continue;
            }
            return Ok(Some(path));
        }

        let is_standard_directory = matches!(
            entry.file_name().to_str(),
            Some("models" | "engines" | "runtime" | "logs" | "cache")
        );
        if !is_standard_directory || !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Ok(Some(path));
        }

        let mut children = fs::read_dir(&path).map_err(|error| {
            CliError::General(format!("无法检查受管目录 {}：{error}", path.display()))
        })?;
        if let Some(child) = children.next() {
            let child = child.map_err(|error| {
                CliError::General(format!("无法检查受管目录 {}：{error}", path.display()))
            })?;
            return Ok(Some(child.path()));
        }
    }
    Ok(None)
}

fn data_dir_state_error(scope: &str, home: &Path, state: &Path) -> CliError {
    CliError::General(format!(
        "拒绝切换 data.dir：{scope}数据目录 {} 仍包含受管状态 {}。请先停止 serve/share，并清理或受控迁移该目录后重试；MindOne 不会自动丢弃运行状态、模型或日志",
        home.display(),
        state.display()
    ))
}

fn equivalent_paths(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => {
            #[cfg(windows)]
            {
                left.to_string_lossy()
                    .replace('/', "\\")
                    .eq_ignore_ascii_case(&right.to_string_lossy().replace('/', "\\"))
            }
            #[cfg(not(windows))]
            {
                left == right
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{first_managed_state, MindOnePaths};

    #[test]
    fn data_dir_state_check_allows_only_empty_managed_layout_and_control_config() {
        let temporary_root = std::env::temp_dir()
            .canonicalize()
            .expect("应规范化系统临时目录");
        let temporary = tempfile::tempdir_in(temporary_root).expect("应创建受控临时目录");
        let paths =
            MindOnePaths::from_home(temporary.path().join("data")).expect("受控数据路径应有效");
        paths.ensure_directories().expect("应创建受管目录");
        let control = paths.config.clone();
        fs::write(&control, "server_url = 'http://127.0.0.1:8787'\n").expect("应写入控制配置");
        assert!(first_managed_state(&paths, &control)
            .expect("应检查空布局")
            .is_none());

        let state = paths.runtime.join("serve.json");
        fs::write(&state, "{}").expect("应写入运行状态");
        assert_eq!(
            first_managed_state(&paths, &control).expect("应发现运行状态"),
            Some(state)
        );
    }

    use std::fs;
}
