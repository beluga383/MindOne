use mindone_engine::{
    detect_hardware, is_audited_managed_serve_release, EngineInstaller,
    EngineName as CoreEngineName, InstalledEngine, AUDITED_MANAGED_LLAMA_CPP_RELEASE,
};

use crate::cli::{EngineInstallArgs, EngineName, EngineTargetArgs};
use crate::context::AppContext;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;

pub fn list(context: &AppContext) -> CliResult<CommandOutput> {
    let installer = installer(context)?;
    let installed = installer.registry().list().map_err(engine_error)?;
    let default = installer
        .registry()
        .configured_default()
        .map_err(engine_error)?;
    let capabilities = installer.capabilities();
    let installed_status = installed
        .into_iter()
        .map(|record| {
            let integrity_error = installer
                .registry()
                .verify_record(&record)
                .err()
                .map(|error| error.to_string());
            (record, integrity_error)
        })
        .collect::<Vec<_>>();
    let human = capabilities
        .iter()
        .map(|capability| {
            let records = installed_status
                .iter()
                .filter(|(record, _)| record.name == capability.name)
                .map(|(record, integrity_error)| {
                    let integrity = match integrity_error {
                        Some(error) => format!("校验失败：{error}"),
                        None => "校验通过".to_owned(),
                    };
                    format!(
                        "{}（{}；SHA-256={}；{}）",
                        record.version,
                        record.executable.display(),
                        record.sha256,
                        integrity
                    )
                })
                .collect::<Vec<_>>();
            let state = if records.is_empty() {
                "未安装".to_owned()
            } else {
                format!("已安装 {}", records.join(", "))
            };
            format!(
                "{}：{}；平台支持={}；{}",
                capability.name, state, capability.supported, capability.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(
        format!(
            "{}\n默认引擎：{}",
            human,
            default.map(CoreEngineName::as_str).unwrap_or("未设置")
        ),
        serde_json::json!({
            "capabilities": capabilities,
            "installed": installed_status.iter().map(|(record, integrity_error)| serde_json::json!({
                "record": record,
                "integrity_verified": integrity_error.is_none(),
                "integrity_error": integrity_error,
            })).collect::<Vec<_>>(),
            "default": default,
        }),
    )
}

pub async fn install(context: &AppContext, args: &EngineInstallArgs) -> CliResult<CommandOutput> {
    let installer = installer(context)?;
    let requested_version = requested_install_version(args);
    let record = installer
        .install(to_core_name(args.name), requested_version)
        .await
        .map_err(engine_error)?;
    CommandOutput::new(
        format!(
            "{} 安装成功\n版本：{}\n目标：{}\n可执行文件：{}\nSHA-256：{}\n来源：{}\n未修改系统 PATH",
            record.name,
            record.version,
            record.target,
            record.executable.display(),
            record.sha256,
            record.source
        ),
        record,
    )
}

fn requested_install_version(args: &EngineInstallArgs) -> &str {
    args.version.as_deref().unwrap_or(match args.name {
        EngineName::LlamaCpp => AUDITED_MANAGED_LLAMA_CPP_RELEASE,
        EngineName::Vllm | EngineName::Ollama | EngineName::TensorRtLlm => "latest",
    })
}

pub fn detect() -> CliResult<CommandOutput> {
    let profile = detect_hardware();
    let gpu = if profile.gpus.is_empty() {
        "未检测到".to_owned()
    } else {
        profile
            .gpus
            .iter()
            .map(|item| {
                format!(
                    "{}（显存={}，温度={}）",
                    item.name,
                    item.memory_bytes
                        .map(|value| format!("{value} bytes"))
                        .unwrap_or_else(|| "平台未提供".to_owned()),
                    item.temperature_celsius
                        .map(|value| format!("{value}°C"))
                        .unwrap_or_else(|| "平台未提供".to_owned())
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    CommandOutput::new(
        format!(
            "系统：{} {} / 内核 {} ({})\nCPU：{} / {} 逻辑核\n内存：{} bytes\nGPU：{}\nMetal：{}\nCUDA：{}\n推荐后端：{}",
            profile.os,
            profile.os_version,
            profile.kernel_version,
            profile.architecture,
            profile.cpu_brand,
            profile.logical_cpu_count,
            profile.total_memory_bytes,
            gpu,
            profile.metal_available,
            profile.cuda_available,
            profile.recommended_backend
        ),
        profile,
    )
}

pub fn set_default(context: &AppContext, args: &EngineTargetArgs) -> CliResult<CommandOutput> {
    let installer = installer(context)?;
    // 必须先读取并验证实际安装登记的版本，再让 registry/config 发生任何写入。
    // `engine install latest` 只代表安装链路可信，不代表该上游版本的受管运行时
    // 语义已经完成独立审计。
    let validated = validated_default_engine_record(context, args.engine)?;
    let record = installer
        .registry()
        .set_default_version(to_core_name(args.engine), &validated.version)
        .map_err(engine_error)?;
    let mut config = context.config.clone();
    config.default_engine = Some(args.engine.as_str().to_owned());
    context.config_store.save(&config)?;
    CommandOutput::new(
        format!("默认推理引擎已设置为 {} ({})", record.name, record.version),
        serde_json::json!({ "default_engine": record.name, "version": record.version }),
    )
}

pub fn resolve_engine(context: &AppContext, name: EngineName) -> CliResult<InstalledEngine> {
    validated_default_engine_record(context, name)
}

pub fn default_engine(context: &AppContext) -> CliResult<EngineName> {
    let installer = installer(context)?;
    if let Some(name) = installer
        .registry()
        .configured_default()
        .map_err(engine_error)?
    {
        let name = from_core_name(name);
        validate_default_engine_candidate(context, name)?;
        return Ok(name);
    }
    let configured = match context.config.default_engine.as_deref() {
        Some("llama.cpp") => Ok(EngineName::LlamaCpp),
        Some("vllm") => Ok(EngineName::Vllm),
        Some("ollama") => Ok(EngineName::Ollama),
        Some("tensorrt-llm") => Ok(EngineName::TensorRtLlm),
        Some(other) => Err(CliError::EngineOrSandbox(format!(
            "配置中的默认引擎无效：{other}"
        ))),
        None => Err(CliError::EngineOrSandbox(
            "尚未设置默认引擎，请使用 --engine 或 mindone engine set-default".to_owned(),
        )),
    }?;
    validate_default_engine_candidate(context, configured)?;
    Ok(configured)
}

/// 校验一个引擎是否能成为 v1 `serve` 的默认运行时。
///
/// `engine install` 的平台能力只证明官方资产、依赖闭包和入口可被受管安装，不能
/// 等同于 CLI 已实现对应的模型格式、沙盒与生命周期适配器。默认值必须满足后者，
/// 否则会把一份能够成功写入、却必然无法由 `serve run` 启动的配置留给用户。
pub fn validate_default_engine_candidate(context: &AppContext, name: EngineName) -> CliResult<()> {
    let _validated = validated_default_engine_record(context, name)?;
    Ok(())
}

fn validated_default_engine_record(
    context: &AppContext,
    name: EngineName,
) -> CliResult<InstalledEngine> {
    require_managed_serve_adapter(name)?;
    let installer = installer(context)?;
    let installed = installer
        .registry()
        .version(
            to_core_name(name),
            match name {
                EngineName::LlamaCpp => AUDITED_MANAGED_LLAMA_CPP_RELEASE,
                EngineName::Vllm | EngineName::Ollama | EngineName::TensorRtLlm => "latest",
            },
        )
        .map_err(engine_error)?;
    require_audited_managed_release(&installed)?;
    require_supported(&installer, installed.name)?;
    Ok(installed)
}

fn require_audited_managed_release(installed: &InstalledEngine) -> CliResult<()> {
    if is_audited_managed_serve_release(installed.name, &installed.version) {
        Ok(())
    } else {
        Err(CliError::EngineOrSandbox(format!(
            "{} {} 尚未完成受管运行时审计；当前唯一允许 {} {}，拒绝将其设为默认引擎",
            installed.name,
            installed.version,
            CoreEngineName::LlamaCpp,
            AUDITED_MANAGED_LLAMA_CPP_RELEASE
        )))
    }
}

fn installer(context: &AppContext) -> CliResult<EngineInstaller> {
    EngineInstaller::new(
        context.paths.engines.clone(),
        context.paths.cache.clone(),
        context.paths.engines.join("index.json"),
    )
    .map_err(engine_error)
}

fn require_supported(installer: &EngineInstaller, name: CoreEngineName) -> CliResult<()> {
    let capability = installer.capability(name);
    if capability.supported {
        Ok(())
    } else {
        Err(CliError::EngineOrSandbox(format!(
            "当前不能安全使用 {}：{}",
            name, capability.reason
        )))
    }
}

fn require_managed_serve_adapter(name: EngineName) -> CliResult<()> {
    if name == EngineName::LlamaCpp {
        Ok(())
    } else {
        Err(CliError::EngineOrSandbox(format!(
            "当前 v1 受管 serve 仅支持真实 llama.cpp；{} 虽可通过 engine install 安装和验证，但尚未实现可运行的 serve adapter，不能设为默认推理引擎",
            name.as_str()
        )))
    }
}

fn to_core_name(name: EngineName) -> CoreEngineName {
    match name {
        EngineName::LlamaCpp => CoreEngineName::LlamaCpp,
        EngineName::Vllm => CoreEngineName::Vllm,
        EngineName::Ollama => CoreEngineName::Ollama,
        EngineName::TensorRtLlm => CoreEngineName::TensorrtLlm,
    }
}

fn from_core_name(name: CoreEngineName) -> EngineName {
    match name {
        CoreEngineName::LlamaCpp => EngineName::LlamaCpp,
        CoreEngineName::Vllm => EngineName::Vllm,
        CoreEngineName::Ollama => EngineName::Ollama,
        CoreEngineName::TensorrtLlm => EngineName::TensorRtLlm,
    }
}

fn engine_error(error: impl std::fmt::Display) -> CliError {
    CliError::EngineOrSandbox(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mindone_common::MindOnePaths;
    use mindone_engine::{EngineFileIntegrity, EngineName as CoreEngineName, InstalledEngine};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::*;
    use crate::config::{AppConfig, ConfigStore};
    use crate::coordinator::CoordinatorClient;
    use crate::vault::SystemVault;

    fn test_context(temporary: &tempfile::TempDir) -> AppContext {
        // macOS 的 tempfile 通常经 `/var` 符号链接落到 `/private/var`；生产路径校验
        // 会正确拒绝符号链接父链，所以测试必须先解析受控临时根目录。
        let canonical_temporary =
            fs::canonicalize(temporary.path()).expect("应解析临时目录真实路径");
        let paths = MindOnePaths::from_home(canonical_temporary.join("mindone-home"))
            .expect("临时 MindOne home 应有效");
        paths.ensure_directories().expect("应创建测试目录");
        let config = AppConfig::default();
        let config_store = ConfigStore::new(paths.config.clone());
        config_store.save(&config).expect("应写入初始配置");
        AppContext {
            paths: paths.clone(),
            config,
            config_store,
            coordinator: CoordinatorClient::new("http://127.0.0.1:8787")
                .expect("loopback 测试地址应有效"),
            vault: SystemVault::for_home(&paths.home).expect("应创建测试凭证命名空间"),
        }
    }

    fn write_test_llama_registry(
        context: &AppContext,
        version: &str,
        configured_default: bool,
    ) -> InstalledEngine {
        let target = "unit-test-target";
        let directory = context
            .paths
            .engines
            .join(CoreEngineName::LlamaCpp.as_str())
            .join(version)
            .join(target);
        fs::create_dir_all(&directory).expect("应创建测试引擎目录");
        let executable = directory.join("llama-server");
        let executable_bytes = format!("unit-test-llama-{version}").into_bytes();
        fs::write(&executable, &executable_bytes).expect("应写入测试引擎");
        let directory = fs::canonicalize(directory).expect("应解析测试引擎目录");
        let executable = fs::canonicalize(executable).expect("应解析测试引擎文件");
        let sha256 = hex::encode(Sha256::digest(&executable_bytes));
        let record = InstalledEngine {
            id: Uuid::now_v7(),
            name: CoreEngineName::LlamaCpp,
            version: version.to_owned(),
            target: target.to_owned(),
            directory,
            executable,
            sha256: sha256.clone(),
            files: vec![EngineFileIntegrity {
                relative_path: "llama-server".into(),
                size_bytes: executable_bytes.len() as u64,
                sha256,
            }],
            installed_at_unix: 1,
            source: "unit-test".to_owned(),
        };
        let registry = serde_json::json!({
            "version": 1,
            "default": configured_default.then_some(CoreEngineName::LlamaCpp),
            "engines": [&record],
        });
        fs::write(
            context.paths.engines.join("index.json"),
            serde_json::to_vec_pretty(&registry).expect("registry 应可序列化"),
        )
        .expect("应写入测试 registry");
        record
    }

    #[test]
    fn cli_support_guard_matches_verified_platform_capabilities() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let engines = temporary.path().join("engines");
        let cache = temporary.path().join("cache");
        let installer = EngineInstaller::new(&engines, &cache, engines.join("index.json"))
            .expect("应创建引擎安装器");
        for name in [
            CoreEngineName::Vllm,
            CoreEngineName::Ollama,
            CoreEngineName::TensorrtLlm,
        ] {
            let capability = installer.capability(name);
            let result = require_supported(&installer, name);
            assert_eq!(result.is_ok(), capability.supported);
            if let Err(error) = result {
                assert!(error.to_string().contains("当前不能安全使用"));
            }
        }
    }

    #[test]
    fn default_engine_guard_rejects_install_only_adapters() {
        assert!(require_managed_serve_adapter(EngineName::LlamaCpp).is_ok());
        for name in [
            EngineName::Ollama,
            EngineName::Vllm,
            EngineName::TensorRtLlm,
        ] {
            let error = require_managed_serve_adapter(name)
                .expect_err("没有 v1 serve adapter 的引擎不能成为默认值");
            assert!(matches!(error, CliError::EngineOrSandbox(_)));
            assert!(error.to_string().contains("尚未实现可运行的 serve adapter"));
            assert!(error.to_string().contains(name.as_str()));
        }
    }

    #[test]
    fn omitted_llama_version_is_the_audited_release_not_upstream_latest() {
        let llama = EngineInstallArgs {
            name: EngineName::LlamaCpp,
            version: None,
        };
        assert_eq!(
            requested_install_version(&llama),
            AUDITED_MANAGED_LLAMA_CPP_RELEASE
        );

        let ollama = EngineInstallArgs {
            name: EngineName::Ollama,
            version: None,
        };
        assert_eq!(requested_install_version(&ollama), "latest");

        let explicit = EngineInstallArgs {
            name: EngineName::LlamaCpp,
            version: Some("b10063".to_owned()),
        };
        assert_eq!(requested_install_version(&explicit), "b10063");
    }

    #[test]
    fn set_default_requires_the_exact_audited_release_without_mutation() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let context = test_context(&temporary);
        let unaudited = "b10065";
        write_test_llama_registry(&context, unaudited, false);
        let registry_path = context.paths.engines.join("index.json");
        let registry_before = fs::read(&registry_path).expect("应读取初始 registry");
        let config_before = fs::read(&context.paths.config).expect("应读取初始配置");

        let error = set_default(
            &context,
            &EngineTargetArgs {
                engine: EngineName::LlamaCpp,
            },
        )
        .expect_err("未受审计 release 不得成为默认值");

        assert!(error
            .to_string()
            .contains(AUDITED_MANAGED_LLAMA_CPP_RELEASE));
        assert!(
            !error.to_string().contains("尚未完成受管运行时审计"),
            "精确版本选择不应把另一个已安装版本误当成默认候选"
        );
        assert_eq!(
            fs::read(&registry_path).expect("应重新读取 registry"),
            registry_before,
            "拒绝路径不得改写 registry"
        );
        assert_eq!(
            fs::read(&context.paths.config).expect("应重新读取配置"),
            config_before,
            "拒绝路径不得改写 config"
        );
    }

    #[test]
    fn default_engine_requires_the_exact_audited_registry_record_without_mutation() {
        let temporary = tempfile::TempDir::new().expect("应创建临时目录");
        let context = test_context(&temporary);
        let unaudited = "b10065";
        write_test_llama_registry(&context, unaudited, true);
        let registry_path = context.paths.engines.join("index.json");
        let registry_before = fs::read(&registry_path).expect("应读取初始 registry");
        let config_before = fs::read(&context.paths.config).expect("应读取初始配置");

        let error = default_engine(&context).expect_err("registry 默认值也必须校验实际版本");

        assert!(error
            .to_string()
            .contains(AUDITED_MANAGED_LLAMA_CPP_RELEASE));
        assert!(
            !error.to_string().contains("尚未完成受管运行时审计"),
            "registry 默认名称不能让较新但未受审计的版本遮蔽精确版本选择"
        );
        assert_eq!(
            fs::read(&registry_path).expect("应重新读取 registry"),
            registry_before
        );
        assert_eq!(
            fs::read(&context.paths.config).expect("应重新读取配置"),
            config_before
        );
    }
}
