use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use mindone_engine::{
    download_model, parse_gguf_split_filename, probe_model_download, validate_gguf_split_reports,
    validate_model, ModelDownloadProbeRequest, ModelDownloadRequest,
    ModelPlatform as CoreModelPlatform, ModelRecord, ModelRegistry, ValidationReport,
};
use reqwest::header::LINK;
use serde::Deserialize;
use url::Url;

use crate::cli::{
    EngineInstallArgs, EngineName, EngineTargetArgs, ModelCatalogArgs, ModelDeleteArgs,
    ModelDeployArgs, ModelDownloadArgs, ModelPlatform, ModelProbeArgs, ModelRecommendArgs,
    ModelTargetArgs, ServeRunArgs, ServeStopArgs,
};
use crate::context::AppContext;
use crate::error::{CliError, CliResult};
use crate::output::{CommandOutput, OutputMode};

#[derive(Debug, Deserialize)]
struct HfTreeEntry {
    path: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    lfs: Option<HfLfs>,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct HfLfs {
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    size: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ModelScopeManifestEnvelope {
    #[serde(rename = "Code")]
    code: u16,
    #[serde(rename = "Success")]
    success: bool,
    #[serde(rename = "Data")]
    data: Option<ModelScopeManifestData>,
}

#[derive(Debug, Deserialize)]
struct ModelScopeManifestData {
    #[serde(rename = "Files")]
    files: Option<Vec<ModelScopeManifestEntry>>,
}

#[derive(Debug, Deserialize)]
struct ModelScopeManifestEntry {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Type")]
    kind: String,
    #[serde(rename = "Sha256", default)]
    sha256: Option<String>,
}

#[derive(Debug, Clone)]
struct RemoteArtifact {
    file: String,
    trusted_sha256: Option<String>,
    size_bytes: Option<u64>,
}

const MODEL_MANIFEST_MAX_BYTES: usize = 8 * 1024 * 1024;
const HF_MANIFEST_MAX_BYTES: usize = 32 * 1024 * 1024;
const HF_MANIFEST_MAX_PAGES: usize = 16;

pub fn list(context: &AppContext) -> CliResult<CommandOutput> {
    let records = registry(context).list().map_err(model_registry_error)?;
    if records.is_empty() {
        return CommandOutput::new("尚未下载任何模型", records);
    }
    let lines = records
        .iter()
        .map(|record| {
            format!(
                "{} | {:?} | {} | {} | {} | {} | {}",
                record.name,
                record.format,
                human_bytes(record.size_bytes),
                if record.verification_is_current_in(&context.paths.models) {
                    "通过"
                } else {
                    "失效"
                },
                record.sha256,
                record.path.display(),
                record.compatible_engines.join(",")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(
        format!("名称 | 格式 | 大小 | 验证 | SHA-256 | 路径 | 兼容引擎\n{lines}"),
        records,
    )
}

pub fn catalog(args: &ModelCatalogArgs) -> CliResult<CommandOutput> {
    let models = crate::model_catalog::catalog(args.query.as_deref());
    if models.is_empty() {
        return CommandOutput::new("没有匹配的官方模型", models);
    }
    let lines = models
        .iter()
        .map(|model| {
            let memory = model
                .estimated_q4_memory_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "需下载时核验".to_owned());
            format!("{} | {} | {}", model.repository, model.provider, memory)
        })
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(
        format!(
            "官方 Hugging Face 目标目录（下载发生在当前用户设备）\n模型 | 厂商 | 保守 Q4 内存估算\n{lines}"
        ),
        models,
    )
}

pub fn recommend(args: &ModelRecommendArgs) -> CliResult<CommandOutput> {
    let (hardware, recommendations) = crate::model_catalog::recommend(usize::from(args.limit));
    if recommendations.is_empty() {
        return CommandOutput::new(
            "当前硬件没有满足保守内存预算的目录模型；可使用 model catalog 查看目录",
            serde_json::json!({
                "hardware": hardware,
                "recommendations": recommendations,
            }),
        );
    }
    let lines = recommendations
        .iter()
        .map(|item| {
            format!(
                "{}. {} | 估算 {} | {}",
                item.rank,
                item.repository,
                human_bytes(item.estimated_q4_memory_bytes),
                item.backend
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(
        format!(
            "本机推荐（下载前还会实时核验 HF 文件和可用后端）\n{lines}\n\n探测首选：mindone model probe {}",
            recommendations[0].repository
        ),
        serde_json::json!({
            "hardware": hardware,
            "recommendations": recommendations,
        }),
    )
}

pub async fn probe(args: &ModelProbeArgs) -> CliResult<CommandOutput> {
    validate_repository(&args.model)?;
    validate_single_segment(&args.branch, "分支")?;
    if !crate::model_catalog::contains(&args.model) {
        return Err(CliError::General(format!(
            "模型不在官方支持目录中：{}；请先运行 mindone model catalog",
            args.model
        )));
    }
    let (repository, artifact, candidate_count, deployment_artifacts) = if args.deployment {
        if args.branch != "main" {
            return Err(CliError::General(
                "--deployment 当前只允许官方 main 版本，不能同时覆盖 --branch".to_owned(),
            ));
        }
        let deployment = discover_deployment_artifact(&args.model).await?;
        let shard_count = deployment.artifacts.len();
        let artifact = deployment.primary()?.clone();
        (
            deployment.repository,
            artifact,
            shard_count,
            deployment.artifacts,
        )
    } else {
        let mut candidates = fetch_huggingface_artifacts(&args.model, &args.branch).await?;
        if let Some(requested) = &args.file {
            validate_remote_path(requested)?;
            candidates.retain(|candidate| candidate.file == *requested);
        } else {
            candidates.sort_by(|left, right| {
                probe_artifact_priority(&left.file)
                    .cmp(&probe_artifact_priority(&right.file))
                    .then_with(|| left.file.cmp(&right.file))
            });
        }
        let candidate_count = candidates.len();
        let artifact = candidates.into_iter().next().ok_or_else(|| {
            CliError::ModelValidation("仓库中未发现可探测的 GGUF 或 safetensors 文件".to_owned())
        })?;
        (
            args.model.clone(),
            artifact.clone(),
            candidate_count,
            vec![artifact],
        )
    };
    if args.metadata_only {
        let total_size = deployment_artifacts.iter().try_fold(0_u64, |sum, item| {
            item.size_bytes.and_then(|size| sum.checked_add(size))
        });
        let files = deployment_artifacts
            .iter()
            .map(|item| {
                serde_json::json!({
                    "file": item.file,
                    "size_bytes": item.size_bytes,
                    "trusted_sha256": item.trusted_sha256,
                })
            })
            .collect::<Vec<_>>();
        return CommandOutput::new(
            format!(
                "HF 部署元数据已解析（未请求权重）\n仓库：{repository}\n主文件：{}\n分片数：{}\n总大小：{}\nLFS SHA-256：{}",
                artifact.file,
                deployment_artifacts.len(),
                total_size
                    .map(human_bytes)
                    .unwrap_or_else(|| "清单不完整".to_owned()),
                if deployment_artifacts
                    .iter()
                    .all(|item| item.trusted_sha256.is_some())
                {
                    "全部可信"
                } else {
                    "不完整"
                }
            ),
            serde_json::json!({
                "repository": repository,
                "primary_file": artifact.file,
                "files": files,
                "shard_count": deployment_artifacts.len(),
                "total_size_bytes": total_size,
                "candidate_count": candidate_count,
                "persisted": false,
                "download_started": false,
                "download_location": "client",
                "deployment_artifact": args.deployment,
            }),
        );
    }
    let report = probe_model_download(ModelDownloadProbeRequest {
        platform: CoreModelPlatform::HuggingFace,
        repository,
        branch: args.branch.clone(),
        remote_file: artifact.file,
        expected_sha256: artifact.trusted_sha256,
        huggingface_token: huggingface_token_from_env()?,
        override_base_url: None,
    })
    .await
    .map_err(model_download_error)?;
    CommandOutput::new(
        format!(
            "HF 下载已成功开始并主动中止（未写入模型文件）\n仓库：{}\n文件：{}\n读取：{}\n远端总大小：{}\nRange：{}\n安全候选数：{}",
            report.repository,
            report.remote_file,
            human_bytes(report.bytes_received),
            report
                .total_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "未知".to_owned()),
            if report.range_supported { "支持" } else { "远端忽略；客户端仍已限流中止" },
            candidate_count,
        ),
        serde_json::json!({
            "probe": report,
            "candidate_count": candidate_count,
            "persisted": false,
            "download_location": "client",
            "deployment_artifact": args.deployment,
            "deployment_shard_count": deployment_artifacts.len(),
        }),
    )
}

fn probe_artifact_priority(file: &str) -> u8 {
    let lower = file.to_ascii_lowercase();
    if lower.ends_with(".gguf") {
        0
    } else if lower == "model.safetensors" {
        1
    } else {
        2
    }
}

#[derive(Debug)]
struct DeploymentArtifact {
    repository: String,
    artifacts: Vec<RemoteArtifact>,
}

impl DeploymentArtifact {
    fn primary(&self) -> CliResult<&RemoteArtifact> {
        self.artifacts
            .first()
            .ok_or_else(|| CliError::General("部署产物集合意外为空".to_owned()))
    }
}

pub async fn deploy(
    context: &AppContext,
    args: &ModelDeployArgs,
    output_mode: OutputMode,
) -> CliResult<CommandOutput> {
    let selected = if args.model == "auto" {
        let (_, recommendations) = crate::model_catalog::recommend(1);
        recommendations
            .first()
            .map(|item| item.repository.to_owned())
            .ok_or_else(|| {
                CliError::EngineOrSandbox(
                    "当前硬件没有满足保守内存预算的目录模型，无法自动部署".to_owned(),
                )
            })?
    } else {
        args.model.clone()
    };
    if !crate::model_catalog::contains(&selected) {
        return Err(CliError::General(format!(
            "模型不在官方支持目录中：{selected}；请运行 mindone model catalog"
        )));
    }
    let deployment = discover_deployment_artifact(&selected).await?;
    enforce_deployment_memory_budget(&deployment.artifacts)?;

    let local_name = selected
        .rsplit_once('/')
        .map(|value| value.1.to_owned())
        .ok_or_else(|| CliError::General("官方模型 ID 无法生成本地名称".to_owned()))?;
    let record = match registry(context).find(&local_name) {
        Ok(record) => {
            if !record.verification_is_current_in(&context.paths.models) {
                return Err(CliError::ModelValidation(format!(
                    "已登记模型 {local_name} 的验证状态失效；请先执行 model verify 或删除后重下"
                )));
            }
            record
        }
        Err(error) if error.to_string().starts_with("未找到模型：") => {
            if deployment.artifacts.len() == 1 {
                let primary = deployment.primary()?;
                let download_args = ModelDownloadArgs {
                    platform: ModelPlatform::HuggingFace,
                    repo: deployment.repository.clone(),
                    branch: "main".to_owned(),
                    name: Some(local_name.clone()),
                    file: Some(primary.file.clone()),
                    sha256: primary.trusted_sha256.clone(),
                };
                let _download = download(context, &download_args, output_mode).await?;
                registry(context)
                    .find(&local_name)
                    .map_err(model_registry_error)?
            } else {
                download_deployment_bundle(context, &local_name, &deployment, output_mode).await?
            }
        }
        Err(error) => return Err(model_registry_error(error)),
    };

    let engine_install = match crate::engine::resolve_engine(context, EngineName::LlamaCpp) {
        Ok(_) => None,
        Err(error) if error.to_string().contains("未找到已安装引擎") => Some(
            crate::engine::install(
                context,
                &EngineInstallArgs {
                    name: EngineName::LlamaCpp,
                    version: None,
                },
            )
            .await?,
        ),
        Err(error) => return Err(error),
    };
    let _default = crate::engine::set_default(
        context,
        &EngineTargetArgs {
            engine: EngineName::LlamaCpp,
        },
    )?;

    let serve_state = crate::serve::state_path(context, args.port);
    let replaced = if serve_state.exists() {
        if !args.replace {
            return Err(CliError::EngineOrSandbox(
                format!(
                    "端口 {} 已有受管模型状态；替换该端口请增加 --replace，或先执行 mindone serve stop --port {}",
                    args.port, args.port
                ),
            ));
        }
        crate::serve::stop(
            context,
            &ServeStopArgs {
                port: args.port,
                timeout: 10,
            },
        )
        .await?;
        true
    } else {
        false
    };
    let served = crate::serve::run(
        context,
        &ServeRunArgs {
            model: record.name.clone(),
            engine: Some(EngineName::LlamaCpp),
            port: args.port,
            config: None,
        },
    )
    .await?;
    CommandOutput::new(
        format!(
            "模型已自动下载并部署\n目录模型：{}\nHF 权重仓库：{}\n主文件：{}\n分片数：{}\n本地模型：{}\n服务：http://127.0.0.1:{}\n引擎：llama.cpp {}\n切换旧服务：{}",
            selected,
            deployment.repository,
            deployment.primary()?.file,
            deployment.artifacts.len(),
            record.name,
            args.port,
            if engine_install.is_some() { "（本次自动安装）" } else { "（已验证安装）" },
            if replaced { "是" } else { "否" },
        ),
        serde_json::json!({
            "catalog_model": selected,
            "artifact_repository": deployment.repository.clone(),
            "artifact_file": deployment.primary()?.file.clone(),
            "artifact_files": deployment.artifacts.iter().map(|artifact| artifact.file.as_str()).collect::<Vec<_>>(),
            "shard_count": deployment.artifacts.len(),
            "model": record,
            "engine_install": engine_install.map(|output| output.data),
            "serve": served.data,
            "replaced": replaced,
        }),
    )
}

async fn discover_deployment_artifact(model: &str) -> CliResult<DeploymentArtifact> {
    validate_repository(model)?;
    let (_, name) = model
        .split_once('/')
        .ok_or_else(|| CliError::General("模型 ID 必须为 owner/name".to_owned()))?;
    let owner = model
        .split_once('/')
        .map(|value| value.0)
        .ok_or_else(|| CliError::General("模型 ID 必须为 owner/name".to_owned()))?;
    let mut repositories = vec![
        model.to_owned(),
        format!("{owner}/{name}-GGUF"),
        format!("ggml-org/{name}-GGUF"),
        format!("bartowski/{name}-GGUF"),
        format!("unsloth/{name}-GGUF"),
        format!("lmstudio-community/{name}-GGUF"),
        format!("mradermacher/{name}-GGUF"),
        format!("ubergarm/{name}-GGUF"),
        format!("DevQuasar/{owner}.{name}-GGUF"),
        format!("bartowski/{owner}_{name}-GGUF"),
    ];
    match model {
        "deepseek-ai/DeepSeek-V3.2-Exp" => {
            // 这两个公开转换保留原始 Exp 权重，并分别提供关闭/启用 lightning
            // attention 的 llama.cpp 兼容布局。受管 b10064 优先使用 dense fallback。
            repositories.push("sszymczyk/DeepSeek-V3.2-Exp-nolight-GGUF".to_owned());
            repositories.push("sszymczyk/DeepSeek-V3.2-Exp-light-GGUF".to_owned());
            repositories.push("lovedheart/DeepSeek-V3.2-GGUF-Experimental".to_owned());
        }
        "ibm-granite/granite-3.2-8b-instruct" => {
            repositories.push("ibm-research/granite-3.2-8b-instruct-GGUF".to_owned());
        }
        "microsoft/Phi-4-multimodal-instruct" => {
            repositories.push("Swicked86/phi4-mm-gguf".to_owned());
            repositories.push("shmarymane/Phi-4-multimodal-instruct-gguf".to_owned());
        }
        _ => {}
    }
    let mut seen_repositories = BTreeSet::new();
    repositories.retain(|repository| seen_repositories.insert(repository.clone()));
    let memory_budget = deployment_memory_budget();
    let mut best: Option<(bool, u8, u64, usize, DeploymentArtifact)> = None;
    let mut skipped_auth_candidate = false;
    for (repository_rank, repository) in repositories.into_iter().enumerate() {
        let artifacts = match fetch_huggingface_artifacts(&repository, "main").await {
            Ok(artifacts) => artifacts,
            Err(error)
                if error.to_string().contains("HTTP 401")
                    || error.to_string().contains("HTTP 403") =>
            {
                skipped_auth_candidate = true;
                continue;
            }
            Err(error) if deployment_candidate_unavailable(&error) => continue,
            Err(error) => return Err(error),
        };
        let mut groups = deployment_artifact_groups(artifacts);
        groups.sort_by(|left, right| {
            let left_primary = left
                .first()
                .map(|artifact| artifact.file.as_str())
                .unwrap_or("");
            let right_primary = right
                .first()
                .map(|artifact| artifact.file.as_str())
                .unwrap_or("");
            deployment_quantization_priority(left_primary)
                .cmp(&deployment_quantization_priority(right_primary))
                .then_with(|| deployment_group_size(left).cmp(&deployment_group_size(right)))
                .then_with(|| left_primary.cmp(right_primary))
        });
        for artifacts in groups {
            let primary = artifacts
                .first()
                .map(|artifact| artifact.file.as_str())
                .unwrap_or("");
            let size = deployment_group_size(&artifacts);
            let fits = size
                .checked_add(2 * 1024 * 1024 * 1024)
                .is_some_and(|required| required <= memory_budget);
            let priority = deployment_quantization_priority(primary);
            let candidate = DeploymentArtifact {
                repository: repository.clone(),
                artifacts,
            };
            let key = (!fits, priority, size, repository_rank);
            let replace = best
                .as_ref()
                .is_none_or(|current| key < (current.0, current.1, current.2, current.3));
            if replace {
                best = Some((!fits, priority, size, repository_rank, candidate));
            }
            if fits && priority == 0 {
                return best
                    .map(|value| value.4)
                    .ok_or_else(|| CliError::General("部署候选意外为空".to_owned()));
            }
        }
    }
    if let Some((_, _, _, _, candidate)) = best {
        return Ok(candidate);
    }
    Err(CliError::EngineOrSandbox(format!(
        "尚未在受信 HF 候选仓库中找到可由当前跨平台 llama.cpp 适配器运行的完整 GGUF：{model}；分片必须数量、LFS 哈希和内部 split 元数据全部一致，safetensors 不会被误当成可运行部署{}",
        if skipped_auth_candidate {
            "；部分候选需要 HF_TOKEN 或先接受仓库许可"
        } else {
            ""
        }
    )))
}

fn deployment_candidate_unavailable(error: &CliError) -> bool {
    let message = error.to_string();
    message.contains("HTTP 404")
        || message.contains("仓库中未发现 GGUF 或 safetensors 模型文件")
        || message.contains("Hugging Face 模型清单跳转到非预期来源")
}

fn deployment_memory_budget() -> u64 {
    let hardware = mindone_engine::detect_hardware();
    hardware
        .gpus
        .iter()
        .filter(|gpu| !gpu.unified_memory)
        .filter_map(|gpu| gpu.memory_bytes)
        .max()
        .unwrap_or(hardware.total_memory_bytes)
        .saturating_mul(7)
        / 10
}

fn deployment_artifact_groups(artifacts: Vec<RemoteArtifact>) -> Vec<Vec<RemoteArtifact>> {
    let mut groups = Vec::new();
    let mut split_groups: BTreeMap<(String, String, u16), Vec<RemoteArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        let lower = artifact.file.to_ascii_lowercase();
        if !lower.ends_with(".gguf")
            || auxiliary_gguf(&lower)
            || artifact.trusted_sha256.is_none()
            || artifact.size_bytes.is_none()
        {
            continue;
        }
        if let Some(parsed) = parse_gguf_split_filename(Path::new(&artifact.file)) {
            let parent = Path::new(&artifact.file)
                .parent()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_owned();
            split_groups
                .entry((parent, parsed.prefix, parsed.count))
                .or_default()
                .push(artifact);
        } else if !lower.contains("-of-") {
            groups.push(vec![artifact]);
        }
    }
    for ((_, prefix, count), mut artifacts) in split_groups {
        artifacts.sort_by_key(|artifact| {
            parse_gguf_split_filename(Path::new(&artifact.file))
                .map(|parsed| parsed.index)
                .unwrap_or(u16::MAX)
        });
        let complete = artifacts.len() == usize::from(count)
            && artifacts.iter().enumerate().all(|(position, artifact)| {
                parse_gguf_split_filename(Path::new(&artifact.file)).is_some_and(|parsed| {
                    parsed.prefix == prefix
                        && parsed.count == count
                        && usize::from(parsed.index) == position + 1
                })
            });
        if complete {
            groups.push(artifacts);
        }
    }
    groups
}

fn auxiliary_gguf(lower_file: &str) -> bool {
    let basename = lower_file.rsplit('/').next().unwrap_or(lower_file);
    lower_file.contains("mmproj")
        || lower_file.contains("projector")
        || basename.contains("imatrix")
        || basename.starts_with("mtp-")
        || basename.starts_with("draft-")
        || basename.contains("-draft-")
}

fn deployment_group_size(artifacts: &[RemoteArtifact]) -> u64 {
    artifacts.iter().fold(0_u64, |total, artifact| {
        total.saturating_add(artifact.size_bytes.unwrap_or(u64::MAX))
    })
}

fn deployment_quantization_priority(file: &str) -> u8 {
    let lower = file.to_ascii_lowercase();
    if lower.contains("q4_k_m") {
        0
    } else if lower.contains("q4_k_xl") || lower.contains("q4_k_l") {
        1
    } else if lower.contains("q4_0") {
        2
    } else if lower.contains("q4_k_s") {
        3
    } else if lower.contains("iq4") {
        4
    } else if lower.contains("q5_k_m") {
        5
    } else if lower.contains("iq3") {
        6
    } else if lower.contains("q3") {
        7
    } else if lower.contains("iq2") {
        8
    } else if lower.contains("iq1") {
        9
    } else {
        20
    }
}

fn enforce_deployment_memory_budget(artifacts: &[RemoteArtifact]) -> CliResult<()> {
    let size = artifacts.iter().try_fold(0_u64, |total, artifact| {
        let artifact_size = artifact.size_bytes.ok_or_else(|| {
            CliError::EngineOrSandbox(
                "HF 清单没有提供完整分片大小，拒绝跳过部署内存预检".to_owned(),
            )
        })?;
        total
            .checked_add(artifact_size)
            .ok_or_else(|| CliError::EngineOrSandbox("GGUF 分片总大小溢出".to_owned()))
    })?;
    let hardware = mindone_engine::detect_hardware();
    let available = hardware
        .gpus
        .iter()
        .filter(|gpu| !gpu.unified_memory)
        .filter_map(|gpu| gpu.memory_bytes)
        .max()
        .unwrap_or(hardware.total_memory_bytes);
    let required = size.saturating_add(2 * 1024 * 1024 * 1024);
    if required > available.saturating_mul(7) / 10 {
        return Err(CliError::EngineOrSandbox(format!(
            "所选 GGUF（{} 个分片）合计 {}，连同运行余量至少按 {} 预检，超过当前设备内存 70% 安全预算 {}；请选择更小模型或更小量化",
            artifacts.len(),
            human_bytes(size),
            human_bytes(required),
            human_bytes(available.saturating_mul(7) / 10),
        )));
    }
    Ok(())
}

async fn download_deployment_bundle(
    context: &AppContext,
    local_name: &str,
    deployment: &DeploymentArtifact,
    output_mode: OutputMode,
) -> CliResult<ModelRecord> {
    validate_single_segment(local_name, "本地模型名称")?;
    if deployment.artifacts.len() < 2 {
        return Err(CliError::General(
            "分片下载路径至少需要两个 GGUF 文件".to_owned(),
        ));
    }
    fs::create_dir_all(&context.paths.models)
        .map_err(|error| CliError::General(format!("无法创建模型目录：{error}")))?;
    let models_root = fs::canonicalize(&context.paths.models)
        .map_err(|error| CliError::General(format!("无法规范化模型目录：{error}")))?;
    let staging = models_root.join(format!(".{local_name}.bundle.part"));
    let final_directory = models_root.join(format!("{local_name}.bundle"));
    match fs::symlink_metadata(&final_directory) {
        Ok(_) => {
            return Err(CliError::General(format!(
                "模型包目标已存在但未登记，拒绝覆盖：{}",
                final_directory.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(CliError::General(format!(
                "无法检查模型包最终目录：{error}"
            )));
        }
    }
    match fs::symlink_metadata(&staging) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(CliError::ModelValidation(format!(
                    "模型包续传目录不是安全目录：{}",
                    staging.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&staging)
                .map_err(|error| CliError::General(format!("无法创建模型包续传目录：{error}")))?;
        }
        Err(error) => {
            return Err(CliError::General(format!(
                "无法检查模型包续传目录：{error}"
            )));
        }
    }
    let canonical_staging = fs::canonicalize(&staging)
        .map_err(|error| CliError::General(format!("无法规范化模型包目录：{error}")))?;
    if canonical_staging.parent() != Some(models_root.as_path()) {
        return Err(CliError::ModelValidation(
            "模型包续传目录不在受管 models 根目录直属范围内".to_owned(),
        ));
    }

    let mut output_names = Vec::with_capacity(deployment.artifacts.len());
    let mut allowed_entries = BTreeSet::new();
    for artifact in &deployment.artifacts {
        let output_name = Path::new(&artifact.file)
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| CliError::ModelValidation("GGUF 分片缺少安全文件名".to_owned()))?
            .to_owned();
        validate_single_segment(&output_name, "GGUF 分片文件名")?;
        if !allowed_entries.insert(output_name.clone()) {
            return Err(CliError::ModelValidation(format!(
                "GGUF 分片本地文件名重复：{output_name}"
            )));
        }
        let path = Path::new(&output_name);
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .ok_or_else(|| CliError::ModelValidation("GGUF 分片扩展名无效".to_owned()))?;
        let stem = output_name
            .get(..output_name.len().saturating_sub(extension.len() + 1))
            .ok_or_else(|| CliError::ModelValidation("GGUF 分片文件名无效".to_owned()))?;
        allowed_entries.insert(format!(".{stem}.part.{extension}"));
        output_names.push(output_name);
    }
    for entry in fs::read_dir(&canonical_staging)
        .map_err(|error| CliError::General(format!("无法读取模型包续传目录：{error}")))?
    {
        let entry =
            entry.map_err(|error| CliError::General(format!("无法读取模型包条目：{error}")))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| CliError::General(format!("无法检查模型包条目：{error}")))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| CliError::ModelValidation("模型包条目不是有效 UTF-8".to_owned()))?
            .to_owned();
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || !allowed_entries.contains(&name)
        {
            return Err(CliError::ModelValidation(format!(
                "模型包续传目录包含未登记或不安全条目：{}",
                entry.path().display()
            )));
        }
    }

    let mut reports = Vec::with_capacity(deployment.artifacts.len());
    for (position, artifact) in deployment.artifacts.iter().enumerate() {
        let expected_sha256 = artifact
            .trusted_sha256
            .as_deref()
            .ok_or_else(|| CliError::ModelValidation("GGUF 分片缺少可信 LFS SHA-256".to_owned()))?;
        let expected_size = artifact
            .size_bytes
            .ok_or_else(|| CliError::ModelValidation("GGUF 分片缺少可信远端大小".to_owned()))?;
        let target = canonical_staging.join(&output_names[position]);
        let report = match fs::symlink_metadata(&target) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(CliError::ModelValidation(format!(
                        "已完成分片不是安全普通文件：{}",
                        target.display()
                    )));
                }
                validate_model(&target, Some(expected_sha256)).map_err(model_validation_error)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                download_bundle_artifact(
                    &canonical_staging,
                    &output_names[position],
                    deployment,
                    artifact,
                    output_mode,
                )
                .await?
            }
            Err(error) => {
                return Err(CliError::General(format!(
                    "无法检查 GGUF 分片目标：{error}"
                )));
            }
        };
        if report.size_bytes != expected_size {
            return Err(CliError::ModelValidation(format!(
                "GGUF 分片大小与 HF 清单不一致：{}",
                artifact.file
            )));
        }
        reports.push(report);
    }
    validate_gguf_split_reports(&reports).map_err(model_validation_error)?;

    fs::rename(&canonical_staging, &final_directory)
        .map_err(|error| CliError::General(format!("无法原子完成模型包目录：{error}")))?;
    #[cfg(unix)]
    if let Err(error) = fs::File::open(&models_root).and_then(|directory| directory.sync_all()) {
        return Err(rollback_bundle_directory(
            &final_directory,
            &staging,
            CliError::General(format!("无法同步模型包目录：{error}")),
        ));
    }
    let final_reports_result = output_names
        .iter()
        .zip(&deployment.artifacts)
        .map(|(name, artifact)| {
            let expected = artifact.trusted_sha256.as_deref().ok_or_else(|| {
                CliError::ModelValidation("GGUF 分片缺少可信 LFS SHA-256".to_owned())
            })?;
            validate_model(&final_directory.join(name), Some(expected))
                .map_err(model_validation_error)
        })
        .collect::<CliResult<Vec<ValidationReport>>>();
    let final_reports = match final_reports_result {
        Ok(reports) => reports,
        Err(error) => {
            return Err(rollback_bundle_directory(&final_directory, &staging, error));
        }
    };
    if let Err(error) = validate_gguf_split_reports(&final_reports) {
        return Err(rollback_bundle_directory(
            &final_directory,
            &staging,
            model_validation_error(error),
        ));
    }
    let registered =
        match registry(context).register_bundle(local_name, final_reports, &models_root) {
            Ok(record) => record,
            Err(error) => {
                return Err(rollback_bundle_directory(
                    &final_directory,
                    &staging,
                    model_registry_error(error),
                ));
            }
        };
    Ok(registered)
}

fn rollback_bundle_directory(final_directory: &Path, staging: &Path, cause: CliError) -> CliError {
    match fs::rename(final_directory, staging) {
        Ok(()) => cause,
        Err(rollback_error) => CliError::General(format!(
            "{cause}；模型包回滚失败，已拒绝登记，请保留现场并检查 {} 与 {}：{rollback_error}",
            final_directory.display(),
            staging.display()
        )),
    }
}

async fn download_bundle_artifact(
    directory: &Path,
    output_name: &str,
    deployment: &DeploymentArtifact,
    artifact: &RemoteArtifact,
    output_mode: OutputMode,
) -> CliResult<ValidationReport> {
    let (progress, progress_task) = if show_download_progress(output_mode) {
        let label = output_name.to_owned();
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<mindone_engine::DownloadProgress>();
        let task = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                let total = progress
                    .total_bytes
                    .map(|value| format!(" / {value}"))
                    .unwrap_or_default();
                eprintln!(
                    "模型分片 {label}：{}{} bytes{}",
                    progress.downloaded_bytes,
                    total,
                    if progress.resumed { "（续传）" } else { "" }
                );
            }
        });
        (Some(progress_tx), Some(task))
    } else {
        (None, None)
    };
    let report = download_model(ModelDownloadRequest {
        platform: CoreModelPlatform::HuggingFace,
        repository: deployment.repository.clone(),
        branch: "main".to_owned(),
        remote_file: artifact.file.clone(),
        output_name: output_name.to_owned(),
        models_directory: directory.to_path_buf(),
        expected_sha256: artifact.trusted_sha256.clone(),
        progress,
        huggingface_token: huggingface_token_from_env()?,
        override_base_url: None,
    })
    .await
    .map_err(model_download_error);
    if let Some(task) = progress_task {
        let _ = task.await;
    }
    report
}

pub async fn download(
    context: &AppContext,
    args: &ModelDownloadArgs,
    output_mode: OutputMode,
) -> CliResult<CommandOutput> {
    validate_repository(&args.repo)?;
    validate_single_segment(&args.branch, "分支")?;
    let artifact = resolve_artifact(args).await?;
    let expected_sha256 =
        select_expected_sha256(args.sha256.as_deref(), artifact.trusted_sha256.as_deref())?;
    let local_name = args
        .name
        .clone()
        .or_else(|| args.repo.rsplit('/').next().map(str::to_owned))
        .ok_or_else(|| CliError::General("无法从仓库名生成本地模型名称".to_owned()))?;
    validate_single_segment(&local_name, "本地模型名称")?;
    let registry = registry(context);
    if registry.find(&local_name).is_ok() {
        return Err(CliError::General(format!(
            "模型名称 {local_name} 已登记；请使用其他 --name"
        )));
    }
    let extension = Path::new(&artifact.file)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or_else(|| CliError::ModelValidation("远程模型文件缺少格式扩展名".to_owned()))?;
    let output_name = format!("{local_name}.{extension}");
    let (progress, progress_task) = if show_download_progress(output_mode) {
        let (progress_tx, mut progress_rx) =
            tokio::sync::mpsc::unbounded_channel::<mindone_engine::DownloadProgress>();
        let task = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                let total = progress
                    .total_bytes
                    .map(|value| format!(" / {value}"))
                    .unwrap_or_default();
                eprintln!(
                    "模型下载：{}{} bytes{}",
                    progress.downloaded_bytes,
                    total,
                    if progress.resumed { "（续传）" } else { "" }
                );
            }
        });
        (Some(progress_tx), Some(task))
    } else {
        (None, None)
    };
    let request = ModelDownloadRequest {
        platform: match args.platform {
            ModelPlatform::HuggingFace => CoreModelPlatform::HuggingFace,
            ModelPlatform::ModelScope => CoreModelPlatform::ModelScope,
        },
        repository: args.repo.clone(),
        branch: args.branch.clone(),
        remote_file: artifact.file,
        output_name,
        models_directory: context.paths.models.clone(),
        expected_sha256: Some(expected_sha256),
        progress,
        huggingface_token: if args.platform == ModelPlatform::HuggingFace {
            huggingface_token_from_env()?
        } else {
            None
        },
        override_base_url: None,
    };
    let report = download_model(request)
        .await
        .map_err(model_download_error)?;
    if let Some(task) = progress_task {
        let _ = task.await;
    }
    let record = registry
        .register(&local_name, report, &context.paths.models)
        .map_err(model_registry_error)?;
    CommandOutput::new(
        format!(
            "模型下载并验证成功\n名称：{}\n格式：{:?}\n大小：{}\nSHA-256：{}\n路径：{}",
            record.name,
            record.format,
            human_bytes(record.size_bytes),
            record.sha256,
            record.path.display()
        ),
        record,
    )
}

pub fn delete(
    context: &AppContext,
    args: &ModelDeleteArgs,
    mode: OutputMode,
) -> CliResult<CommandOutput> {
    let registry = registry(context);
    let record = registry.find(&args.model).map_err(model_registry_error)?;
    let in_use = model_in_use(context, &record);
    if !args.yes {
        if mode.json {
            return Err(CliError::General(
                "JSON 模式不能交互确认；请确认目标后增加 --yes".to_owned(),
            ));
        }
        print!(
            "确认删除模型 {}（{}）？输入 yes 继续：",
            record.name,
            record.path.display()
        );
        std::io::stdout()
            .flush()
            .map_err(|error| CliError::General(format!("无法显示确认提示：{error}")))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|error| CliError::General(format!("无法读取确认输入：{error}")))?;
        if answer.trim() != "yes" {
            return Err(CliError::General("已取消删除，未修改任何文件".to_owned()));
        }
    }
    let deleted = registry
        .delete(&args.model, &context.paths.models, in_use)
        .map_err(model_registry_error)?;
    CommandOutput::new(
        format!("已删除模型 {} 及其登记记录", deleted.name),
        serde_json::json!({
            "deleted": true,
            "id": deleted.id,
            "name": deleted.name,
        }),
    )
}

pub fn verify(context: &AppContext, args: &ModelTargetArgs) -> CliResult<CommandOutput> {
    let record = registry(context)
        .reverify(&args.model, &context.paths.models)
        .map_err(model_validation_error)?;
    CommandOutput::new(
        format!(
            "模型验证通过\n名称：{}\n格式：{:?}\n大小：{}\nSHA-256：{}",
            record.name,
            record.format,
            human_bytes(record.size_bytes),
            record.sha256
        ),
        record,
    )
}

pub fn find_verified_model(context: &AppContext, target: &str) -> CliResult<ModelRecord> {
    let registry = registry(context);
    let target_path = Path::new(target);
    let record = if target_path.is_absolute() {
        registry
            .find_by_managed_path(target_path, &context.paths.models)
            .map_err(model_registry_error)?
    } else if target_path.components().count() > 1 {
        return Err(CliError::ModelValidation(
            "模型路径必须是受管 models 目录内的绝对路径；相对值仅可使用模型名称或 ID".to_owned(),
        ));
    } else {
        registry.find(target).map_err(model_registry_error)?
    };
    if !record.verification_is_current_in(&context.paths.models) {
        return Err(CliError::ModelValidation(format!(
            "模型 {} 已变化，请先运行 mindone model verify {}",
            record.name, record.name
        )));
    }
    validate_model(&record.path, Some(&record.sha256)).map_err(model_validation_error)?;
    Ok(record)
}

pub fn validate_model_file(path: &Path) -> CliResult<mindone_engine::ValidationReport> {
    validate_model(path, None).map_err(model_validation_error)
}

async fn resolve_artifact(args: &ModelDownloadArgs) -> CliResult<RemoteArtifact> {
    match args.platform {
        ModelPlatform::HuggingFace => resolve_huggingface_artifact(args).await,
        ModelPlatform::ModelScope => resolve_modelscope_artifact(args).await,
    }
}

async fn resolve_modelscope_artifact(args: &ModelDownloadArgs) -> CliResult<RemoteArtifact> {
    let api_base = Url::parse("https://modelscope.cn/api/v1/models/")
        .map_err(|error| CliError::General(format!("内置 ModelScope 地址无效：{error}")))?;
    resolve_modelscope_artifact_from(args, &api_base, false).await
}

async fn resolve_modelscope_artifact_from(
    args: &ModelDownloadArgs,
    api_base: &Url,
    allow_loopback_http: bool,
) -> CliResult<RemoteArtifact> {
    // 保留 v1 已公开的显式旅程：用户同时给出仓库内文件与可信 checksum 时，
    // 无需依赖清单服务即可下载。文件仍会经过 HTTPS、SHA-256 和结构校验。
    if let (Some(file), Some(_)) = (&args.file, &args.sha256) {
        validate_remote_path(file)?;
        return Ok(RemoteArtifact {
            file: file.clone(),
            trusted_sha256: None,
            size_bytes: None,
        });
    }

    let url = modelscope_manifest_url(api_base, &args.repo, &args.branch)?;
    enforce_manifest_transport(&url, allow_loopback_http)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.stop()
            } else if attempt.url().scheme() == "https" {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|error| CliError::General(format!("无法初始化模型清单客户端：{error}")))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| CliError::General(format!("无法读取 ModelScope 模型清单：{error}")))?;
    enforce_manifest_transport(response.url(), allow_loopback_http)?;
    if !response.status().is_success() {
        return Err(CliError::General(format!(
            "ModelScope 模型清单请求失败（HTTP {}）",
            response.status().as_u16()
        )));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MODEL_MANIFEST_MAX_BYTES as u64)
    {
        return Err(CliError::General(format!(
            "ModelScope 模型清单超过 {MODEL_MANIFEST_MAX_BYTES} 字节安全上限"
        )));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|error| CliError::General(format!("读取 ModelScope 模型清单失败：{error}")))?;
        if body.len().saturating_add(chunk.len()) > MODEL_MANIFEST_MAX_BYTES {
            return Err(CliError::General(format!(
                "ModelScope 模型清单超过 {MODEL_MANIFEST_MAX_BYTES} 字节安全上限"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    let envelope: ModelScopeManifestEnvelope = serde_json::from_slice(&body)
        .map_err(|error| CliError::General(format!("ModelScope 模型清单无效：{error}")))?;
    if !envelope.success || envelope.code != 200 {
        return Err(CliError::General(format!(
            "ModelScope 模型清单返回失败状态（Code {}）",
            envelope.code
        )));
    }
    let entries = envelope
        .data
        .and_then(|data| data.files)
        .ok_or_else(|| CliError::General("ModelScope 模型清单没有文件列表".to_owned()))?;
    select_modelscope_artifact(args, entries)
}

fn select_modelscope_artifact(
    args: &ModelDownloadArgs,
    entries: Vec<ModelScopeManifestEntry>,
) -> CliResult<RemoteArtifact> {
    let mut candidates = Vec::new();
    for entry in entries {
        if entry.kind != "blob" || !allowed_model_file(&entry.path) {
            continue;
        }
        validate_remote_path(&entry.path)?;
        if candidates
            .iter()
            .any(|candidate: &RemoteArtifact| candidate.file == entry.path)
        {
            return Err(CliError::General(format!(
                "ModelScope 模型清单包含重复文件路径：{}",
                entry.path
            )));
        }
        candidates.push(RemoteArtifact {
            file: entry.path,
            trusted_sha256: entry.sha256.and_then(normalize_modelscope_sha256),
            size_bytes: None,
        });
    }
    let artifact = if let Some(requested) = &args.file {
        validate_remote_path(requested)?;
        candidates
            .into_iter()
            .find(|candidate| candidate.file == *requested)
            .ok_or_else(|| {
                CliError::General(format!(
                    "ModelScope 仓库清单中不存在指定的安全模型文件：{requested}"
                ))
            })?
    } else {
        match candidates.len() {
            0 => {
                return Err(CliError::ModelValidation(
                    "ModelScope 仓库中未发现 GGUF 或 safetensors 模型文件".to_owned(),
                ));
            }
            1 => candidates
                .pop()
                .ok_or_else(|| CliError::General("模型候选列表意外为空".to_owned()))?,
            _ => {
                return Err(CliError::General(format!(
                    "ModelScope 仓库包含多个安全模型文件，请使用 --file 选择：{}",
                    candidates
                        .iter()
                        .map(|candidate| candidate.file.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    };
    if artifact.trusted_sha256.is_none() && args.sha256.is_none() {
        return Err(CliError::ModelValidation(
            "ModelScope 清单没有为所选文件提供可信 SHA-256；请使用 --sha256 明确提供校验值"
                .to_owned(),
        ));
    }
    Ok(artifact)
}

fn modelscope_manifest_url(api_base: &Url, repository: &str, branch: &str) -> CliResult<Url> {
    let mut url = api_base.clone();
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| CliError::General("无法构造 ModelScope API 地址".to_owned()))?;
        segments.pop_if_empty();
        for segment in repository.split('/') {
            segments.push(segment);
        }
        segments.push("repo").push("files");
    }
    url.query_pairs_mut()
        .append_pair("Revision", branch)
        .append_pair("Recursive", "true");
    Ok(url)
}

fn enforce_manifest_transport(url: &Url, allow_loopback_http: bool) -> CliResult<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = allow_loopback_http
        && url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if loopback {
        Ok(())
    } else {
        Err(CliError::General(
            "模型清单地址必须使用 HTTPS；仅 loopback 测试允许 HTTP".to_owned(),
        ))
    }
}

async fn resolve_huggingface_artifact(args: &ModelDownloadArgs) -> CliResult<RemoteArtifact> {
    let mut candidates = fetch_huggingface_artifacts(&args.repo, &args.branch).await?;
    if let Some(requested) = &args.file {
        validate_remote_path(requested)?;
        return candidates
            .into_iter()
            .find(|candidate| candidate.file == *requested)
            .ok_or_else(|| {
                CliError::General(format!("仓库清单中不存在指定的安全模型文件：{requested}"))
            });
    }
    match candidates.len() {
        0 => Err(CliError::ModelValidation(
            "仓库中未发现 GGUF 或 safetensors 模型文件".to_owned(),
        )),
        1 => candidates
            .pop()
            .ok_or_else(|| CliError::General("模型候选列表意外为空".to_owned())),
        _ => Err(CliError::General(format!(
            "仓库包含多个安全模型文件，请使用 --file 选择：{}",
            candidates
                .iter()
                .map(|candidate| candidate.file.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

async fn fetch_huggingface_artifacts(
    repository: &str,
    branch: &str,
) -> CliResult<Vec<RemoteArtifact>> {
    let url = huggingface_tree_url(repository, branch)?;
    let token = huggingface_token_from_env()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 {
                attempt.stop()
            } else if attempt.url().scheme() == "https"
                && attempt.url().host_str() == Some("huggingface.co")
            {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .build()
        .map_err(|error| CliError::General(format!("无法初始化模型清单客户端：{error}")))?;
    let mut next = Some(url);
    let mut visited = BTreeSet::new();
    let mut entries = Vec::new();
    let mut received_bytes = 0_usize;
    for _ in 0..HF_MANIFEST_MAX_PAGES {
        let Some(page_url) = next.take() else {
            break;
        };
        if !visited.insert(page_url.as_str().to_owned()) {
            return Err(CliError::ModelValidation(
                "Hugging Face 模型清单分页出现循环".to_owned(),
            ));
        }
        let response = send_huggingface_tree_request(
            &client,
            &page_url,
            token.as_ref().map(|value| value.as_str()),
        )
        .await?;
        if response.url().scheme() != "https"
            || response.url().host_str() != Some("huggingface.co")
            || response.url().path() != page_url.path()
        {
            return Err(CliError::ModelValidation(
                "Hugging Face 模型清单跳转到非预期来源".to_owned(),
            ));
        }
        if !response.status().is_success() {
            return Err(CliError::General(format!(
                "Hugging Face 模型清单请求失败（HTTP {}）",
                response.status().as_u16()
            )));
        }
        if response.content_length().is_some_and(|length| {
            length
                > u64::try_from(HF_MANIFEST_MAX_BYTES.saturating_sub(received_bytes)).unwrap_or(0)
        }) {
            return Err(CliError::ModelValidation(format!(
                "Hugging Face 模型清单超过 {HF_MANIFEST_MAX_BYTES} 字节安全上限"
            )));
        }
        let next_header = response
            .headers()
            .get(LINK)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                CliError::General(format!("读取 Hugging Face 模型清单失败：{error}"))
            })?;
            received_bytes = received_bytes.checked_add(chunk.len()).ok_or_else(|| {
                CliError::ModelValidation("Hugging Face 模型清单大小溢出".to_owned())
            })?;
            if received_bytes > HF_MANIFEST_MAX_BYTES {
                return Err(CliError::ModelValidation(format!(
                    "Hugging Face 模型清单超过 {HF_MANIFEST_MAX_BYTES} 字节安全上限"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let mut page_entries: Vec<HfTreeEntry> = serde_json::from_slice(&body)
            .map_err(|error| CliError::General(format!("Hugging Face 模型清单无效：{error}")))?;
        entries.append(&mut page_entries);
        next = match next_header {
            Some(header) => hf_next_page_url(&header, &page_url)?,
            None => None,
        };
    }
    if next.is_some() {
        return Err(CliError::ModelValidation(format!(
            "Hugging Face 模型清单超过 {HF_MANIFEST_MAX_PAGES} 页安全上限"
        )));
    }
    let mut seen_paths = BTreeSet::new();
    let mut candidates = Vec::new();
    for entry in entries {
        if entry.kind != "file" || !allowed_model_file(&entry.path) {
            continue;
        }
        validate_remote_path(&entry.path)?;
        if !seen_paths.insert(entry.path.clone()) {
            return Err(CliError::ModelValidation(format!(
                "Hugging Face 模型清单包含重复文件路径：{}",
                entry.path
            )));
        }
        let size_bytes = entry.lfs.as_ref().and_then(|lfs| lfs.size).or(entry.size);
        candidates.push(RemoteArtifact {
            file: entry.path,
            trusted_sha256: entry
                .lfs
                .and_then(|lfs| lfs.oid)
                .and_then(normalize_lfs_sha256),
            size_bytes,
        });
    }
    if candidates.is_empty() {
        return Err(CliError::ModelValidation(
            "仓库中未发现 GGUF 或 safetensors 模型文件".to_owned(),
        ));
    }
    Ok(candidates)
}

async fn send_huggingface_tree_request(
    client: &reqwest::Client,
    page_url: &Url,
    token: Option<&str>,
) -> CliResult<reqwest::Response> {
    const MAX_ATTEMPTS: u8 = 4;
    for attempt in 0..MAX_ATTEMPTS {
        let mut request = client.get(page_url.clone());
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(|error| {
            CliError::General(format!("无法读取 Hugging Face 模型清单：{error}"))
        })?;
        let retryable = matches!(response.status().as_u16(), 429 | 502 | 503 | 504);
        if !retryable || attempt + 1 == MAX_ATTEMPTS {
            return Ok(response);
        }
        let delay_millis = 500_u64.saturating_mul(1_u64 << attempt);
        tokio::time::sleep(Duration::from_millis(delay_millis)).await;
    }
    Err(CliError::General(
        "Hugging Face 模型清单重试状态异常".to_owned(),
    ))
}

fn hf_next_page_url(header: &str, current: &Url) -> CliResult<Option<Url>> {
    let Some(value) = header
        .split(',')
        .map(str::trim)
        .find(|value| value.contains("rel=\"next\""))
    else {
        return Ok(None);
    };
    let start = value
        .find('<')
        .ok_or_else(|| CliError::ModelValidation("Hugging Face 分页 Link 缺少起始符".to_owned()))?;
    let end = value[start + 1..]
        .find('>')
        .map(|offset| start + 1 + offset)
        .ok_or_else(|| CliError::ModelValidation("Hugging Face 分页 Link 缺少结束符".to_owned()))?;
    let next = Url::parse(&value[start + 1..end])
        .map_err(|error| CliError::ModelValidation(format!("HF 分页 URL 无效：{error}")))?;
    if next.scheme() != "https"
        || next.host_str() != Some("huggingface.co")
        || !next.username().is_empty()
        || next.password().is_some()
        || next.path() != current.path()
        || !next.query_pairs().any(|(key, _)| key == "cursor")
    {
        return Err(CliError::ModelValidation(
            "Hugging Face 分页 Link 来源、路径或 cursor 无效".to_owned(),
        ));
    }
    Ok(Some(next))
}

fn huggingface_token_from_env() -> CliResult<Option<zeroize::Zeroizing<String>>> {
    let token = match env::var("HF_TOKEN") {
        Ok(token) => token,
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(CliError::Authentication(
                "HF_TOKEN 必须是有效 UTF-8，且不得写入 MindOne 配置".to_owned(),
            ));
        }
    };
    if !(8..=512).contains(&token.len())
        || token
            .chars()
            .any(|value| value.is_control() || value.is_whitespace())
    {
        return Err(CliError::Authentication(
            "HF_TOKEN 长度或字符无效；请在用户终端环境中设置合法 Hugging Face Token".to_owned(),
        ));
    }
    Ok(Some(zeroize::Zeroizing::new(token)))
}

fn huggingface_tree_url(repository: &str, branch: &str) -> CliResult<Url> {
    let mut url = Url::parse("https://huggingface.co/api/models/")
        .map_err(|error| CliError::General(format!("内置 Hugging Face 地址无效：{error}")))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| CliError::General("无法构造 Hugging Face API 地址".to_owned()))?;
        // 基址以 `/` 结尾；先移除空 segment，否则会生成 `/api/models//org/repo`，
        // Hugging Face 对该路径严格返回 404。
        segments.pop_if_empty();
        for segment in repository.split('/') {
            segments.push(segment);
        }
        segments.push("tree").push(branch);
    }
    url.query_pairs_mut()
        .append_pair("recursive", "true")
        .append_pair("limit", "1000");
    Ok(url)
}

fn registry(context: &AppContext) -> ModelRegistry {
    ModelRegistry::new(context.paths.models.join("index.json"))
}

fn model_in_use(context: &AppContext, record: &ModelRecord) -> bool {
    let Ok(entries) = std::fs::read_dir(&context.paths.runtime) else {
        return false;
    };
    entries.filter_map(Result::ok).any(|entry| {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        let managed_state = name == "share.json" || is_serve_state_name(name);
        if !managed_state {
            return false;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return false;
        }
        std::fs::read_to_string(path)
            .map(|raw| {
                raw.contains(&record.path.display().to_string()) || raw.contains(&record.name)
            })
            .unwrap_or(false)
    })
}

fn is_serve_state_name(name: &str) -> bool {
    name == "serve.json"
        || name
            .strip_prefix("serve-")
            .and_then(|value| value.strip_suffix(".json"))
            .and_then(|value| value.parse::<u16>().ok())
            .is_some_and(|port| port > 0)
}

fn validate_repository(value: &str) -> CliResult<()> {
    let segments = value.split('/').collect::<Vec<_>>();
    if segments.len() < 2
        || segments
            .iter()
            .any(|segment| !safe_component(segment) || *segment == "." || *segment == "..")
    {
        return Err(CliError::General(
            "模型仓库必须是安全的 org/name 格式".to_owned(),
        ));
    }
    Ok(())
}

fn validate_remote_path(value: &str) -> CliResult<()> {
    if value.starts_with('/')
        || value.split('/').any(|segment| {
            segment.is_empty()
                || segment == "."
                || segment == ".."
                || segment.contains('\\')
                || segment.contains('\0')
        })
        || !allowed_model_file(value)
    {
        return Err(CliError::ModelValidation(format!(
            "远程模型路径不安全或格式不受支持：{value}"
        )));
    }
    Ok(())
}

fn validate_single_segment(value: &str, label: &str) -> CliResult<()> {
    if !safe_component(value) || value == "." || value == ".." {
        return Err(CliError::General(format!(
            "{label}只能包含字母、数字、点、下划线和连字符"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> CliResult<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::General(
            "--sha256 必须是 64 位十六进制字符串".to_owned(),
        ));
    }
    Ok(())
}

fn select_expected_sha256(
    user_sha256: Option<&str>,
    platform_sha256: Option<&str>,
) -> CliResult<String> {
    if let Some(value) = user_sha256 {
        validate_sha256(value)?;
    }
    match (user_sha256, platform_sha256) {
        (Some(user), Some(platform)) if !user.eq_ignore_ascii_case(platform) => Err(
            CliError::ModelValidation("--sha256 与平台可信模型清单中的 SHA-256 不一致".to_owned()),
        ),
        (Some(user), _) => Ok(user.to_ascii_lowercase()),
        (None, Some(platform)) => Ok(platform.to_owned()),
        (None, None) => Err(CliError::ModelValidation(
            "下载源没有可信 SHA-256；请使用 --sha256 明确提供校验值".to_owned(),
        )),
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn allowed_model_file(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.ends_with(".gguf") || lower.ends_with(".safetensors")
}

fn normalize_lfs_sha256(value: String) -> Option<String> {
    let normalized = value.strip_prefix("sha256:").unwrap_or(&value);
    (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| normalized.to_ascii_lowercase())
}

fn normalize_modelscope_sha256(value: String) -> Option<String> {
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn model_download_error(error: impl std::fmt::Display) -> CliError {
    let message = error.to_string();
    if message.contains("安全校验")
        || message.contains("SHA-256")
        || message.contains("可信")
        || message.contains("格式")
    {
        CliError::ModelValidation(message)
    } else {
        CliError::General(message)
    }
}

fn model_registry_error(error: impl std::fmt::Display) -> CliError {
    let message = error.to_string();
    if message.contains("安全校验") {
        CliError::ModelValidation(message)
    } else {
        CliError::General(message)
    }
}

fn model_validation_error(error: impl std::fmt::Display) -> CliError {
    CliError::ModelValidation(error.to_string())
}

fn show_download_progress(mode: OutputMode) -> bool {
    !mode.quiet && !mode.json
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.2} GiB", value / GIB)
    } else if value >= MIB {
        format!("{:.2} MiB", value / MIB)
    } else if value >= KIB {
        format!("{:.2} KiB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;

    use tempfile::NamedTempFile;
    use url::Url;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        deployment_artifact_groups, deployment_candidate_unavailable,
        deployment_quantization_priority, hf_next_page_url, huggingface_tree_url,
        is_serve_state_name, resolve_modelscope_artifact_from, rollback_bundle_directory,
        select_expected_sha256, show_download_progress, validate_model_file, validate_remote_path,
        validate_repository, RemoteArtifact,
    };
    use crate::cli::{ModelDownloadArgs, ModelPlatform};
    use crate::error::CliError;

    #[test]
    fn huggingface_tree_url_has_no_empty_path_segment() {
        let url = huggingface_tree_url("ggml-org/Qwen3-0.6B-GGUF", "main")
            .expect("官方仓库 URL 应可构造");
        assert_eq!(
            url.as_str(),
            "https://huggingface.co/api/models/ggml-org/Qwen3-0.6B-GGUF/tree/main?recursive=true&limit=1000"
        );
        assert!(!url.path().contains("//"));
    }

    #[test]
    fn huggingface_pagination_is_cursor_bound_to_exact_tree_path() {
        let current = huggingface_tree_url("org/model", "main").expect("URL 应有效");
        let valid = "<https://huggingface.co/api/models/org/model/tree/main?recursive=true&limit=1000&cursor=abc>; rel=\"next\"";
        let next = hf_next_page_url(valid, &current)
            .expect("Link 应可解析")
            .expect("应包含下一页");
        assert!(next
            .query_pairs()
            .any(|(key, value)| key == "cursor" && value == "abc"));
        assert!(hf_next_page_url(
            "<https://evil.example/api/models/org/model/tree/main?cursor=abc>; rel=\"next\"",
            &current
        )
        .is_err());
        assert!(hf_next_page_url(
            "<https://huggingface.co/api/models/other/model/tree/main?cursor=abc>; rel=\"next\"",
            &current
        )
        .is_err());
    }
    use crate::output::OutputMode;

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_repository("../model").is_err());
        assert!(validate_remote_path("../../secret.gguf").is_err());
        assert!(validate_remote_path("safe/model.gguf").is_ok());
    }

    #[test]
    fn active_model_detection_recognizes_every_managed_serve_port_state() {
        assert!(is_serve_state_name("serve.json"));
        assert!(is_serve_state_name("serve-8081.json"));
        assert!(is_serve_state_name("serve-65535.json"));
        assert!(!is_serve_state_name("serve-0.json"));
        assert!(!is_serve_state_name("serve-secret.json"));
        assert!(!is_serve_state_name("serve-8081.json.bak"));
    }

    #[test]
    fn deployment_groups_require_complete_trusted_ordered_gguf_shards() {
        let artifact = |file: &str, trusted: bool| RemoteArtifact {
            file: file.to_owned(),
            trusted_sha256: trusted.then(|| "ab".repeat(32)),
            size_bytes: Some(64),
        };
        let groups = deployment_artifact_groups(vec![
            artifact("Q4/model-q4_k_m-00002-of-00003.gguf", true),
            artifact("Q4/model-q4_k_m-00001-of-00003.gguf", true),
            artifact("Q4/model-q4_k_m-00003-of-00003.gguf", true),
            artifact("Q5/model-q5_k_m-00001-of-00002.gguf", true),
            artifact("Q5/model-q5_k_m-00002-of-00002.gguf", false),
            artifact("mmproj-model-f16.gguf", true),
            artifact("model-imatrix.gguf", true),
            artifact("mtp-model-q4_0.gguf", true),
            artifact("model-q4_0.gguf", true),
        ]);
        assert_eq!(groups.len(), 2);
        let split = groups
            .iter()
            .find(|group| group.len() == 3)
            .expect("完整 Q4 分片组应保留");
        assert!(split[0].file.ends_with("00001-of-00003.gguf"));
        assert!(split[2].file.ends_with("00003-of-00003.gguf"));
        assert!(groups.iter().all(|group| {
            group.iter().all(|item| {
                !item.file.contains("mmproj")
                    && !item.file.contains("imatrix")
                    && !item.file.contains("mtp-")
                    && !item.file.contains("Q5/")
            })
        }));
        assert!(
            deployment_quantization_priority(&split[0].file)
                < deployment_quantization_priority("model-iq2_xxs.gguf")
        );
    }

    #[test]
    fn deployment_skips_only_expected_unavailable_candidates() {
        assert!(deployment_candidate_unavailable(&CliError::General(
            "Hugging Face 模型清单请求失败（HTTP 404）".to_owned()
        )));
        assert!(deployment_candidate_unavailable(
            &CliError::ModelValidation("仓库中未发现 GGUF 或 safetensors 模型文件".to_owned())
        ));
        assert!(!deployment_candidate_unavailable(
            &CliError::ModelValidation("Hugging Face 模型清单包含重复文件路径".to_owned())
        ));
    }

    #[test]
    fn bundle_rollback_restores_the_resumable_staging_directory() {
        let root = tempfile::tempdir().expect("应创建临时目录");
        let final_directory = root.path().join("model.bundle");
        let staging = root.path().join(".model.bundle.part");
        fs::create_dir(&final_directory).expect("应创建最终目录");
        let error = rollback_bundle_directory(
            &final_directory,
            &staging,
            CliError::ModelValidation("测试失败".to_owned()),
        );
        assert!(matches!(error, CliError::ModelValidation(_)));
        assert!(staging.is_dir());
        assert!(!final_directory.exists());
    }

    #[test]
    fn rejects_pickle_family() {
        for extension in ["pkl", "pickle", "pt", "pth"] {
            let file = NamedTempFile::with_suffix(format!(".{extension}")).expect("应创建临时文件");
            assert_eq!(
                validate_model_file(file.path())
                    .expect_err("危险格式必须拒绝")
                    .exit_code(),
                21
            );
        }
    }

    #[test]
    fn rejects_gguf_extension_spoofing() {
        let mut file = NamedTempFile::with_suffix(".gguf").expect("应创建临时文件");
        file.write_all(b"not a gguf file").expect("应写入伪造文件");
        assert!(validate_model_file(file.path()).is_err());
    }

    #[test]
    fn quiet_and_json_modes_suppress_download_progress() {
        assert!(!show_download_progress(OutputMode {
            json: false,
            quiet: true,
            verbose: 0,
        }));
        assert!(!show_download_progress(OutputMode {
            json: true,
            quiet: false,
            verbose: 0,
        }));
        assert!(show_download_progress(OutputMode {
            json: false,
            quiet: false,
            verbose: 0,
        }));
    }

    fn modelscope_args(file: Option<&str>, sha256: Option<&str>) -> ModelDownloadArgs {
        ModelDownloadArgs {
            platform: ModelPlatform::ModelScope,
            repo: "owner/model".to_owned(),
            branch: "release-v1".to_owned(),
            name: Some("local-model".to_owned()),
            file: file.map(str::to_owned),
            sha256: sha256.map(str::to_owned),
        }
    }

    fn modelscope_api_base(server: &MockServer) -> Url {
        Url::parse(&format!("{}/api/v1/models/", server.uri()))
            .expect("mock ModelScope API URL 应有效")
    }

    #[tokio::test]
    async fn modelscope_manifest_resolves_the_only_safe_artifact_and_sha256() {
        let server = MockServer::start().await;
        let checksum = "A1".repeat(32);
        Mock::given(method("GET"))
            .and(path("/api/v1/models/owner/model/repo/files"))
            .and(query_param("Revision", "release-v1"))
            .and(query_param("Recursive", "true"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 200,
                "Success": true,
                "Data": {
                    "Files": [
                        {"Path": "README.md", "Type": "blob", "Sha256": "11"},
                        {"Path": "weights/model.gguf", "Type": "blob", "Sha256": checksum}
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let artifact = resolve_modelscope_artifact_from(
            &modelscope_args(None, None),
            &modelscope_api_base(&server),
            true,
        )
        .await
        .expect("唯一安全 artifact 应从官方形状清单解析");
        assert_eq!(artifact.file, "weights/model.gguf");
        assert_eq!(
            artifact.trusted_sha256.as_deref(),
            Some("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
        );
    }

    #[tokio::test]
    async fn modelscope_manifest_uses_file_to_disambiguate_multiple_artifacts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/models/owner/model/repo/files"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 200,
                "Success": true,
                "Data": {"Files": [
                    {"Path": "q4.gguf", "Type": "blob", "Sha256": "22".repeat(32)},
                    {"Path": "q8.gguf", "Type": "blob", "Sha256": "33".repeat(32)}
                ]}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let artifact = resolve_modelscope_artifact_from(
            &modelscope_args(Some("q8.gguf"), None),
            &modelscope_api_base(&server),
            true,
        )
        .await
        .expect("--file 应只选择清单中的精确路径");
        assert_eq!(artifact.file, "q8.gguf");
        assert_eq!(artifact.trusted_sha256, Some("33".repeat(32)));
    }

    #[tokio::test]
    async fn modelscope_manifest_fails_closed_without_trusted_sha256() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 200,
                "Success": true,
                "Data": {"Files": [
                    {"Path": "model.safetensors", "Type": "blob", "Sha256": "not-a-sha256"}
                ]}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = resolve_modelscope_artifact_from(
            &modelscope_args(None, None),
            &modelscope_api_base(&server),
            true,
        )
        .await
        .expect_err("缺少可信 SHA-256 必须失败关闭");
        assert!(error.to_string().contains("可信 SHA-256"));
    }

    #[tokio::test]
    async fn modelscope_manifest_requires_file_when_multiple_artifacts_exist() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Code": 200,
                "Success": true,
                "Data": {"Files": [
                    {"Path": "one.gguf", "Type": "blob", "Sha256": "44".repeat(32)},
                    {"Path": "two.gguf", "Type": "blob", "Sha256": "55".repeat(32)}
                ]}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let error = resolve_modelscope_artifact_from(
            &modelscope_args(None, None),
            &modelscope_api_base(&server),
            true,
        )
        .await
        .expect_err("多 artifact 不得猜测选择");
        assert!(error.to_string().contains("请使用 --file 选择"));
    }

    #[tokio::test]
    async fn modelscope_explicit_file_and_user_sha256_preserve_offline_manifest_compatibility() {
        let server = MockServer::start().await;
        let checksum = "66".repeat(32);
        let artifact = resolve_modelscope_artifact_from(
            &modelscope_args(Some("chosen.gguf"), Some(&checksum)),
            &modelscope_api_base(&server),
            true,
        )
        .await
        .expect("显式文件与用户 checksum 不应依赖清单服务");
        assert_eq!(artifact.file, "chosen.gguf");
        assert!(artifact.trusted_sha256.is_none());
        assert_eq!(
            select_expected_sha256(Some(&checksum), artifact.trusted_sha256.as_deref())
                .expect("用户 checksum 应可使用"),
            checksum
        );
    }

    #[test]
    fn trusted_platform_and_user_sha256_must_not_conflict() {
        let error = select_expected_sha256(Some(&"77".repeat(32)), Some(&"88".repeat(32)))
            .expect_err("两个可信来源冲突必须失败关闭");
        assert!(error.to_string().contains("不一致"));
    }
}
