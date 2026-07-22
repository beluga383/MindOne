use crate::hardware::{detect_hardware, HardwareProfile};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use tempfile::{NamedTempFile, TempDir};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_EXTRACTED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANAGED_ENGINE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const CONTAINER_COMMAND_TIMEOUT_SECS: u64 = 60 * 60;
const ENGINE_PROBE_TIMEOUT_SECS: u64 = 120;
const DOCKER_SOCKET: &str = "unix:///var/run/docker.sock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EngineName {
    #[serde(rename = "llama.cpp")]
    LlamaCpp,
    Vllm,
    Ollama,
    TensorrtLlm,
}

impl EngineName {
    pub const ALL: [Self; 4] = [Self::LlamaCpp, Self::Vllm, Self::Ollama, Self::TensorrtLlm];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LlamaCpp => "llama.cpp",
            Self::Vllm => "vllm",
            Self::Ollama => "ollama",
            Self::TensorrtLlm => "tensorrt-llm",
        }
    }

    fn executable_names(self) -> &'static [&'static str] {
        match self {
            Self::LlamaCpp => &["llama-server", "llama-server.exe"],
            Self::Vllm => &["vllm", "vllm.exe"],
            Self::Ollama => &["ollama", "ollama.exe"],
            Self::TensorrtLlm => &["trtllm-serve", "trtllm-serve.exe"],
        }
    }
}

impl fmt::Display for EngineName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EngineName {
    type Err = EngineInstallError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "llama.cpp" | "llama-cpp" => Ok(Self::LlamaCpp),
            "vllm" => Ok(Self::Vllm),
            "ollama" => Ok(Self::Ollama),
            "tensorrt-llm" | "tensorrt_llm" => Ok(Self::TensorrtLlm),
            _ => Err(EngineInstallError::UnknownEngine(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCapability {
    pub name: EngineName,
    pub supported: bool,
    pub installed_binary: Option<PathBuf>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledEngine {
    pub id: Uuid,
    pub name: EngineName,
    pub version: String,
    pub target: String,
    pub directory: PathBuf,
    pub executable: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub files: Vec<EngineFileIntegrity>,
    pub installed_at_unix: i64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineFileIntegrity {
    pub relative_path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

impl InstalledEngine {
    pub fn verify_integrity(&self) -> Result<(), EngineInstallError> {
        self.verify_integrity_inner(None)
    }

    pub fn verify_integrity_in(&self, engines_root: &Path) -> Result<(), EngineInstallError> {
        self.verify_integrity_inner(Some(engines_root))
    }

    fn verify_integrity_inner(
        &self,
        engines_root: Option<&Path>,
    ) -> Result<(), EngineInstallError> {
        let directory = fs::canonicalize(&self.directory).map_err(|error| {
            EngineInstallError::RegistryCorrupt(format!(
                "引擎目录无法解析 {}：{error}",
                self.directory.display()
            ))
        })?;
        if directory != self.directory {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎目录已被重定向：{}",
                self.directory.display()
            )));
        }
        validate_version(&self.version).map_err(|_| {
            EngineInstallError::RegistryCorrupt(format!("引擎版本字段不安全：{}", self.version))
        })?;
        validate_path_segment(&self.target).map_err(|_| {
            EngineInstallError::RegistryCorrupt(format!("引擎 target 字段不安全：{}", self.target))
        })?;
        if let Some(root) = engines_root {
            let root = fs::canonicalize(root).map_err(|error| {
                EngineInstallError::RegistryCorrupt(format!(
                    "引擎受管根目录无法解析 {}：{error}",
                    root.display()
                ))
            })?;
            let expected = root
                .join(self.name.as_str())
                .join(&self.version)
                .join(&self.target);
            if directory != expected || !directory.starts_with(&root) {
                return Err(EngineInstallError::RegistryCorrupt(format!(
                    "引擎目录不属于登记文件对应的受管路径：{}",
                    self.directory.display()
                )));
            }
        }
        let metadata = fs::symlink_metadata(&self.executable)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎可执行文件不是受管普通文件：{}",
                self.executable.display()
            )));
        }
        let executable = fs::canonicalize(&self.executable)?;
        if executable != self.executable || !executable.starts_with(&directory) {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎可执行文件逃逸安装目录：{}",
                executable.display()
            )));
        }
        let executable_name = executable.file_name().and_then(|value| value.to_str());
        if !executable_name.is_some_and(|value| self.name.executable_names().contains(&value)) {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎可执行文件名与引擎类型不匹配：{}",
                executable.display()
            )));
        }
        let actual = sha256_file(&executable)?;
        if actual != self.sha256 {
            return Err(EngineInstallError::ChecksumMismatch {
                expected: self.sha256.clone(),
                actual,
            });
        }
        if self.files.is_empty() {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎登记缺少完整目录清单：{}",
                directory.display()
            )));
        }
        let actual_files = build_engine_manifest(&directory)?;
        if actual_files != self.files {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎目录文件清单或哈希已变化：{}",
                directory.display()
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EngineRegistryData {
    version: u32,
    default: Option<EngineName>,
    engines: Vec<InstalledEngine>,
}

#[derive(Debug, Clone)]
pub struct EngineRegistry {
    path: PathBuf,
    lock_path: PathBuf,
    engines_root: PathBuf,
}

#[derive(Debug, Error)]
pub enum EngineInstallError {
    #[error("未知推理引擎：{0}")]
    UnknownEngine(String),
    #[error("当前平台不支持 {engine}：{reason}")]
    Unsupported { engine: EngineName, reason: String },
    #[error("引擎版本字符串无效")]
    InvalidVersion,
    #[error("GitHub release 中没有匹配当前平台的官方发行文件：{0}")]
    MissingReleaseAsset(String),
    #[error("官方 release 没有可信 SHA-256：{0}")]
    MissingReleaseChecksum(String),
    #[error("引擎校验失败：期望 {expected}，实际 {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("引擎归档解压失败：{0}")]
    ExtractionFailed(String),
    #[error("引擎登记文件损坏：{0}")]
    RegistryCorrupt(String),
    #[error("未找到已安装引擎：{0}")]
    NotInstalled(String),
    #[error("引擎下载失败：{0}")]
    Http(#[from] reqwest::Error),
    #[error("引擎下载超过 {limit_bytes} 字节安全上限")]
    DownloadTooLarge { limit_bytes: u64 },
    #[error("受管引擎命令执行失败：{0}")]
    CommandFailed(String),
    #[error("引擎健康探测失败：{0}")]
    HealthCheckFailed(String),
    #[error("引擎文件操作失败：{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct EngineInstaller {
    engines_root: PathBuf,
    cache_root: PathBuf,
    registry: EngineRegistry,
    client: Client,
}

impl EngineInstaller {
    pub fn new(
        engines_root: impl Into<PathBuf>,
        cache_root: impl Into<PathBuf>,
        registry_path: impl Into<PathBuf>,
    ) -> Result<Self, EngineInstallError> {
        let engines_root = engines_root.into();
        let cache_root = cache_root.into();
        let registry_path = registry_path.into();
        let client = Client::builder()
            .user_agent("MindOne/1.0.0")
            .redirect(https_redirect_policy())
            .build()?;
        Ok(Self {
            registry: EngineRegistry::for_root(registry_path, engines_root.clone()),
            engines_root,
            cache_root,
            client,
        })
    }

    pub fn capabilities(&self) -> Vec<EngineCapability> {
        let hardware = detect_hardware();
        EngineName::ALL
            .iter()
            .copied()
            .map(|name| engine_capability(name, &hardware))
            .collect()
    }

    pub fn capability(&self, name: EngineName) -> EngineCapability {
        engine_capability(name, &detect_hardware())
    }

    pub async fn install(
        &self,
        name: EngineName,
        requested_version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        validate_version(requested_version)?;
        fs::create_dir_all(&self.engines_root)?;
        fs::create_dir_all(&self.cache_root)?;
        let engines_root = fs::canonicalize(&self.engines_root)?;
        let registry_root = self.registry.managed_root()?;
        if engines_root != registry_root {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎登记文件与受管 engines 根目录不一致：{} / {}",
                registry_root.display(),
                engines_root.display()
            )));
        }
        let capability = self.capability(name);
        if !capability.supported {
            return Err(EngineInstallError::Unsupported {
                engine: name,
                reason: capability.reason,
            });
        }
        match name {
            EngineName::LlamaCpp => self.install_llama_cpp(requested_version).await,
            EngineName::Ollama => self.install_ollama(requested_version).await,
            EngineName::Vllm | EngineName::TensorrtLlm => {
                self.install_container_engine(name, requested_version).await
            }
        }
    }

    pub fn registry(&self) -> &EngineRegistry {
        &self.registry
    }

    async fn install_llama_cpp(
        &self,
        requested_version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        let release = self.resolve_llama_release(requested_version).await?;
        validate_version(&release.tag_name)?;
        if requested_version != "latest" && release.tag_name != requested_version {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "release 返回版本 {}，与请求版本 {requested_version} 不一致",
                release.tag_name
            )));
        }
        let selector = release_asset_selector().ok_or_else(|| EngineInstallError::Unsupported {
            engine: EngineName::LlamaCpp,
            reason: format!(
                "没有 {}-{} 的官方预编译资产映射",
                env::consts::OS,
                env::consts::ARCH
            ),
        })?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name.ends_with(selector))
            .cloned()
            .ok_or_else(|| EngineInstallError::MissingReleaseAsset(selector.to_owned()))?;
        validate_path_segment(&asset.name).map_err(|_| {
            EngineInstallError::MissingReleaseAsset(format!(
                "发行资产名称不是安全单段路径：{}",
                asset.name
            ))
        })?;
        let target = target_triple();
        validate_path_segment(&target)?;
        let engines_root = fs::canonicalize(&self.engines_root)?;
        let version_parent = ensure_managed_directory_chain(
            &engines_root,
            &[EngineName::LlamaCpp.as_str(), &release.tag_name],
        )?;
        let _install_lock = acquire_install_lock(&version_parent, &target)?;
        let final_directory = version_parent.join(&target);
        if path_entry_exists(&final_directory)? {
            return self.registry.exact(
                EngineName::LlamaCpp,
                &release.tag_name,
                &target,
                &final_directory,
            );
        }
        let checksum = if let Some(digest) = asset.digest.as_deref().and_then(parse_sha256_digest) {
            digest
        } else {
            self.release_checksum(&release, &asset.name).await?
        };
        let cache_root = fs::canonicalize(&self.cache_root)?;
        let archive = cache_root.join(&asset.name);
        self.ensure_cached_asset(&asset.browser_download_url, &archive, &checksum)
            .await?;
        let staging = TempDir::new_in(&version_parent)?;
        extract_archive(&archive, staging.path(), &asset.name)?;
        let staged_executable = find_engine_executable(staging.path(), EngineName::LlamaCpp)?;
        let relative = staged_executable
            .strip_prefix(staging.path())
            .map_err(|_| {
                EngineInstallError::ExtractionFailed("引擎路径逃逸 staging 目录".to_owned())
            })?;
        make_executable(&staged_executable)?;
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, &final_directory) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(EngineInstallError::Io(error));
        }
        sync_directory(&version_parent)?;
        let executable = final_directory.join(relative);
        let installed = InstalledEngine {
            id: Uuid::now_v7(),
            name: EngineName::LlamaCpp,
            version: release.tag_name,
            target,
            directory: fs::canonicalize(&final_directory)?,
            sha256: sha256_file(&executable)?,
            files: build_engine_manifest(&final_directory)?,
            executable: fs::canonicalize(executable)?,
            installed_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            source: asset.browser_download_url,
        };
        self.registry.upsert(installed.clone())?;
        Ok(installed)
    }

    async fn install_ollama(
        &self,
        requested_version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        let release = self
            .resolve_github_release("ollama/ollama", requested_version)
            .await?;
        validate_version(&release.tag_name)?;
        if requested_version != "latest" && release.tag_name != requested_version {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "release 返回版本 {}，与请求版本 {requested_version} 不一致",
                release.tag_name
            )));
        }
        let selector = ollama_release_asset_selector(env::consts::OS, env::consts::ARCH)
            .ok_or_else(|| EngineInstallError::Unsupported {
                engine: EngineName::Ollama,
                reason: format!(
                    "Ollama 官方 release 没有 {}-{} 的受管资产映射",
                    env::consts::OS,
                    env::consts::ARCH
                ),
            })?;
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == selector)
            .cloned()
            .ok_or_else(|| EngineInstallError::MissingReleaseAsset(selector.to_owned()))?;
        validate_path_segment(&asset.name).map_err(|_| {
            EngineInstallError::MissingReleaseAsset(format!(
                "发行资产名称不是安全单段路径：{}",
                asset.name
            ))
        })?;

        let target = target_triple();
        validate_path_segment(&target)?;
        let engines_root = fs::canonicalize(&self.engines_root)?;
        let version_parent = ensure_managed_directory_chain(
            &engines_root,
            &[EngineName::Ollama.as_str(), &release.tag_name],
        )?;
        let _install_lock = acquire_install_lock(&version_parent, &target)?;
        let final_directory = version_parent.join(&target);
        if path_entry_exists(&final_directory)? {
            return self.registry.exact(
                EngineName::Ollama,
                &release.tag_name,
                &target,
                &final_directory,
            );
        }

        let checksum = if let Some(digest) = asset.digest.as_deref().and_then(parse_sha256_digest) {
            digest
        } else {
            self.release_checksum(&release, &asset.name).await?
        };
        let cache_root = fs::canonicalize(&self.cache_root)?;
        let archive = cache_root.join(&asset.name);
        self.ensure_cached_asset(&asset.browser_download_url, &archive, &checksum)
            .await?;
        let staging = TempDir::new_in(&version_parent)?;
        extract_archive(&archive, staging.path(), &asset.name)?;
        let staged_executable = find_engine_executable(staging.path(), EngineName::Ollama)?;
        let relative = staged_executable
            .strip_prefix(staging.path())
            .map_err(|_| {
                EngineInstallError::ExtractionFailed("引擎路径逃逸 staging 目录".to_owned())
            })?
            .to_path_buf();
        make_executable(&staged_executable)?;
        probe_native_engine(
            &staged_executable,
            &["--version"],
            Some(release.tag_name.trim_start_matches('v')),
        )
        .await?;
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, &final_directory) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(EngineInstallError::Io(error));
        }
        sync_directory(&version_parent)?;
        let executable = final_directory.join(relative);
        let installed = InstalledEngine {
            id: Uuid::now_v7(),
            name: EngineName::Ollama,
            version: release.tag_name,
            target,
            directory: fs::canonicalize(&final_directory)?,
            sha256: sha256_file(&executable)?,
            files: build_engine_manifest(&final_directory)?,
            executable: fs::canonicalize(executable)?,
            installed_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            source: asset.browser_download_url,
        };
        self.registry.upsert(installed.clone())?;
        Ok(installed)
    }

    async fn install_container_engine(
        &self,
        name: EngineName,
        requested_version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        let plan = container_engine_plan(name).ok_or_else(|| EngineInstallError::Unsupported {
            engine: name,
            reason: "该引擎没有官方 OCI 安装计划".to_owned(),
        })?;
        let runtime = detect_container_runtime().ok_or_else(|| EngineInstallError::Unsupported {
            engine: name,
            reason: "需要本机 /var/run/docker.sock 与固定绝对路径的 Docker Engine；不读取 PATH，也不连接远程 daemon"
                .to_owned(),
        })?;
        let release = self
            .resolve_github_release(plan.github_repository, requested_version)
            .await?;
        validate_version(&release.tag_name)?;
        if requested_version != "latest" && release.tag_name != requested_version {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "release 返回版本 {}，与请求版本 {requested_version} 不一致",
                release.tag_name
            )));
        }
        let image_tag = (plan.image_tag)(&release.tag_name);
        validate_oci_tag(&image_tag)?;
        verify_container_runtime(&runtime, plan.registry, name).await?;
        let tagged_reference = format!("{}:{image_tag}", plan.image_repository);
        let digest = resolve_container_digest(
            &runtime,
            &tagged_reference,
            "linux",
            oci_architecture(env::consts::ARCH).ok_or_else(|| EngineInstallError::Unsupported {
                engine: name,
                reason: format!("OCI 官方镜像不支持架构 {}", env::consts::ARCH),
            })?,
        )
        .await?;
        let pinned_reference = format!("{}@{digest}", plan.image_repository);

        let target = target_triple();
        validate_path_segment(&target)?;
        let engines_root = fs::canonicalize(&self.engines_root)?;
        let version_parent =
            ensure_managed_directory_chain(&engines_root, &[name.as_str(), &release.tag_name])?;
        let _install_lock = acquire_install_lock(&version_parent, &target)?;
        let final_directory = version_parent.join(&target);
        if path_entry_exists(&final_directory)? {
            return self
                .registry
                .exact(name, &release.tag_name, &target, &final_directory);
        }

        docker_output(
            &runtime,
            &[
                "pull",
                "--platform",
                plan.platform,
                pinned_reference.as_str(),
            ],
            CONTAINER_COMMAND_TIMEOUT_SECS,
        )
        .await?;
        verify_pulled_container_digest(&runtime, &pinned_reference, &digest).await?;
        let image_size = docker_output(
            &runtime,
            &[
                "image",
                "inspect",
                "--format",
                "{{.Size}}",
                pinned_reference.as_str(),
            ],
            ENGINE_PROBE_TIMEOUT_SECS,
        )
        .await?
        .trim()
        .parse::<u64>()
        .map_err(|_| {
            EngineInstallError::RegistryCorrupt("Docker 未返回可信的镜像大小".to_owned())
        })?;
        if image_size == 0 || image_size > MAX_MANAGED_ENGINE_BYTES {
            return Err(EngineInstallError::DownloadTooLarge {
                limit_bytes: MAX_MANAGED_ENGINE_BYTES,
            });
        }
        probe_container_engine(&runtime, &pinned_reference, plan).await?;

        let staging = TempDir::new_in(&version_parent)?;
        let bundle = staging.path().join("engine-image.tar");
        let bundle_text = bundle.to_str().ok_or_else(|| {
            EngineInstallError::RegistryCorrupt("OCI bundle 路径不是 UTF-8".to_owned())
        })?;
        docker_output(
            &runtime,
            &[
                "image",
                "save",
                "--output",
                bundle_text,
                pinned_reference.as_str(),
            ],
            CONTAINER_COMMAND_TIMEOUT_SECS,
        )
        .await?;
        let bundle_metadata = fs::symlink_metadata(&bundle)?;
        if bundle_metadata.file_type().is_symlink()
            || !bundle_metadata.is_file()
            || bundle_metadata.len() == 0
            || bundle_metadata.len() > MAX_MANAGED_ENGINE_BYTES
        {
            return Err(EngineInstallError::RegistryCorrupt(
                "Docker 导出的 OCI bundle 不是大小合法的普通文件".to_owned(),
            ));
        }
        let bundle_sha256 = sha256_file(&bundle)?;
        let executable = staging.path().join(name.executable_names()[0]);
        let final_bundle = final_directory.join("engine-image.tar");
        write_container_launcher(
            &executable,
            &runtime,
            &pinned_reference,
            &final_bundle,
            plan.entrypoint,
        )?;
        let metadata = ContainerEngineMetadata {
            schema_version: 1,
            engine: name,
            release: release.tag_name.clone(),
            image: pinned_reference.clone(),
            manifest_digest: digest,
            bundle_sha256,
            runtime: runtime.clone(),
            docker_socket: DOCKER_SOCKET.to_owned(),
        };
        write_json_create_new(&staging.path().join("engine.json"), &metadata)?;
        let relative_executable = executable
            .strip_prefix(staging.path())
            .map_err(|_| {
                EngineInstallError::RegistryCorrupt("容器引擎 launcher 逃逸 staging".to_owned())
            })?
            .to_path_buf();
        let staging_path = staging.keep();
        if let Err(error) = fs::rename(&staging_path, &final_directory) {
            let _ = fs::remove_dir_all(&staging_path);
            return Err(EngineInstallError::Io(error));
        }
        sync_directory(&version_parent)?;
        let executable = final_directory.join(relative_executable);
        let installed = InstalledEngine {
            id: Uuid::now_v7(),
            name,
            version: release.tag_name,
            target,
            directory: fs::canonicalize(&final_directory)?,
            sha256: sha256_file(&executable)?,
            files: build_engine_manifest(&final_directory)?,
            executable: fs::canonicalize(executable)?,
            installed_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            source: format!("oci://{pinned_reference}"),
        };
        self.registry.upsert(installed.clone())?;
        Ok(installed)
    }

    async fn resolve_llama_release(
        &self,
        requested_version: &str,
    ) -> Result<GithubRelease, EngineInstallError> {
        self.resolve_github_release("ggml-org/llama.cpp", requested_version)
            .await
    }

    async fn resolve_github_release(
        &self,
        repository: &str,
        requested_version: &str,
    ) -> Result<GithubRelease, EngineInstallError> {
        if !matches!(
            repository,
            "ggml-org/llama.cpp" | "ollama/ollama" | "vllm-project/vllm" | "NVIDIA/TensorRT-LLM"
        ) {
            return Err(EngineInstallError::RegistryCorrupt(
                "GitHub release 仓库不在引擎适配器白名单".to_owned(),
            ));
        }
        let url = if requested_version == "latest" {
            format!("https://api.github.com/repos/{repository}/releases/latest")
        } else {
            format!("https://api.github.com/repos/{repository}/releases/tags/{requested_version}")
        };
        let response = self.client.get(url).send().await?.error_for_status()?;
        Ok(response.json::<GithubRelease>().await?)
    }

    async fn release_checksum(
        &self,
        release: &GithubRelease,
        asset_name: &str,
    ) -> Result<String, EngineInstallError> {
        let checksum_asset = release
            .assets
            .iter()
            .find(|asset| {
                let name = asset.name.to_ascii_lowercase();
                name == "sha256sum.txt" || name == "sha256sums.txt" || name == "checksums.txt"
            })
            .ok_or_else(|| EngineInstallError::MissingReleaseChecksum(asset_name.to_owned()))?;
        validate_path_segment(&checksum_asset.name).map_err(|_| {
            EngineInstallError::MissingReleaseChecksum(format!(
                "checksum 资产名称不安全：{}",
                checksum_asset.name
            ))
        })?;
        let checksum_url = parse_https_url(&checksum_asset.browser_download_url).map_err(|_| {
            EngineInstallError::MissingReleaseChecksum(format!(
                "checksum 下载地址不是 HTTPS：{}",
                checksum_asset.browser_download_url
            ))
        })?;
        let response = self
            .client
            .get(checksum_url)
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_CHECKSUM_BYTES)
        {
            return Err(EngineInstallError::DownloadTooLarge {
                limit_bytes: MAX_CHECKSUM_BYTES,
            });
        }
        let bytes = read_limited_response(response, MAX_CHECKSUM_BYTES).await?;
        let text = String::from_utf8(bytes).map_err(|error| {
            EngineInstallError::MissingReleaseChecksum(format!("checksum 文件不是 UTF-8：{error}"))
        })?;
        text.lines()
            .find_map(|line| parse_checksum_line(line, asset_name))
            .ok_or_else(|| EngineInstallError::MissingReleaseChecksum(asset_name.to_owned()))
    }

    async fn download_asset(
        &self,
        url: &str,
        destination: &Path,
    ) -> Result<(), EngineInstallError> {
        let parsed = parse_https_url(url).map_err(|_| EngineInstallError::Unsupported {
            engine: EngineName::LlamaCpp,
            reason: "发行文件下载地址不是有效 HTTPS URL".to_owned(),
        })?;
        let response = self.client.get(parsed).send().await?.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
        {
            return Err(EngineInstallError::DownloadTooLarge {
                limit_bytes: MAX_ARCHIVE_BYTES,
            });
        }
        let mut temp = NamedTempFile::new_in(&self.cache_root)?;
        let mut stream = response.bytes_stream();
        let mut downloaded = 0_u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            downloaded = downloaded
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    EngineInstallError::DownloadTooLarge {
                        limit_bytes: MAX_ARCHIVE_BYTES,
                    }
                })?)
                .ok_or(EngineInstallError::DownloadTooLarge {
                    limit_bytes: MAX_ARCHIVE_BYTES,
                })?;
            if downloaded > MAX_ARCHIVE_BYTES {
                return Err(EngineInstallError::DownloadTooLarge {
                    limit_bytes: MAX_ARCHIVE_BYTES,
                });
            }
            temp.write_all(&chunk)?;
        }
        temp.as_file().sync_all()?;
        temp.persist_noclobber(destination)
            .map_err(|error| EngineInstallError::Io(error.error))?;
        if let Some(parent) = destination.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }

    async fn ensure_cached_asset(
        &self,
        url: &str,
        archive: &Path,
        expected_sha256: &str,
    ) -> Result<(), EngineInstallError> {
        if prepare_cached_asset(archive, expected_sha256)? {
            return Ok(());
        }
        self.download_asset(url, archive).await?;
        let actual = sha256_file(archive)?;
        if actual != expected_sha256 {
            let _ = fs::remove_file(archive);
            return Err(EngineInstallError::ChecksumMismatch {
                expected: expected_sha256.to_owned(),
                actual,
            });
        }
        Ok(())
    }
}

fn detect_container_runtime() -> Option<PathBuf> {
    if env::consts::OS != "linux" {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        let socket = fs::symlink_metadata("/var/run/docker.sock").ok()?;
        if !socket.file_type().is_socket() {
            return None;
        }
    }
    ["/usr/bin/docker", "/usr/local/bin/docker"]
        .iter()
        .find_map(|candidate| {
            let path = Path::new(candidate);
            let canonical = fs::canonicalize(path).ok()?;
            let metadata = fs::metadata(&canonical).ok()?;
            if !metadata.is_file() {
                return None;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if !trusted_container_runtime_permissions(metadata.uid(), metadata.mode()) {
                    return None;
                }
            }
            Some(canonical)
        })
}

#[cfg(any(unix, test))]
fn trusted_container_runtime_permissions(owner_uid: u32, mode: u32) -> bool {
    owner_uid == 0 && mode & 0o022 == 0
}

async fn verify_container_runtime(
    runtime: &Path,
    registry: &str,
    engine: EngineName,
) -> Result<(), EngineInstallError> {
    let version = docker_output(
        runtime,
        &["version", "--format", "{{.Server.APIVersion}}"],
        ENGINE_PROBE_TIMEOUT_SECS,
    )
    .await?;
    if version.trim().is_empty() {
        return Err(EngineInstallError::HealthCheckFailed(
            "Docker Engine 没有返回 Server API 版本".to_owned(),
        ));
    }
    let registry_config = docker_output(
        runtime,
        &["info", "--format", "{{json .RegistryConfig.IndexConfigs}}"],
        ENGINE_PROBE_TIMEOUT_SECS,
    )
    .await?;
    ensure_secure_registry_config(&registry_config, registry, engine)
}

fn ensure_secure_registry_config(
    output: &str,
    registry: &str,
    engine: EngineName,
) -> Result<(), EngineInstallError> {
    let value: serde_json::Value = serde_json::from_str(output.trim()).map_err(|error| {
        EngineInstallError::RegistryCorrupt(format!("Docker registry 配置不是 JSON：{error}"))
    })?;
    let configs = value.as_object().ok_or_else(|| {
        EngineInstallError::RegistryCorrupt("Docker registry 配置不是对象".to_owned())
    })?;
    if let Some(config) = configs.get(registry) {
        if config.get("Secure").and_then(serde_json::Value::as_bool) != Some(true) {
            return Err(EngineInstallError::Unsupported {
                engine,
                reason: format!("Docker registry {registry} 被配置为非 TLS，已拒绝"),
            });
        }
        if config
            .get("Mirrors")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|mirrors| !mirrors.is_empty())
        {
            return Err(EngineInstallError::Unsupported {
                engine,
                reason: format!("Docker registry {registry} 配置了未纳入校验链的 mirror，已拒绝"),
            });
        }
    }
    Ok(())
}

async fn resolve_container_digest(
    runtime: &Path,
    tagged_reference: &str,
    operating_system: &str,
    architecture: &str,
) -> Result<String, EngineInstallError> {
    let output = docker_output(
        runtime,
        &["manifest", "inspect", "--verbose", tagged_reference],
        ENGINE_PROBE_TIMEOUT_SECS,
    )
    .await?;
    select_container_digest(&output, operating_system, architecture)
}

fn select_container_digest(
    output: &str,
    operating_system: &str,
    architecture: &str,
) -> Result<String, EngineInstallError> {
    let value: serde_json::Value = serde_json::from_str(output).map_err(|error| {
        EngineInstallError::RegistryCorrupt(format!("OCI manifest 不是 JSON：{error}"))
    })?;
    let descriptors = match value.as_array() {
        Some(items) => items.iter().collect::<Vec<_>>(),
        None => vec![&value],
    };
    for item in descriptors {
        let descriptor = item.get("Descriptor").unwrap_or(item);
        let platform = descriptor
            .get("platform")
            .or_else(|| descriptor.get("Platform"));
        let matches_platform = platform.is_some_and(|platform| {
            platform
                .get("os")
                .or_else(|| platform.get("OS"))
                .and_then(serde_json::Value::as_str)
                == Some(operating_system)
                && platform
                    .get("architecture")
                    .or_else(|| platform.get("Architecture"))
                    .and_then(serde_json::Value::as_str)
                    == Some(architecture)
        });
        if !matches_platform {
            continue;
        }
        let digest = descriptor
            .get("digest")
            .or_else(|| descriptor.get("Digest"))
            .and_then(serde_json::Value::as_str)
            .and_then(parse_sha256_digest)
            .ok_or_else(|| {
                EngineInstallError::RegistryCorrupt(
                    "匹配平台的 OCI descriptor 缺少 SHA-256 digest".to_owned(),
                )
            })?;
        return Ok(format!("sha256:{digest}"));
    }
    Err(EngineInstallError::MissingReleaseAsset(format!(
        "OCI manifest 没有 {operating_system}/{architecture} descriptor"
    )))
}

async fn probe_container_engine(
    runtime: &Path,
    pinned_reference: &str,
    plan: ContainerEnginePlan,
) -> Result<(), EngineInstallError> {
    let output = docker_output(
        runtime,
        &[
            "run",
            "--rm",
            "--gpus",
            "all",
            "--entrypoint",
            plan.entrypoint,
            pinned_reference,
            plan.probe_argument,
        ],
        ENGINE_PROBE_TIMEOUT_SECS,
    )
    .await?;
    if output.trim().is_empty() {
        return Err(EngineInstallError::HealthCheckFailed(format!(
            "{} 容器入口没有返回版本/帮助信息",
            plan.entrypoint
        )));
    }
    Ok(())
}

async fn verify_pulled_container_digest(
    runtime: &Path,
    pinned_reference: &str,
    expected_digest: &str,
) -> Result<(), EngineInstallError> {
    let output = docker_output(
        runtime,
        &[
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            pinned_reference,
        ],
        ENGINE_PROBE_TIMEOUT_SECS,
    )
    .await?;
    let digests: Vec<String> = serde_json::from_str(output.trim()).map_err(|error| {
        EngineInstallError::RegistryCorrupt(format!("Docker RepoDigests 不是 JSON：{error}"))
    })?;
    let suffix = format!("@{expected_digest}");
    if !digests.iter().any(|digest| digest.ends_with(&suffix)) {
        return Err(EngineInstallError::ChecksumMismatch {
            expected: expected_digest.to_owned(),
            actual: digests.join(","),
        });
    }
    Ok(())
}

async fn docker_output(
    runtime: &Path,
    arguments: &[&str],
    timeout_seconds: u64,
) -> Result<String, EngineInstallError> {
    let mut command = tokio::process::Command::new(runtime);
    command
        .args(["--host", DOCKER_SOCKET])
        .args(arguments)
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_seconds),
        command.output(),
    )
    .await
    .map_err(|_| {
        EngineInstallError::CommandFailed(format!("Docker 命令超过 {timeout_seconds} 秒安全时限"))
    })??;
    let total = output.stdout.len().saturating_add(output.stderr.len());
    if total > MAX_COMMAND_OUTPUT_BYTES {
        return Err(EngineInstallError::CommandFailed(
            "Docker 命令输出超过 1 MiB 安全上限".to_owned(),
        ));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        let detail = text.trim();
        return Err(EngineInstallError::CommandFailed(if detail.is_empty() {
            format!("Docker 命令退出状态 {}", output.status)
        } else {
            format!("Docker 命令退出状态 {}：{detail}", output.status)
        }));
    }
    Ok(text)
}

async fn probe_native_engine(
    executable: &Path,
    arguments: &[&str],
    expected_fragment: Option<&str>,
) -> Result<(), EngineInstallError> {
    let mut command = tokio::process::Command::new(executable);
    command
        .args(arguments)
        .env_remove("OLLAMA_HOST")
        .env_remove("OLLAMA_MODELS")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(ENGINE_PROBE_TIMEOUT_SECS),
        command.output(),
    )
    .await
    .map_err(|_| {
        EngineInstallError::HealthCheckFailed(format!("{} 健康探测超时", executable.display()))
    })??;
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_COMMAND_OUTPUT_BYTES {
        return Err(EngineInstallError::HealthCheckFailed(
            "引擎健康探测输出超过 1 MiB 安全上限".to_owned(),
        ));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() || text.trim().is_empty() {
        return Err(EngineInstallError::HealthCheckFailed(format!(
            "{} --version 未成功返回真实版本",
            executable.display()
        )));
    }
    if expected_fragment.is_some_and(|expected| !text.contains(expected)) {
        return Err(EngineInstallError::HealthCheckFailed(format!(
            "{} 返回版本与官方 release 不一致",
            executable.display()
        )));
    }
    Ok(())
}

fn write_container_launcher(
    destination: &Path,
    runtime: &Path,
    image: &str,
    bundle: &Path,
    entrypoint: &str,
) -> Result<(), EngineInstallError> {
    #[cfg(not(unix))]
    {
        let _ = (destination, runtime, image, bundle, entrypoint);
        Err(EngineInstallError::Unsupported {
            engine: EngineName::Vllm,
            reason: "容器 launcher 仅支持 Linux".to_owned(),
        })
    }
    #[cfg(unix)]
    {
        let runtime = runtime.to_str().ok_or_else(|| {
            EngineInstallError::RegistryCorrupt("Docker 路径不是 UTF-8".to_owned())
        })?;
        let bundle = bundle.to_str().ok_or_else(|| {
            EngineInstallError::RegistryCorrupt("OCI bundle 路径不是 UTF-8".to_owned())
        })?;
        let script = format!(
            "#!/bin/sh\nset -eu\nruntime={}\nsocket={}\nimage={}\nbundle={}\nif ! \"$runtime\" --host \"$socket\" image inspect \"$image\" >/dev/null 2>&1; then\n  \"$runtime\" --host \"$socket\" image load --input \"$bundle\" >/dev/null\nfi\nexec \"$runtime\" --host \"$socket\" run --rm --gpus all --entrypoint {} \"$image\" \"$@\"\n",
            posix_shell_quote(runtime),
            posix_shell_quote(DOCKER_SOCKET),
            posix_shell_quote(image),
            posix_shell_quote(bundle),
            posix_shell_quote(entrypoint),
        );
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(destination)?;
        file.write_all(script.as_bytes())?;
        file.sync_all()?;
        make_executable(destination)
    }
}

#[cfg(unix)]
fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn write_json_create_new(
    destination: &Path,
    value: &impl Serialize,
) -> Result<(), EngineInstallError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| EngineInstallError::RegistryCorrupt(error.to_string()))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn prepare_cached_asset(archive: &Path, expected_sha256: &str) -> Result<bool, EngineInstallError> {
    match fs::symlink_metadata(archive) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(EngineInstallError::RegistryCorrupt(format!(
                    "引擎缓存目标不是受管普通文件：{}",
                    archive.display()
                )));
            }
            if sha256_file(archive)? == expected_sha256 {
                return Ok(true);
            }
            fs::remove_file(archive)?;
            if let Some(parent) = archive.parent() {
                sync_directory(parent)?;
            }
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(EngineInstallError::Io(error)),
    }
}

async fn read_limited_response(
    response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, EngineInstallError> {
    let mut bytes = Vec::new();
    let mut downloaded = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        downloaded = downloaded
            .checked_add(
                u64::try_from(chunk.len())
                    .map_err(|_| EngineInstallError::DownloadTooLarge { limit_bytes: limit })?,
            )
            .ok_or(EngineInstallError::DownloadTooLarge { limit_bytes: limit })?;
        if downloaded > limit {
            return Err(EngineInstallError::DownloadTooLarge { limit_bytes: limit });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn https_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("MindOne 拒绝超过 5 次的重定向");
        }
        if attempt.url().scheme() == "https" {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

fn parse_https_url(value: &str) -> Result<url::Url, ()> {
    let parsed = url::Url::parse(value).map_err(|_| ())?;
    if parsed.scheme() == "https" && parsed.host_str().is_some() {
        Ok(parsed)
    } else {
        Err(())
    }
}

impl EngineRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let engines_root = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::for_root(path, engines_root)
    }

    fn for_root(path: PathBuf, engines_root: PathBuf) -> Self {
        let lock_path = path.with_extension("lock");
        Self {
            path,
            lock_path,
            engines_root,
        }
    }

    pub fn list(&self) -> Result<Vec<InstalledEngine>, EngineInstallError> {
        self.with_lock(false, |data| Ok(data.engines.clone()))
    }

    pub fn verify_record(&self, installed: &InstalledEngine) -> Result<(), EngineInstallError> {
        installed.verify_integrity_in(&self.managed_root()?)
    }

    pub fn latest(&self, name: EngineName) -> Result<InstalledEngine, EngineInstallError> {
        self.with_lock(false, |data| {
            let installed = newest_engine(data.engines.iter().filter(|engine| engine.name == name))
                .cloned()
                .ok_or_else(|| EngineInstallError::NotInstalled(name.to_string()))?;
            self.verify_record(&installed)?;
            Ok(installed)
        })
    }

    /// 返回指定发行版本的可信安装记录，而不是让后来安装的更高版本遮蔽它。
    ///
    /// 受管运行时只能启动完成独立语义审计的固定发行版；“最新安装”只适合展示
    /// 和通用安装管理，不能替代显式版本选择。
    pub fn version(
        &self,
        name: EngineName,
        version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        self.with_lock(false, |data| {
            let installed = newest_engine(
                data.engines
                    .iter()
                    .filter(|engine| engine.name == name && engine.version == version),
            )
            .cloned()
            .ok_or_else(|| EngineInstallError::NotInstalled(format!("{name} {version}")))?;
            self.verify_record(&installed)?;
            Ok(installed)
        })
    }

    pub fn default(&self) -> Result<Option<InstalledEngine>, EngineInstallError> {
        self.with_lock(false, |data| {
            let installed = data.default.and_then(|name| {
                newest_engine(data.engines.iter().filter(|engine| engine.name == name)).cloned()
            });
            if let Some(engine) = &installed {
                self.verify_record(engine)?;
            }
            Ok(installed)
        })
    }

    pub fn configured_default(&self) -> Result<Option<EngineName>, EngineInstallError> {
        self.with_lock(false, |data| Ok(data.default))
    }

    pub fn set_default(&self, name: EngineName) -> Result<InstalledEngine, EngineInstallError> {
        self.with_lock(true, |data| {
            let installed = newest_engine(data.engines.iter().filter(|engine| engine.name == name))
                .cloned()
                .ok_or_else(|| EngineInstallError::NotInstalled(name.to_string()))?;
            self.verify_record(&installed)?;
            data.default = Some(name);
            Ok(installed)
        })
    }

    /// 将一个明确版本登记为默认引擎名称，并返回该版本的可信记录。
    ///
    /// registry v1 的持久字段仍只保存引擎名；调用方之后必须继续用 `version`
    /// 解析其受审计版本，不能重新退回 `latest`。
    pub fn set_default_version(
        &self,
        name: EngineName,
        version: &str,
    ) -> Result<InstalledEngine, EngineInstallError> {
        self.with_lock(true, |data| {
            let installed = newest_engine(
                data.engines
                    .iter()
                    .filter(|engine| engine.name == name && engine.version == version),
            )
            .cloned()
            .ok_or_else(|| EngineInstallError::NotInstalled(format!("{name} {version}")))?;
            self.verify_record(&installed)?;
            data.default = Some(name);
            Ok(installed)
        })
    }

    fn exact(
        &self,
        name: EngineName,
        version: &str,
        target: &str,
        expected_directory: &Path,
    ) -> Result<InstalledEngine, EngineInstallError> {
        self.with_lock(false, |data| {
            let installed = data
                .engines
                .iter()
                .find(|engine| {
                    engine.name == name && engine.version == version && engine.target == target
                })
                .cloned()
                .ok_or_else(|| {
                    EngineInstallError::RegistryCorrupt(format!(
                        "安装目录已存在但没有可信登记，拒绝接管：{}",
                        expected_directory.display()
                    ))
                })?;
            if installed.directory != expected_directory {
                return Err(EngineInstallError::RegistryCorrupt(format!(
                    "已有安装登记目录与预期受管目录不一致：{} / {}",
                    installed.directory.display(),
                    expected_directory.display()
                )));
            }
            self.verify_record(&installed)?;
            Ok(installed)
        })
    }

    fn upsert(&self, installed: InstalledEngine) -> Result<(), EngineInstallError> {
        self.verify_record(&installed)?;
        self.with_lock(true, |data| {
            data.engines.retain(|engine| {
                !(engine.name == installed.name
                    && engine.version == installed.version
                    && engine.target == installed.target)
            });
            data.engines.push(installed);
            Ok(())
        })
    }

    fn managed_root(&self) -> Result<PathBuf, EngineInstallError> {
        fs::create_dir_all(&self.engines_root)?;
        Ok(fs::canonicalize(&self.engines_root)?)
    }

    fn with_lock<T>(
        &self,
        write: bool,
        operation: impl FnOnce(&mut EngineRegistryData) -> Result<T, EngineInstallError>,
    ) -> Result<T, EngineInstallError> {
        let parent = self.path.parent().ok_or_else(|| {
            EngineInstallError::RegistryCorrupt("registry 路径缺少父目录".to_owned())
        })?;
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&self.lock_path)?;
        if write {
            FileExt::lock_exclusive(&lock)?;
        } else {
            FileExt::lock_shared(&lock)?;
        }
        let mut data = self.read_data()?;
        let result = operation(&mut data);
        if write && result.is_ok() {
            self.write_data(&data)?;
        }
        FileExt::unlock(&lock)?;
        result
    }

    fn read_data(&self) -> Result<EngineRegistryData, EngineInstallError> {
        if !self.path.exists() {
            return Ok(EngineRegistryData {
                version: 1,
                default: None,
                engines: Vec::new(),
            });
        }
        let bytes = fs::read(&self.path)?;
        if bytes.is_empty() {
            return Ok(EngineRegistryData {
                version: 1,
                default: None,
                engines: Vec::new(),
            });
        }
        let data: EngineRegistryData = serde_json::from_slice(&bytes)
            .map_err(|error| EngineInstallError::RegistryCorrupt(error.to_string()))?;
        if data.version != 1 {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "不支持 registry 版本 {}",
                data.version
            )));
        }
        Ok(data)
    }

    fn write_data(&self, data: &EngineRegistryData) -> Result<(), EngineInstallError> {
        let parent = self.path.parent().ok_or_else(|| {
            EngineInstallError::RegistryCorrupt("registry 路径缺少父目录".to_owned())
        })?;
        let bytes = serde_json::to_vec_pretty(data)
            .map_err(|error| EngineInstallError::RegistryCorrupt(error.to_string()))?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|error| EngineInstallError::Io(error.error))?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn newest_engine<'a>(
    engines: impl Iterator<Item = &'a InstalledEngine>,
) -> Option<&'a InstalledEngine> {
    engines.max_by(|left, right| {
        compare_versions(&left.version, &right.version)
            .then_with(|| left.installed_at_unix.cmp(&right.installed_at_unix))
            .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
    })
}

fn compare_versions(left: &str, right: &str) -> Ordering {
    if let (Some(left), Some(right)) = (parse_semver(left), parse_semver(right)) {
        return compare_semver(&left, &right);
    }
    let left_numbers = numeric_runs(left);
    let right_numbers = numeric_runs(right);
    for (left_number, right_number) in left_numbers.iter().zip(&right_numbers) {
        let left_number = left_number.trim_start_matches('0');
        let right_number = right_number.trim_start_matches('0');
        let left_number = if left_number.is_empty() {
            "0"
        } else {
            left_number
        };
        let right_number = if right_number.is_empty() {
            "0"
        } else {
            right_number
        };
        let ordering = left_number
            .len()
            .cmp(&right_number.len())
            .then_with(|| left_number.cmp(right_number));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_numbers
        .len()
        .cmp(&right_numbers.len())
        .then_with(|| left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()))
}

#[derive(Debug)]
struct ParsedSemver<'a> {
    core: Vec<u64>,
    prerelease: Option<&'a str>,
}

fn parse_semver(value: &str) -> Option<ParsedSemver<'_>> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let without_build = value.split_once('+').map_or(value, |(core, _)| core);
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, suffix)| (core, Some(suffix)));
    let components = core.split('.').collect::<Vec<_>>();
    if components.len() < 2
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
        || prerelease.is_some_and(str::is_empty)
    {
        return None;
    }
    let core = components
        .into_iter()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    Some(ParsedSemver { core, prerelease })
}

fn compare_semver(left: &ParsedSemver<'_>, right: &ParsedSemver<'_>) -> Ordering {
    let component_count = left.core.len().max(right.core.len());
    for index in 0..component_count {
        let ordering = left
            .core
            .get(index)
            .copied()
            .unwrap_or(0)
            .cmp(&right.core.get(index).copied().unwrap_or(0));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    match (left.prerelease, right.prerelease) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(left), Some(right)) => compare_prerelease(left, right),
    }
}

fn compare_prerelease(left: &str, right: &str) -> Ordering {
    let mut left = left.split('.');
    let mut right = right.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => {
                let ordering = match (left.parse::<u64>(), right.parse::<u64>()) {
                    (Ok(left), Ok(right)) => left.cmp(&right),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => left.cmp(right),
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

fn numeric_runs(value: &str) -> Vec<&str> {
    let mut runs = Vec::new();
    let bytes = value.as_bytes();
    let mut start = None;
    for (index, byte) in bytes.iter().enumerate() {
        if byte.is_ascii_digit() {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            runs.push(&value[begin..index]);
        }
    }
    if let Some(begin) = start {
        runs.push(&value[begin..]);
    }
    runs
}

fn engine_capability(name: EngineName, hardware: &HardwareProfile) -> EngineCapability {
    engine_capability_for(
        name,
        hardware,
        env::consts::OS,
        env::consts::ARCH,
        release_asset_selector().is_some(),
        detect_container_runtime().is_some(),
    )
}

fn engine_capability_for(
    name: EngineName,
    hardware: &HardwareProfile,
    operating_system: &str,
    architecture: &str,
    llama_release_supported: bool,
    container_runtime_available: bool,
) -> EngineCapability {
    match name {
        EngineName::LlamaCpp => EngineCapability {
            name,
            supported: llama_release_supported,
            installed_binary: None,
            reason: if llama_release_supported {
                "支持官方 release 的隔离安装".to_owned()
            } else {
                "官方 release 没有当前 OS/架构映射".to_owned()
            },
        },
        EngineName::Vllm => {
            let platform = operating_system == "linux" && architecture == "x86_64";
            let runtime_versions =
                hardware.nvidia_driver_version.is_some() && hardware.cuda_driver_version.is_some();
            EngineCapability {
                name,
                supported: platform
                    && hardware.cuda_available
                    && runtime_versions
                    && container_runtime_available,
                installed_binary: None,
                reason: if !platform {
                    "vLLM 适配器要求 Linux x86_64".to_owned()
                } else if !hardware.cuda_available {
                    "已检测 Linux x86_64，但未检测到可查询的 CUDA GPU runtime".to_owned()
                } else if !runtime_versions {
                    "已检测 NVIDIA GPU，但无法同时读取 NVIDIA driver 与 CUDA driver 版本，已拒绝安装"
                        .to_owned()
                } else if !container_runtime_available {
                    "需要本机 /var/run/docker.sock 与固定绝对路径的 Docker Engine；不读取 PATH，也不连接远程 daemon"
                        .to_owned()
                } else {
                    format!(
                        "支持官方 vLLM OCI 镜像的 digest 固定、受管 bundle、GPU 入口健康验证（NVIDIA driver {}，CUDA driver {}）",
                        hardware.nvidia_driver_version.as_deref().unwrap_or("未知"),
                        hardware.cuda_driver_version.as_deref().unwrap_or("未知")
                    )
                },
            }
        }
        EngineName::Ollama => {
            let asset = ollama_release_asset_selector(operating_system, architecture);
            EngineCapability {
                name,
                supported: asset.is_some(),
                installed_binary: None,
                reason: if let Some(asset) = asset {
                    format!(
                        "支持官方 {asset} 的 SHA-256 校验、隔离安装与真实版本健康探测（后端 {}）",
                        hardware.recommended_backend
                    )
                } else {
                    format!(
                        "Ollama 官方 release 没有 {operating_system}-{architecture} 的受管资产映射"
                    )
                },
            }
        }
        EngineName::TensorrtLlm => {
            let platform = operating_system == "linux" && architecture == "x86_64";
            let runtime_versions =
                hardware.nvidia_driver_version.is_some() && hardware.cuda_driver_version.is_some();
            EngineCapability {
                name,
                supported: platform
                    && hardware.cuda_available
                    && runtime_versions
                    && container_runtime_available,
                installed_binary: None,
                reason: if !platform {
                    "TensorRT-LLM 适配器要求 Linux x86_64".to_owned()
                } else if !hardware.cuda_available {
                    "已检测 Linux x86_64，但未检测到可查询的 CUDA GPU runtime".to_owned()
                } else if !runtime_versions {
                    "已检测 NVIDIA GPU，但无法同时读取 NVIDIA driver 与 CUDA driver 版本，已拒绝安装"
                        .to_owned()
                } else if !container_runtime_available {
                    "需要本机 /var/run/docker.sock 与固定绝对路径的 Docker Engine；不读取 PATH，也不连接远程 daemon"
                        .to_owned()
                } else {
                    format!(
                        "支持 NVIDIA 官方 TensorRT-LLM OCI 镜像的 digest 固定、受管 bundle、GPU 入口健康验证（NVIDIA driver {}，CUDA driver {}）",
                        hardware.nvidia_driver_version.as_deref().unwrap_or("未知"),
                        hardware.cuda_driver_version.as_deref().unwrap_or("未知")
                    )
                },
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}

fn release_asset_selector() -> Option<&'static str> {
    llama_cpp_release_asset_selector(env::consts::OS, env::consts::ARCH)
}

fn llama_cpp_release_asset_selector(
    operating_system: &str,
    architecture: &str,
) -> Option<&'static str> {
    match (operating_system, architecture) {
        ("macos", "aarch64") => Some("bin-macos-arm64.tar.gz"),
        ("macos", "x86_64") => Some("bin-macos-x64.tar.gz"),
        ("linux", "x86_64") => Some("bin-ubuntu-x64.tar.gz"),
        ("linux", "aarch64") => Some("bin-ubuntu-arm64.tar.gz"),
        ("windows", "x86_64") => Some("bin-win-cpu-x64.zip"),
        ("windows", "aarch64") => Some("bin-win-cpu-arm64.zip"),
        _ => None,
    }
}

fn ollama_release_asset_selector(
    operating_system: &str,
    architecture: &str,
) -> Option<&'static str> {
    match (operating_system, architecture) {
        ("macos", "aarch64" | "x86_64") => Some("ollama-darwin.tgz"),
        ("linux", "x86_64") => Some("ollama-linux-amd64.tar.zst"),
        ("linux", "aarch64") => Some("ollama-linux-arm64.tar.zst"),
        ("windows", "x86_64") => Some("ollama-windows-amd64.zip"),
        ("windows", "aarch64") => Some("ollama-windows-arm64.zip"),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct ContainerEnginePlan {
    github_repository: &'static str,
    registry: &'static str,
    image_repository: &'static str,
    image_tag: fn(&str) -> String,
    platform: &'static str,
    entrypoint: &'static str,
    probe_argument: &'static str,
}

fn container_engine_plan(name: EngineName) -> Option<ContainerEnginePlan> {
    match name {
        EngineName::Vllm => Some(ContainerEnginePlan {
            github_repository: "vllm-project/vllm",
            registry: "docker.io",
            image_repository: "docker.io/vllm/vllm-openai",
            image_tag: str::to_owned,
            platform: "linux/amd64",
            entrypoint: "vllm",
            probe_argument: "--version",
        }),
        EngineName::TensorrtLlm => Some(ContainerEnginePlan {
            github_repository: "NVIDIA/TensorRT-LLM",
            registry: "nvcr.io",
            image_repository: "nvcr.io/nvidia/tensorrt-llm/release",
            image_tag: |release| release.trim_start_matches('v').to_owned(),
            platform: "linux/amd64",
            entrypoint: "trtllm-serve",
            probe_argument: "--help",
        }),
        EngineName::LlamaCpp | EngineName::Ollama => None,
    }
}

fn oci_architecture(architecture: &str) -> Option<&'static str> {
    match architecture {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

fn validate_oci_tag(value: &str) -> Result<(), EngineInstallError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(EngineInstallError::InvalidVersion);
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ContainerEngineMetadata {
    schema_version: u32,
    engine: EngineName,
    release: String,
    image: String,
    manifest_digest: String,
    bundle_sha256: String,
    runtime: PathBuf,
    docker_socket: String,
}

fn parse_sha256_digest(value: &str) -> Option<String> {
    let digest = value.strip_prefix("sha256:")?.to_ascii_lowercase();
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(digest)
    } else {
        None
    }
}

fn parse_checksum_line(line: &str, asset_name: &str) -> Option<String> {
    let mut fields = line.split_whitespace();
    let checksum = fields.next()?.to_ascii_lowercase();
    let filename = fields.next()?.trim_start_matches('*');
    if filename == asset_name
        && checksum.len() == 64
        && checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        Some(checksum)
    } else {
        None
    }
}

fn extract_archive(
    archive: &Path,
    destination: &Path,
    asset_name: &str,
) -> Result<(), EngineInstallError> {
    if asset_name.ends_with(".tar.gz") || asset_name.ends_with(".tgz") {
        extract_tar_gz(archive, destination)
    } else if asset_name.ends_with(".tar.zst") {
        extract_tar_zstd(archive, destination)
    } else if asset_name.ends_with(".zip") {
        extract_zip(archive, destination)
    } else {
        Err(EngineInstallError::ExtractionFailed(
            "不支持的归档类型".to_owned(),
        ))
    }
}

fn extract_tar_gz(archive: &Path, destination: &Path) -> Result<(), EngineInstallError> {
    let source = File::open(archive)?;
    let decoder = flate2::read::GzDecoder::new(source);
    extract_tar_reader(decoder, destination)
}

fn extract_tar_zstd(archive: &Path, destination: &Path) -> Result<(), EngineInstallError> {
    let source = File::open(archive)?;
    let decoder = zstd::stream::read::Decoder::new(source)?;
    extract_tar_reader(decoder, destination)
}

fn extract_tar_reader(reader: impl Read, destination: &Path) -> Result<(), EngineInstallError> {
    let mut archive = tar::Archive::new(reader);
    let mut paths = HashSet::new();
    let mut pending_links = HashMap::new();
    let mut total_bytes = 0_u64;
    let mut entries = archive.entries()?;
    for index in 0..MAX_ARCHIVE_ENTRIES {
        let Some(entry) = entries.next() else {
            materialize_archive_links(destination, pending_links, &mut total_bytes)?;
            return Ok(());
        };
        let mut entry = entry?;
        let relative = safe_archive_path(&entry.path()?)?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let output = destination.join(&relative);
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        if kind.is_symlink() {
            if !paths.insert(relative.clone()) {
                return Err(EngineInstallError::ExtractionFailed(format!(
                    "归档包含重复文件：{}",
                    relative.display()
                )));
            }
            let target = entry.link_name()?.ok_or_else(|| {
                EngineInstallError::ExtractionFailed(format!(
                    "归档符号链接缺少目标：{}",
                    relative.display()
                ))
            })?;
            let parent = relative.parent().unwrap_or_else(|| Path::new(""));
            let target = resolve_archive_link_target(parent, &target)?;
            pending_links.insert(relative, target);
            continue;
        }
        if !kind.is_file() {
            return Err(EngineInstallError::ExtractionFailed(format!(
                "归档条目 {} 不是普通文件、目录或安全内部符号链接，已拒绝硬链接与设备文件",
                relative.display()
            )));
        }
        if !paths.insert(relative.clone()) {
            return Err(EngineInstallError::ExtractionFailed(format!(
                "归档包含重复文件：{}",
                relative.display()
            )));
        }
        let size = entry.header().size()?;
        add_extracted_size(&mut total_bytes, size)?;
        write_archive_file(&mut entry, &output, size)?;

        if index + 1 == MAX_ARCHIVE_ENTRIES {
            return Err(EngineInstallError::ExtractionFailed(
                "归档条目数量超过安全上限".to_owned(),
            ));
        }
    }
    Err(EngineInstallError::ExtractionFailed(
        "归档条目数量超过安全上限".to_owned(),
    ))
}

fn resolve_archive_link_target(
    link_parent: &Path,
    target: &Path,
) -> Result<PathBuf, EngineInstallError> {
    let mut resolved = safe_archive_path(link_parent)?;
    for component in target.components() {
        match component {
            Component::Normal(value) => resolved.push(value),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() {
                    return Err(EngineInstallError::ExtractionFailed(format!(
                        "归档符号链接试图逃逸安装目录：{}",
                        target.display()
                    )));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(EngineInstallError::ExtractionFailed(format!(
                    "归档符号链接目标不是安全相对路径：{}",
                    target.display()
                )));
            }
        }
    }
    if resolved.as_os_str().is_empty() {
        return Err(EngineInstallError::ExtractionFailed(
            "归档符号链接不能指向安装根目录".to_owned(),
        ));
    }
    Ok(resolved)
}

fn materialize_archive_links(
    destination: &Path,
    mut pending: HashMap<PathBuf, PathBuf>,
    total_bytes: &mut u64,
) -> Result<(), EngineInstallError> {
    while !pending.is_empty() {
        let mut completed = Vec::new();
        for (link, target) in &pending {
            let source = destination.join(target);
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(EngineInstallError::Io(error)),
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(EngineInstallError::ExtractionFailed(format!(
                    "归档符号链接目标不是已解压普通文件：{} -> {}",
                    link.display(),
                    target.display()
                )));
            }
            add_extracted_size(total_bytes, metadata.len())?;
            let output = destination.join(link);
            let parent = output.parent().ok_or_else(|| {
                EngineInstallError::ExtractionFailed("符号链接物化路径缺少父目录".to_owned())
            })?;
            fs::create_dir_all(parent)?;
            copy_file_create_new(&source, &output)?;
            completed.push(link.clone());
        }
        if completed.is_empty() {
            return Err(EngineInstallError::ExtractionFailed(
                "归档包含悬空或循环符号链接".to_owned(),
            ));
        }
        for link in completed {
            pending.remove(&link);
        }
    }
    Ok(())
}

fn extract_zip(archive: &Path, destination: &Path) -> Result<(), EngineInstallError> {
    let source = File::open(archive)?;
    let mut archive = zip::ZipArchive::new(source)
        .map_err(|error| EngineInstallError::ExtractionFailed(error.to_string()))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(EngineInstallError::ExtractionFailed(
            "归档条目数量超过安全上限".to_owned(),
        ));
    }
    let mut paths = HashSet::new();
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| EngineInstallError::ExtractionFailed(error.to_string()))?;
        if entry.name().contains('\\') || entry.name().contains('\0') {
            return Err(EngineInstallError::ExtractionFailed(
                "ZIP 条目路径无效".to_owned(),
            ));
        }
        let relative = safe_archive_path(Path::new(entry.name()))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let output = destination.join(&relative);
        if entry.is_dir() {
            fs::create_dir_all(&output)?;
            continue;
        }
        if !entry.is_file() || entry.is_symlink() {
            return Err(EngineInstallError::ExtractionFailed(format!(
                "ZIP 条目 {} 不是普通文件，已拒绝符号链接",
                relative.display()
            )));
        }
        if !paths.insert(relative.clone()) {
            return Err(EngineInstallError::ExtractionFailed(format!(
                "归档包含重复文件：{}",
                relative.display()
            )));
        }
        let size = entry.size();
        add_extracted_size(&mut total_bytes, size)?;
        write_archive_file(&mut entry, &output, size)?;
    }
    Ok(())
}

fn safe_archive_path(path: &Path) -> Result<PathBuf, EngineInstallError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => normalized.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(EngineInstallError::ExtractionFailed(format!(
                    "归档路径试图逃逸安装目录：{}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}

fn add_extracted_size(total: &mut u64, size: u64) -> Result<(), EngineInstallError> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| EngineInstallError::ExtractionFailed("归档解压大小溢出".to_owned()))?;
    if *total > MAX_EXTRACTED_BYTES {
        return Err(EngineInstallError::ExtractionFailed(
            "归档解压总大小超过 8 GiB 安全上限".to_owned(),
        ));
    }
    Ok(())
}

fn add_managed_engine_size(total: &mut u64, size: u64) -> Result<(), EngineInstallError> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| EngineInstallError::RegistryCorrupt("受管引擎目录大小溢出".to_owned()))?;
    if *total > MAX_MANAGED_ENGINE_BYTES {
        return Err(EngineInstallError::RegistryCorrupt(
            "受管引擎目录超过 64 GiB 安全上限".to_owned(),
        ));
    }
    Ok(())
}

fn write_archive_file(
    source: &mut impl Read,
    output: &Path,
    expected_size: u64,
) -> Result<(), EngineInstallError> {
    let parent = output
        .parent()
        .ok_or_else(|| EngineInstallError::ExtractionFailed("归档文件缺少父目录".to_owned()))?;
    fs::create_dir_all(parent)?;
    let mut target = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)?;
    let copied = std::io::copy(source, &mut target)?;
    if copied != expected_size {
        return Err(EngineInstallError::ExtractionFailed(format!(
            "归档条目 {} 声明大小 {expected_size}，实际解压 {copied}",
            output.display()
        )));
    }
    target.sync_all()?;
    Ok(())
}

fn find_engine_executable(root: &Path, name: EngineName) -> Result<PathBuf, EngineInstallError> {
    find_file_recursive(root, name.executable_names(), 6)?.ok_or_else(|| {
        EngineInstallError::ExtractionFailed(format!("归档中没有 {name} 可执行文件"))
    })
}

fn find_file_recursive(
    root: &Path,
    candidates: &[&str],
    depth: u8,
) -> Result<Option<PathBuf>, EngineInstallError> {
    if depth == 0 {
        return Ok(None);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        if metadata.is_symlink() {
            continue;
        }
        let path = entry.path();
        if metadata.is_file()
            && path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| candidates.contains(&value))
        {
            return Ok(Some(path));
        }
        if metadata.is_dir() {
            if let Some(found) = find_file_recursive(&path, candidates, depth - 1)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

fn make_executable(path: &Path) -> Result<(), EngineInstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, EngineInstallError> {
    let file = File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn build_engine_manifest(root: &Path) -> Result<Vec<EngineFileIntegrity>, EngineInstallError> {
    let canonical_root = fs::canonicalize(root)?;
    let mut directories = vec![canonical_root.clone()];
    let mut files = Vec::new();
    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            entries = entries.checked_add(1).ok_or_else(|| {
                EngineInstallError::RegistryCorrupt("引擎目录条目数量溢出".to_owned())
            })?;
            if entries > MAX_ARCHIVE_ENTRIES {
                return Err(EngineInstallError::RegistryCorrupt(
                    "引擎目录条目超过安全上限".to_owned(),
                ));
            }
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(EngineInstallError::RegistryCorrupt(format!(
                    "引擎目录包含符号链接：{}",
                    path.display()
                )));
            }
            if file_type.is_dir() {
                directories.push(path);
                continue;
            }
            if !file_type.is_file() {
                return Err(EngineInstallError::RegistryCorrupt(format!(
                    "引擎目录包含非普通文件：{}",
                    path.display()
                )));
            }
            let metadata = entry.metadata()?;
            add_managed_engine_size(&mut total_bytes, metadata.len())?;
            let relative_path = path
                .strip_prefix(&canonical_root)
                .map_err(|_| {
                    EngineInstallError::RegistryCorrupt(format!(
                        "引擎目录文件逃逸根目录：{}",
                        path.display()
                    ))
                })?
                .to_path_buf();
            files.push(EngineFileIntegrity {
                relative_path,
                size_bytes: metadata.len(),
                sha256: sha256_file(&path)?,
            });
        }
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(files)
}

fn path_entry_exists(path: &Path) -> Result<bool, EngineInstallError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(EngineInstallError::Io(error)),
    }
}

fn acquire_install_lock(parent: &Path, target: &str) -> Result<File, EngineInstallError> {
    validate_path_segment(target)?;
    let path = parent.join(format!(".{target}.install.lock"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "引擎安装锁不是受管普通文件：{}",
                path.display()
            )));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(EngineInstallError::Io(error)),
    }
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let lock = options.open(path)?;
    FileExt::lock_exclusive(&lock)?;
    Ok(lock)
}

fn ensure_managed_directory_chain(
    canonical_root: &Path,
    segments: &[&str],
) -> Result<PathBuf, EngineInstallError> {
    let mut current = canonical_root.to_path_buf();
    for segment in segments {
        validate_path_segment(segment)?;
        let candidate = current.join(segment);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(EngineInstallError::RegistryCorrupt(format!(
                        "受管引擎目录链包含链接或非目录：{}",
                        candidate.display()
                    )));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&candidate)?;
            }
            Err(error) => return Err(EngineInstallError::Io(error)),
        }
        let canonical = fs::canonicalize(&candidate)?;
        if canonical != candidate || !canonical.starts_with(canonical_root) {
            return Err(EngineInstallError::RegistryCorrupt(format!(
                "受管引擎目录链逃逸根目录：{}",
                candidate.display()
            )));
        }
        current = canonical;
    }
    Ok(current)
}

fn copy_file_create_new(source: &Path, destination: &Path) -> Result<(), EngineInstallError> {
    let mut source = File::open(source)?;
    copy_open_file_create_new(&mut source, destination)
}

fn copy_open_file_create_new(
    source: &mut File,
    destination: &Path,
) -> Result<(), EngineInstallError> {
    source.rewind()?;
    let mut destination = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)?;
    std::io::copy(source, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), EngineInstallError> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn validate_version(value: &str) -> Result<(), EngineInstallError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(EngineInstallError::InvalidVersion);
    }
    Ok(())
}

fn validate_path_segment(value: &str) -> Result<(), EngineInstallError> {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.chars().any(|character| {
            matches!(character, '/' | '\\' | '\0' | '\n' | '\r') || character.is_control()
        })
    {
        return Err(EngineInstallError::RegistryCorrupt(format!(
            "不安全的路径段：{value:?}"
        )));
    }
    Ok(())
}

fn target_triple() -> String {
    format!("{}-{}", env::consts::OS, env::consts::ARCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine(
        root: &Path,
        version: &str,
        installed_at_unix: i64,
    ) -> Result<InstalledEngine, EngineInstallError> {
        let target = target_triple();
        let directory = root
            .join(EngineName::LlamaCpp.as_str())
            .join(version)
            .join(&target);
        fs::create_dir_all(&directory)?;
        let executable = directory.join("llama-server");
        fs::write(&executable, format!("trusted-engine-{version}"))?;
        let directory = fs::canonicalize(directory)?;
        let executable = fs::canonicalize(executable)?;
        let files = build_engine_manifest(&directory)?;
        Ok(InstalledEngine {
            id: Uuid::now_v7(),
            name: EngineName::LlamaCpp,
            version: version.to_owned(),
            target,
            directory,
            sha256: sha256_file(&executable)?,
            files,
            executable,
            installed_at_unix,
            source: "unit-test".to_owned(),
        })
    }

    #[test]
    fn parses_engine_names_and_rejects_unknown() {
        assert_eq!(
            EngineName::from_str("llama.cpp").ok(),
            Some(EngineName::LlamaCpp)
        );
        assert_eq!(EngineName::from_str("vllm").ok(), Some(EngineName::Vllm));
        assert!(EngineName::from_str("fake").is_err());
    }

    #[test]
    fn release_asset_has_current_target_mapping() {
        assert!(release_asset_selector().is_some());
    }

    #[test]
    fn validates_release_digest_and_checksum_lines() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_sha256_digest(&format!("sha256:{digest}")),
            Some(digest.clone())
        );
        assert_eq!(
            parse_checksum_line(&format!("{digest}  llama.tar.gz"), "llama.tar.gz"),
            Some(digest)
        );
        assert_eq!(parse_sha256_digest("sha256:bad"), None);
        assert!(validate_path_segment("llama-bin.tar.gz").is_ok());
        assert!(validate_path_segment("../llama-bin.tar.gz").is_err());
        assert!("prefix-bin-macos-arm64.tar.gz".ends_with("bin-macos-arm64.tar.gz"));
        assert!(!"bin-macos-arm64.tar.gz.sig".ends_with("bin-macos-arm64.tar.gz"));
        assert!(parse_https_url("https://github.com/file.tar.gz").is_ok());
        assert!(parse_https_url("http://github.com/file.tar.gz").is_err());
    }

    #[test]
    fn registry_requires_installed_executable_for_default() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let registry = EngineRegistry::new(temp.path().join("engines.json"));
        assert!(matches!(
            registry.set_default(EngineName::LlamaCpp),
            Err(EngineInstallError::NotInstalled(_))
        ));
    }

    #[test]
    fn registry_rejects_tampered_engine_binary() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let installed = create_test_engine(temp.path(), "test", 1);
        assert!(installed.is_ok());
        let Ok(installed) = installed else { return };
        let canonical_executable = installed.executable.clone();
        let registry = EngineRegistry::new(temp.path().join("engines.json"));
        assert!(registry.upsert(installed).is_ok());
        assert!(registry.set_default(EngineName::LlamaCpp).is_ok());
        assert!(fs::write(&canonical_executable, b"tampered-binary").is_ok());
        assert!(matches!(
            registry.set_default(EngineName::LlamaCpp),
            Err(EngineInstallError::ChecksumMismatch { .. })
        ));
        assert!(matches!(
            registry.default(),
            Err(EngineInstallError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn registry_rejects_tampered_engine_support_library() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let installed = create_test_engine(temp.path(), "b1", 1);
        assert!(installed.is_ok());
        let Ok(mut installed) = installed else { return };
        let library = installed.directory.join("libggml.dylib");
        assert!(fs::write(&library, b"trusted-library").is_ok());
        installed.files = build_engine_manifest(&installed.directory).unwrap_or_default();
        let registry = EngineRegistry::new(temp.path().join("index.json"));
        assert!(registry.upsert(installed).is_ok());
        assert!(registry.set_default(EngineName::LlamaCpp).is_ok());
        assert!(fs::write(&library, b"tampered-library").is_ok());
        assert!(matches!(
            registry.latest(EngineName::LlamaCpp),
            Err(EngineInstallError::RegistryCorrupt(message)) if message.contains("文件清单")
        ));
    }

    #[test]
    fn registry_selects_latest_version_not_first_or_most_recent_install() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let registry = EngineRegistry::new(temp.path().join("index.json"));
        let newer_install_of_old_version = create_test_engine(temp.path(), "b9", 999);
        let latest_version = create_test_engine(temp.path(), "b10", 1);
        assert!(newer_install_of_old_version.is_ok() && latest_version.is_ok());
        let (Ok(old), Ok(latest)) = (newer_install_of_old_version, latest_version) else {
            return;
        };
        assert!(registry.upsert(old).is_ok());
        assert!(registry.upsert(latest).is_ok());
        assert!(
            matches!(registry.latest(EngineName::LlamaCpp), Ok(engine) if engine.version == "b10")
        );
        assert!(
            matches!(registry.set_default(EngineName::LlamaCpp), Ok(engine) if engine.version == "b10")
        );
        assert!(matches!(registry.default(), Ok(Some(engine)) if engine.version == "b10"));
        assert_eq!(compare_versions("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(compare_versions("1.0.0", "1.0.0-rc.10"), Ordering::Greater);
        assert_eq!(
            compare_versions("1.0.0-rc.10", "1.0.0-rc.2"),
            Ordering::Greater
        );
    }

    #[test]
    fn registry_exact_version_is_not_shadowed_by_a_newer_install() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let registry = EngineRegistry::new(temp.path().join("index.json"));
        let audited = create_test_engine(temp.path(), "b10064", 1);
        let newer = create_test_engine(temp.path(), "b10065", 2);
        assert!(audited.is_ok() && newer.is_ok());
        let (Ok(audited), Ok(newer)) = (audited, newer) else {
            return;
        };
        assert!(registry.upsert(audited).is_ok());
        assert!(registry.upsert(newer).is_ok());
        assert!(
            matches!(registry.latest(EngineName::LlamaCpp), Ok(engine) if engine.version == "b10065")
        );
        assert!(
            matches!(registry.version(EngineName::LlamaCpp, "b10064"), Ok(engine) if engine.version == "b10064")
        );
        assert!(
            matches!(registry.set_default_version(EngineName::LlamaCpp, "b10064"), Ok(engine) if engine.version == "b10064")
        );
        assert_eq!(
            registry.configured_default().ok(),
            Some(Some(EngineName::LlamaCpp))
        );
    }

    #[test]
    fn registry_rejects_external_executable_from_tampered_json() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let outside = tempfile::tempdir();
        assert!(outside.is_ok());
        let (Ok(temp), Ok(outside)) = (temp, outside) else {
            return;
        };
        let outside_directory = outside
            .path()
            .join("llama.cpp")
            .join("b99")
            .join(target_triple());
        assert!(fs::create_dir_all(&outside_directory).is_ok());
        let outside_executable = outside_directory.join("llama-server");
        assert!(fs::write(&outside_executable, b"external").is_ok());
        let checksum = sha256_file(&outside_executable);
        assert!(checksum.is_ok());
        let Ok(checksum) = checksum else { return };
        let files = build_engine_manifest(&outside_directory).unwrap_or_default();
        let canonical_directory = fs::canonicalize(&outside_directory).unwrap_or(outside_directory);
        let canonical_executable =
            fs::canonicalize(&outside_executable).unwrap_or(outside_executable);
        let record = InstalledEngine {
            id: Uuid::now_v7(),
            name: EngineName::LlamaCpp,
            version: "b99".to_owned(),
            target: target_triple(),
            directory: canonical_directory,
            executable: canonical_executable,
            sha256: checksum,
            files,
            installed_at_unix: 1,
            source: "tampered-registry".to_owned(),
        };
        let data = EngineRegistryData {
            version: 1,
            default: Some(EngineName::LlamaCpp),
            engines: vec![record],
        };
        assert!(fs::write(
            temp.path().join("index.json"),
            serde_json::to_vec(&data).unwrap_or_default()
        )
        .is_ok());
        let registry = EngineRegistry::new(temp.path().join("index.json"));
        assert!(matches!(
            registry.latest(EngineName::LlamaCpp),
            Err(EngineInstallError::RegistryCorrupt(_))
        ));
        assert!(matches!(
            registry.default(),
            Err(EngineInstallError::RegistryCorrupt(_))
        ));
    }

    #[test]
    fn existing_unregistered_directory_is_never_adopted() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let target = target_triple();
        let directory = temp
            .path()
            .join(EngineName::LlamaCpp.as_str())
            .join("b1")
            .join(&target);
        assert!(fs::create_dir_all(&directory).is_ok());
        assert!(fs::write(directory.join("llama-server"), b"attacker-controlled").is_ok());
        let directory = fs::canonicalize(directory);
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let registry = EngineRegistry::new(temp.path().join("index.json"));
        assert!(matches!(
            registry.exact(EngineName::LlamaCpp, "b1", &target, &directory),
            Err(EngineInstallError::RegistryCorrupt(message)) if message.contains("没有可信登记")
        ));
    }

    #[test]
    fn cache_reuses_valid_file_and_removes_only_corrupt_regular_file() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let archive = temp.path().join("llama.tar.gz");
        assert!(fs::write(&archive, b"trusted archive").is_ok());
        let checksum = sha256_file(&archive);
        assert!(checksum.is_ok());
        let Ok(checksum) = checksum else { return };
        assert!(matches!(
            prepare_cached_asset(&archive, &checksum),
            Ok(true)
        ));
        assert!(archive.is_file());
        assert!(fs::write(&archive, b"corrupt archive").is_ok());
        assert!(matches!(
            prepare_cached_asset(&archive, &checksum),
            Ok(false)
        ));
        assert!(!archive.exists());
    }

    #[cfg(unix)]
    #[test]
    fn managed_directory_chain_and_cache_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir();
        let outside = tempfile::tempdir();
        assert!(temp.is_ok() && outside.is_ok());
        let (Ok(temp), Ok(outside)) = (temp, outside) else {
            return;
        };
        assert!(symlink(outside.path(), temp.path().join("llama.cpp")).is_ok());
        assert!(matches!(
            ensure_managed_directory_chain(temp.path(), &["llama.cpp", "b1"]),
            Err(EngineInstallError::RegistryCorrupt(_))
        ));
        let cache_link = temp.path().join("cache.tar.gz");
        let outside_file = outside.path().join("outside.bin");
        assert!(fs::write(&outside_file, b"outside").is_ok());
        assert!(symlink(&outside_file, &cache_link).is_ok());
        assert!(matches!(
            prepare_cached_asset(&cache_link, &"0".repeat(64)),
            Err(EngineInstallError::RegistryCorrupt(_))
        ));
        assert!(outside_file.is_file());
    }

    #[test]
    fn external_adapters_require_complete_platform_backend_and_runtime() {
        let cuda = HardwareProfile {
            os: "Linux".to_owned(),
            os_version: "test".to_owned(),
            kernel_version: "test".to_owned(),
            architecture: "x86_64".to_owned(),
            cpu_brand: "test".to_owned(),
            logical_cpu_count: 1,
            total_memory_bytes: 1,
            gpus: Vec::new(),
            metal_available: false,
            cuda_available: true,
            nvidia_driver_version: Some("575.57.08".to_owned()),
            cuda_driver_version: Some("12.9".to_owned()),
            recommended_backend: "cuda".to_owned(),
        };
        for name in [
            EngineName::Vllm,
            EngineName::Ollama,
            EngineName::TensorrtLlm,
        ] {
            let capability = engine_capability_for(name, &cuda, "linux", "x86_64", true, true);
            assert!(capability.supported);
            assert!(capability.installed_binary.is_none());
            assert!(capability.reason.contains("官方") || capability.reason.contains("SHA-256"));
        }

        let mut cpu_only = cuda.clone();
        cpu_only.cuda_available = false;
        cpu_only.recommended_backend = "cpu".to_owned();
        let no_cuda =
            engine_capability_for(EngineName::Vllm, &cpu_only, "linux", "x86_64", true, true);
        assert!(!no_cuda.supported);
        assert!(no_cuda.reason.contains("未检测到可查询的 CUDA GPU runtime"));
        let wrong_platform = engine_capability_for(
            EngineName::TensorrtLlm,
            &cuda,
            "macos",
            "aarch64",
            true,
            true,
        );
        assert!(!wrong_platform.supported);
        assert!(wrong_platform.reason.contains("要求 Linux x86_64"));
        let no_docker =
            engine_capability_for(EngineName::Vllm, &cuda, "linux", "x86_64", true, false);
        assert!(!no_docker.supported);
        assert!(no_docker.reason.contains("/var/run/docker.sock"));
    }

    #[tokio::test]
    async fn unsupported_accelerator_engines_never_register_path_binaries() {
        let temp = tempfile::tempdir().expect("应创建临时目录");
        let engines = temp.path().join("engines");
        let cache = temp.path().join("cache");
        let installer = EngineInstaller::new(&engines, &cache, engines.join("index.json"))
            .expect("应创建引擎安装器");
        for name in [EngineName::Vllm, EngineName::TensorrtLlm] {
            assert!(matches!(
                installer.install(name, "latest").await,
                Err(EngineInstallError::Unsupported { engine, .. }) if engine == name
            ));
        }
        assert!(installer
            .registry()
            .list()
            .is_ok_and(|records| records.is_empty()));
    }

    #[test]
    fn ollama_assets_are_explicit_for_every_supported_platform() {
        assert_eq!(
            ollama_release_asset_selector("macos", "aarch64"),
            Some("ollama-darwin.tgz")
        );
        assert_eq!(
            ollama_release_asset_selector("linux", "x86_64"),
            Some("ollama-linux-amd64.tar.zst")
        );
        assert_eq!(
            ollama_release_asset_selector("linux", "aarch64"),
            Some("ollama-linux-arm64.tar.zst")
        );
        assert_eq!(
            ollama_release_asset_selector("windows", "x86_64"),
            Some("ollama-windows-amd64.zip")
        );
        assert_eq!(
            ollama_release_asset_selector("windows", "aarch64"),
            Some("ollama-windows-arm64.zip")
        );
        assert!(ollama_release_asset_selector("freebsd", "x86_64").is_none());
    }

    #[test]
    fn llama_cpp_assets_are_explicit_for_macos_linux_and_windows() {
        assert_eq!(
            llama_cpp_release_asset_selector("macos", "aarch64"),
            Some("bin-macos-arm64.tar.gz")
        );
        assert_eq!(
            llama_cpp_release_asset_selector("macos", "x86_64"),
            Some("bin-macos-x64.tar.gz")
        );
        assert_eq!(
            llama_cpp_release_asset_selector("linux", "x86_64"),
            Some("bin-ubuntu-x64.tar.gz")
        );
        assert_eq!(
            llama_cpp_release_asset_selector("linux", "aarch64"),
            Some("bin-ubuntu-arm64.tar.gz")
        );
        assert_eq!(
            llama_cpp_release_asset_selector("windows", "x86_64"),
            Some("bin-win-cpu-x64.zip")
        );
        assert_eq!(
            llama_cpp_release_asset_selector("windows", "aarch64"),
            Some("bin-win-cpu-arm64.zip")
        );
        assert!(llama_cpp_release_asset_selector("freebsd", "x86_64").is_none());
    }

    #[test]
    fn oci_manifest_selection_requires_exact_platform_sha256() {
        let manifest = r#"[
          {"Descriptor":{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"architecture":"arm64","os":"linux"}}},
          {"Descriptor":{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"architecture":"amd64","os":"linux"}}}
        ]"#;
        assert_eq!(
            select_container_digest(manifest, "linux", "amd64").ok(),
            Some(format!("sha256:{}", "b".repeat(64)))
        );
        assert!(select_container_digest(manifest, "linux", "s390x").is_err());
        assert!(select_container_digest(
            r#"[{"Descriptor":{"digest":"sha256:bad","platform":{"architecture":"amd64","os":"linux"}}}]"#,
            "linux",
            "amd64"
        )
        .is_err());
    }

    #[test]
    fn container_registry_rejects_insecure_or_mirrored_sources() {
        assert!(ensure_secure_registry_config(
            r#"{"docker.io":{"Secure":true,"Mirrors":[]}}"#,
            "docker.io",
            EngineName::Vllm
        )
        .is_ok());
        assert!(ensure_secure_registry_config(
            r#"{"docker.io":{"Secure":false,"Mirrors":[]}}"#,
            "docker.io",
            EngineName::Vllm
        )
        .is_err());
        assert!(ensure_secure_registry_config(
            r#"{"docker.io":{"Secure":true,"Mirrors":["http://mirror.invalid"]}}"#,
            "docker.io",
            EngineName::Vllm
        )
        .is_err());
    }

    #[test]
    fn container_runtime_binary_must_be_root_owned_and_not_writable_by_others() {
        assert!(trusted_container_runtime_permissions(0, 0o100755));
        assert!(trusted_container_runtime_permissions(0, 0o100700));
        assert!(!trusted_container_runtime_permissions(501, 0o100755));
        assert!(!trusted_container_runtime_permissions(0, 0o100775));
        assert!(!trusted_container_runtime_permissions(0, 0o100757));
    }

    #[cfg(unix)]
    #[test]
    fn container_launcher_and_bundle_are_digest_pinned_and_fully_manifested() {
        let temp = tempfile::tempdir().expect("应创建临时目录");
        let bundle = temp.path().join("engine-image.tar");
        let launcher = temp.path().join("vllm");
        let metadata = temp.path().join("engine.json");
        let digest = format!("sha256:{}", "a".repeat(64));
        let image = format!("docker.io/vllm/vllm-openai@{digest}");
        assert!(fs::write(&bundle, b"content-addressed-image-bundle").is_ok());
        assert!(write_container_launcher(
            &launcher,
            Path::new("/usr/bin/docker"),
            &image,
            &bundle,
            "vllm"
        )
        .is_ok());
        let record = ContainerEngineMetadata {
            schema_version: 1,
            engine: EngineName::Vllm,
            release: "v0.25.1".to_owned(),
            image: image.clone(),
            manifest_digest: digest,
            bundle_sha256: sha256_file(&bundle).unwrap_or_default(),
            runtime: PathBuf::from("/usr/bin/docker"),
            docker_socket: DOCKER_SOCKET.to_owned(),
        };
        assert!(write_json_create_new(&metadata, &record).is_ok());
        let script = fs::read_to_string(&launcher).unwrap_or_default();
        assert!(script.contains("/usr/bin/docker"));
        assert!(script.contains(&image));
        assert!(script.contains("engine-image.tar"));
        assert!(!script.contains("--network host"));
        assert!(!script.contains("$PATH"));
        let manifest = build_engine_manifest(temp.path()).unwrap_or_default();
        assert_eq!(manifest.len(), 3);
        assert!(manifest
            .iter()
            .any(|file| file.relative_path == Path::new("engine-image.tar")));
        assert!(manifest
            .iter()
            .any(|file| file.relative_path == Path::new("engine.json")));
        assert!(manifest
            .iter()
            .any(|file| file.relative_path == Path::new("vllm")));
    }

    #[test]
    fn archive_paths_cannot_escape_install_directory() {
        assert!(safe_archive_path(Path::new("llama/bin/llama-server")).is_ok());
        assert!(safe_archive_path(Path::new("./llama/bin")).is_ok());
        assert!(safe_archive_path(Path::new("../outside")).is_err());
        assert!(safe_archive_path(Path::new("llama/../../outside")).is_err());
        assert!(safe_archive_path(Path::new("/absolute/path")).is_err());
    }

    #[test]
    fn tar_extraction_rejects_escaping_symbolic_links() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let archive_path = temp.path().join("engine.tar.gz");
        let destination = temp.path().join("destination");
        assert!(fs::create_dir_all(&destination).is_ok());
        let archive_file = File::create(&archive_path);
        assert!(archive_file.is_ok());
        let Ok(archive_file) = archive_file else {
            return;
        };
        let encoder = flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        assert!(header.set_link_name("../outside").is_ok());
        header.set_cksum();
        assert!(builder
            .append_data(&mut header, "llama-link", &[][..])
            .is_ok());
        assert!(builder
            .into_inner()
            .and_then(|encoder| encoder.finish())
            .is_ok());

        assert!(matches!(
            extract_tar_gz(&archive_path, &destination),
            Err(EngineInstallError::ExtractionFailed(message))
                if message.contains("试图逃逸")
        ));
        assert!(!temp.path().join("outside").exists());
    }

    #[test]
    fn tar_extraction_materializes_safe_internal_symlink_as_regular_file() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let archive_path = temp.path().join("engine.tar.gz");
        let destination = temp.path().join("destination");
        assert!(fs::create_dir_all(&destination).is_ok());
        let archive_file = File::create(&archive_path);
        assert!(archive_file.is_ok());
        let Ok(archive_file) = archive_file else {
            return;
        };
        let encoder = flate2::write::GzEncoder::new(archive_file, flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let payload = b"trusted-library";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(payload.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        assert!(builder
            .append_data(&mut file_header, "lib/real.dylib", &payload[..])
            .is_ok());
        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Symlink);
        link_header.set_size(0);
        assert!(link_header.set_link_name("real.dylib").is_ok());
        link_header.set_cksum();
        assert!(builder
            .append_data(&mut link_header, "lib/link.dylib", &[][..])
            .is_ok());
        assert!(builder
            .into_inner()
            .and_then(|encoder| encoder.finish())
            .is_ok());

        assert!(extract_tar_gz(&archive_path, &destination).is_ok());
        let materialized = destination.join("lib/link.dylib");
        assert!(
            matches!(fs::symlink_metadata(&materialized), Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink())
        );
        assert!(matches!(fs::read(materialized), Ok(bytes) if bytes == payload));
    }
}
