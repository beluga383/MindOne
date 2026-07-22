use crate::validation::{
    parse_gguf_split_filename, validate_gguf_split_reports, validate_model, GgufSplitInfo,
    ModelFormat, ValidationError, ValidationReport,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelArtifactRecord {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub modified_unix: i64,
    pub gguf_split: GgufSplitInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRecord {
    pub id: Uuid,
    pub name: String,
    pub format: ModelFormat,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub modified_unix: i64,
    pub verified_at_unix: i64,
    pub compatible_engines: Vec<String>,
    /// 分片 GGUF 的完整、有序文件集合。旧版单文件登记保持为空；非空时第一项
    /// 必须是 `00001` 主分片，`sha256` 是绑定全部分片路径/大小/哈希的包摘要。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ModelArtifactRecord>,
}

impl ModelRecord {
    pub fn verification_is_current(&self) -> bool {
        if !self.artifacts.is_empty() {
            return verify_bundle_record(self).is_ok();
        }
        // 大小和 mtime 都可以被保留或恢复，不能作为模型内容未变化的安全证据。
        // 每次需要信任旧验证结果时重新检查结构并核对已登记的 SHA-256。
        matches!(
            validate_model(&self.path, Some(&self.sha256)),
            Ok(report)
                if report.format == self.format
                    && report.size_bytes == self.size_bytes
                    && report.compatible_engines == self.compatible_engines
        )
    }

    pub fn verification_is_current_in(&self, models_root: &Path) -> bool {
        ensure_managed_path(&self.path, models_root).is_ok()
            && self
                .artifact_paths()
                .iter()
                .all(|path| ensure_managed_path(path, models_root).is_ok())
            && self.verification_is_current()
    }

    pub fn artifact_paths(&self) -> Vec<PathBuf> {
        if self.artifacts.is_empty() {
            vec![self.path.clone()]
        } else {
            self.artifacts
                .iter()
                .map(|artifact| artifact.path.clone())
                .collect()
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RegistryData {
    version: u32,
    models: Vec<ModelRecord>,
}

#[derive(Debug, Clone)]
pub struct ModelRegistry {
    path: PathBuf,
    lock_path: PathBuf,
}

#[derive(Debug, Error)]
pub enum ModelRegistryError {
    #[error("模型名称无效；仅允许字母、数字、点、下划线和连字符")]
    InvalidName,
    #[error("模型路径不在受管 models 目录中：{0}")]
    OutsideManagedDirectory(PathBuf),
    #[error("模型名称已存在：{0}")]
    DuplicateName(String),
    #[error("未找到模型：{0}")]
    NotFound(String),
    #[error("模型仍在使用中，拒绝删除：{0}")]
    InUse(String),
    #[error("模型安全校验失败：{0}")]
    Validation(#[from] ValidationError),
    #[error("模型登记文件损坏：{0}")]
    Corrupt(String),
    #[error("模型登记操作失败：{0}")]
    Io(#[from] std::io::Error),
}

impl ModelRegistry {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock_path = path.with_extension("lock");
        Self { path, lock_path }
    }

    pub fn list(&self) -> Result<Vec<ModelRecord>, ModelRegistryError> {
        let models_root = self.managed_root()?;
        self.with_lock(false, |data| {
            for model in &data.models {
                validate_registry_record(model, &models_root)?;
            }
            Ok(data.models.clone())
        })
    }

    pub fn find(&self, name_or_id: &str) -> Result<ModelRecord, ModelRegistryError> {
        let models_root = self.managed_root()?;
        self.with_lock(false, |data| {
            let record = data
                .models
                .iter()
                .find(|model| model.name == name_or_id || model.id.to_string() == name_or_id)
                .cloned()
                .ok_or_else(|| ModelRegistryError::NotFound(name_or_id.to_owned()))?;
            validate_registry_record(&record, &models_root)?;
            Ok(record)
        })
    }

    pub fn find_by_managed_path(
        &self,
        path: &Path,
        models_root: &Path,
    ) -> Result<ModelRecord, ModelRegistryError> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ModelRegistryError::OutsideManagedDirectory(
                path.to_path_buf(),
            ));
        }
        let canonical = fs::canonicalize(path)?;
        ensure_managed_path(&canonical, models_root)?;
        let managed_root = self.managed_root()?;
        self.with_lock(false, |data| {
            let record = data
                .models
                .iter()
                .find(|model| model.path == canonical)
                .cloned()
                .ok_or_else(|| ModelRegistryError::NotFound(canonical.display().to_string()))?;
            validate_registry_record(&record, &managed_root)?;
            Ok(record)
        })
    }

    pub fn register(
        &self,
        name: &str,
        report: ValidationReport,
        models_root: &Path,
    ) -> Result<ModelRecord, ModelRegistryError> {
        validate_name(name)?;
        if report.gguf_split.is_some() {
            return Err(ModelRegistryError::Validation(
                ValidationError::InvalidGguf(
                    "检测到分片 GGUF；必须下载并验证完整分片集合后登记".to_owned(),
                ),
            ));
        }
        ensure_managed_path(&report.path, models_root)?;
        self.with_lock(true, |data| {
            if data.models.iter().any(|model| model.name == name) {
                return Err(ModelRegistryError::DuplicateName(name.to_owned()));
            }
            let record = record_from_report(Uuid::now_v7(), name, report);
            data.models.push(record.clone());
            Ok(record)
        })
    }

    pub fn register_bundle(
        &self,
        name: &str,
        reports: Vec<ValidationReport>,
        models_root: &Path,
    ) -> Result<ModelRecord, ModelRegistryError> {
        validate_name(name)?;
        for report in &reports {
            ensure_managed_path(&report.path, models_root)?;
        }
        let record = record_from_reports(Uuid::now_v7(), name, reports)?;
        self.with_lock(true, |data| {
            if data.models.iter().any(|model| model.name == name) {
                return Err(ModelRegistryError::DuplicateName(name.to_owned()));
            }
            data.models.push(record.clone());
            Ok(record)
        })
    }

    pub fn reverify(
        &self,
        name_or_id: &str,
        models_root: &Path,
    ) -> Result<ModelRecord, ModelRegistryError> {
        let current = self.find(name_or_id)?;
        for path in current.artifact_paths() {
            ensure_managed_path(&path, models_root)?;
        }
        // `verify` 只能重新确认已登记的可信内容，不能把被替换后的任意新权重
        // 当成新的信任根并覆盖旧 SHA-256。采用新权重必须走显式下载/导入流程，
        // 同时提供独立可信 checksum。
        let refreshed = if current.artifacts.is_empty() {
            record_from_report(
                current.id,
                &current.name,
                validate_model(&current.path, Some(&current.sha256))?,
            )
        } else {
            let reports = verify_bundle_record(&current)?;
            record_from_reports(current.id, &current.name, reports)?
        };
        self.with_lock(true, |data| {
            let record = data
                .models
                .iter_mut()
                .find(|model| model.id == current.id)
                .ok_or_else(|| ModelRegistryError::NotFound(name_or_id.to_owned()))?;
            *record = refreshed;
            Ok(record.clone())
        })
    }

    pub fn delete(
        &self,
        name_or_id: &str,
        models_root: &Path,
        is_in_use: bool,
    ) -> Result<ModelRecord, ModelRegistryError> {
        if is_in_use {
            return Err(ModelRegistryError::InUse(name_or_id.to_owned()));
        }
        let current = self.find(name_or_id)?;
        if !current.artifacts.is_empty() {
            return self.delete_bundle_record(name_or_id, current, models_root);
        }
        ensure_managed_path(&current.path, models_root)?;
        let metadata = fs::symlink_metadata(&current.path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ModelRegistryError::OutsideManagedDirectory(
                current.path.clone(),
            ));
        }
        let parent = current
            .path
            .parent()
            .ok_or_else(|| ModelRegistryError::OutsideManagedDirectory(current.path.clone()))?;
        let quarantine = parent.join(format!(".mindone-delete-{}.tmp", current.id));
        if quarantine.exists() {
            return Err(ModelRegistryError::Corrupt(format!(
                "发现未完成的模型删除：{}",
                quarantine.display()
            )));
        }
        fs::rename(&current.path, &quarantine)?;
        let registry_result = self.with_lock(true, |data| {
            let position = data.models.iter().position(|model| model.id == current.id);
            let Some(position) = position else {
                return Err(ModelRegistryError::NotFound(name_or_id.to_owned()));
            };
            Ok(data.models.remove(position))
        });
        let removed = match registry_result {
            Ok(removed) => removed,
            Err(error) => {
                fs::rename(&quarantine, &current.path)?;
                return Err(error);
            }
        };
        if let Err(delete_error) = fs::remove_file(&quarantine) {
            fs::rename(&quarantine, &current.path)?;
            self.with_lock(true, |data| {
                if !data.models.iter().any(|model| model.id == current.id) {
                    data.models.push(current.clone());
                }
                Ok(())
            })?;
            return Err(ModelRegistryError::Io(delete_error));
        }
        sync_directory(parent)?;
        Ok(removed)
    }

    fn delete_bundle_record(
        &self,
        name_or_id: &str,
        current: ModelRecord,
        models_root: &Path,
    ) -> Result<ModelRecord, ModelRegistryError> {
        for path in current.artifact_paths() {
            ensure_managed_path(&path, models_root)?;
        }
        let bundle_directory = current
            .path
            .parent()
            .ok_or_else(|| ModelRegistryError::OutsideManagedDirectory(current.path.clone()))?;
        let canonical_root = fs::canonicalize(models_root)?;
        let canonical_bundle = fs::canonicalize(bundle_directory)?;
        let bundle_metadata = fs::symlink_metadata(bundle_directory)?;
        if bundle_metadata.file_type().is_symlink()
            || !bundle_metadata.is_dir()
            || canonical_bundle == canonical_root
            || canonical_bundle.parent() != Some(canonical_root.as_path())
        {
            return Err(ModelRegistryError::OutsideManagedDirectory(
                canonical_bundle,
            ));
        }
        let expected = current
            .artifacts
            .iter()
            .filter_map(|artifact| artifact.path.file_name().map(|value| value.to_owned()))
            .collect::<BTreeSet<_>>();
        if expected.len() != current.artifacts.len() {
            return Err(ModelRegistryError::Corrupt(format!(
                "模型包 {} 的文件名重复或缺失",
                current.name
            )));
        }
        let mut observed = BTreeSet::new();
        for entry in fs::read_dir(&canonical_bundle)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || fs::canonicalize(&path)? != path
                || !expected.contains(&entry.file_name())
            {
                return Err(ModelRegistryError::Corrupt(format!(
                    "模型包目录包含未登记或不安全的条目：{}",
                    path.display()
                )));
            }
            observed.insert(entry.file_name());
        }
        if observed != expected {
            return Err(ModelRegistryError::Corrupt(format!(
                "模型包 {} 的分片集合不完整",
                current.name
            )));
        }
        let quarantine = canonical_root.join(format!(".mindone-delete-{}.bundle.tmp", current.id));
        if quarantine.exists() {
            return Err(ModelRegistryError::Corrupt(format!(
                "发现未完成的模型包删除：{}",
                quarantine.display()
            )));
        }
        fs::rename(&canonical_bundle, &quarantine)?;
        let registry_result = self.with_lock(true, |data| {
            let position = data.models.iter().position(|model| model.id == current.id);
            let Some(position) = position else {
                return Err(ModelRegistryError::NotFound(name_or_id.to_owned()));
            };
            Ok(data.models.remove(position))
        });
        let removed = match registry_result {
            Ok(removed) => removed,
            Err(error) => {
                fs::rename(&quarantine, &canonical_bundle)?;
                return Err(error);
            }
        };
        if let Err(delete_error) = fs::remove_dir_all(&quarantine) {
            fs::rename(&quarantine, &canonical_bundle)?;
            self.with_lock(true, |data| {
                if !data.models.iter().any(|model| model.id == current.id) {
                    data.models.push(current.clone());
                }
                Ok(())
            })?;
            return Err(ModelRegistryError::Io(delete_error));
        }
        sync_directory(&canonical_root)?;
        Ok(removed)
    }

    fn with_lock<T>(
        &self,
        write: bool,
        operation: impl FnOnce(&mut RegistryData) -> Result<T, ModelRegistryError>,
    ) -> Result<T, ModelRegistryError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
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

    fn read_data(&self) -> Result<RegistryData, ModelRegistryError> {
        if !self.path.exists() {
            return Ok(RegistryData {
                version: 1,
                models: Vec::new(),
            });
        }
        let mut file = File::open(&self.path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if bytes.is_empty() {
            return Ok(RegistryData {
                version: 1,
                models: Vec::new(),
            });
        }
        let data: RegistryData = serde_json::from_slice(&bytes)
            .map_err(|error| ModelRegistryError::Corrupt(error.to_string()))?;
        if data.version != 1 {
            return Err(ModelRegistryError::Corrupt(format!(
                "不支持 registry 版本 {}",
                data.version
            )));
        }
        Ok(data)
    }

    fn write_data(&self, data: &RegistryData) -> Result<(), ModelRegistryError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ModelRegistryError::Corrupt("registry 路径缺少父目录".to_owned()))?;
        let encoded = serde_json::to_vec_pretty(data)
            .map_err(|error| ModelRegistryError::Corrupt(error.to_string()))?;
        let mut temp = NamedTempFile::new_in(parent)?;
        temp.write_all(&encoded)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path)
            .map_err(|error| ModelRegistryError::Io(error.error))?;
        sync_directory(parent)?;
        Ok(())
    }

    fn managed_root(&self) -> Result<PathBuf, ModelRegistryError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ModelRegistryError::Corrupt("registry 路径缺少父目录".to_owned()))?;
        fs::create_dir_all(parent)?;
        Ok(fs::canonicalize(parent)?)
    }
}

fn record_from_report(id: Uuid, name: &str, report: ValidationReport) -> ModelRecord {
    ModelRecord {
        id,
        name: name.to_owned(),
        format: report.format,
        path: report.path,
        size_bytes: report.size_bytes,
        sha256: report.sha256,
        modified_unix: report.modified_unix,
        verified_at_unix: report.verified_at_unix,
        compatible_engines: report.compatible_engines,
        artifacts: Vec::new(),
    }
}

fn record_from_reports(
    id: Uuid,
    name: &str,
    reports: Vec<ValidationReport>,
) -> Result<ModelRecord, ModelRegistryError> {
    validate_bundle_reports(&reports)?;
    let primary = reports
        .first()
        .ok_or_else(|| ModelRegistryError::Corrupt("模型包没有主分片".to_owned()))?;
    let artifacts = reports
        .iter()
        .map(|report| {
            let gguf_split = report.gguf_split.ok_or_else(|| {
                ModelRegistryError::Corrupt(format!(
                    "模型包分片缺少 GGUF split 元数据：{}",
                    report.path.display()
                ))
            })?;
            Ok(ModelArtifactRecord {
                path: report.path.clone(),
                size_bytes: report.size_bytes,
                sha256: report.sha256.clone(),
                modified_unix: report.modified_unix,
                gguf_split,
            })
        })
        .collect::<Result<Vec<_>, ModelRegistryError>>()?;
    let size_bytes = artifacts.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.size_bytes)
            .ok_or_else(|| ModelRegistryError::Corrupt("模型包总大小溢出".to_owned()))
    })?;
    let verified_at_unix = reports
        .iter()
        .map(|report| report.verified_at_unix)
        .min()
        .unwrap_or(primary.verified_at_unix);
    Ok(ModelRecord {
        id,
        name: name.to_owned(),
        format: primary.format,
        path: primary.path.clone(),
        size_bytes,
        sha256: bundle_sha256(&artifacts),
        modified_unix: artifacts
            .iter()
            .map(|artifact| artifact.modified_unix)
            .max()
            .unwrap_or(primary.modified_unix),
        verified_at_unix,
        compatible_engines: primary.compatible_engines.clone(),
        artifacts,
    })
}

fn validate_bundle_reports(reports: &[ValidationReport]) -> Result<(), ModelRegistryError> {
    validate_gguf_split_reports(reports).map_err(ModelRegistryError::Validation)
}

fn verify_bundle_record(record: &ModelRecord) -> Result<Vec<ValidationReport>, ModelRegistryError> {
    validate_artifact_layout(record)?;
    let mut reports = Vec::with_capacity(record.artifacts.len());
    for artifact in &record.artifacts {
        let report = validate_model(&artifact.path, Some(&artifact.sha256))?;
        if report.size_bytes != artifact.size_bytes
            || report.gguf_split != Some(artifact.gguf_split)
        {
            return Err(ModelRegistryError::Corrupt(format!(
                "模型包分片登记与当前文件不一致：{}",
                artifact.path.display()
            )));
        }
        reports.push(report);
    }
    validate_bundle_reports(&reports)?;
    let rebuilt = record_from_reports(record.id, &record.name, reports.clone())?;
    if rebuilt.path != record.path
        || rebuilt.format != record.format
        || rebuilt.size_bytes != record.size_bytes
        || rebuilt.sha256 != record.sha256
        || rebuilt.compatible_engines != record.compatible_engines
    {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型包 {} 的聚合登记不一致",
            record.name
        )));
    }
    Ok(reports)
}

fn validate_artifact_layout(record: &ModelRecord) -> Result<(), ModelRegistryError> {
    if record.artifacts.is_empty() {
        return Ok(());
    }
    if record.format != ModelFormat::Gguf
        || record.compatible_engines != ModelFormat::Gguf.compatible_engines()
    {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型包 {} 的格式或兼容引擎登记无效",
            record.name
        )));
    }
    if record.artifacts.first().map(|artifact| &artifact.path) != Some(&record.path) {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型包 {} 的主路径不是第一分片",
            record.name
        )));
    }
    let expected_count = u16::try_from(record.artifacts.len())
        .map_err(|_| ModelRegistryError::Corrupt("模型包分片数量溢出".to_owned()))?;
    if !(2..=256).contains(&record.artifacts.len()) {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型包 {} 的分片数量无效",
            record.name
        )));
    }
    let parent = record
        .path
        .parent()
        .ok_or_else(|| ModelRegistryError::Corrupt(format!("模型包 {} 缺少父目录", record.name)))?;
    let mut prefix = None;
    let mut paths = BTreeSet::new();
    for (position, artifact) in record.artifacts.iter().enumerate() {
        if artifact.path.parent() != Some(parent)
            || artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ModelRegistryError::Corrupt(format!(
                "模型包 {} 的分片登记无效",
                record.name
            )));
        }
        let parsed = parse_gguf_split_filename(&artifact.path).ok_or_else(|| {
            ModelRegistryError::Corrupt(format!(
                "模型包分片文件名无效：{}",
                artifact.path.display()
            ))
        })?;
        let expected_index = u16::try_from(position + 1)
            .map_err(|_| ModelRegistryError::Corrupt("模型包分片编号溢出".to_owned()))?;
        if parsed.index != expected_index
            || parsed.count != expected_count
            || artifact.gguf_split.index != expected_index - 1
            || artifact.gguf_split.count != expected_count
        {
            return Err(ModelRegistryError::Corrupt(format!(
                "模型包分片编号不连续：{}",
                artifact.path.display()
            )));
        }
        if prefix.as_ref().is_some_and(|value| value != &parsed.prefix) {
            return Err(ModelRegistryError::Corrupt(
                "模型包包含不同前缀的分片".to_owned(),
            ));
        }
        prefix.get_or_insert(parsed.prefix);
        if !paths.insert(artifact.path.clone()) {
            return Err(ModelRegistryError::Corrupt(
                "模型包包含重复分片路径".to_owned(),
            ));
        }
    }
    let total = record.artifacts.iter().try_fold(0_u64, |sum, artifact| {
        sum.checked_add(artifact.size_bytes)
            .ok_or_else(|| ModelRegistryError::Corrupt("模型包大小溢出".to_owned()))
    })?;
    if total != record.size_bytes || bundle_sha256(&record.artifacts) != record.sha256 {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型包 {} 的聚合大小或摘要无效",
            record.name
        )));
    }
    Ok(())
}

fn bundle_sha256(artifacts: &[ModelArtifactRecord]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"mindone-model-bundle-v1\0");
    for artifact in artifacts {
        let name = artifact
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .as_bytes();
        hash.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_le_bytes());
        hash.update(name);
        hash.update(artifact.size_bytes.to_le_bytes());
        hash.update(artifact.sha256.as_bytes());
        hash.update(artifact.gguf_split.index.to_le_bytes());
        hash.update(artifact.gguf_split.count.to_le_bytes());
    }
    hex::encode(hash.finalize())
}

fn validate_name(value: &str) -> Result<(), ModelRegistryError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ModelRegistryError::InvalidName);
    }
    Ok(())
}

fn ensure_managed_path(path: &Path, models_root: &Path) -> Result<(), ModelRegistryError> {
    let canonical_root = fs::canonicalize(models_root)?;
    let canonical_path = fs::canonicalize(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || path != canonical_path
        || canonical_path == canonical_root
        || !canonical_path.starts_with(&canonical_root)
    {
        return Err(ModelRegistryError::OutsideManagedDirectory(canonical_path));
    }
    Ok(())
}

fn validate_registry_record(
    record: &ModelRecord,
    models_root: &Path,
) -> Result<(), ModelRegistryError> {
    validate_name(&record.name)
        .map_err(|_| ModelRegistryError::Corrupt(format!("模型登记名称无效：{}", record.name)))?;
    if record.sha256.len() != 64 || !record.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ModelRegistryError::Corrupt(format!(
            "模型 {} 的 SHA-256 登记无效",
            record.name
        )));
    }
    ensure_managed_path(&record.path, models_root)?;
    validate_artifact_layout(record)?;
    for artifact in &record.artifacts {
        ensure_managed_path(&artifact.path, models_root)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), ModelRegistryError> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validation::validate_model;
    use std::io::{Seek, SeekFrom, Write};

    fn write_gguf(path: &Path) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(b"GGUF")?;
        file.write_all(&3_u32.to_le_bytes())?;
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(&0_u64.to_le_bytes())?;
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(b"x")?;
        file.write_all(&1_u32.to_le_bytes())?;
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(&0_u32.to_le_bytes())?;
        file.write_all(&0_u64.to_le_bytes())?;
        let position = file.stream_position()?;
        let padding = (32 - (position % 32)) % 32;
        file.write_all(&vec![0_u8; usize::try_from(padding).unwrap_or_default()])?;
        file.write_all(&0_f32.to_le_bytes())?;
        Ok(())
    }

    fn write_split_gguf(path: &Path, index: u16, count: u16) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(b"GGUF")?;
        file.write_all(&3_u32.to_le_bytes())?;
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(&2_u64.to_le_bytes())?;
        for (key, value) in [("split.no", index), ("split.count", count)] {
            file.write_all(&(key.len() as u64).to_le_bytes())?;
            file.write_all(key.as_bytes())?;
            file.write_all(&2_u32.to_le_bytes())?;
            file.write_all(&value.to_le_bytes())?;
        }
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(b"x")?;
        file.write_all(&1_u32.to_le_bytes())?;
        file.write_all(&1_u64.to_le_bytes())?;
        file.write_all(&0_u32.to_le_bytes())?;
        file.write_all(&0_u64.to_le_bytes())?;
        let position = file.stream_position()?;
        let padding = (32 - (position % 32)) % 32;
        file.write_all(&vec![0_u8; usize::try_from(padding).unwrap_or_default()])?;
        file.write_all(&0_f32.to_le_bytes())?;
        Ok(())
    }

    #[test]
    fn registry_is_atomic_and_detects_mutation() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let models = temp.path().join("models");
        assert!(fs::create_dir_all(&models).is_ok());
        let model = models.join("tiny.gguf");
        assert!(write_gguf(&model).is_ok());
        let report = validate_model(&model, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        let registry = ModelRegistry::new(temp.path().join("registry.json"));
        let record = registry.register("tiny", report, &models);
        assert!(record.is_ok());
        let Ok(record) = record else { return };
        assert!(record.verification_is_current());
        assert!(matches!(
            registry.find_by_managed_path(&model, &models),
            Ok(found) if found.id == record.id
        ));
        assert!(OpenOptions::new()
            .append(true)
            .open(&model)
            .and_then(|mut file| file.write_all(&[1]))
            .is_ok());
        assert!(!record.verification_is_current());
        assert!(matches!(registry.list(), Ok(models) if models.len() == 1));
    }

    #[test]
    fn split_bundle_registration_verifies_every_shard_and_deletes_only_exact_directory() {
        let temporary = tempfile::tempdir().expect("应创建临时目录");
        let models = temporary.path().join("models");
        fs::create_dir_all(&models).expect("应创建模型目录");
        let bundle = models.join("tiny.bundle");
        fs::create_dir(&bundle).expect("应创建模型包目录");
        let paths = (1_u16..=2)
            .map(|index| bundle.join(format!("tiny-q4_k_m-{index:05}-of-00002.gguf")))
            .collect::<Vec<_>>();
        for (position, path) in paths.iter().enumerate() {
            write_split_gguf(path, u16::try_from(position).expect("编号应有效"), 2)
                .expect("应写入分片");
        }
        let reports = paths
            .iter()
            .map(|path| validate_model(path, None).expect("分片应通过结构验证"))
            .collect::<Vec<_>>();
        let registry = ModelRegistry::new(models.join("index.json"));
        assert!(matches!(
            registry.register("incomplete", reports[0].clone(), &models),
            Err(ModelRegistryError::Validation(_))
        ));
        let record = registry
            .register_bundle("tiny", reports, &models)
            .expect("完整模型包应登记");
        assert_eq!(record.artifacts.len(), 2);
        assert_eq!(record.path, paths[0].canonicalize().expect("应规范化路径"));
        assert_eq!(record.artifact_paths().len(), 2);
        assert!(record.verification_is_current_in(&models));

        let unexpected = bundle.join("unexpected.txt");
        File::create(&unexpected).expect("应创建未登记条目");
        assert!(matches!(
            registry.delete("tiny", &models, false),
            Err(ModelRegistryError::Corrupt(_))
        ));
        fs::remove_file(unexpected).expect("应移除测试条目");
        let removed = registry
            .delete("tiny", &models, false)
            .expect("精确模型包应删除");
        assert_eq!(removed.id, record.id);
        assert!(!bundle.exists());
        assert!(registry.list().expect("应读取登记").is_empty());
    }

    #[test]
    fn verification_detects_same_size_weight_replacement() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let models = temp.path().join("models");
        assert!(fs::create_dir_all(&models).is_ok());
        let model = models.join("tiny.gguf");
        assert!(write_gguf(&model).is_ok());
        let report = validate_model(&model, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        let registry = ModelRegistry::new(temp.path().join("registry.json"));
        let record = registry.register("tiny", report, &models);
        assert!(record.is_ok());
        let Ok(record) = record else { return };

        let mut file = OpenOptions::new().write(true).open(&model);
        assert!(file.is_ok());
        let Ok(ref mut file) = file else { return };
        assert!(file.seek(SeekFrom::End(-1)).is_ok());
        assert!(file.write_all(&[1]).is_ok());
        assert!(matches!(fs::metadata(&model), Ok(value) if value.len() == record.size_bytes));
        assert!(!record.verification_is_current());
        assert!(matches!(
            registry.reverify("tiny", &models),
            Err(ModelRegistryError::Validation(_))
        ));
        assert!(matches!(
            registry.find("tiny"),
            Ok(stored) if stored.sha256 == record.sha256
        ));
    }

    #[test]
    fn rejects_outside_path_and_unsafe_name() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let models = temp.path().join("models");
        assert!(fs::create_dir_all(&models).is_ok());
        let outside = temp.path().join("outside.gguf");
        assert!(write_gguf(&outside).is_ok());
        let report = validate_model(&outside, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        let registry = ModelRegistry::new(temp.path().join("registry.json"));
        assert!(matches!(
            registry.register("../escape", report.clone(), &models),
            Err(ModelRegistryError::InvalidName)
        ));
        assert!(matches!(
            registry.register("outside", report, &models),
            Err(ModelRegistryError::OutsideManagedDirectory(_))
        ));
    }

    #[test]
    fn tampered_registry_cannot_list_or_find_model_outside_managed_root() {
        let temp = tempfile::tempdir();
        let outside = tempfile::tempdir();
        assert!(temp.is_ok() && outside.is_ok());
        let (Ok(temp), Ok(outside)) = (temp, outside) else {
            return;
        };
        let models = temp.path().join("models");
        assert!(fs::create_dir_all(&models).is_ok());
        let outside_model = outside.path().join("outside.gguf");
        assert!(write_gguf(&outside_model).is_ok());
        let report = validate_model(&outside_model, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        let record = record_from_report(Uuid::now_v7(), "outside", report);
        assert!(!record.verification_is_current_in(&models));
        let data = RegistryData {
            version: 1,
            models: vec![record],
        };
        let index = models.join("index.json");
        assert!(fs::write(&index, serde_json::to_vec(&data).unwrap_or_default()).is_ok());
        let registry = ModelRegistry::new(index);
        assert!(matches!(
            registry.list(),
            Err(ModelRegistryError::OutsideManagedDirectory(_))
        ));
        assert!(matches!(
            registry.find("outside"),
            Err(ModelRegistryError::OutsideManagedDirectory(_))
        ));
    }

    #[test]
    fn delete_removes_file_and_record_but_honors_in_use_guard() {
        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let models = temp.path().join("models");
        assert!(fs::create_dir_all(&models).is_ok());
        let model = models.join("tiny.gguf");
        assert!(write_gguf(&model).is_ok());
        let report = validate_model(&model, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        let registry = ModelRegistry::new(temp.path().join("registry.json"));
        assert!(registry.register("tiny", report, &models).is_ok());

        assert!(matches!(
            registry.delete("tiny", &models, true),
            Err(ModelRegistryError::InUse(_))
        ));
        assert!(model.is_file());
        assert!(matches!(registry.list(), Ok(records) if records.len() == 1));

        assert!(registry.delete("tiny", &models, false).is_ok());
        assert!(!model.exists());
        assert!(matches!(registry.list(), Ok(records) if records.is_empty()));
        let quarantines = fs::read_dir(&models)
            .ok()
            .into_iter()
            .flat_map(|entries| entries.filter_map(Result::ok))
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".mindone-delete-")
            })
            .count();
        assert_eq!(quarantines, 0);
    }
}
