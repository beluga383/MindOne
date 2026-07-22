use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use thiserror::Error;
use time::OffsetDateTime;

pub(crate) const MAX_MODEL_BYTES: u64 = 1 << 40; // 1 TiB，防止错误设备或恶意稀疏文件。
const MAX_GGUF_COUNT: u64 = 10_000_000;
const MAX_STRING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SAFETENSORS_HEADER: u64 = 100 * 1024 * 1024;
const MAX_ARRAY_DEPTH: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Gguf,
    Safetensors,
}

impl ModelFormat {
    pub fn compatible_engines(self) -> Vec<String> {
        match self {
            Self::Gguf => vec!["llama.cpp".to_owned()],
            // 结构验证不等于存在可安全启动的 runtime。v1 尚未提供带校验来源和
            // 完整依赖/健康协议验证的 safetensors 引擎适配器，因此不能暗示可运行。
            Self::Safetensors => Vec::new(),
        }
    }
}

/// GGUF 自带的分片身份。`index` 与 llama.cpp 的 `split.no` 一致，使用从 0
/// 开始的编号；文件名中的 `00001-of-000NN` 则从 1 开始。只有二者同时一致时，
/// 上层模型包验证才会允许 llama.cpp 自动加载相邻分片。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GgufSplitInfo {
    pub index: u16,
    pub count: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GgufSplitFileName {
    pub prefix: String,
    /// 文件名使用从 1 开始的编号。
    pub index: u16,
    pub count: u16,
}

/// 解析 llama.cpp/gguf-split 的规范文件名：
/// `<prefix>-00001-of-000NN.gguf`。严格格式避免把普通文件名中偶然出现的
/// `-of-` 当作完整模型包，也给下载数量设置了明确上限。
pub fn parse_gguf_split_filename(path: &Path) -> Option<GgufSplitFileName> {
    let file_name = path.file_name()?.to_str()?;
    let extension = Path::new(file_name)
        .extension()?
        .to_str()?
        .to_ascii_lowercase();
    if extension != "gguf" {
        return None;
    }
    let stem = file_name.get(..file_name.len().checked_sub(5)?)?;
    let (with_index, count_raw) = stem.rsplit_once("-of-")?;
    let (prefix, index_raw) = with_index.rsplit_once('-')?;
    if prefix.is_empty()
        || index_raw.len() != 5
        || count_raw.len() != 5
        || !index_raw.bytes().all(|byte| byte.is_ascii_digit())
        || !count_raw.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let index = index_raw.parse::<u16>().ok()?;
    let count = count_raw.parse::<u16>().ok()?;
    if !(2..=256).contains(&count) || index == 0 || index > count {
        return None;
    }
    Some(GgufSplitFileName {
        prefix: prefix.to_owned(),
        index,
        count,
    })
}

/// 验证一个已经逐文件完成结构与哈希检查的 GGUF 分片集合。集合必须按
/// `00001..000NN` 排序，文件名、目录和每个文件内部的 `split.no/count`
/// 三方一致；缺片、重片、混入另一量化或仅凭文件名伪装都会失败。
pub fn validate_gguf_split_reports(reports: &[ValidationReport]) -> Result<(), ValidationError> {
    if !(2..=256).contains(&reports.len()) {
        return Err(ValidationError::InvalidGguf(format!(
            "模型包分片数量无效：{}",
            reports.len()
        )));
    }
    let parent = reports
        .first()
        .and_then(|report| report.path.parent())
        .ok_or_else(|| ValidationError::InvalidGguf("模型包路径缺少父目录".to_owned()))?;
    let expected_count = u16::try_from(reports.len())
        .map_err(|_| ValidationError::InvalidGguf("模型包分片数量溢出".to_owned()))?;
    let mut prefix = None;
    let mut names = BTreeSet::new();
    for (position, report) in reports.iter().enumerate() {
        if report.format != ModelFormat::Gguf || report.path.parent() != Some(parent) {
            return Err(ValidationError::InvalidGguf(
                "模型包必须由同一目录内的 GGUF 分片组成".to_owned(),
            ));
        }
        let parsed = parse_gguf_split_filename(&report.path).ok_or_else(|| {
            ValidationError::InvalidGguf(format!(
                "模型包分片文件名不符合规范：{}",
                report.path.display()
            ))
        })?;
        let metadata = report.gguf_split.ok_or_else(|| {
            ValidationError::InvalidGguf(format!(
                "模型包分片缺少 GGUF split 元数据：{}",
                report.path.display()
            ))
        })?;
        let expected_index = u16::try_from(position + 1)
            .map_err(|_| ValidationError::InvalidGguf("模型包分片编号溢出".to_owned()))?;
        if parsed.count != expected_count
            || parsed.index != expected_index
            || metadata.count != expected_count
            || metadata.index != expected_index - 1
        {
            return Err(ValidationError::InvalidGguf(format!(
                "分片编号、文件名与 GGUF 元数据不一致：{}",
                report.path.display()
            )));
        }
        if prefix.as_ref().is_some_and(|value| value != &parsed.prefix) {
            return Err(ValidationError::InvalidGguf(
                "模型包包含不同前缀的分片".to_owned(),
            ));
        }
        prefix.get_or_insert(parsed.prefix);
        let name = report
            .path
            .file_name()
            .ok_or_else(|| ValidationError::InvalidGguf("模型包分片缺少文件名".to_owned()))?;
        if !names.insert(name.to_owned()) {
            return Err(ValidationError::InvalidGguf(
                "模型包包含重复分片文件名".to_owned(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub path: PathBuf,
    pub format: ModelFormat,
    pub size_bytes: u64,
    pub sha256: String,
    pub modified_unix: i64,
    pub tensor_count: u64,
    pub compatible_engines: Vec<String>,
    pub verified_at_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gguf_split: Option<GgufSplitInfo>,
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("模型路径不存在或不是普通文件：{0}")]
    NotAFile(PathBuf),
    #[error("拒绝符号链接模型路径：{0}")]
    Symlink(PathBuf),
    #[error("检测到不安全的模型格式：{0}")]
    UnsafeFormat(String),
    #[error("模型扩展名与实际格式不一致")]
    ExtensionMismatch,
    #[error("模型文件大小无效：{0} 字节")]
    InvalidSize(u64),
    #[error("GGUF 结构验证失败：{0}")]
    InvalidGguf(String),
    #[error("safetensors 结构验证失败：{0}")]
    InvalidSafetensors(String),
    #[error("模型 SHA-256 不匹配：期望 {expected}，实际 {actual}")]
    ChecksumMismatch { expected: String, actual: String },
    #[error("模型在验证期间发生变化，已拒绝：{0}")]
    ConcurrentModification(PathBuf),
    #[error("读取模型失败：{0}")]
    Io(#[from] io::Error),
}

pub fn validate_model(
    path: &Path,
    expected_sha256: Option<&str>,
) -> Result<ValidationReport, ValidationError> {
    let canonical_before =
        fs::canonicalize(path).map_err(|_| ValidationError::NotAFile(path.to_path_buf()))?;
    let symlink_meta =
        fs::symlink_metadata(path).map_err(|_| ValidationError::NotAFile(path.to_path_buf()))?;
    if symlink_meta.file_type().is_symlink() {
        return Err(ValidationError::Symlink(path.to_path_buf()));
    }
    if !symlink_meta.is_file() {
        return Err(ValidationError::NotAFile(path.to_path_buf()));
    }
    reject_unsafe_extension(path)?;
    let mut file = open_model_file(path)?;
    let opened_meta = file.metadata()?;
    if !opened_meta.is_file() || !same_file_identity(&symlink_meta, &opened_meta) {
        return Err(ValidationError::ConcurrentModification(path.to_path_buf()));
    }
    let size = opened_meta.len();
    if !(16..=MAX_MODEL_BYTES).contains(&size) {
        return Err(ValidationError::InvalidSize(size));
    }

    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    let (format, tensor_count, gguf_split) = if &magic[..4] == b"GGUF" {
        let (tensor_count, split) = validate_gguf(&mut file, size)?;
        (ModelFormat::Gguf, tensor_count, split)
    } else if safetensors_magic_plausible(&magic, size) {
        (
            ModelFormat::Safetensors,
            validate_safetensors(&mut file, size)?,
            None,
        )
    } else {
        return Err(ValidationError::UnsafeFormat(
            "文件头既不是 GGUF，也不是 safetensors".to_owned(),
        ));
    };
    validate_extension_matches(path, format)?;

    let sha256 = sha256_open_file(&mut file)?;
    if let Some(expected) = expected_sha256 {
        let normalized =
            normalize_sha256(expected).ok_or_else(|| ValidationError::ChecksumMismatch {
                expected: expected.to_owned(),
                actual: sha256.clone(),
            })?;
        if normalized != sha256 {
            return Err(ValidationError::ChecksumMismatch {
                expected: normalized,
                actual: sha256,
            });
        }
    }
    let after_read_meta = file.metadata()?;
    if !metadata_snapshot_unchanged(&opened_meta, &after_read_meta) {
        return Err(ValidationError::ConcurrentModification(path.to_path_buf()));
    }
    let canonical_after = fs::canonicalize(path)
        .map_err(|_| ValidationError::ConcurrentModification(path.to_path_buf()))?;
    let path_meta = fs::metadata(&canonical_after)
        .map_err(|_| ValidationError::ConcurrentModification(path.to_path_buf()))?;
    if canonical_before != canonical_after || !same_file_identity(&opened_meta, &path_meta) {
        return Err(ValidationError::ConcurrentModification(path.to_path_buf()));
    }
    let modified_unix = opened_meta
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .unwrap_or_default();
    Ok(ValidationReport {
        path: canonical_after,
        format,
        size_bytes: size,
        sha256,
        modified_unix,
        tensor_count,
        compatible_engines: format.compatible_engines(),
        verified_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        gguf_split,
    })
}

fn reject_unsafe_extension(path: &Path) -> Result<(), ValidationError> {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if matches!(
        extension.as_str(),
        "pkl" | "pickle" | "pt" | "pth" | "bin" | "ckpt" | "joblib"
    ) {
        return Err(ValidationError::UnsafeFormat(format!(
            ".{extension} 可能依赖任意代码反序列化"
        )));
    }
    Ok(())
}

fn validate_extension_matches(path: &Path, format: ModelFormat) -> Result<(), ValidationError> {
    let actual = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    let matches = matches!(
        (format, actual.as_deref()),
        (ModelFormat::Gguf, Some("gguf")) | (ModelFormat::Safetensors, Some("safetensors"))
    );
    if matches {
        Ok(())
    } else {
        Err(ValidationError::ExtensionMismatch)
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn sha256_open_file(file: &mut File) -> Result<String, ValidationError> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
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

fn open_model_file(path: &Path) -> Result<File, ValidationError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

#[cfg(unix)]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &Metadata, right: &Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn metadata_snapshot_unchanged(before: &Metadata, after: &Metadata) -> bool {
    if !same_file_identity(before, after)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    true
}

fn safetensors_magic_plausible(magic: &[u8; 8], file_size: u64) -> bool {
    let header_len = u64::from_le_bytes(*magic);
    header_len > 1
        && header_len <= MAX_SAFETENSORS_HEADER
        && header_len
            .checked_add(8)
            .is_some_and(|end| end <= file_size)
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("不含重复对象键的 JSON 值")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("JSON 数字不是有限值"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("JSON 对象包含重复键：{key}")));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn parse_unique_json(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue::deserialize(&mut deserializer)?.0;
    deserializer.end()?;
    Ok(value)
}

fn validate_safetensors(file: &mut File, file_size: u64) -> Result<u64, ValidationError> {
    let header_len =
        read_u64(file).map_err(|error| ValidationError::InvalidSafetensors(error.to_string()))?;
    if header_len == 0 || header_len > MAX_SAFETENSORS_HEADER {
        return Err(ValidationError::InvalidSafetensors(format!(
            "header 长度 {header_len} 超出安全范围"
        )));
    }
    let data_start = 8_u64
        .checked_add(header_len)
        .ok_or_else(|| ValidationError::InvalidSafetensors("header 长度溢出".to_owned()))?;
    if data_start > file_size {
        return Err(ValidationError::InvalidSafetensors(
            "header 超出文件边界".to_owned(),
        ));
    }
    let header_size = usize::try_from(header_len)
        .map_err(|_| ValidationError::InvalidSafetensors("header 无法装入内存".to_owned()))?;
    let mut header = vec![0_u8; header_size];
    file.read_exact(&mut header)
        .map_err(|error| ValidationError::InvalidSafetensors(error.to_string()))?;
    let value = parse_unique_json(&header)
        .map_err(|error| ValidationError::InvalidSafetensors(error.to_string()))?;
    let tensors = value.as_object().ok_or_else(|| {
        ValidationError::InvalidSafetensors("header 顶层必须是 JSON 对象".to_owned())
    })?;
    let data_len = file_size - data_start;
    let mut ranges = Vec::new();
    let mut tensor_count = 0_u64;

    for (name, tensor) in tensors {
        if name == "__metadata__" {
            if !tensor
                .as_object()
                .is_some_and(|metadata| metadata.values().all(Value::is_string))
            {
                return Err(ValidationError::InvalidSafetensors(
                    "__metadata__ 必须是字符串到字符串的对象".to_owned(),
                ));
            }
            continue;
        }
        if name.is_empty() || name.len() > 4096 {
            return Err(ValidationError::InvalidSafetensors(
                "张量名称为空或过长".to_owned(),
            ));
        }
        let object = tensor.as_object().ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 描述不是对象"))
        })?;
        let dtype = object.get("dtype").and_then(Value::as_str).ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 缺少 dtype"))
        })?;
        let element_size = dtype_size(dtype).ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 使用未知 dtype {dtype}"))
        })?;
        let shape = object
            .get("shape")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ValidationError::InvalidSafetensors(format!("张量 {name} 缺少 shape"))
            })?;
        if shape.len() > 32 {
            return Err(ValidationError::InvalidSafetensors(format!(
                "张量 {name} 维度过多"
            )));
        }
        let elements = shape.iter().try_fold(1_u64, |product, dimension| {
            let value = dimension.as_u64().ok_or_else(|| {
                ValidationError::InvalidSafetensors(format!("张量 {name} shape 无效"))
            })?;
            product.checked_mul(value).ok_or_else(|| {
                ValidationError::InvalidSafetensors(format!("张量 {name} 元素数溢出"))
            })
        })?;
        let offsets = object
            .get("data_offsets")
            .and_then(Value::as_array)
            .filter(|offsets| offsets.len() == 2)
            .ok_or_else(|| {
                ValidationError::InvalidSafetensors(format!("张量 {name} data_offsets 无效"))
            })?;
        let start = offsets[0].as_u64().ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 起始偏移无效"))
        })?;
        let end = offsets[1].as_u64().ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 结束偏移无效"))
        })?;
        if start > end || end > data_len {
            return Err(ValidationError::InvalidSafetensors(format!(
                "张量 {name} 偏移越界"
            )));
        }
        let wanted = elements.checked_mul(element_size).ok_or_else(|| {
            ValidationError::InvalidSafetensors(format!("张量 {name} 字节数溢出"))
        })?;
        if end - start != wanted {
            return Err(ValidationError::InvalidSafetensors(format!(
                "张量 {name} 字节数与 shape/dtype 不一致"
            )));
        }
        ranges.push((start, end, name.clone()));
        tensor_count = tensor_count
            .checked_add(1)
            .ok_or_else(|| ValidationError::InvalidSafetensors("张量数量溢出".to_owned()))?;
    }
    if tensor_count == 0 {
        return Err(ValidationError::InvalidSafetensors(
            "文件没有张量".to_owned(),
        ));
    }
    ranges.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then(Ordering::Equal)
    });
    if ranges.first().is_none_or(|range| range.0 != 0) {
        return Err(ValidationError::InvalidSafetensors(
            "张量数据没有从 data buffer 起点连续覆盖".to_owned(),
        ));
    }
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(ValidationError::InvalidSafetensors(format!(
                "张量 {} 与 {} 数据区重叠",
                pair[0].2, pair[1].2
            )));
        }
        if pair[0].1 < pair[1].0 {
            return Err(ValidationError::InvalidSafetensors(format!(
                "张量 {} 与 {} 之间存在未索引数据空洞",
                pair[0].2, pair[1].2
            )));
        }
    }
    if ranges.last().is_none_or(|range| range.1 != data_len) {
        return Err(ValidationError::InvalidSafetensors(
            "data buffer 尾部存在未索引字节".to_owned(),
        ));
    }
    Ok(tensor_count)
}

fn dtype_size(dtype: &str) -> Option<u64> {
    match dtype {
        "BOOL" | "U8" | "I8" | "F8_E4M3" | "F8_E5M2" => Some(1),
        "U16" | "I16" | "F16" | "BF16" => Some(2),
        "U32" | "I32" | "F32" => Some(4),
        "U64" | "I64" | "F64" => Some(8),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
struct GgufTensor {
    offset: u64,
    elements: u64,
    kind: u32,
}

fn validate_gguf(
    file: &mut File,
    file_size: u64,
) -> Result<(u64, Option<GgufSplitInfo>), ValidationError> {
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)
        .map_err(|error| ValidationError::InvalidGguf(error.to_string()))?;
    if &magic != b"GGUF" {
        return Err(ValidationError::InvalidGguf("magic 不匹配".to_owned()));
    }
    let version = read_u32(file).map_err(invalid_gguf_io)?;
    if !(1..=3).contains(&version) {
        return Err(ValidationError::InvalidGguf(format!(
            "不支持 GGUF v{version}"
        )));
    }
    let tensor_count = read_u64(file).map_err(invalid_gguf_io)?;
    let metadata_count = read_u64(file).map_err(invalid_gguf_io)?;
    if tensor_count == 0 || tensor_count > MAX_GGUF_COUNT {
        return Err(ValidationError::InvalidGguf(format!(
            "张量数量 {tensor_count} 无效"
        )));
    }
    if metadata_count > MAX_GGUF_COUNT {
        return Err(ValidationError::InvalidGguf(format!(
            "元数据数量 {metadata_count} 超限"
        )));
    }

    let mut alignment = 32_u64;
    let mut split_index = None;
    let mut split_count = None;
    for _ in 0..metadata_count {
        let key = read_gguf_string(file)?;
        let value_type = read_u32(file).map_err(invalid_gguf_io)?;
        if key == "general.alignment" && value_type == 4 {
            alignment = u64::from(read_u32(file).map_err(invalid_gguf_io)?);
            if alignment == 0 || !alignment.is_power_of_two() || alignment > 4096 {
                return Err(ValidationError::InvalidGguf(
                    "general.alignment 无效".to_owned(),
                ));
            }
        } else if key == "split.no" {
            if value_type != 2 || split_index.is_some() {
                return Err(ValidationError::InvalidGguf(
                    "split.no 类型无效或重复".to_owned(),
                ));
            }
            split_index = Some(read_u16(file).map_err(invalid_gguf_io)?);
        } else if key == "split.count" {
            if value_type != 2 || split_count.is_some() {
                return Err(ValidationError::InvalidGguf(
                    "split.count 类型无效或重复".to_owned(),
                ));
            }
            split_count = Some(read_u16(file).map_err(invalid_gguf_io)?);
        } else {
            skip_gguf_value(file, value_type, 0)?;
        }
    }
    let split = match (split_index, split_count) {
        (None, None) | (Some(0), Some(0 | 1)) => None,
        (Some(index), Some(count)) if count > 1 && index < count => {
            Some(GgufSplitInfo { index, count })
        }
        _ => {
            return Err(ValidationError::InvalidGguf(
                "split.no/split.count 必须同时存在且编号有效".to_owned(),
            ));
        }
    };

    let capacity = usize::try_from(tensor_count.min(1_000_000))
        .map_err(|_| ValidationError::InvalidGguf("张量数量无法分配".to_owned()))?;
    let mut tensors = Vec::with_capacity(capacity);
    for _ in 0..tensor_count {
        let _name = read_gguf_string(file)?;
        let dimensions = read_u32(file).map_err(invalid_gguf_io)?;
        if !(1..=4).contains(&dimensions) {
            return Err(ValidationError::InvalidGguf(format!(
                "张量维度 {dimensions} 无效"
            )));
        }
        let mut elements = 1_u64;
        for _ in 0..dimensions {
            let dimension = read_u64(file).map_err(invalid_gguf_io)?;
            if dimension == 0 {
                return Err(ValidationError::InvalidGguf("张量维度不能为零".to_owned()));
            }
            elements = elements
                .checked_mul(dimension)
                .ok_or_else(|| ValidationError::InvalidGguf("张量元素数量溢出".to_owned()))?;
        }
        let kind = read_u32(file).map_err(invalid_gguf_io)?;
        let offset = read_u64(file).map_err(invalid_gguf_io)?;
        tensors.push(GgufTensor {
            offset,
            elements,
            kind,
        });
    }
    let info_end = file.stream_position().map_err(invalid_gguf_io)?;
    let data_start = align_up(info_end, alignment)
        .ok_or_else(|| ValidationError::InvalidGguf("数据区偏移溢出".to_owned()))?;
    if data_start >= file_size {
        return Err(ValidationError::InvalidGguf(
            "GGUF 没有有效数据区".to_owned(),
        ));
    }
    let data_len = file_size - data_start;
    let mut ranges = Vec::with_capacity(tensors.len());
    for tensor in tensors {
        validate_tensor_alignment(tensor.offset, alignment)?;
        let bytes = ggml_tensor_bytes(tensor.elements, tensor.kind)?;
        let end = tensor
            .offset
            .checked_add(bytes)
            .ok_or_else(|| ValidationError::InvalidGguf("张量数据偏移溢出".to_owned()))?;
        if end > data_len {
            return Err(ValidationError::InvalidGguf(format!(
                "张量数据越界：offset={} bytes={} data={data_len}",
                tensor.offset, bytes
            )));
        }
        ranges.push((tensor.offset, end));
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(ValidationError::InvalidGguf("张量数据区重叠".to_owned()));
        }
    }
    Ok((tensor_count, split))
}

fn validate_tensor_alignment(offset: u64, alignment: u64) -> Result<(), ValidationError> {
    if !offset.is_multiple_of(alignment) {
        return Err(ValidationError::InvalidGguf(format!(
            "张量偏移 {offset} 未按 {alignment} 字节对齐"
        )));
    }
    Ok(())
}

fn invalid_gguf_io(error: io::Error) -> ValidationError {
    ValidationError::InvalidGguf(error.to_string())
}

fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

fn read_gguf_string(file: &mut File) -> Result<String, ValidationError> {
    let length = read_u64(file).map_err(invalid_gguf_io)?;
    if length > MAX_STRING_BYTES {
        return Err(ValidationError::InvalidGguf(format!(
            "字符串长度 {length} 超限"
        )));
    }
    let size = usize::try_from(length)
        .map_err(|_| ValidationError::InvalidGguf("字符串长度溢出".to_owned()))?;
    let mut value = vec![0_u8; size];
    file.read_exact(&mut value).map_err(invalid_gguf_io)?;
    String::from_utf8(value)
        .map_err(|error| ValidationError::InvalidGguf(format!("字符串不是 UTF-8：{error}")))
}

fn skip_gguf_value(file: &mut File, value_type: u32, depth: u8) -> Result<(), ValidationError> {
    if depth > MAX_ARRAY_DEPTH {
        return Err(ValidationError::InvalidGguf(
            "元数据数组嵌套过深".to_owned(),
        ));
    }
    match value_type {
        0 | 1 | 7 => seek_forward(file, 1),
        2 | 3 => seek_forward(file, 2),
        4..=6 => seek_forward(file, 4),
        8 => {
            let _ = read_gguf_string(file)?;
            Ok(())
        }
        9 => {
            let element_type = read_u32(file).map_err(invalid_gguf_io)?;
            let count = read_u64(file).map_err(invalid_gguf_io)?;
            if count > MAX_GGUF_COUNT {
                return Err(ValidationError::InvalidGguf(format!(
                    "元数据数组长度 {count} 超限"
                )));
            }
            if let Some(width) = gguf_fixed_width(element_type) {
                let bytes = count
                    .checked_mul(width)
                    .ok_or_else(|| ValidationError::InvalidGguf("元数据数组大小溢出".to_owned()))?;
                seek_forward(file, bytes)
            } else {
                for _ in 0..count {
                    skip_gguf_value(file, element_type, depth + 1)?;
                }
                Ok(())
            }
        }
        10..=12 => seek_forward(file, 8),
        _ => Err(ValidationError::InvalidGguf(format!(
            "未知元数据类型 {value_type}"
        ))),
    }
}

fn gguf_fixed_width(value_type: u32) -> Option<u64> {
    match value_type {
        0 | 1 | 7 => Some(1),
        2 | 3 => Some(2),
        4..=6 => Some(4),
        10..=12 => Some(8),
        _ => None,
    }
}

fn seek_forward(file: &mut File, bytes: u64) -> Result<(), ValidationError> {
    let offset = i64::try_from(bytes)
        .map_err(|_| ValidationError::InvalidGguf("跳过长度溢出".to_owned()))?;
    file.seek(SeekFrom::Current(offset))
        .map(|_| ())
        .map_err(invalid_gguf_io)
}

fn ggml_tensor_bytes(elements: u64, kind: u32) -> Result<u64, ValidationError> {
    let (block, bytes) = match kind {
        0 => (1_u64, 4_u64),
        1 => (1, 2),
        2 => (32, 18),
        3 => (32, 20),
        6 => (32, 22),
        7 => (32, 24),
        8 => (32, 34),
        9 => (32, 40),
        10 => (256, 84),
        11 => (256, 110),
        12 => (256, 144),
        13 => (256, 176),
        14 => (256, 210),
        15 => (256, 292),
        16 => (256, 66),
        17 => (256, 74),
        18 => (256, 98),
        19 => (256, 50),
        20 => (32, 18),
        21 => (256, 110),
        22 => (256, 82),
        23 => (256, 136),
        24 => (1, 1),
        25 => (1, 2),
        26 => (1, 4),
        27 => (1, 8),
        28 => (1, 8),
        29 => (256, 56),
        30 => (1, 2),
        _ => {
            return Err(ValidationError::InvalidGguf(format!(
                "不支持的 GGML 张量类型 {kind}"
            )))
        }
    };
    if !elements.is_multiple_of(block) {
        return Err(ValidationError::InvalidGguf(format!(
            "张量元素数 {elements} 不是量化块 {block} 的整数倍"
        )));
    }
    let blocks = elements
        .checked_div(block)
        .ok_or_else(|| ValidationError::InvalidGguf("张量块数量无效".to_owned()))?;
    blocks
        .checked_mul(bytes)
        .ok_or_else(|| ValidationError::InvalidGguf("张量字节数溢出".to_owned()))
}

fn read_u32(reader: &mut impl Read) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u16(reader: &mut impl Read) -> io::Result<u16> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn model_format_does_not_advertise_unmanaged_engines() {
        assert_eq!(ModelFormat::Gguf.compatible_engines(), vec!["llama.cpp"]);
        assert!(ModelFormat::Safetensors.compatible_engines().is_empty());
    }

    fn write_minimal_gguf(path: &Path) -> io::Result<()> {
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
        let current = file.stream_position()?;
        let padding = (32 - (current % 32)) % 32;
        file.write_all(&vec![0_u8; usize::try_from(padding).unwrap_or_default()])?;
        file.write_all(&0_f32.to_le_bytes())?;
        Ok(())
    }

    fn write_split_gguf(path: &Path, index: u16, count: u16) -> io::Result<()> {
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
        let current = file.stream_position()?;
        let padding = (32 - (current % 32)) % 32;
        file.write_all(&vec![0_u8; usize::try_from(padding).unwrap_or_default()])?;
        file.write_all(&0_f32.to_le_bytes())?;
        Ok(())
    }

    fn write_safetensors(path: &Path, overlap: bool) -> io::Result<()> {
        let second = if overlap { "[2,6]" } else { "[4,8]" };
        let header = format!(
            "{{\"a\":{{\"dtype\":\"F32\",\"shape\":[1],\"data_offsets\":[0,4]}},\
             \"b\":{{\"dtype\":\"F32\",\"shape\":[1],\"data_offsets\":{second}}}}}"
        );
        let mut file = File::create(path)?;
        file.write_all(&(header.len() as u64).to_le_bytes())?;
        file.write_all(header.as_bytes())?;
        file.write_all(&[0_u8; 8])?;
        Ok(())
    }

    fn write_raw_safetensors(path: &Path, header: &str, data_len: usize) -> io::Result<()> {
        let mut file = File::create(path)?;
        file.write_all(&(header.len() as u64).to_le_bytes())?;
        file.write_all(header.as_bytes())?;
        file.write_all(&vec![0_u8; data_len])?;
        Ok(())
    }

    #[test]
    fn validates_minimal_gguf_and_checksum() {
        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let path = directory.path().join("tiny.gguf");
        assert!(write_minimal_gguf(&path).is_ok());
        let report = validate_model(&path, None);
        assert!(report.is_ok());
        let Ok(report) = report else { return };
        assert_eq!(report.format, ModelFormat::Gguf);
        assert_eq!(report.tensor_count, 1);
        assert!(validate_model(&path, Some(&report.sha256)).is_ok());
        assert!(matches!(
            validate_model(&path, Some(&"0".repeat(64))),
            Err(ValidationError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn split_gguf_requires_filename_order_and_internal_metadata_to_match() {
        let directory = tempfile::tempdir().expect("应创建临时目录");
        let paths = (1_u16..=3)
            .map(|index| {
                directory
                    .path()
                    .join(format!("tiny-q4_k_m-{index:05}-of-00003.gguf"))
            })
            .collect::<Vec<_>>();
        for (position, path) in paths.iter().enumerate() {
            write_split_gguf(path, u16::try_from(position).expect("编号应有效"), 3)
                .expect("应写入分片 GGUF");
        }
        let reports = paths
            .iter()
            .map(|path| validate_model(path, None).expect("分片结构应有效"))
            .collect::<Vec<_>>();
        assert_eq!(
            reports[0].gguf_split,
            Some(GgufSplitInfo { index: 0, count: 3 })
        );
        validate_gguf_split_reports(&reports).expect("完整集合应通过");
        assert!(validate_gguf_split_reports(&reports[..2]).is_err());

        let mismatched = directory.path().join("other-00003-of-00003.gguf");
        fs::rename(&paths[2], &mismatched).expect("应重命名测试分片");
        let mut wrong_prefix = reports[..2].to_vec();
        wrong_prefix.push(validate_model(&mismatched, None).expect("单片结构仍有效"));
        assert!(validate_gguf_split_reports(&wrong_prefix).is_err());
    }

    #[test]
    fn validates_safetensors_and_rejects_overlap() {
        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let valid = directory.path().join("valid.safetensors");
        let overlap = directory.path().join("overlap.safetensors");
        assert!(write_safetensors(&valid, false).is_ok());
        assert!(write_safetensors(&overlap, true).is_ok());
        assert!(validate_model(&valid, None).is_ok());
        assert!(matches!(
            validate_model(&overlap, None),
            Err(ValidationError::InvalidSafetensors(_))
        ));
    }

    #[test]
    fn safetensors_rejects_holes_trailing_bytes_and_duplicate_keys() {
        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let cases = [
            (
                "first-hole.safetensors",
                r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[1,5]}}"#,
                5,
            ),
            (
                "middle-hole.safetensors",
                r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"b":{"dtype":"F32","shape":[1],"data_offsets":[5,9]}}"#,
                9,
            ),
            (
                "trailing.safetensors",
                r#"{"a":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
                5,
            ),
            (
                "duplicate.safetensors",
                r#"{"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},"x":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}"#,
                4,
            ),
        ];
        for (name, header, data_len) in cases {
            let path = directory.path().join(name);
            assert!(write_raw_safetensors(&path, header, data_len).is_ok());
            assert!(matches!(
                validate_model(&path, None),
                Err(ValidationError::InvalidSafetensors(_))
            ));
        }
    }

    #[test]
    fn gguf_quantized_tensors_require_complete_blocks() {
        assert!(ggml_tensor_bytes(32, 2).is_ok());
        assert!(matches!(
            ggml_tensor_bytes(31, 2),
            Err(ValidationError::InvalidGguf(message)) if message.contains("整数倍")
        ));
        assert!(validate_tensor_alignment(64, 32).is_ok());
        assert!(validate_tensor_alignment(1, 32).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn open_file_identity_detects_path_replacement_and_refuses_symlink() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let path = directory.path().join("model.gguf");
        let old_path = directory.path().join("old.gguf");
        assert!(write_minimal_gguf(&path).is_ok());
        let opened = open_model_file(&path);
        assert!(opened.is_ok());
        let Ok(opened) = opened else { return };
        let before = opened.metadata();
        assert!(before.is_ok());
        let Ok(before) = before else { return };
        assert!(fs::rename(&path, &old_path).is_ok());
        assert!(write_minimal_gguf(&path).is_ok());
        let after = fs::metadata(&path);
        assert!(after.is_ok());
        let Ok(after) = after else { return };
        assert!(!same_file_identity(&before, &after));

        let link = directory.path().join("link.gguf");
        assert!(symlink(&path, &link).is_ok());
        assert!(open_model_file(&link).is_err());
        assert!(matches!(
            validate_model(&link, None),
            Err(ValidationError::Symlink(_))
        ));
    }

    #[test]
    fn rejects_dangerous_extension_and_spoofed_extension() {
        let dangerous = NamedTempFile::with_suffix(".pt");
        assert!(dangerous.is_ok());
        let Ok(mut dangerous) = dangerous else {
            return;
        };
        assert!(dangerous.write_all(&[0_u8; 32]).is_ok());
        assert!(matches!(
            validate_model(dangerous.path(), None),
            Err(ValidationError::UnsafeFormat(_))
        ));

        let directory = tempfile::tempdir();
        assert!(directory.is_ok());
        let Ok(directory) = directory else { return };
        let spoofed = directory.path().join("model.safetensors");
        assert!(write_minimal_gguf(&spoofed).is_ok());
        assert!(matches!(
            validate_model(&spoofed, None),
            Err(ValidationError::ExtensionMismatch)
        ));
    }
}
