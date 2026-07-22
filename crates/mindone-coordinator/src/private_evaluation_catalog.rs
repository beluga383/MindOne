//! 服务器侧私有模型真实性题库。
//!
//! 题库文件与 evaluator 私钥都不属于仓库或客户端配置。常驻协调器只从部署方的
//! 受控目录读取一个短期、Ed25519 签名的 catalog；数据库和日志只接触题目/行为的
//! commitment，不持久化 Prompt 或模型输出明文。

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::config::PrivateEvaluationHmacKey;

pub const PRIVATE_EVALUATION_CATALOG_SCHEMA: &str = "mindone-private-evaluation-catalog-v1";
pub const PRIVATE_EVALUATION_CATALOG_FILE: &str = "private-evaluation-catalog-v1.json";
pub const PRIVATE_EVALUATION_NORMALIZATION: &str = "utf8-trim-v1";

const CATALOG_SIGNING_DOMAIN: &[u8] = b"mindone:private-evaluation-catalog:v1\0";
const MAX_CATALOG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CATALOG_ENTRIES: usize = 4_096;
const MAX_PROMPT_BYTES: usize = 16 * 1024;
const MAX_OUTPUT_TOKENS: u32 = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_CATALOG_VALIDITY: Duration = Duration::days(30);
const MAX_CLOCK_SKEW: Duration = Duration::minutes(5);

/// 独立 evaluator 交付的签名 envelope。生产文件必须位于仓库外。
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivateEvaluationCatalog {
    pub statement: PrivateEvaluationCatalogStatement,
    /// 对 [`private_evaluation_catalog_signing_message`] 的 Ed25519 签名，小写 hex。
    pub signature: String,
}

/// 签名 catalog 的稳定 statement。
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PrivateEvaluationCatalogStatement {
    pub schema: String,
    pub catalog_id: String,
    pub evaluator_id: String,
    pub issued_at: String,
    pub valid_until: String,
    pub behavior_normalization: String,
    pub entries: Vec<PrivateEvaluationCatalogEntry>,
}

/// 一条只使用一次的模型行为挑战。
///
/// `expected_behavior_sha256` 是目标权重在固定生成参数下，响应文本执行
/// `utf8-trim-v1` 后的 SHA-256；catalog 不需要保存预期响应明文。
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct PrivateEvaluationCatalogEntry {
    pub entry_id: String,
    pub case_family: String,
    pub model_weights_sha256: String,
    pub prompt: String,
    pub expected_behavior_sha256: String,
    pub inference_seed: u32,
    pub max_output_tokens: u32,
}

/// 独立 evaluator 签名时必须使用的域分隔消息。
pub fn private_evaluation_catalog_signing_message(
    statement: &PrivateEvaluationCatalogStatement,
) -> Result<Vec<u8>, serde_json::Error> {
    let canonical = serde_json::to_vec(statement)?;
    let mut message = Vec::with_capacity(CATALOG_SIGNING_DOMAIN.len() + canonical.len());
    message.extend_from_slice(CATALOG_SIGNING_DOMAIN);
    message.extend_from_slice(&canonical);
    Ok(message)
}

/// private-hidden 数据在数据库、日志或审计记录中出现时使用的稳定 HMAC 域。
///
/// 每个语义字段都拥有独立且带版本的域，防止相同低熵值在不同字段间被关联或重放。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrivateEvaluationCommitmentDomain {
    CatalogStatement,
    CatalogId,
    EntryId,
    CaseFamily,
    EvaluatorId,
    EvaluatorKey,
    Prompt,
    ExpectedBehavior,
    AccountId,
    DeviceId,
    NodeId,
}

impl PrivateEvaluationCommitmentDomain {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::CatalogStatement => b"mindone:private-hidden:commitment:v1:catalog-statement\0",
            Self::CatalogId => b"mindone:private-hidden:commitment:v1:catalog-id\0",
            Self::EntryId => b"mindone:private-hidden:commitment:v1:entry-id\0",
            Self::CaseFamily => b"mindone:private-hidden:commitment:v1:case-family\0",
            Self::EvaluatorId => b"mindone:private-hidden:commitment:v1:evaluator-id\0",
            Self::EvaluatorKey => b"mindone:private-hidden:commitment:v1:evaluator-key\0",
            Self::Prompt => b"mindone:private-hidden:commitment:v1:prompt\0",
            Self::ExpectedBehavior => b"mindone:private-hidden:commitment:v1:expected-behavior\0",
            Self::AccountId => b"mindone:private-hidden:commitment:v1:account-id\0",
            Self::DeviceId => b"mindone:private-hidden:commitment:v1:device-id\0",
            Self::NodeId => b"mindone:private-hidden:commitment:v1:node-id\0",
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum PrivateEvaluationCommitmentError {
    #[error("private-hidden HMAC 密钥版本不受支持")]
    UnsupportedKeyVersion,
    #[error("private-hidden HMAC 初始化失败")]
    InvalidKey,
    #[error("private-hidden commitment 输入过长")]
    InputTooLong,
    #[error("private-hidden expected behavior SHA-256 无效")]
    InvalidExpectedBehaviorSha256,
    #[error("private-hidden SHA-256 输入无效")]
    InvalidSha256,
    #[error("private-hidden commitment 编码无效")]
    InvalidCommitment,
}

/// 计算小写 hex 的域分离 HMAC-SHA256 commitment。
///
/// 认证消息严格为 `domain || u64_be(value.len()) || value`。调用方不能直接访问 HMAC
/// 密钥材料，只能显式选择语义域。
pub(crate) fn private_evaluation_commitment_hex(
    key: &PrivateEvaluationHmacKey,
    domain: PrivateEvaluationCommitmentDomain,
    value: &[u8],
) -> Result<String, PrivateEvaluationCommitmentError> {
    let commitment = private_evaluation_commitment_bytes(key, domain, value)?;
    Ok(hex::encode(commitment))
}

/// 对规范的 64 位小写 SHA-256 先解码为 32 字节，再计算指定语义域的 commitment。
pub(crate) fn private_evaluation_sha256_commitment_hex(
    key: &PrivateEvaluationHmacKey,
    domain: PrivateEvaluationCommitmentDomain,
    sha256: &str,
) -> Result<String, PrivateEvaluationCommitmentError> {
    if !valid_sha256(sha256) {
        return Err(PrivateEvaluationCommitmentError::InvalidSha256);
    }
    let mut digest = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(sha256.as_bytes(), &mut *digest)
        .map_err(|_| PrivateEvaluationCommitmentError::InvalidSha256)?;
    private_evaluation_commitment_hex(key, domain, digest.as_ref())
}

/// 以常量时间比较重新计算的 commitment 与规范小写 hex。
pub(crate) fn private_evaluation_commitment_matches_hex(
    key: &PrivateEvaluationHmacKey,
    domain: PrivateEvaluationCommitmentDomain,
    value: &[u8],
    expected_commitment: &str,
) -> Result<bool, PrivateEvaluationCommitmentError> {
    if !valid_sha256(expected_commitment) {
        return Err(PrivateEvaluationCommitmentError::InvalidCommitment);
    }
    let mut expected = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(expected_commitment.as_bytes(), &mut *expected)
        .map_err(|_| PrivateEvaluationCommitmentError::InvalidCommitment)?;
    let actual = private_evaluation_commitment_bytes(key, domain, value)?;
    Ok(actual.ct_eq(expected.as_ref()).unwrap_u8() == 1)
}

/// 将 catalog 中规范的 64 位小写 SHA-256 解码为 32 字节后再做 HMAC commitment。
///
/// 有意不对 hex 文本本身做 HMAC，避免同一摘要出现两种 wire representation。
pub(crate) fn private_evaluation_expected_behavior_commitment_hex(
    key: &PrivateEvaluationHmacKey,
    expected_behavior_sha256: &str,
) -> Result<String, PrivateEvaluationCommitmentError> {
    if !valid_sha256(expected_behavior_sha256) {
        return Err(PrivateEvaluationCommitmentError::InvalidExpectedBehaviorSha256);
    }
    private_evaluation_sha256_commitment_hex(
        key,
        PrivateEvaluationCommitmentDomain::ExpectedBehavior,
        expected_behavior_sha256,
    )
}

fn private_evaluation_commitment_bytes(
    key: &PrivateEvaluationHmacKey,
    domain: PrivateEvaluationCommitmentDomain,
    value: &[u8],
) -> Result<[u8; 32], PrivateEvaluationCommitmentError> {
    if key.version() != 1 {
        return Err(PrivateEvaluationCommitmentError::UnsupportedKeyVersion);
    }
    let value_length =
        u64::try_from(value.len()).map_err(|_| PrivateEvaluationCommitmentError::InputTooLong)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key.material())
        .map_err(|_| PrivateEvaluationCommitmentError::InvalidKey)?;
    mac.update(domain.as_bytes());
    mac.update(&value_length.to_be_bytes());
    mac.update(value);
    let output = mac.finalize().into_bytes();
    let mut commitment = [0_u8; 32];
    commitment.copy_from_slice(&output);
    Ok(commitment)
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct VerifiedPrivateEvaluationCatalog {
    pub catalog_id: String,
    pub catalog_commitment: String,
    pub evaluator_id: String,
    pub evaluator_key_fingerprint: String,
    #[zeroize(skip)]
    pub valid_until: OffsetDateTime,
    pub entries: Vec<PrivateEvaluationCatalogEntry>,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub(crate) enum PrivateEvaluationCatalogError {
    #[error("私有评价 catalog 存储边界无效")]
    InsecureStorage,
    #[error("私有评价 catalog 格式无效")]
    InvalidCatalog,
    #[error("私有评价 catalog 签名无效")]
    SignatureInvalid,
    #[error("私有评价 catalog 已过期或尚未生效")]
    OutsideValidityWindow,
}

impl PrivateEvaluationCatalogError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InsecureStorage => "insecure_storage",
            Self::InvalidCatalog => "invalid_catalog",
            Self::SignatureInvalid => "signature_invalid",
            Self::OutsideValidityWindow => "outside_validity_window",
        }
    }
}

/// 从部署方受控目录读取并验证当前私有 catalog。
///
/// 没有配置 keys 目录或目录中没有 catalog 是显式的“未配置”，调用方只能降级为
/// 公开 canary，不能把公开模板标记为 hidden benchmark。配置存在但不安全、签名错误
/// 或过期则返回稳定错误码；错误从不包含路径、Prompt 或响应内容。
pub(crate) fn load_private_evaluation_catalog(
    trusted_keys_dir: Option<&Path>,
    now: OffsetDateTime,
) -> Result<Option<VerifiedPrivateEvaluationCatalog>, PrivateEvaluationCatalogError> {
    let Some(trusted_keys_dir) = trusted_keys_dir else {
        return Ok(None);
    };
    let directory = canonical_trusted_directory(trusted_keys_dir)?;
    let catalog_path = directory.join(PRIVATE_EVALUATION_CATALOG_FILE);
    let catalog_bytes = match read_bounded_regular_file(&catalog_path, MAX_CATALOG_BYTES) {
        Ok(bytes) => bytes,
        Err(ReadSecureFileError::NotFound) => return Ok(None),
        Err(ReadSecureFileError::Invalid) => {
            return Err(PrivateEvaluationCatalogError::InsecureStorage);
        }
    };
    let envelope: SignedPrivateEvaluationCatalog = serde_json::from_slice(&catalog_bytes)
        .map_err(|_| PrivateEvaluationCatalogError::InvalidCatalog)?;
    validate_catalog_statement(&envelope.statement, now)?;
    let verifying_key = load_trusted_evaluator_key(&directory, &envelope.statement.evaluator_id)?;
    let message = private_evaluation_catalog_signing_message(&envelope.statement)
        .map_err(|_| PrivateEvaluationCatalogError::InvalidCatalog)?;
    let signature = decode_signature(&envelope.signature)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)?;
    let canonical_statement = serde_json::to_vec(&envelope.statement)
        .map_err(|_| PrivateEvaluationCatalogError::InvalidCatalog)?;
    let valid_until =
        postgres_microsecond_timestamp(parse_timestamp(&envelope.statement.valid_until)?)?;
    Ok(Some(VerifiedPrivateEvaluationCatalog {
        catalog_id: envelope.statement.catalog_id.clone(),
        catalog_commitment: hex::encode(Sha256::digest(&canonical_statement)),
        evaluator_id: envelope.statement.evaluator_id.clone(),
        evaluator_key_fingerprint: hex::encode(Sha256::digest(verifying_key.as_bytes())),
        valid_until,
        entries: envelope.statement.entries.clone(),
    }))
}

fn validate_catalog_statement(
    statement: &PrivateEvaluationCatalogStatement,
    now: OffsetDateTime,
) -> Result<(), PrivateEvaluationCatalogError> {
    if statement.schema != PRIVATE_EVALUATION_CATALOG_SCHEMA
        || statement.behavior_normalization != PRIVATE_EVALUATION_NORMALIZATION
        || !valid_identifier(&statement.catalog_id)
        || !valid_identifier(&statement.evaluator_id)
        || statement.entries.is_empty()
        || statement.entries.len() > MAX_CATALOG_ENTRIES
    {
        return Err(PrivateEvaluationCatalogError::InvalidCatalog);
    }
    let issued_at = parse_timestamp(&statement.issued_at)?;
    let valid_until = parse_timestamp(&statement.valid_until)?;
    if issued_at > now + MAX_CLOCK_SKEW
        || valid_until <= now
        || valid_until <= issued_at
        || valid_until - issued_at > MAX_CATALOG_VALIDITY
    {
        return Err(PrivateEvaluationCatalogError::OutsideValidityWindow);
    }

    let mut entry_ids = BTreeSet::new();
    let mut prompt_hashes = BTreeSet::new();
    let mut behavior_hashes = BTreeSet::new();
    let mut family_counts = BTreeMap::<(String, String), usize>::new();
    for entry in &statement.entries {
        if !valid_identifier(&entry.entry_id)
            || !valid_identifier(&entry.case_family)
            || !valid_sha256(&entry.model_weights_sha256)
            || !valid_sha256(&entry.expected_behavior_sha256)
            || entry.prompt.is_empty()
            || entry.prompt.len() > MAX_PROMPT_BYTES
            || entry.prompt.trim() != entry.prompt
            || entry.prompt.chars().any(|character| character == '\0')
            || prompt_reveals_evaluation(&entry.prompt)
            || !(1..=MAX_OUTPUT_TOKENS).contains(&entry.max_output_tokens)
        {
            return Err(PrivateEvaluationCatalogError::InvalidCatalog);
        }
        let prompt_hash = hex::encode(Sha256::digest(entry.prompt.as_bytes()));
        // 全 catalog 的 Prompt、行为指纹和 entry id 都必须唯一。结合数据库的一次性
        // entry 约束，这使旧输出不能作为另一个挑战的有效重放。
        if !entry_ids.insert(entry.entry_id.clone())
            || !prompt_hashes.insert(prompt_hash)
            || !behavior_hashes.insert(entry.expected_behavior_sha256.clone())
        {
            return Err(PrivateEvaluationCatalogError::InvalidCatalog);
        }
        let family_count = family_counts
            .entry((
                entry.model_weights_sha256.clone(),
                entry.case_family.clone(),
            ))
            .or_default();
        *family_count = family_count
            .checked_add(1)
            .ok_or(PrivateEvaluationCatalogError::InvalidCatalog)?;
    }
    if family_counts.values().any(|count| *count < 2) {
        return Err(PrivateEvaluationCatalogError::InvalidCatalog);
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, PrivateEvaluationCatalogError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| PrivateEvaluationCatalogError::InvalidCatalog)
}

fn postgres_microsecond_timestamp(
    value: OffsetDateTime,
) -> Result<OffsetDateTime, PrivateEvaluationCatalogError> {
    let nanoseconds = value.unix_timestamp_nanos();
    let quantized = nanoseconds.div_euclid(1_000) * 1_000;
    OffsetDateTime::from_unix_timestamp_nanos(quantized)
        .map_err(|_| PrivateEvaluationCatalogError::InvalidCatalog)
}

fn prompt_reveals_evaluation(prompt: &str) -> bool {
    let lower = prompt.to_ascii_lowercase();
    [
        "mindone",
        "evaluation",
        "benchmark",
        "canary",
        "hidden",
        "challenge",
        "评价",
        "评测",
        "挑战",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_trusted_directory(path: &Path) -> Result<PathBuf, PrivateEvaluationCatalogError> {
    if !path.is_absolute() {
        return Err(PrivateEvaluationCatalogError::InsecureStorage);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PrivateEvaluationCatalogError::InsecureStorage)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PrivateEvaluationCatalogError::InsecureStorage);
    }
    reject_group_or_world_writable(&metadata)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| PrivateEvaluationCatalogError::InsecureStorage)?;
    if canonical != path {
        return Err(PrivateEvaluationCatalogError::InsecureStorage);
    }
    reject_insecure_directory_chain(&canonical)?;
    Ok(canonical)
}

fn load_trusted_evaluator_key(
    directory: &Path,
    evaluator_id: &str,
) -> Result<VerifyingKey, PrivateEvaluationCatalogError> {
    let key_path = directory.join(format!("{evaluator_id}.pub"));
    let key_bytes = read_bounded_regular_file(&key_path, 256)
        .map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)?;
    let key_text = std::str::from_utf8(&key_bytes)
        .map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)?
        .trim();
    if !valid_sha256(key_text) {
        return Err(PrivateEvaluationCatalogError::SignatureInvalid);
    }
    let mut raw = [0_u8; 32];
    hex::decode_to_slice(key_text, &mut raw)
        .map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)
}

fn decode_signature(value: &str) -> Result<Signature, PrivateEvaluationCatalogError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PrivateEvaluationCatalogError::SignatureInvalid);
    }
    let mut raw = [0_u8; 64];
    hex::decode_to_slice(value, &mut raw)
        .map_err(|_| PrivateEvaluationCatalogError::SignatureInvalid)?;
    Ok(Signature::from_bytes(&raw))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadSecureFileError {
    NotFound,
    Invalid,
}

fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Vec<u8>, ReadSecureFileError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ReadSecureFileError::NotFound);
        }
        Err(_) => return Err(ReadSecureFileError::Invalid),
    };
    if !path.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(ReadSecureFileError::Invalid);
    }
    reject_group_or_world_writable(&metadata).map_err(|_| ReadSecureFileError::Invalid)?;
    let canonical = fs::canonicalize(path).map_err(|_| ReadSecureFileError::Invalid)?;
    if canonical != path {
        return Err(ReadSecureFileError::Invalid);
    }
    let mut file = File::open(path).map_err(|_| ReadSecureFileError::Invalid)?;
    let opened = file.metadata().map_err(|_| ReadSecureFileError::Invalid)?;
    if !same_file(&metadata, &opened) {
        return Err(ReadSecureFileError::Invalid);
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| ReadSecureFileError::Invalid)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ReadSecureFileError::Invalid)?;
    let after = file.metadata().map_err(|_| ReadSecureFileError::Invalid)?;
    let actual = u64::try_from(bytes.len()).map_err(|_| ReadSecureFileError::Invalid)?;
    if actual != metadata.len() || actual > maximum_bytes || !same_file(&opened, &after) {
        return Err(ReadSecureFileError::Invalid);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.is_file() == right.is_file()
}

#[cfg(unix)]
fn reject_insecure_directory_chain(path: &Path) -> Result<(), PrivateEvaluationCatalogError> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| PrivateEvaluationCatalogError::InsecureStorage)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PrivateEvaluationCatalogError::InsecureStorage);
        }
        reject_group_or_world_writable(&metadata)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_directory_chain(_path: &Path) -> Result<(), PrivateEvaluationCatalogError> {
    Ok(())
}

#[cfg(unix)]
fn reject_group_or_world_writable(
    metadata: &fs::Metadata,
) -> Result<(), PrivateEvaluationCatalogError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(PrivateEvaluationCatalogError::InsecureStorage);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_group_or_world_writable(
    _metadata: &fs::Metadata,
) -> Result<(), PrivateEvaluationCatalogError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::config::Config;

    fn secure_tempdir() -> tempfile::TempDir {
        let parent = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("crate 目录应可规范化");
        tempfile::Builder::new()
            .prefix(".mindone-private-evaluation-test-")
            .tempdir_in(parent)
            .expect("应在权限受控的 crate 目录创建临时目录")
    }

    fn statement(now: OffsetDateTime) -> PrivateEvaluationCatalogStatement {
        PrivateEvaluationCatalogStatement {
            schema: PRIVATE_EVALUATION_CATALOG_SCHEMA.to_owned(),
            catalog_id: "catalog-2026-07-18-a".to_owned(),
            evaluator_id: "private-evaluator-1".to_owned(),
            issued_at: now.format(&Rfc3339).expect("应格式化 issued_at"),
            valid_until: (now + Duration::hours(1))
                .format(&Rfc3339)
                .expect("应格式化 valid_until"),
            behavior_normalization: PRIVATE_EVALUATION_NORMALIZATION.to_owned(),
            entries: vec![
                PrivateEvaluationCatalogEntry {
                    entry_id: "entry-a".to_owned(),
                    case_family: "family-a".to_owned(),
                    model_weights_sha256: "1".repeat(64),
                    prompt: "测试环境私有行为探针 ALPHA-42".to_owned(),
                    expected_behavior_sha256: hex::encode(Sha256::digest("期望-A".as_bytes())),
                    inference_seed: 7,
                    max_output_tokens: 32,
                },
                PrivateEvaluationCatalogEntry {
                    entry_id: "entry-b".to_owned(),
                    case_family: "family-a".to_owned(),
                    model_weights_sha256: "1".repeat(64),
                    prompt: "测试环境私有行为探针 BETA-43".to_owned(),
                    expected_behavior_sha256: hex::encode(Sha256::digest("期望-B".as_bytes())),
                    inference_seed: 8,
                    max_output_tokens: 32,
                },
            ],
        }
    }

    fn write_signed_catalog(
        directory: &Path,
        signing_key: &SigningKey,
        statement: &PrivateEvaluationCatalogStatement,
    ) {
        fs::write(
            directory.join(format!("{}.pub", statement.evaluator_id)),
            hex::encode(signing_key.verifying_key().to_bytes()),
        )
        .expect("应写入 evaluator 公钥");
        let signature = signing_key
            .sign(&private_evaluation_catalog_signing_message(statement).expect("应生成签名消息"));
        let envelope = SignedPrivateEvaluationCatalog {
            statement: statement.clone(),
            signature: hex::encode(signature.to_bytes()),
        };
        fs::write(
            directory.join(PRIVATE_EVALUATION_CATALOG_FILE),
            serde_json::to_vec(&envelope).expect("应编码签名 catalog"),
        )
        .expect("应写入签名 catalog");
    }

    fn test_hmac_key() -> crate::config::PrivateEvaluationHmacKey {
        Config::development_for_tests("postgres://invalid".to_owned())
            .private_evaluation_hmac_key
            .expect("测试配置应提供 private-hidden HMAC key")
    }

    #[test]
    fn private_commitments_are_deterministic_and_domain_separated() {
        let key = test_hmac_key();
        let expected = private_evaluation_commitment_hex(
            &key,
            PrivateEvaluationCommitmentDomain::Prompt,
            b"yes",
        )
        .expect("Prompt commitment 应生成");
        assert_eq!(
            expected,
            "37e601d82a8c227803dee3de35549f5516e353b8973bfa9f9dce5a23243b0f4e"
        );
        assert_eq!(
            private_evaluation_commitment_hex(
                &key,
                PrivateEvaluationCommitmentDomain::Prompt,
                b"yes",
            )
            .expect("相同输入应生成 commitment"),
            expected
        );

        let domains = [
            PrivateEvaluationCommitmentDomain::CatalogStatement,
            PrivateEvaluationCommitmentDomain::CatalogId,
            PrivateEvaluationCommitmentDomain::EntryId,
            PrivateEvaluationCommitmentDomain::CaseFamily,
            PrivateEvaluationCommitmentDomain::EvaluatorId,
            PrivateEvaluationCommitmentDomain::EvaluatorKey,
            PrivateEvaluationCommitmentDomain::Prompt,
            PrivateEvaluationCommitmentDomain::ExpectedBehavior,
            PrivateEvaluationCommitmentDomain::AccountId,
            PrivateEvaluationCommitmentDomain::DeviceId,
            PrivateEvaluationCommitmentDomain::NodeId,
        ];
        let commitments = domains
            .into_iter()
            .map(|domain| {
                private_evaluation_commitment_hex(&key, domain, b"same-low-entropy-value")
                    .expect("每个域都应生成 commitment")
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(commitments.len(), domains.len());
    }

    #[test]
    fn low_entropy_behavior_uses_decoded_sha_and_never_bare_hash() {
        let key = test_hmac_key();
        let bare_sha = hex::encode(Sha256::digest(b"yes"));
        let commitment = private_evaluation_expected_behavior_commitment_hex(&key, &bare_sha)
            .expect("expected behavior commitment 应生成");
        assert_eq!(
            commitment,
            "815d17ce0904b73247871ca0867acebeed7d63f766bb5efd0b17a02123a41e11"
        );
        assert_ne!(commitment, bare_sha);
        assert_ne!(commitment, "yes");
        assert_ne!(
            commitment,
            private_evaluation_commitment_hex(
                &key,
                PrivateEvaluationCommitmentDomain::ExpectedBehavior,
                bare_sha.as_bytes(),
            )
            .expect("ASCII hex 对照 commitment 应生成")
        );
        assert!(private_evaluation_commitment_matches_hex(
            &key,
            PrivateEvaluationCommitmentDomain::ExpectedBehavior,
            &Sha256::digest(b"yes")[..],
            &commitment,
        )
        .expect("常量时间 commitment 比较应执行"));
        assert!(!private_evaluation_commitment_matches_hex(
            &key,
            PrivateEvaluationCommitmentDomain::ExpectedBehavior,
            &Sha256::digest(b"no")[..],
            &commitment,
        )
        .expect("错误输入应安全比较"));
        assert_eq!(
            private_evaluation_expected_behavior_commitment_hex(&key, &bare_sha.to_uppercase()),
            Err(PrivateEvaluationCommitmentError::InvalidExpectedBehaviorSha256)
        );
    }

    #[test]
    fn sha256_commitment_helper_decodes_catalog_and_evaluator_fingerprints() {
        let key = test_hmac_key();
        let digest_hex = "2a".repeat(32);
        for domain in [
            PrivateEvaluationCommitmentDomain::CatalogStatement,
            PrivateEvaluationCommitmentDomain::EvaluatorKey,
        ] {
            let decoded = private_evaluation_sha256_commitment_hex(&key, domain, &digest_hex)
                .expect("规范 SHA-256 应解码后 commitment");
            let raw = [0x2a_u8; 32];
            assert_eq!(
                decoded,
                private_evaluation_commitment_hex(&key, domain, &raw)
                    .expect("raw digest commitment 应生成")
            );
            assert_ne!(
                decoded,
                private_evaluation_commitment_hex(&key, domain, digest_hex.as_bytes())
                    .expect("ASCII digest 对照应生成")
            );
        }
    }

    #[test]
    fn signed_private_catalog_is_verified_and_tampering_fails_closed() {
        let temp = secure_tempdir();
        let directory = fs::canonicalize(temp.path()).expect("临时目录应可规范化");
        let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
        let now = OffsetDateTime::now_utc();
        let statement = statement(now);
        let stale_signature = signing_key.sign(
            &private_evaluation_catalog_signing_message(&statement).expect("应生成原始签名消息"),
        );
        write_signed_catalog(&directory, &signing_key, &statement);

        let verified = load_private_evaluation_catalog(Some(&directory), now)
            .expect("签名 catalog 应通过")
            .expect("应加载 catalog");
        assert_eq!(verified.catalog_id, statement.catalog_id);
        assert_eq!(verified.entries.len(), 2);
        assert_eq!(verified.entries[0].prompt, statement.entries[0].prompt);

        let mut tampered = statement;
        tampered.entries[0].prompt.push_str("-tampered");
        let envelope = SignedPrivateEvaluationCatalog {
            statement: tampered,
            signature: hex::encode(stale_signature.to_bytes()),
        };
        fs::write(
            directory.join(PRIVATE_EVALUATION_CATALOG_FILE),
            serde_json::to_vec(&envelope).expect("应编码篡改 catalog"),
        )
        .expect("应写入篡改 catalog");
        assert!(matches!(
            load_private_evaluation_catalog(Some(&directory), now),
            Err(PrivateEvaluationCatalogError::SignatureInvalid)
        ));
    }

    #[test]
    fn catalog_rejects_replayable_duplicate_behavior_or_expiry() {
        let now = OffsetDateTime::now_utc();
        let mut duplicate = statement(now);
        let mut second = duplicate.entries[0].clone();
        second.entry_id = "entry-c".to_owned();
        second.prompt = "另一个私有测试探针 BETA-99".to_owned();
        duplicate.entries.push(second);
        assert_eq!(
            validate_catalog_statement(&duplicate, now),
            Err(PrivateEvaluationCatalogError::InvalidCatalog)
        );

        let mut expired = statement(now);
        expired.issued_at = (now - Duration::hours(2))
            .format(&Rfc3339)
            .expect("应格式化时间");
        expired.valid_until = (now - Duration::hours(1))
            .format(&Rfc3339)
            .expect("应格式化时间");
        assert_eq!(
            validate_catalog_statement(&expired, now),
            Err(PrivateEvaluationCatalogError::OutsideValidityWindow)
        );

        let mut revealing = statement(now);
        revealing.entries[0].prompt = "这是一个 hidden benchmark 探针".to_owned();
        assert_eq!(
            validate_catalog_statement(&revealing, now),
            Err(PrivateEvaluationCatalogError::InvalidCatalog)
        );

        let mut singleton_families = statement(now);
        singleton_families.entries[1].case_family = "family-b".to_owned();
        assert_eq!(
            validate_catalog_statement(&singleton_families, now),
            Err(PrivateEvaluationCatalogError::InvalidCatalog)
        );
    }

    #[test]
    fn catalog_timestamp_is_quantized_to_postgres_microseconds_before_binding() {
        let temp = secure_tempdir();
        let directory = fs::canonicalize(temp.path()).expect("临时目录应可规范化");
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let now = OffsetDateTime::parse("2026-07-18T12:00:00.123456789Z", &Rfc3339)
            .expect("固定测试时间应有效");
        let catalog = statement(now);
        write_signed_catalog(&directory, &signing_key, &catalog);

        let verified = load_private_evaluation_catalog(Some(&directory), now)
            .expect("带纳秒时间的签名 catalog 应通过")
            .expect("应加载 catalog");
        assert_eq!(verified.valid_until.nanosecond() % 1_000, 0);
    }
}
