//! Coordinator-only audited SLA exclusion recording.
//!
//! This module is intentionally not routed through the public HTTP API or the
//! user CLI. Evidence paths are consumed locally through the shared bounded-file
//! primitive and only their SHA-256 commitment crosses the database boundary.

use std::path::{Path, PathBuf};

use mindone_common::sha256_bounded_regular_file;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub const CONTENT_POLICY_REFUSAL: &str = "content_policy_refusal";
pub const FORCE_MAJEURE: &str = "force_majeure";

const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MIN_REASON_CHARS: usize = 8;
const MAX_REASON_CHARS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSlaExclusionRequest {
    pub job_id: Uuid,
    pub category: String,
    pub evidence_path: PathBuf,
    pub operator_id: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorSlaExclusionResult {
    pub event_id: Uuid,
    pub job_id: Uuid,
    pub category: String,
    pub operator_id: String,
    pub reason: String,
    pub evidence_sha256: String,
    pub request_fingerprint: String,
    pub created_at: OffsetDateTime,
    pub idempotent_replay: bool,
}

#[derive(Debug, Error)]
pub enum OperatorSlaExclusionError {
    #[error("SLA 排除参数无效：{0}")]
    InvalidInput(String),
    #[error("SLA 排除 evidence 文件无效：{0}")]
    InvalidEvidence(String),
    #[error("任务不存在：{0}")]
    JobNotFound(Uuid),
    #[error("只有已经 failed 或 cancelled 的任务才能记录 SLA 排除")]
    JobNotTerminal,
    #[error("幂等键已用于不同的 SLA 排除请求")]
    IdempotencyConflict,
    #[error("该任务已经存在 SLA 排除决定")]
    JobConflict,
    #[error("SLA 排除数据库操作失败")]
    Database(#[from] sqlx::Error),
}

impl OperatorSlaExclusionRequest {
    pub fn validate(&self) -> Result<(), OperatorSlaExclusionError> {
        if !matches!(
            self.category.as_str(),
            CONTENT_POLICY_REFUSAL | FORCE_MAJEURE
        ) {
            return Err(OperatorSlaExclusionError::InvalidInput(
                "category 只允许 content_policy_refusal 或 force_majeure".to_owned(),
            ));
        }
        if !valid_ascii_identifier(&self.operator_id) {
            return Err(OperatorSlaExclusionError::InvalidInput(
                "operator 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
            ));
        }
        if !valid_ascii_identifier(&self.idempotency_key) {
            return Err(OperatorSlaExclusionError::InvalidInput(
                "idempotency_key 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
            ));
        }
        let reason_chars = self.reason.chars().count();
        if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&reason_chars)
            || self.reason.trim() != self.reason
            || self.reason.chars().any(char::is_control)
        {
            return Err(OperatorSlaExclusionError::InvalidInput(format!(
                "reason 必须是 {MIN_REASON_CHARS} 到 {MAX_REASON_CHARS} 个字符、无首尾空白或控制字符"
            )));
        }
        Ok(())
    }
}

/// 记录一个经过本地 evidence 验证的运维 SLA 排除决定。
///
/// 唯一写入由 0036 的 `SECURITY DEFINER` 函数完成。该函数在同一事务中
/// 持有幂等 advisory lock 和 job row lock；本函数不暴露 HTTP 路由。
pub async fn record_operator_sla_exclusion(
    pool: &PgPool,
    request: &OperatorSlaExclusionRequest,
) -> Result<OperatorSlaExclusionResult, OperatorSlaExclusionError> {
    request.validate()?;
    let evidence_sha256 = hash_evidence_file(&request.evidence_path)?;
    let request_fingerprint = request_fingerprint(request, &evidence_sha256)?;
    let proposed_event_id = Uuid::now_v7();

    let row = sqlx::query(
        r#"
        SELECT out_event_id,out_created_at,out_idempotent_replay
        FROM mindone_record_sla_exclusion_v1($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(proposed_event_id)
    .bind(request.job_id)
    .bind(&request.category)
    .bind(&request.operator_id)
    .bind(&request.reason)
    .bind(&request.idempotency_key)
    .bind(&evidence_sha256)
    .bind(&request_fingerprint)
    .fetch_one(pool)
    .await
    .map_err(|error| map_database_error(error, request.job_id))?;

    Ok(OperatorSlaExclusionResult {
        event_id: row.try_get("out_event_id")?,
        job_id: request.job_id,
        category: request.category.clone(),
        operator_id: request.operator_id.clone(),
        reason: request.reason.clone(),
        evidence_sha256,
        request_fingerprint,
        created_at: row.try_get("out_created_at")?,
        idempotent_replay: row.try_get("out_idempotent_replay")?,
    })
}

fn map_database_error(error: sqlx::Error, job_id: Uuid) -> OperatorSlaExclusionError {
    if let sqlx::Error::Database(database) = &error {
        return match database.message() {
            "sla exclusion job does not exist" => OperatorSlaExclusionError::JobNotFound(job_id),
            "sla exclusion requires a failed or cancelled job" => {
                OperatorSlaExclusionError::JobNotTerminal
            }
            "sla exclusion idempotency conflict" => OperatorSlaExclusionError::IdempotencyConflict,
            "sla exclusion job conflict" => OperatorSlaExclusionError::JobConflict,
            _ => OperatorSlaExclusionError::Database(error),
        };
    }
    OperatorSlaExclusionError::Database(error)
}

fn hash_evidence_file(path: &Path) -> Result<String, OperatorSlaExclusionError> {
    let digest = sha256_bounded_regular_file(path, MAX_EVIDENCE_BYTES).map_err(|error| {
        OperatorSlaExclusionError::InvalidEvidence(format!("evidence_file：{error}"))
    })?;
    if digest.size_bytes == 0 {
        return Err(OperatorSlaExclusionError::InvalidEvidence(
            "evidence_file 必须非空且不超过 1 GiB".to_owned(),
        ));
    }
    Ok(digest.sha256)
}

fn request_fingerprint(
    request: &OperatorSlaExclusionRequest,
    evidence_sha256: &str,
) -> Result<String, OperatorSlaExclusionError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        job_id: Uuid,
        category: &'a str,
        operator_id: &'a str,
        reason: &'a str,
        idempotency_key: &'a str,
        evidence_sha256: &'a str,
    }

    let payload = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        job_id: request.job_id,
        category: &request.category,
        operator_id: &request.operator_id,
        reason: &request.reason,
        idempotency_key: &request.idempotency_key,
        evidence_sha256,
    })
    .map_err(|error| {
        OperatorSlaExclusionError::InvalidInput(format!("无法规范化 SLA 排除请求：{error}"))
    })?;
    Ok(hex::encode(Sha256::digest(payload)))
}

fn valid_ascii_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn request() -> OperatorSlaExclusionRequest {
        OperatorSlaExclusionRequest {
            job_id: Uuid::nil(),
            category: CONTENT_POLICY_REFUSAL.to_owned(),
            evidence_path: PathBuf::from("/unused/in-shape-tests"),
            operator_id: "ops/governance".to_owned(),
            reason: "经独立证据确认属于内容政策拒绝".to_owned(),
            idempotency_key: "sla-exclusion-2026-0001".to_owned(), // gitleaks:allow 测试向量
        }
    }

    #[test]
    fn validates_only_two_audited_categories() {
        request().validate().expect("合法类别应通过");

        let mut force_majeure = request();
        force_majeure.category = FORCE_MAJEURE.to_owned();
        force_majeure.validate().expect("不可抗力类别应通过");

        let mut node_error = request();
        node_error.category = "worker_error_class".to_owned();
        assert!(matches!(
            node_error.validate(),
            Err(OperatorSlaExclusionError::InvalidInput(_))
        ));
    }

    #[test]
    fn fingerprint_binds_every_semantic_field() {
        let original = request();
        let evidence = "11".repeat(32);
        let expected = request_fingerprint(&original, &evidence).expect("应生成指纹");

        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.job_id = Uuid::from_u128(1);
        variants.push(changed);
        let mut changed = original.clone();
        changed.category = FORCE_MAJEURE.to_owned();
        variants.push(changed);
        let mut changed = original.clone();
        changed.operator_id.push_str("-2");
        variants.push(changed);
        let mut changed = original.clone();
        changed.reason.push('。');
        variants.push(changed);
        let mut changed = original.clone();
        changed.idempotency_key.push_str("-2");
        variants.push(changed);

        for variant in variants {
            assert_ne!(
                expected,
                request_fingerprint(&variant, &evidence).expect("变更请求也应可生成指纹")
            );
        }
        assert_ne!(
            expected,
            request_fingerprint(&original, &"22".repeat(32)).expect("证据变化应改变指纹")
        );
    }

    #[test]
    fn evidence_must_be_nonempty_canonical_regular_file() {
        let directory_guard = tempfile::Builder::new()
            .prefix(".mindone-sla-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("应创建测试目录");
        let directory = fs::canonicalize(directory_guard.path()).expect("测试目录应规范化");
        let evidence = directory.join("evidence.txt");
        fs::write(&evidence, b"independent incident evidence").expect("应写入测试证据");
        assert_eq!(
            hash_evidence_file(&evidence).expect("规范普通文件应可哈希"),
            hex::encode(Sha256::digest(b"independent incident evidence"))
        );

        let empty = directory.join("empty.txt");
        fs::write(&empty, []).expect("应写入空文件");
        assert!(hash_evidence_file(&empty).is_err());
        assert!(hash_evidence_file(Path::new("relative-evidence.txt")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let directory_guard = tempfile::Builder::new()
            .prefix(".mindone-sla-symlink-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("应创建测试目录");
        let directory = fs::canonicalize(directory_guard.path()).expect("测试目录应规范化");
        let evidence = directory.join("evidence.txt");
        fs::write(&evidence, b"incident evidence").expect("应写入测试证据");
        let link = directory.join("evidence-link.txt");
        symlink(&evidence, &link).expect("应创建符号链接");
        assert!(hash_evidence_file(&link).is_err());
    }
}
