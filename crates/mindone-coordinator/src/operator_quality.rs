use std::{
    fs,
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, VerifyingKey};
use mindone_accounting::Glicko2Score;
use mindone_common::{
    read_bounded_regular_file as secure_read_bounded_regular_file,
    sha256_bounded_regular_file as secure_sha256_bounded_regular_file,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use thiserror::Error;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::quality::{
    blind_evaluation_event, canary_event, hidden_benchmark_event, lock_quality_event_idempotency,
    record_trusted_event_in_transaction, validate_trusted_event, QualityGovernanceError,
    QualityUpdate, TrustedBlindEvaluation, TrustedCanaryEvaluation, TrustedHiddenBenchmark,
};

pub const QUALITY_EVIDENCE_SCHEMA: &str = "mindone-quality-evidence-v1";
const SIGNING_DOMAIN: &[u8] = b"mindone:quality-evidence:v1\0";
const MAX_EVIDENCE_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_EVIDENCE_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_EVIDENCE_VALIDITY: Duration = Duration::hours(24);
const MAX_CLOCK_SKEW: Duration = Duration::minutes(5);
const MAX_IDENTIFIER_BYTES: usize = 128;
const MIN_REASON_CHARS: usize = 8;
const MAX_REASON_CHARS: usize = 512;

#[derive(Clone, Debug)]
pub struct OperatorQualityRecordRequest {
    pub evidence_path: PathBuf,
    pub artifact_path: PathBuf,
    pub trusted_keys_dir: PathBuf,
    pub operator_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedQualityEvidence {
    pub statement: QualityEvidenceStatement,
    /// Ed25519 signature over [`quality_evidence_signing_message`], as lowercase hex.
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualityEvidenceStatement {
    pub schema: String,
    pub evaluator_id: String,
    pub model_id: Uuid,
    pub idempotency_key: String,
    pub observed_at: String,
    pub valid_until: String,
    pub artifact_sha256: String,
    pub measurement: QualityEvidenceMeasurement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum QualityEvidenceMeasurement {
    HiddenBenchmark {
        score_normalized: i32,
        sample_count: i32,
    },
    Canary {
        passed: bool,
    },
    BlindEvaluation {
        opponent_rating_milli: i64,
        opponent_deviation_milli: i64,
        outcome: Glicko2Score,
    },
}

impl QualityEvidenceMeasurement {
    fn event_kind(&self) -> &'static str {
        match self {
            Self::HiddenBenchmark { .. } => "hidden_benchmark",
            Self::Canary { .. } => "canary",
            Self::BlindEvaluation { .. } => "blind_evaluation",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorQualityRecordResult {
    pub evidence_audit_id: Uuid,
    pub evaluator_id: String,
    pub evaluator_key_fingerprint: String,
    pub statement_sha256: String,
    pub artifact_sha256: String,
    pub quality: QualityUpdate,
    pub idempotent_replay: bool,
}

#[derive(Debug, Error)]
pub enum OperatorQualityError {
    #[error("质量 evidence 参数无效：{0}")]
    InvalidInput(String),
    #[error("质量 evidence 文件无效：{0}")]
    InvalidFile(String),
    #[error("质量 evidence 的 evaluator 不受信任或签名无效")]
    SignatureInvalid,
    #[error("质量 evidence 幂等键已用于不同请求，或存在未绑定签名 evidence 的旧事件")]
    IdempotencyConflict,
    #[error("质量治理失败：{0}")]
    Quality(#[from] QualityGovernanceError),
    #[error("质量 evidence 数据库操作失败：{0}")]
    Database(#[from] sqlx::Error),
}

struct PreparedQualityEvidence {
    envelope: SignedQualityEvidence,
    canonical_statement: String,
    statement_sha256: String,
}

struct QualityEvidenceVerification {
    evaluator_key_fingerprint: String,
    verified_at: OffsetDateTime,
}

/// 返回 evaluator 必须使用 Ed25519 签名的稳定、带域分隔消息。
pub fn quality_evidence_signing_message(
    statement: &QualityEvidenceStatement,
) -> Result<Vec<u8>, OperatorQualityError> {
    let canonical = serde_json::to_vec(statement).map_err(|error| {
        OperatorQualityError::InvalidInput(format!("无法规范化 evidence statement：{error}"))
    })?;
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + canonical.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&canonical);
    Ok(message)
}

/// 受控服务器命令的唯一质量写入口。分数、模型、幂等键和 artifact commitment
/// 必须来自受信 evaluator 的签名 statement，不能由命令行参数裸写。
pub async fn record_operator_quality_evidence(
    pool: &PgPool,
    request: &OperatorQualityRecordRequest,
) -> Result<OperatorQualityRecordResult, OperatorQualityError> {
    validate_operator(&request.operator_id, &request.reason)?;
    let prepared = prepare_evidence_files(&request.evidence_path, &request.artifact_path)?;
    let statement = &prepared.envelope.statement;
    let event_kind = statement.measurement.event_kind();
    let event = match &statement.measurement {
        QualityEvidenceMeasurement::HiddenBenchmark {
            score_normalized,
            sample_count,
        } => hidden_benchmark_event(TrustedHiddenBenchmark {
            model_id: statement.model_id,
            idempotency_key: statement.idempotency_key.clone(),
            evidence_hash: statement.artifact_sha256.clone(),
            score_normalized: *score_normalized,
            sample_count: *sample_count,
        }),
        QualityEvidenceMeasurement::Canary { passed } => canary_event(TrustedCanaryEvaluation {
            model_id: statement.model_id,
            idempotency_key: statement.idempotency_key.clone(),
            evidence_hash: statement.artifact_sha256.clone(),
            passed: *passed,
        }),
        QualityEvidenceMeasurement::BlindEvaluation {
            opponent_rating_milli,
            opponent_deviation_milli,
            outcome,
        } => blind_evaluation_event(TrustedBlindEvaluation {
            model_id: statement.model_id,
            idempotency_key: statement.idempotency_key.clone(),
            evidence_hash: statement.artifact_sha256.clone(),
            opponent_rating_milli: *opponent_rating_milli,
            opponent_deviation_milli: *opponent_deviation_milli,
            outcome: *outcome,
        }),
    };
    validate_statement_shape(statement)?;
    validate_trusted_event(&event)?;
    let mut tx = pool.begin().await?;
    lock_quality_event_idempotency(&mut tx, &statement.idempotency_key).await?;
    let existing_audit = sqlx::query(
        r#"
        SELECT id,quality_event_id,model_id,evaluator_id,operator_id,reason,event_kind,
               idempotency_key,request_fingerprint,evidence_schema,statement_json,
               statement_sha256,artifact_sha256,evaluator_key_fingerprint,signature_hex
        FROM quality_evidence_audits
        WHERE idempotency_key=$1
        "#,
    )
    .bind(&statement.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = existing_audit {
        // A committed audit is the durable proof that this exact statement was fresh and signed
        // by the then-pinned key. Replays must not start depending on an expired validity window or
        // a key file that has since been deliberately rotated away.
        let quality = record_trusted_event_in_transaction(&mut tx, event).await?;
        if !quality.idempotent_replay
            || row.try_get::<Uuid, _>("quality_event_id")? != quality.update.event_id
        {
            return Err(OperatorQualityError::IdempotencyConflict);
        }
        let evaluator_key_fingerprint = row.try_get::<String, _>("evaluator_key_fingerprint")?;
        let fingerprint = request_fingerprint(&prepared, &evaluator_key_fingerprint, request)?;
        let same = row.try_get::<Uuid, _>("model_id")? == statement.model_id
            && row.try_get::<String, _>("evaluator_id")? == statement.evaluator_id
            && row.try_get::<String, _>("operator_id")? == request.operator_id
            && row.try_get::<String, _>("reason")? == request.reason
            && row.try_get::<String, _>("event_kind")? == event_kind
            && row.try_get::<String, _>("idempotency_key")? == statement.idempotency_key
            && row.try_get::<String, _>("request_fingerprint")? == fingerprint
            && row.try_get::<String, _>("evidence_schema")? == statement.schema
            && row.try_get::<String, _>("statement_json")? == prepared.canonical_statement
            && row.try_get::<String, _>("statement_sha256")? == prepared.statement_sha256
            && row.try_get::<String, _>("artifact_sha256")? == statement.artifact_sha256
            && row.try_get::<String, _>("signature_hex")? == prepared.envelope.signature;
        if !same {
            return Err(OperatorQualityError::IdempotencyConflict);
        }
        let result = OperatorQualityRecordResult {
            evidence_audit_id: row.try_get("id")?,
            evaluator_id: statement.evaluator_id.clone(),
            evaluator_key_fingerprint,
            statement_sha256: prepared.statement_sha256.clone(),
            artifact_sha256: statement.artifact_sha256.clone(),
            quality: quality.update,
            idempotent_replay: true,
        };
        tx.commit().await?;
        return Ok(result);
    }

    let legacy_event_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM model_quality_events WHERE idempotency_key=$1)",
    )
    .bind(&statement.idempotency_key)
    .fetch_one(&mut *tx)
    .await?;
    if legacy_event_exists {
        return Err(OperatorQualityError::IdempotencyConflict);
    }

    let verification = verify_prepared_evidence(
        &prepared,
        &request.trusted_keys_dir,
        OffsetDateTime::now_utc(),
    )?;
    let fingerprint =
        request_fingerprint(&prepared, &verification.evaluator_key_fingerprint, request)?;
    let quality = record_trusted_event_in_transaction(&mut tx, event).await?;
    if quality.idempotent_replay {
        return Err(OperatorQualityError::IdempotencyConflict);
    }

    let evidence_audit_id = Uuid::now_v7();
    let observed_at = parse_timestamp(&statement.observed_at, "observed_at")?;
    let valid_until = parse_timestamp(&statement.valid_until, "valid_until")?;
    sqlx::query(
        r#"
        INSERT INTO quality_evidence_audits
            (id,quality_event_id,model_id,evaluator_id,operator_id,reason,event_kind,
             idempotency_key,request_fingerprint,evidence_schema,statement_json,statement_sha256,
             artifact_sha256,evaluator_key_fingerprint,signature_hex,observed_at,
             valid_until,verified_at)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        "#,
    )
    .bind(evidence_audit_id)
    .bind(quality.update.event_id)
    .bind(statement.model_id)
    .bind(&statement.evaluator_id)
    .bind(&request.operator_id)
    .bind(&request.reason)
    .bind(event_kind)
    .bind(&statement.idempotency_key)
    .bind(&fingerprint)
    .bind(&statement.schema)
    .bind(&prepared.canonical_statement)
    .bind(&prepared.statement_sha256)
    .bind(&statement.artifact_sha256)
    .bind(&verification.evaluator_key_fingerprint)
    .bind(&prepared.envelope.signature)
    .bind(observed_at)
    .bind(valid_until)
    .bind(verification.verified_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(OperatorQualityRecordResult {
        evidence_audit_id,
        evaluator_id: statement.evaluator_id.clone(),
        evaluator_key_fingerprint: verification.evaluator_key_fingerprint,
        statement_sha256: prepared.statement_sha256.clone(),
        artifact_sha256: statement.artifact_sha256.clone(),
        quality: quality.update,
        idempotent_replay: false,
    })
}

fn prepare_evidence_files(
    evidence_path: &Path,
    artifact_path: &Path,
) -> Result<PreparedQualityEvidence, OperatorQualityError> {
    let evidence_bytes = read_bounded_regular_file(
        evidence_path,
        MAX_EVIDENCE_MANIFEST_BYTES,
        "evidence manifest",
    )?;
    let envelope: SignedQualityEvidence =
        serde_json::from_slice(&evidence_bytes).map_err(|error| {
            OperatorQualityError::InvalidFile(format!("evidence manifest JSON 无效：{error}"))
        })?;
    let artifact_sha256 = hash_bounded_regular_file(artifact_path)?;
    if artifact_sha256 != envelope.statement.artifact_sha256 {
        return Err(OperatorQualityError::InvalidFile(
            "artifact SHA-256 与签名 statement 不一致".to_owned(),
        ));
    }
    let canonical_statement = serde_json::to_string(&envelope.statement).map_err(|error| {
        OperatorQualityError::InvalidInput(format!("无法规范化 evidence statement：{error}"))
    })?;
    let statement_sha256 = hex::encode(Sha256::digest(canonical_statement.as_bytes()));
    Ok(PreparedQualityEvidence {
        envelope,
        canonical_statement,
        statement_sha256,
    })
}

fn verify_prepared_evidence(
    prepared: &PreparedQualityEvidence,
    trusted_keys_dir: &Path,
    now: OffsetDateTime,
) -> Result<QualityEvidenceVerification, OperatorQualityError> {
    validate_statement(&prepared.envelope.statement, now)?;
    let verifying_key =
        load_trusted_evaluator_key(trusted_keys_dir, &prepared.envelope.statement.evaluator_id)?;
    let message = quality_evidence_signing_message(&prepared.envelope.statement)?;
    let signature = decode_signature(&prepared.envelope.signature)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| OperatorQualityError::SignatureInvalid)?;
    Ok(QualityEvidenceVerification {
        evaluator_key_fingerprint: hex::encode(Sha256::digest(verifying_key.as_bytes())),
        verified_at: now,
    })
}

fn validate_statement(
    statement: &QualityEvidenceStatement,
    now: OffsetDateTime,
) -> Result<(), OperatorQualityError> {
    let (observed_at, valid_until) = validate_statement_shape(statement)?;
    if observed_at > now + MAX_CLOCK_SKEW {
        return Err(OperatorQualityError::InvalidInput(
            "observed_at 超出允许的未来时钟偏差".to_owned(),
        ));
    }
    if valid_until <= now {
        return Err(OperatorQualityError::InvalidInput(
            "quality evidence 已过期".to_owned(),
        ));
    }
    Ok(())
}

fn validate_statement_shape(
    statement: &QualityEvidenceStatement,
) -> Result<(OffsetDateTime, OffsetDateTime), OperatorQualityError> {
    if statement.schema != QUALITY_EVIDENCE_SCHEMA {
        return Err(OperatorQualityError::InvalidInput(
            "evidence schema 不受支持".to_owned(),
        ));
    }
    if !valid_evaluator_id(&statement.evaluator_id) {
        return Err(OperatorQualityError::InvalidInput(
            "evaluator_id 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
        ));
    }
    validate_sha256(&statement.artifact_sha256, "artifact_sha256")?;
    let observed_at = parse_timestamp(&statement.observed_at, "observed_at")?;
    let valid_until = parse_timestamp(&statement.valid_until, "valid_until")?;
    if valid_until <= observed_at {
        return Err(OperatorQualityError::InvalidInput(
            "quality evidence 有效期无效".to_owned(),
        ));
    }
    let validity = valid_until - observed_at;
    if validity > MAX_EVIDENCE_VALIDITY {
        return Err(OperatorQualityError::InvalidInput(
            "quality evidence 有效期不得超过 24 小时".to_owned(),
        ));
    }
    Ok((observed_at, valid_until))
}

fn parse_timestamp(value: &str, field: &str) -> Result<OffsetDateTime, OperatorQualityError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| OperatorQualityError::InvalidInput(format!("{field} 必须是 RFC 3339 时间")))
}

fn load_trusted_evaluator_key(
    trusted_keys_dir: &Path,
    evaluator_id: &str,
) -> Result<VerifyingKey, OperatorQualityError> {
    let directory = canonical_trusted_directory(trusted_keys_dir)?;
    let key_path = directory.join(format!("{evaluator_id}.pub"));
    let key_file = secure_read_bounded_regular_file(&key_path, 256)
        .map_err(|error| OperatorQualityError::InvalidFile(format!("evaluator 公钥：{error}")))?;
    reject_group_or_world_writable(key_file.metadata(), "evaluator 公钥")?;
    let key_bytes = key_file.into_bytes();
    let key_text = std::str::from_utf8(&key_bytes)
        .map_err(|_| OperatorQualityError::SignatureInvalid)?
        .trim();
    if key_text.len() != 64
        || !key_text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OperatorQualityError::SignatureInvalid);
    }
    let mut raw = [0_u8; 32];
    hex::decode_to_slice(key_text, &mut raw).map_err(|_| OperatorQualityError::SignatureInvalid)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| OperatorQualityError::SignatureInvalid)
}

fn canonical_trusted_directory(path: &Path) -> Result<PathBuf, OperatorQualityError> {
    if !path.is_absolute() {
        return Err(OperatorQualityError::InvalidFile(
            "trusted evaluator keys 目录必须是绝对路径".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        OperatorQualityError::InvalidFile("trusted evaluator keys 目录不可访问".to_owned())
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(OperatorQualityError::InvalidFile(
            "trusted evaluator keys 路径必须是非符号链接目录".to_owned(),
        ));
    }
    reject_group_or_world_writable(&metadata, "trusted evaluator keys 目录")?;
    let canonical = fs::canonicalize(path).map_err(|_| {
        OperatorQualityError::InvalidFile("无法规范化 trusted evaluator keys 目录".to_owned())
    })?;
    if canonical != path {
        return Err(OperatorQualityError::InvalidFile(
            "trusted evaluator keys 目录必须使用规范绝对路径且父链不得含符号链接".to_owned(),
        ));
    }
    reject_insecure_directory_chain(&canonical, "trusted evaluator keys 目录")?;
    Ok(canonical)
}

#[cfg(unix)]
fn reject_insecure_directory_chain(path: &Path, label: &str) -> Result<(), OperatorQualityError> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| {
            OperatorQualityError::InvalidFile(format!("无法检查{label}的父目录权限"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(OperatorQualityError::InvalidFile(format!(
                "{label}的父链必须全部是非符号链接目录"
            )));
        }
        reject_group_or_world_writable(&metadata, label)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_directory_chain(_path: &Path, _label: &str) -> Result<(), OperatorQualityError> {
    Ok(())
}

fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>, OperatorQualityError> {
    secure_read_bounded_regular_file(path, maximum_bytes)
        .map(|contents| contents.into_bytes())
        .map_err(|error| OperatorQualityError::InvalidFile(format!("{label}：{error}")))
}

fn hash_bounded_regular_file(path: &Path) -> Result<String, OperatorQualityError> {
    let digest =
        secure_sha256_bounded_regular_file(path, MAX_EVIDENCE_ARTIFACT_BYTES).map_err(|error| {
            OperatorQualityError::InvalidFile(format!("evidence artifact：{error}"))
        })?;
    if digest.size_bytes == 0 {
        return Err(OperatorQualityError::InvalidFile(
            "evidence artifact 不能为空".to_owned(),
        ));
    }
    Ok(digest.sha256)
}

#[cfg(unix)]
fn reject_group_or_world_writable(
    metadata: &fs::Metadata,
    label: &str,
) -> Result<(), OperatorQualityError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(OperatorQualityError::InvalidFile(format!(
            "{label}不得允许 group/other 写入"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_group_or_world_writable(
    _metadata: &fs::Metadata,
    _label: &str,
) -> Result<(), OperatorQualityError> {
    Ok(())
}

fn decode_signature(value: &str) -> Result<Signature, OperatorQualityError> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OperatorQualityError::SignatureInvalid);
    }
    let mut raw = [0_u8; 64];
    hex::decode_to_slice(value, &mut raw).map_err(|_| OperatorQualityError::SignatureInvalid)?;
    Ok(Signature::from_bytes(&raw))
}

fn validate_operator(operator_id: &str, reason: &str) -> Result<(), OperatorQualityError> {
    if !valid_operator_id(operator_id) {
        return Err(OperatorQualityError::InvalidInput(
            "operator 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
        ));
    }
    let reason_chars = reason.chars().count();
    if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&reason_chars)
        || reason.trim() != reason
        || reason.chars().any(char::is_control)
    {
        return Err(OperatorQualityError::InvalidInput(format!(
            "reason 必须是 {MIN_REASON_CHARS} 到 {MAX_REASON_CHARS} 个字符、无首尾空白或控制字符"
        )));
    }
    Ok(())
}

fn valid_evaluator_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_operator_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_IDENTIFIER_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'@' | b'/' | b'-')
        })
}

fn validate_sha256(value: &str, field: &str) -> Result<(), OperatorQualityError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(OperatorQualityError::InvalidInput(format!(
            "{field} 必须是 64 位小写 SHA-256"
        )));
    }
    Ok(())
}

fn request_fingerprint(
    prepared: &PreparedQualityEvidence,
    evaluator_key_fingerprint: &str,
    request: &OperatorQualityRecordRequest,
) -> Result<String, OperatorQualityError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        statement_sha256: &'a str,
        artifact_sha256: &'a str,
        evaluator_key_fingerprint: &'a str,
        signature_hex: &'a str,
        operator_id: &'a str,
        reason: &'a str,
    }
    let payload = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        statement_sha256: &prepared.statement_sha256,
        artifact_sha256: &prepared.envelope.statement.artifact_sha256,
        evaluator_key_fingerprint,
        signature_hex: &prepared.envelope.signature,
        operator_id: &request.operator_id,
        reason: &request.reason,
    })
    .map_err(|error| OperatorQualityError::InvalidInput(format!("无法计算请求指纹：{error}")))?;
    Ok(hex::encode(Sha256::digest(payload)))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use time::format_description::well_known::Rfc3339;

    use super::*;

    fn secure_tempdir() -> tempfile::TempDir {
        let parent = fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("crate 目录应可规范化");
        tempfile::Builder::new()
            .prefix(".mindone-quality-test-")
            .tempdir_in(parent)
            .expect("应在权限受控的 crate 目录创建临时目录")
    }

    fn statement(artifact_sha256: String) -> QualityEvidenceStatement {
        let now = OffsetDateTime::now_utc();
        QualityEvidenceStatement {
            schema: QUALITY_EVIDENCE_SCHEMA.to_owned(),
            evaluator_id: "trusted-evaluator-1".to_owned(),
            model_id: Uuid::nil(),
            idempotency_key: "quality-test-1".to_owned(),
            observed_at: now.format(&Rfc3339).expect("测试时间应可格式化"),
            valid_until: (now + Duration::hours(1))
                .format(&Rfc3339)
                .expect("测试时间应可格式化"),
            artifact_sha256,
            measurement: QualityEvidenceMeasurement::HiddenBenchmark {
                score_normalized: 700_000,
                sample_count: 20,
            },
        }
    }

    #[test]
    fn signature_binds_statement_and_real_artifact() {
        let directory = secure_tempdir();
        let directory_path = fs::canonicalize(directory.path()).expect("临时目录应可规范化");
        let keys = directory_path.join("keys");
        fs::create_dir(&keys).expect("应创建 keys 目录");
        let artifact = directory_path.join("artifact.bin");
        fs::write(&artifact, b"independent evaluator artifact").expect("应写入测试 artifact");
        let artifact_hash = hex::encode(Sha256::digest(b"independent evaluator artifact"));
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        fs::write(
            keys.join("trusted-evaluator-1.pub"),
            hex::encode(signing_key.verifying_key().to_bytes()),
        )
        .expect("应写入测试公钥");
        let statement = statement(artifact_hash);
        let signature = signing_key
            .sign(&quality_evidence_signing_message(&statement).expect("应生成签名消息"));
        let envelope = SignedQualityEvidence {
            statement,
            signature: hex::encode(signature.to_bytes()),
        };
        let evidence = directory_path.join("evidence.json");
        fs::write(
            &evidence,
            serde_json::to_vec(&envelope).expect("应编码测试 evidence"),
        )
        .expect("应写入测试 evidence");

        let prepared = prepare_evidence_files(&evidence, &artifact)
            .expect("artifact 匹配的 evidence 应可准备");
        verify_prepared_evidence(&prepared, &keys, OffsetDateTime::now_utc())
            .expect("签名且 artifact 匹配的 evidence 应通过");
        assert_eq!(prepared.envelope, envelope);

        fs::write(&artifact, b"tampered artifact").expect("应篡改测试 artifact");
        assert!(prepare_evidence_files(&evidence, &artifact).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn manifest_and_artifact_reject_final_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = secure_tempdir();
        let root = fs::canonicalize(directory.path()).expect("临时目录应可规范化");
        let real_directory = root.join("real");
        fs::create_dir(&real_directory).expect("应创建真实目录");
        let manifest = real_directory.join("evidence.json");
        let artifact = real_directory.join("artifact.bin");
        fs::write(&manifest, b"{}").expect("应写入测试 manifest");
        fs::write(&artifact, b"artifact").expect("应写入测试 artifact");

        let manifest_link = root.join("evidence-link.json");
        symlink(&manifest, &manifest_link).expect("应创建 manifest 符号链接");
        assert!(read_bounded_regular_file(
            &manifest_link,
            MAX_EVIDENCE_MANIFEST_BYTES,
            "evidence manifest"
        )
        .is_err());

        let parent_link = root.join("parent-link");
        symlink(&real_directory, &parent_link).expect("应创建父目录符号链接");
        assert!(hash_bounded_regular_file(&parent_link.join("artifact.bin")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_key_directory_rejects_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let directory = secure_tempdir();
        let root = fs::canonicalize(directory.path()).expect("临时目录应可规范化");
        let writable_parent = root.join("writable-parent");
        let keys = writable_parent.join("keys");
        fs::create_dir_all(&keys).expect("应创建嵌套 keys 目录");
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
            .expect("应能设置不安全父目录权限");
        assert!(canonical_trusted_directory(&keys).is_err());
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o700))
            .expect("应恢复安全权限以清理临时目录");
    }

    #[test]
    fn statement_rejects_expired_or_overlong_validity() {
        let now = OffsetDateTime::now_utc();
        let mut expired = statement("0".repeat(64));
        expired.observed_at = (now - Duration::hours(2))
            .format(&Rfc3339)
            .expect("应格式化时间");
        expired.valid_until = (now - Duration::hours(1))
            .format(&Rfc3339)
            .expect("应格式化时间");
        assert!(validate_statement(&expired, now).is_err());

        let mut long = statement("0".repeat(64));
        long.observed_at = now.format(&Rfc3339).expect("应格式化时间");
        long.valid_until = (now + Duration::hours(25))
            .format(&Rfc3339)
            .expect("应格式化时间");
        assert!(validate_statement(&long, now).is_err());
    }
}
