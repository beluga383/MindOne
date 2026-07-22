use std::path::{Path, PathBuf};

use mindone_accounting::{
    maximum_reservation_micro, ServerReferenceBillingProfile, SERVER_REFERENCE_UPPER_BOUND_V1,
};
use mindone_common::sha256_bounded_regular_file;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MIN_REASON_CHARS: usize = 8;
const MAX_REASON_CHARS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorBillingProfileRequest {
    pub model_id: Uuid,
    pub profile_version: i64,
    pub reference_hardware_class: String,
    pub maximum_input_tokens: i64,
    pub maximum_output_tokens: i64,
    pub fixed_gpu_time_us: i64,
    pub gpu_time_us_per_1k_tokens: i64,
    pub reference_vram_mib: i64,
    pub token_rate_micro_per_1k: i64,
    pub gpu_rate_micro_per_second: i64,
    pub vram_rate_micro_per_gib_second: i64,
    pub evidence_path: PathBuf,
    pub valid_from: OffsetDateTime,
    pub valid_until: OffsetDateTime,
    pub operator_id: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorBillingProfileResult {
    pub audit_id: Uuid,
    pub profile_id: Uuid,
    pub contract_version: &'static str,
    pub model_id: Uuid,
    pub model_weights_hash: String,
    pub profile_version: i64,
    pub profile_fingerprint: String,
    pub request_fingerprint: String,
    pub evidence_sha256: String,
    pub valid_from: OffsetDateTime,
    pub valid_until: OffsetDateTime,
    pub maximum_reservation_micro: i64,
    pub created_at: OffsetDateTime,
    pub idempotent_replay: bool,
}

#[derive(Debug, Error)]
pub enum OperatorBillingProfileError {
    #[error("计费 profile 参数无效：{0}")]
    InvalidInput(String),
    #[error("计费 profile evidence 文件无效：{0}")]
    InvalidEvidence(String),
    #[error("模型不存在：{0}")]
    ModelNotFound(Uuid),
    #[error("幂等键已用于不同的计费 profile 请求")]
    IdempotencyConflict,
    #[error("该模型的 profile version 已存在")]
    ProfileVersionConflict,
    #[error("计费 profile 上界校验失败：{0}")]
    Accounting(#[source] mindone_accounting::AccountingError),
    #[error("计费 profile 数据库操作失败")]
    Database(#[from] sqlx::Error),
}

impl OperatorBillingProfileRequest {
    pub fn validate(&self) -> Result<i64, OperatorBillingProfileError> {
        if self.profile_version <= 0 {
            return Err(OperatorBillingProfileError::InvalidInput(
                "profile_version 必须大于零".to_owned(),
            ));
        }
        if self.reference_hardware_class.is_empty()
            || self.reference_hardware_class.len() > MAX_IDENTIFIER_BYTES
            || self.reference_hardware_class.trim() != self.reference_hardware_class
            || self.reference_hardware_class.chars().any(char::is_control)
        {
            return Err(OperatorBillingProfileError::InvalidInput(
                "reference_hardware_class 必须是 1 到 128 字节、无首尾空白或控制字符".to_owned(),
            ));
        }
        if !valid_ascii_identifier(&self.operator_id) {
            return Err(OperatorBillingProfileError::InvalidInput(
                "operator 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
            ));
        }
        if !valid_ascii_identifier(&self.idempotency_key) {
            return Err(OperatorBillingProfileError::InvalidInput(
                "idempotency_key 必须是 1 到 128 字节的安全 ASCII 标识符".to_owned(),
            ));
        }
        let reason_chars = self.reason.chars().count();
        if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&reason_chars)
            || self.reason.trim() != self.reason
            || self.reason.chars().any(char::is_control)
        {
            return Err(OperatorBillingProfileError::InvalidInput(format!(
                "reason 必须是 {MIN_REASON_CHARS} 到 {MAX_REASON_CHARS} 个字符、无首尾空白或控制字符"
            )));
        }
        if self.valid_until <= self.valid_from {
            return Err(OperatorBillingProfileError::InvalidInput(
                "valid_until 必须晚于 valid_from".to_owned(),
            ));
        }
        validate_postgres_timestamp_precision(self.valid_from, "valid_from")?;
        validate_postgres_timestamp_precision(self.valid_until, "valid_until")?;

        let profile = self.billing_profile();
        maximum_reservation_micro(
            profile,
            self.maximum_input_tokens,
            self.maximum_output_tokens,
        )
        .map(|amount| amount.as_i64())
        .map_err(OperatorBillingProfileError::Accounting)
    }

    fn billing_profile(&self) -> ServerReferenceBillingProfile {
        ServerReferenceBillingProfile {
            maximum_input_tokens: self.maximum_input_tokens,
            maximum_output_tokens: self.maximum_output_tokens,
            fixed_gpu_time_us: self.fixed_gpu_time_us,
            gpu_time_us_per_1k_tokens: self.gpu_time_us_per_1k_tokens,
            reference_vram_mib: self.reference_vram_mib,
            token_rate_micro_per_1k: self.token_rate_micro_per_1k,
            gpu_rate_micro_per_second: self.gpu_rate_micro_per_second,
            vram_rate_micro_per_gib_second: self.vram_rate_micro_per_gib_second,
        }
    }
}

/// 协调服务器二进制专用的 production profile 写入口；不注册 HTTP 路由，
/// 也不暴露在用户 `mindone` CLI。evidence 本地路径只用于读取，数据库仅保存内容哈希。
pub async fn record_operator_billing_profile(
    pool: &PgPool,
    request: &OperatorBillingProfileRequest,
) -> Result<OperatorBillingProfileResult, OperatorBillingProfileError> {
    let maximum_reservation_micro = request.validate()?;
    let evidence_sha256 = hash_evidence_file(&request.evidence_path)?;
    let request_fingerprint = request_fingerprint(request, &evidence_sha256)?;
    let profile_id = Uuid::now_v7();
    let audit_id = Uuid::now_v7();

    // 0033 revokes direct billing_profiles INSERT from mindone_app. This
    // SECURITY DEFINER function is the single atomic profile + audit boundary;
    // it also calls mindone_billing_profile_fingerprint_v1 inside PostgreSQL.
    let row = sqlx::query(
        r#"
        SELECT out_audit_id,out_profile_id,out_model_weights_hash,
               out_profile_fingerprint,out_created_at,out_idempotent_replay
        FROM mindone_record_billing_profile_v1(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            $11,$12,$13,$14,$15,$16,$17,$18,$19,$20
        )
        "#,
    )
    .bind(profile_id)
    .bind(audit_id)
    .bind(request.model_id)
    .bind(request.profile_version)
    .bind(&request.reference_hardware_class)
    .bind(request.maximum_input_tokens)
    .bind(request.maximum_output_tokens)
    .bind(request.fixed_gpu_time_us)
    .bind(request.gpu_time_us_per_1k_tokens)
    .bind(request.reference_vram_mib)
    .bind(request.token_rate_micro_per_1k)
    .bind(request.gpu_rate_micro_per_second)
    .bind(request.vram_rate_micro_per_gib_second)
    .bind(&evidence_sha256)
    .bind(request.valid_from)
    .bind(request.valid_until)
    .bind(&request.operator_id)
    .bind(&request.reason)
    .bind(&request.idempotency_key)
    .bind(&request_fingerprint)
    .fetch_one(pool)
    .await
    .map_err(|error| map_database_error(error, request.model_id))?;

    Ok(OperatorBillingProfileResult {
        audit_id: row.try_get("out_audit_id")?,
        profile_id: row.try_get("out_profile_id")?,
        contract_version: SERVER_REFERENCE_UPPER_BOUND_V1,
        model_id: request.model_id,
        model_weights_hash: row.try_get("out_model_weights_hash")?,
        profile_version: request.profile_version,
        profile_fingerprint: row.try_get("out_profile_fingerprint")?,
        request_fingerprint,
        evidence_sha256,
        valid_from: request.valid_from,
        valid_until: request.valid_until,
        maximum_reservation_micro,
        created_at: row.try_get("out_created_at")?,
        idempotent_replay: row.try_get("out_idempotent_replay")?,
    })
}

fn map_database_error(error: sqlx::Error, model_id: Uuid) -> OperatorBillingProfileError {
    if let sqlx::Error::Database(database) = &error {
        let message = database.message().to_owned();
        return match message.as_str() {
            "billing profile idempotency conflict" => {
                OperatorBillingProfileError::IdempotencyConflict
            }
            "billing profile version conflict" => {
                OperatorBillingProfileError::ProfileVersionConflict
            }
            "billing profile model does not exist" => {
                OperatorBillingProfileError::ModelNotFound(model_id)
            }
            _ => OperatorBillingProfileError::Database(error),
        };
    }
    OperatorBillingProfileError::Database(error)
}

fn validate_postgres_timestamp_precision(
    value: OffsetDateTime,
    field: &str,
) -> Result<(), OperatorBillingProfileError> {
    if value.nanosecond() % 1_000 != 0 {
        return Err(OperatorBillingProfileError::InvalidInput(format!(
            "{field} 最多允许微秒精度"
        )));
    }
    unix_timestamp_microseconds(value).map(|_| ())
}

fn unix_timestamp_microseconds(value: OffsetDateTime) -> Result<i64, OperatorBillingProfileError> {
    i64::try_from(value.unix_timestamp_nanos() / 1_000).map_err(|_| {
        OperatorBillingProfileError::InvalidInput("时间超出 PostgreSQL 微秒范围".to_owned())
    })
}

fn hash_evidence_file(path: &Path) -> Result<String, OperatorBillingProfileError> {
    let digest = sha256_bounded_regular_file(path, MAX_EVIDENCE_BYTES).map_err(|error| {
        OperatorBillingProfileError::InvalidEvidence(format!("evidence_file：{error}"))
    })?;
    if digest.size_bytes == 0 {
        return Err(OperatorBillingProfileError::InvalidEvidence(
            "evidence_file 必须非空且不超过 1 GiB".to_owned(),
        ));
    }
    Ok(digest.sha256)
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

fn request_fingerprint(
    request: &OperatorBillingProfileRequest,
    evidence_sha256: &str,
) -> Result<String, OperatorBillingProfileError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        contract_version: &'static str,
        model_id: Uuid,
        profile_version: i64,
        reference_hardware_class: &'a str,
        maximum_input_tokens: i64,
        maximum_output_tokens: i64,
        fixed_gpu_time_us: i64,
        gpu_time_us_per_1k_tokens: i64,
        reference_vram_mib: i64,
        token_rate_micro_per_1k: i64,
        gpu_rate_micro_per_second: i64,
        vram_rate_micro_per_gib_second: i64,
        evidence_sha256: &'a str,
        valid_from_unix_us: i64,
        valid_until_unix_us: i64,
        operator_id: &'a str,
        reason: &'a str,
        idempotency_key: &'a str,
    }

    let payload = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        contract_version: SERVER_REFERENCE_UPPER_BOUND_V1,
        model_id: request.model_id,
        profile_version: request.profile_version,
        reference_hardware_class: &request.reference_hardware_class,
        maximum_input_tokens: request.maximum_input_tokens,
        maximum_output_tokens: request.maximum_output_tokens,
        fixed_gpu_time_us: request.fixed_gpu_time_us,
        gpu_time_us_per_1k_tokens: request.gpu_time_us_per_1k_tokens,
        reference_vram_mib: request.reference_vram_mib,
        token_rate_micro_per_1k: request.token_rate_micro_per_1k,
        gpu_rate_micro_per_second: request.gpu_rate_micro_per_second,
        vram_rate_micro_per_gib_second: request.vram_rate_micro_per_gib_second,
        evidence_sha256,
        valid_from_unix_us: unix_timestamp_microseconds(request.valid_from)?,
        valid_until_unix_us: unix_timestamp_microseconds(request.valid_until)?,
        operator_id: &request.operator_id,
        reason: &request.reason,
        idempotency_key: &request.idempotency_key,
    })
    .map_err(|error| {
        OperatorBillingProfileError::InvalidInput(format!("无法规范化计费 profile 请求：{error}"))
    })?;
    Ok(hex::encode(Sha256::digest(payload)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use time::format_description::well_known::Rfc3339;

    use super::*;

    fn timestamp(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &Rfc3339).expect("测试时间必须有效")
    }

    fn request() -> OperatorBillingProfileRequest {
        OperatorBillingProfileRequest {
            model_id: Uuid::nil(),
            profile_version: 1,
            reference_hardware_class: "nvidia-h100-sxm-80gb".to_owned(),
            maximum_input_tokens: 4_096,
            maximum_output_tokens: 1_024,
            fixed_gpu_time_us: 100_000,
            gpu_time_us_per_1k_tokens: 2_000_000,
            reference_vram_mib: 81_920,
            token_rate_micro_per_1k: 1_000,
            gpu_rate_micro_per_second: 2_000,
            vram_rate_micro_per_gib_second: 3_000,
            evidence_path: PathBuf::from("/unused/in-shape-tests"),
            valid_from: timestamp("2026-07-20T00:00:00Z"),
            valid_until: timestamp("2026-08-20T00:00:00Z"),
            operator_id: "ops/billing".to_owned(),
            reason: "根据独立硬件基准证据发布生产费率".to_owned(),
            idempotency_key: "billing-h100-2026-0001".to_owned(),
        }
    }

    #[test]
    fn validates_complete_profile_and_worst_case_reservation() {
        let maximum = request().validate().expect("完整 profile 应通过上界校验");
        assert!(maximum > 0);

        let mut invalid = request();
        invalid.maximum_output_tokens = 0;
        assert!(matches!(
            invalid.validate(),
            Err(OperatorBillingProfileError::Accounting(_))
        ));

        let mut invalid = request();
        invalid.valid_until = invalid.valid_from;
        assert!(matches!(
            invalid.validate(),
            Err(OperatorBillingProfileError::InvalidInput(_))
        ));

        let mut invalid = request();
        invalid.idempotency_key = "shell$meta".to_owned();
        assert!(matches!(
            invalid.validate(),
            Err(OperatorBillingProfileError::InvalidInput(_))
        ));
    }

    #[test]
    fn request_fingerprint_binds_every_semantic_field() {
        let original = request();
        let evidence = "11".repeat(32);
        let expected = request_fingerprint(&original, &evidence).expect("应生成请求指纹");

        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.model_id = Uuid::from_u128(1);
        variants.push(changed);
        let mut changed = original.clone();
        changed.profile_version += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.reference_hardware_class.push_str("-v2");
        variants.push(changed);
        let mut changed = original.clone();
        changed.maximum_input_tokens += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.maximum_output_tokens += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.fixed_gpu_time_us += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.gpu_time_us_per_1k_tokens += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.reference_vram_mib += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.token_rate_micro_per_1k += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.gpu_rate_micro_per_second += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.vram_rate_micro_per_gib_second += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.valid_from += time::Duration::microseconds(1);
        variants.push(changed);
        let mut changed = original.clone();
        changed.valid_until += time::Duration::microseconds(1);
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
    fn hashes_only_canonical_absolute_regular_evidence() {
        let directory_guard = tempfile::Builder::new()
            .prefix(".mindone-billing-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("应创建测试目录");
        let directory = fs::canonicalize(directory_guard.path()).expect("测试目录应规范化");
        let evidence = directory.join("evidence.txt");
        fs::write(&evidence, b"independent H100 benchmark evidence").expect("应写入测试证据");
        assert_eq!(
            hash_evidence_file(&evidence).expect("规范普通文件应可哈希"),
            hex::encode(Sha256::digest(b"independent H100 benchmark evidence"))
        );
        assert!(hash_evidence_file(Path::new("relative-evidence.txt")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn evidence_hash_rejects_final_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let directory_guard = tempfile::Builder::new()
            .prefix(".mindone-billing-symlink-test-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("应创建测试目录");
        let directory = fs::canonicalize(directory_guard.path()).expect("测试目录应规范化");
        let real_directory = directory.join("real");
        fs::create_dir(&real_directory).expect("应创建真实目录");
        let evidence = real_directory.join("evidence.txt");
        fs::write(&evidence, b"independent benchmark").expect("应写入测试证据");

        let final_link = directory.join("evidence-link.txt");
        symlink(&evidence, &final_link).expect("应创建 evidence 符号链接");
        assert!(hash_evidence_file(&final_link).is_err());

        let parent_link = directory.join("parent-link");
        symlink(&real_directory, &parent_link).expect("应创建父目录符号链接");
        assert!(hash_evidence_file(&parent_link.join("evidence.txt")).is_err());
    }
}
