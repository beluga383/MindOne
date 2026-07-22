use std::collections::BTreeMap;

use mindone_accounting::{LedgerEntry, LedgerKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub const MAX_OPERATOR_GRANT_MICRO: i64 = 1_000_000_000_000;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MIN_REASON_CHARS: usize = 8;
const MAX_REASON_CHARS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorQuotaGrantRequest {
    pub user_id: Uuid,
    pub amount_micro: i64,
    pub idempotency_key: String,
    pub operator_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperatorQuotaGrantResult {
    pub grant_id: Uuid,
    pub user_id: Uuid,
    pub amount_micro: i64,
    pub balance_before_micro: i64,
    pub balance_after_micro: i64,
    pub quota_ledger_id: Uuid,
    pub quota_ledger_entry_hash: String,
    pub idempotent_replay: bool,
}

#[derive(Debug, Error)]
pub enum OperatorQuotaGrantError {
    #[error("赠额参数无效：{0}")]
    InvalidInput(String),
    #[error("用户不存在：{0}")]
    UserNotFound(Uuid),
    #[error("用户额度账户不存在：{0}")]
    AccountNotFound(Uuid),
    #[error("幂等键已用于不同的赠额请求")]
    IdempotencyConflict,
    #[error("赠额后的余额超出整数范围")]
    BalanceOverflow,
    #[error("赠额账本校验失败")]
    Accounting(#[source] mindone_accounting::AccountingError),
    #[error("数据库操作失败")]
    Database(#[source] sqlx::Error),
}

impl From<mindone_accounting::AccountingError> for OperatorQuotaGrantError {
    fn from(error: mindone_accounting::AccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<sqlx::Error> for OperatorQuotaGrantError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error)
    }
}

impl OperatorQuotaGrantRequest {
    pub fn validate(&self) -> Result<(), OperatorQuotaGrantError> {
        if !(1..=MAX_OPERATOR_GRANT_MICRO).contains(&self.amount_micro) {
            return Err(OperatorQuotaGrantError::InvalidInput(format!(
                "amount_micro 必须在 1..={MAX_OPERATOR_GRANT_MICRO}"
            )));
        }
        if !valid_ascii_identifier(&self.idempotency_key) {
            return Err(OperatorQuotaGrantError::InvalidInput(
                "idempotency_key 必须是 1 到 128 字节的 ASCII 标识符".to_owned(),
            ));
        }
        if !valid_ascii_identifier(&self.operator_id) {
            return Err(OperatorQuotaGrantError::InvalidInput(
                "operator 必须是 1 到 128 字节的 ASCII 标识符".to_owned(),
            ));
        }
        let reason_chars = self.reason.chars().count();
        if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&reason_chars)
            || self.reason.trim() != self.reason
            || self.reason.chars().any(char::is_control)
        {
            return Err(OperatorQuotaGrantError::InvalidInput(format!(
                "reason 必须是 {MIN_REASON_CHARS} 到 {MAX_REASON_CHARS} 个字符、无首尾空白或控制字符"
            )));
        }
        Ok(())
    }
}

/// 仅供持有协调服务器数据库环境的受控运维命令调用；不注册任何 HTTP 路由。
pub async fn grant_operator_quota(
    pool: &PgPool,
    request: &OperatorQuotaGrantRequest,
) -> Result<OperatorQuotaGrantResult, OperatorQuotaGrantError> {
    request.validate()?;
    let fingerprint = request_fingerprint(request)?;
    let ledger_idempotency_key = format!("operator-grant:{}", request.idempotency_key);
    let mut tx = pool.begin().await?;

    // 全局幂等键先串行化；哈希碰撞最多造成无害的额外串行等待。
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&request.idempotency_key)
        .execute(&mut *tx)
        .await?;

    if let Some(row) = sqlx::query(
        r#"
        SELECT g.id,g.user_id,g.operator_id,g.reason,g.amount_micro,
               g.request_fingerprint,g.quota_ledger_id,g.quota_ledger_entry_hash,
               q.balance_before_micro,q.balance_after_micro
        FROM operator_quota_grants g
        JOIN quota_ledger q ON q.id = g.quota_ledger_id
        WHERE g.idempotency_key = $1
        "#,
    )
    .bind(&request.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let same_request = row.try_get::<Uuid, _>("user_id")? == request.user_id
            && row.try_get::<i64, _>("amount_micro")? == request.amount_micro
            && row.try_get::<String, _>("operator_id")? == request.operator_id
            && row.try_get::<String, _>("reason")? == request.reason
            && row.try_get::<String, _>("request_fingerprint")? == fingerprint;
        if !same_request {
            return Err(OperatorQuotaGrantError::IdempotencyConflict);
        }
        let result = OperatorQuotaGrantResult {
            grant_id: row.try_get("id")?,
            user_id: request.user_id,
            amount_micro: request.amount_micro,
            balance_before_micro: row.try_get("balance_before_micro")?,
            balance_after_micro: row.try_get("balance_after_micro")?,
            quota_ledger_id: row.try_get("quota_ledger_id")?,
            quota_ledger_entry_hash: row.try_get("quota_ledger_entry_hash")?,
            idempotent_replay: true,
        };
        tx.commit().await?;
        return Ok(result);
    }

    let account = sqlx::query(
        r#"
        SELECT qa.spendable_micro,qa.quota_ledger_head_hash
        FROM users u
        JOIN quota_accounts qa ON qa.user_id = u.id
        WHERE u.id = $1
        FOR UPDATE OF u,qa
        "#,
    )
    .bind(request.user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(account) = account else {
        let user_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)")
                .bind(request.user_id)
                .fetch_one(&mut *tx)
                .await?;
        return Err(if user_exists {
            OperatorQuotaGrantError::AccountNotFound(request.user_id)
        } else {
            OperatorQuotaGrantError::UserNotFound(request.user_id)
        });
    };
    let balance_before_micro: i64 = account.try_get("spendable_micro")?;
    let balance_after_micro = balance_before_micro
        .checked_add(request.amount_micro)
        .ok_or(OperatorQuotaGrantError::BalanceOverflow)?;
    let previous_hash: String = account.try_get("quota_ledger_head_hash")?;

    let grant_id = Uuid::now_v7();
    let quota_ledger_id = Uuid::now_v7();
    let created_at = OffsetDateTime::now_utc();
    let ledger = LedgerEntry::new(
        quota_ledger_id,
        request.user_id,
        None,
        &ledger_idempotency_key,
        LedgerKind::OperatorGrant,
        request.amount_micro,
        balance_before_micro,
        balance_after_micro,
        created_at,
        previous_hash,
        BTreeMap::from([
            ("operator_id".to_owned(), request.operator_id.clone()),
            ("reason".to_owned(), request.reason.clone()),
        ]),
    )?;
    let ledger_metadata = serde_json::Value::Object(
        ledger
            .metadata
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    );

    // ledger insert trigger 会原子更新 spendable_micro, quota_ledger_head_hash 和 count
    sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(ledger.id)
    .bind(request.user_id)
    .bind(request.amount_micro)
    .bind(balance_before_micro)
    .bind(balance_after_micro)
    .bind(&ledger_idempotency_key)
    .bind(&ledger.previous_hash)
    .bind(&ledger.hash)
    .bind(ledger.hash_version)
    .bind(ledger_metadata)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO operator_quota_grants
            (id,user_id,operator_id,reason,amount_micro,idempotency_key,
             request_fingerprint,quota_ledger_id,quota_ledger_entry_hash,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(grant_id)
    .bind(request.user_id)
    .bind(&request.operator_id)
    .bind(&request.reason)
    .bind(request.amount_micro)
    .bind(&request.idempotency_key)
    .bind(&fingerprint)
    .bind(ledger.id)
    .bind(&ledger.hash)
    .bind(created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(OperatorQuotaGrantResult {
        grant_id,
        user_id: request.user_id,
        amount_micro: request.amount_micro,
        balance_before_micro,
        balance_after_micro,
        quota_ledger_id: ledger.id,
        quota_ledger_entry_hash: ledger.hash,
        idempotent_replay: false,
    })
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
    request: &OperatorQuotaGrantRequest,
) -> Result<String, OperatorQuotaGrantError> {
    #[derive(Serialize)]
    struct Fingerprint<'a> {
        schema_version: u8,
        user_id: Uuid,
        amount_micro: i64,
        idempotency_key: &'a str,
        operator_id: &'a str,
        reason: &'a str,
    }
    let payload = serde_json::to_vec(&Fingerprint {
        schema_version: 1,
        user_id: request.user_id,
        amount_micro: request.amount_micro,
        idempotency_key: &request.idempotency_key,
        operator_id: &request.operator_id,
        reason: &request.reason,
    })
    .map_err(|error| {
        OperatorQuotaGrantError::InvalidInput(format!("无法规范化赠额请求：{error}"))
    })?;
    Ok(hex::encode(Sha256::digest(payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> OperatorQuotaGrantRequest {
        OperatorQuotaGrantRequest {
            user_id: Uuid::nil(),
            amount_micro: 1_000_000,
            idempotency_key: "launch-2026-0001".to_owned(),
            operator_id: "ops/oncall@example.com".to_owned(),
            reason: "生产网络首批供应启动额度".to_owned(),
        }
    }

    #[test]
    fn validates_strict_operator_grant_boundaries() {
        assert!(request().validate().is_ok());
        for amount in [i64::MIN, -1, 0, MAX_OPERATOR_GRANT_MICRO + 1] {
            let mut invalid = request();
            invalid.amount_micro = amount;
            assert!(matches!(
                invalid.validate(),
                Err(OperatorQuotaGrantError::InvalidInput(_))
            ));
        }
        for identifier in ["", " space", "非ascii", "has space", "shell$meta"] {
            let mut invalid = request();
            invalid.operator_id = identifier.to_owned();
            assert!(matches!(
                invalid.validate(),
                Err(OperatorQuotaGrantError::InvalidInput(_))
            ));
        }
        let mut short_reason = request();
        short_reason.reason = "太短".to_owned();
        assert!(short_reason.validate().is_err());
        let mut padded_reason = request();
        padded_reason.reason = " 生产网络首批供应启动额度".to_owned();
        assert!(padded_reason.validate().is_err());
    }

    #[test]
    fn fingerprint_binds_every_request_field() {
        let original = request();
        let expected = request_fingerprint(&original).expect("有效请求应可计算指纹");
        let mut changed = original.clone();
        changed.reason.push('。');
        assert_ne!(
            expected,
            request_fingerprint(&changed).expect("变更请求也应可计算指纹")
        );
    }
}
