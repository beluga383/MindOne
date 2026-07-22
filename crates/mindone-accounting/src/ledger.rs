use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{AccountingError, Result};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const LEDGER_HASH_VERSION: i16 = 2;

const LEDGER_HASH_DOMAIN: &str = "mindone-ledger";
const POSTGRES_EPOCH_UNIX_SECONDS: i128 = 946_684_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    ConsumerDeduction,
    NodeQuotaCredit,
    ContributionCredit,
    ReserveInflow,
    ReserveRelease,
    BootstrapGrant,
    OperatorGrant,
}

impl LedgerKind {
    const fn expects_debit(self) -> bool {
        matches!(self, Self::ConsumerDeduction | Self::ReserveRelease)
    }

    const fn scope(self) -> &'static str {
        match self {
            Self::ConsumerDeduction
            | Self::NodeQuotaCredit
            | Self::BootstrapGrant
            | Self::OperatorGrant => "quota",
            Self::ContributionCredit => "contribution",
            Self::ReserveInflow | Self::ReserveRelease => "reserve",
        }
    }

    fn entry_type(self, metadata: &BTreeMap<String, String>) -> Result<&str> {
        let fixed = match self {
            Self::ConsumerDeduction => Some("consumer_deduction"),
            Self::NodeQuotaCredit => Some("node_reward"),
            Self::ContributionCredit => Some("node_contribution"),
            Self::ReserveInflow => Some("settlement_inflow"),
            Self::BootstrapGrant => Some("bootstrap_grant"),
            Self::OperatorGrant => Some("operator_grant"),
            Self::ReserveRelease => None,
        };
        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
        metadata
            .get("purpose")
            .map(String::as_str)
            .filter(|purpose| {
                matches!(
                    *purpose,
                    "verification" | "retry" | "bandwidth" | "peak_capacity"
                )
            })
            .ok_or_else(|| {
                AccountingError::InvalidLedger(
                    "准备金释放账本缺少有效的 metadata.purpose".to_owned(),
                )
            })
    }
}

/// 可持久化的只追加账本记录。`hash` 覆盖其余全部字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub hash_version: i16,
    pub id: Uuid,
    pub account_id: Uuid,
    pub request_id: Option<Uuid>,
    pub idempotency_key: String,
    pub kind: LedgerKind,
    pub amount_micro: i64,
    pub balance_before_micro: i64,
    pub balance_after_micro: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub previous_hash: String,
    pub metadata: BTreeMap<String, String>,
    pub hash: String,
}

impl LedgerEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        account_id: Uuid,
        request_id: Option<Uuid>,
        idempotency_key: impl Into<String>,
        kind: LedgerKind,
        amount_micro: i64,
        balance_before_micro: i64,
        balance_after_micro: i64,
        created_at: OffsetDateTime,
        previous_hash: impl Into<String>,
        metadata: BTreeMap<String, String>,
    ) -> Result<Self> {
        let mut entry = Self {
            hash_version: LEDGER_HASH_VERSION,
            id,
            account_id,
            request_id,
            idempotency_key: idempotency_key.into(),
            kind,
            amount_micro,
            balance_before_micro,
            balance_after_micro,
            created_at,
            previous_hash: previous_hash.into(),
            metadata,
            hash: String::new(),
        };
        entry.validate_fields()?;
        entry.hash = entry.recompute_hash()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_fields()?;
        let expected = self.recompute_hash()?;
        if self.hash != expected {
            return Err(AccountingError::InvalidLedger(
                "记录哈希与规范化内容不一致".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn recompute_hash(&self) -> Result<String> {
        if self.hash_version != LEDGER_HASH_VERSION {
            return Err(AccountingError::InvalidLedger(format!(
                "不支持的账本哈希版本：{}",
                self.hash_version
            )));
        }
        let unix_nanos = self.created_at.unix_timestamp_nanos();
        // SQLx/PostgreSQL 按“距 2000-01-01 的整微秒”编码 timestamptz，负值向零
        // 截断；先复现该量化，再转回 Unix 微秒，才能让 2000 年前的边界值也与
        // 数据库实际持久化值完全一致。
        let postgres_epoch_unix_nanos = POSTGRES_EPOCH_UNIX_SECONDS * 1_000_000_000;
        let created_at_unix_micros = i64::try_from(
            (unix_nanos - postgres_epoch_unix_nanos) / 1_000
                + POSTGRES_EPOCH_UNIX_SECONDS * 1_000_000,
        )
        .map_err(|_| AccountingError::InvalidLedger("账本时间戳超出范围".to_owned()))?;
        let entry_type = self.kind.entry_type(&self.metadata)?;
        let mut bytes = Vec::with_capacity(512);
        append_canonical_field(&mut bytes, LEDGER_HASH_DOMAIN);
        append_canonical_field(&mut bytes, &self.hash_version.to_string());
        append_canonical_field(&mut bytes, self.kind.scope());
        append_canonical_field(&mut bytes, &self.id.to_string());
        append_canonical_field(&mut bytes, &self.account_id.to_string());
        let request_id = self.request_id.map(|request_id| request_id.to_string());
        append_canonical_field(&mut bytes, request_id.as_deref().unwrap_or(""));
        append_canonical_field(&mut bytes, &self.idempotency_key);
        append_canonical_field(&mut bytes, entry_type);
        append_canonical_field(&mut bytes, &self.amount_micro.to_string());
        append_canonical_field(&mut bytes, &self.balance_before_micro.to_string());
        append_canonical_field(&mut bytes, &self.balance_after_micro.to_string());
        append_canonical_field(&mut bytes, &created_at_unix_micros.to_string());
        append_canonical_field(&mut bytes, &self.previous_hash);
        append_canonical_field(&mut bytes, &self.metadata.len().to_string());
        for (key, value) in &self.metadata {
            append_canonical_field(&mut bytes, key);
            append_canonical_field(&mut bytes, value);
        }
        Ok(hex::encode(Sha256::digest(bytes)))
    }

    fn validate_fields(&self) -> Result<()> {
        if self.hash_version != LEDGER_HASH_VERSION {
            return Err(AccountingError::InvalidLedger(format!(
                "不支持的账本哈希版本：{}",
                self.hash_version
            )));
        }
        if !is_sha256(&self.previous_hash) {
            return Err(AccountingError::InvalidLedger(
                "previous_hash 必须是 64 位小写 SHA-256".to_owned(),
            ));
        }
        // 贡献权重可被反滥用策略降为 0；仍追加一条零额记录，才能把该次结算的
        // 幂等键和 canonical 证据纳入链。其它账本类型不得产生无意义零额记录。
        if self.amount_micro == 0 && self.kind != LedgerKind::ContributionCredit {
            return Err(AccountingError::InvalidLedger(
                "账本金额不得为零".to_owned(),
            ));
        }
        if self.idempotency_key.trim().is_empty()
            || self.idempotency_key.len() > 255
            || self.idempotency_key.chars().any(char::is_control)
        {
            return Err(AccountingError::InvalidLedger(
                "idempotency_key 为空或无效".to_owned(),
            ));
        }
        if self.kind.expects_debit() != self.amount_micro.is_negative() {
            return Err(AccountingError::InvalidLedger(format!(
                "账本类型 {:?} 的借贷方向错误",
                self.kind
            )));
        }
        if self.balance_before_micro < 0 || self.balance_after_micro < 0 {
            return Err(AccountingError::InvalidLedger(
                "账本前后余额不得为负".to_owned(),
            ));
        }
        let expected_after = self
            .balance_before_micro
            .checked_add(self.amount_micro)
            .ok_or(AccountingError::Overflow {
                operation: "账本余额计算",
            })?;
        if expected_after != self.balance_after_micro {
            return Err(AccountingError::InvalidLedger(
                "余额变化与账本金额不一致".to_owned(),
            ));
        }
        if self.metadata.iter().any(|(key, value)| {
            key.is_empty()
                || key.len() > 128
                || key.chars().any(char::is_control)
                || value.len() > 2_048
                || value.chars().any(char::is_control)
        }) {
            return Err(AccountingError::InvalidLedger(
                "metadata 键值为空或超过长度限制".to_owned(),
            ));
        }
        Ok(())
    }
}

fn append_canonical_field(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(value.len().to_string().as_bytes());
    output.push(b':');
    output.extend_from_slice(value.as_bytes());
}

pub fn validate_chain(entries: &[LedgerEntry]) -> Result<()> {
    let mut expected_previous = GENESIS_HASH;
    let mut previous_timestamp: Option<OffsetDateTime> = None;
    for entry in entries {
        entry.validate()?;
        if entry.previous_hash != expected_previous {
            return Err(AccountingError::InvalidLedger(format!(
                "记录 {} 未连接到前一条哈希",
                entry.id
            )));
        }
        if previous_timestamp.is_some_and(|timestamp| entry.created_at < timestamp) {
            return Err(AccountingError::InvalidLedger(
                "账本时间戳顺序倒退".to_owned(),
            ));
        }
        expected_previous = &entry.hash;
        previous_timestamp = Some(entry.created_at);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn entry(previous_hash: &str, before: i64, amount: i64, second: u8) -> LedgerEntry {
        LedgerEntry::new(
            Uuid::from_u128(u128::from(second) + 1),
            Uuid::from_u128(100),
            Some(Uuid::from_u128(200 + u128::from(second))),
            format!("entry-{second}"),
            if amount.is_negative() {
                LedgerKind::ConsumerDeduction
            } else {
                LedgerKind::NodeQuotaCredit
            },
            amount,
            before,
            before + amount,
            datetime!(2026-07-17 10:00 UTC) + time::Duration::seconds(i64::from(second)),
            previous_hash,
            BTreeMap::from([("source".to_owned(), "unit_test".to_owned())]),
        )
        .expect("测试账本应有效")
    }

    #[test]
    fn creates_and_validates_canonical_chain() {
        let first = entry(GENESIS_HASH, 2_000_000, -500_000, 0);
        let second = entry(&first.hash, 1_500_000, 200_000, 1);
        validate_chain(&[first, second]).expect("完整链应通过");
    }

    #[test]
    fn detects_content_and_link_tampering() {
        let first = entry(GENESIS_HASH, 2_000_000, -500_000, 0);
        let mut tampered = first.clone();
        tampered.balance_after_micro = 1_400_000;
        assert!(tampered.validate().is_err());

        let disconnected = entry(GENESIS_HASH, 1_500_000, 200_000, 1);
        assert!(validate_chain(&[first, disconnected]).is_err());
    }

    #[test]
    fn rejects_wrong_direction_and_zero_amount() {
        let wrong_direction = LedgerEntry::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            None,
            "wrong-direction",
            LedgerKind::ConsumerDeduction,
            1,
            0,
            1,
            datetime!(2026-07-17 10:00 UTC),
            GENESIS_HASH,
            BTreeMap::new(),
        );
        assert!(wrong_direction.is_err());
        let zero = LedgerEntry::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            None,
            "zero",
            LedgerKind::NodeQuotaCredit,
            0,
            0,
            0,
            datetime!(2026-07-17 10:00 UTC),
            GENESIS_HASH,
            BTreeMap::new(),
        );
        assert!(zero.is_err());
    }
}
