use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{AccountingError, MicroQuota, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservePurpose {
    ResultValidation,
    FailedRetry,
    BandwidthSubsidy,
    PeakGuarantee,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveRelease {
    pub id: Uuid,
    pub purpose: ReservePurpose,
    pub amount: MicroQuota,
    pub reference_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub balance_before: MicroQuota,
    pub balance_after: MicroQuota,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveState {
    pub balance: MicroQuota,
    pub total_inflow: MicroQuota,
    pub total_outflow: MicroQuota,
}

impl Default for ReserveState {
    fn default() -> Self {
        Self {
            balance: MicroQuota::zero(),
            total_inflow: MicroQuota::zero(),
            total_outflow: MicroQuota::zero(),
        }
    }
}

impl ReserveState {
    pub fn add_inflow(&mut self, amount: MicroQuota) -> Result<()> {
        if amount == MicroQuota::zero() {
            return Err(AccountingError::InvalidReserveRelease(
                "准备金流入不得为零".to_owned(),
            ));
        }
        self.balance = self.balance.checked_add(amount)?;
        self.total_inflow = self.total_inflow.checked_add(amount)?;
        Ok(())
    }

    pub fn release(
        &mut self,
        id: Uuid,
        purpose: ReservePurpose,
        amount: MicroQuota,
        reference_id: impl Into<String>,
        created_at: OffsetDateTime,
    ) -> Result<ReserveRelease> {
        if amount == MicroQuota::zero() {
            return Err(AccountingError::InvalidReserveRelease(
                "准备金释放金额不得为零".to_owned(),
            ));
        }
        let reference_id = reference_id.into();
        if reference_id.trim().is_empty()
            || reference_id.len() > 255
            || reference_id.chars().any(char::is_control)
        {
            return Err(AccountingError::InvalidReserveRelease(
                "准备金释放必须包含有效审计引用".to_owned(),
            ));
        }

        let balance_before = self.balance;
        let balance_after = self.balance.checked_sub(amount)?;
        let total_outflow = self.total_outflow.checked_add(amount)?;
        self.balance = balance_after;
        self.total_outflow = total_outflow;

        Ok(ReserveRelease {
            id,
            purpose,
            amount,
            reference_id,
            created_at,
            balance_before,
            balance_after,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn only_releases_audited_available_reserve() {
        let mut reserve = ReserveState::default();
        reserve
            .add_inflow(MicroQuota::new(1_000).expect("金额有效"))
            .expect("流入应成功");
        let release = reserve
            .release(
                Uuid::from_u128(1),
                ReservePurpose::FailedRetry,
                MicroQuota::new(400).expect("金额有效"),
                "job-attempt-2",
                datetime!(2026-07-17 10:00 UTC),
            )
            .expect("合法释放应成功");
        assert_eq!(release.balance_after.as_i64(), 600);
        assert_eq!(reserve.total_outflow.as_i64(), 400);
        assert!(reserve
            .release(
                Uuid::from_u128(2),
                ReservePurpose::PeakGuarantee,
                MicroQuota::new(700).expect("金额有效"),
                "peak-1",
                datetime!(2026-07-17 10:01 UTC),
            )
            .is_err());
        assert_eq!(reserve.balance.as_i64(), 600);
    }

    #[test]
    fn requires_nonempty_reference_and_amount() {
        let mut reserve = ReserveState::default();
        reserve
            .add_inflow(MicroQuota::new(100).expect("金额有效"))
            .expect("流入应成功");
        assert!(reserve
            .release(
                Uuid::from_u128(1),
                ReservePurpose::ResultValidation,
                MicroQuota::zero(),
                "verification-1",
                OffsetDateTime::UNIX_EPOCH,
            )
            .is_err());
        assert!(reserve
            .release(
                Uuid::from_u128(2),
                ReservePurpose::BandwidthSubsidy,
                MicroQuota::new(1).expect("金额有效"),
                " ",
                OffsetDateTime::UNIX_EPOCH,
            )
            .is_err());
    }
}
