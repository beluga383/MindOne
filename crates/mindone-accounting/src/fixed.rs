use serde::{Deserialize, Serialize};

use crate::{AccountingError, Result};

pub const MICROQUOTA_PER_QUOTA: i64 = 1_000_000;
const MULTIPLIER_SCALE: i128 = 1_000;

/// 非负的整数最小额度单位。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MicroQuota(i64);

impl MicroQuota {
    pub fn new(value: i64) -> Result<Self> {
        if value < 0 {
            return Err(AccountingError::NegativeAmount {
                field: "microquota",
            });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn as_i64(self) -> i64 {
        self.0
    }

    pub fn checked_add(self, other: Self) -> Result<Self> {
        let value = self
            .0
            .checked_add(other.0)
            .ok_or(AccountingError::Overflow {
                operation: "microquota 加法",
            })?;
        Self::new(value)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self> {
        if other.0 > self.0 {
            return Err(AccountingError::InsufficientBalance {
                required: other.0,
                available: self.0,
            });
        }
        Self::new(self.0 - other.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceTier {
    High,
    Medium,
    Low,
}

impl PerformanceTier {
    #[must_use]
    pub const fn multiplier_milli(self) -> i64 {
        match self {
            Self::High => 1_500,
            Self::Medium => 1_000,
            Self::Low => 700,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    Enhanced,
    Standard,
    Unverified,
}

impl TrustClass {
    #[must_use]
    pub const fn multiplier_milli(self) -> i64 {
        match self {
            Self::Enhanced => 1_100,
            Self::Standard => 1_000,
            Self::Unverified => 500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settlement {
    pub base_cost: MicroQuota,
    pub user_deduction: MicroQuota,
    pub node_spendable_quota: MicroQuota,
    pub node_contribution_points: MicroQuota,
    pub reserve_inflow: MicroQuota,
    pub performance_tier: PerformanceTier,
    pub trust_class: TrustClass,
}

impl Settlement {
    /// 用户扣费向上取整，节点可用额度和贡献值向下取整。
    /// 这种非对称舍入确保任意最小单位下准备金都不会因舍入成为负数。
    pub fn calculate(
        base_cost: MicroQuota,
        performance_tier: PerformanceTier,
        trust_class: TrustClass,
    ) -> Result<Self> {
        let user_deduction = MicroQuota::new(mul_ratio_ceil(
            base_cost.as_i64(),
            performance_tier.multiplier_milli(),
            MULTIPLIER_SCALE,
            "用户扣费",
        )?)?;

        let node_spendable_quota = MicroQuota::new(mul_two_ratios_floor(
            user_deduction.as_i64(),
            800,
            trust_class.multiplier_milli(),
            "节点可用额度",
        )?)?;
        let node_contribution_points = MicroQuota::new(mul_two_ratios_floor(
            user_deduction.as_i64(),
            1_200,
            trust_class.multiplier_milli(),
            "节点贡献值",
        )?)?;
        let reserve_inflow = user_deduction.checked_sub(node_spendable_quota)?;

        Ok(Self {
            base_cost,
            user_deduction,
            node_spendable_quota,
            node_contribution_points,
            reserve_inflow,
            performance_tier,
            trust_class,
        })
    }
}

fn mul_ratio_ceil(
    value: i64,
    numerator: i64,
    denominator: i128,
    operation: &'static str,
) -> Result<i64> {
    let product = i128::from(value)
        .checked_mul(i128::from(numerator))
        .ok_or(AccountingError::Overflow { operation })?;
    let adjusted = product
        .checked_add(denominator - 1)
        .ok_or(AccountingError::Overflow { operation })?;
    i64::try_from(adjusted / denominator).map_err(|_| AccountingError::Overflow { operation })
}

fn mul_two_ratios_floor(
    value: i64,
    first_milli: i64,
    second_milli: i64,
    operation: &'static str,
) -> Result<i64> {
    let product = i128::from(value)
        .checked_mul(i128::from(first_milli))
        .and_then(|current| current.checked_mul(i128::from(second_milli)))
        .ok_or(AccountingError::Overflow { operation })?;
    let denominator = MULTIPLIER_SCALE * MULTIPLIER_SCALE;
    i64::try_from(product / denominator).map_err(|_| AccountingError::Overflow { operation })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_quota() -> MicroQuota {
        MicroQuota::new(MICROQUOTA_PER_QUOTA).expect("常量应有效")
    }

    #[test]
    fn matches_all_whitepaper_golden_values() {
        let standard_high =
            Settlement::calculate(one_quota(), PerformanceTier::High, TrustClass::Standard)
                .expect("结算应成功");
        assert_eq!(standard_high.user_deduction.as_i64(), 1_500_000);
        assert_eq!(standard_high.node_spendable_quota.as_i64(), 1_200_000);
        assert_eq!(standard_high.node_contribution_points.as_i64(), 1_800_000);
        assert_eq!(standard_high.reserve_inflow.as_i64(), 300_000);

        let standard_low =
            Settlement::calculate(one_quota(), PerformanceTier::Low, TrustClass::Standard)
                .expect("结算应成功");
        assert_eq!(standard_low.user_deduction.as_i64(), 700_000);
        assert_eq!(standard_low.node_spendable_quota.as_i64(), 560_000);
        assert_eq!(standard_low.node_contribution_points.as_i64(), 840_000);
        assert_eq!(standard_low.reserve_inflow.as_i64(), 140_000);

        let enhanced_high =
            Settlement::calculate(one_quota(), PerformanceTier::High, TrustClass::Enhanced)
                .expect("结算应成功");
        assert_eq!(enhanced_high.node_spendable_quota.as_i64(), 1_320_000);
        assert_eq!(enhanced_high.node_contribution_points.as_i64(), 1_980_000);
        assert_eq!(enhanced_high.reserve_inflow.as_i64(), 180_000);

        let unverified_high =
            Settlement::calculate(one_quota(), PerformanceTier::High, TrustClass::Unverified)
                .expect("结算应成功");
        assert_eq!(unverified_high.node_spendable_quota.as_i64(), 600_000);
        assert_eq!(unverified_high.node_contribution_points.as_i64(), 900_000);
        assert_eq!(unverified_high.reserve_inflow.as_i64(), 900_000);
    }

    #[test]
    fn preserves_deflation_under_minimal_rounding() {
        let settlement = Settlement::calculate(
            MicroQuota::new(1).expect("一个最小单位有效"),
            PerformanceTier::High,
            TrustClass::Enhanced,
        )
        .expect("结算应成功");
        assert_eq!(settlement.user_deduction.as_i64(), 2);
        assert_eq!(settlement.node_spendable_quota.as_i64(), 1);
        assert_eq!(settlement.reserve_inflow.as_i64(), 1);
    }

    #[test]
    fn rejects_negative_and_checked_underflow() {
        assert!(MicroQuota::new(-1).is_err());
        let one = MicroQuota::new(1).expect("应有效");
        let two = MicroQuota::new(2).expect("应有效");
        assert!(one.checked_sub(two).is_err());
    }
}
