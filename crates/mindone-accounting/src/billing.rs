//! 由协调器控制的物理计费参考上界。
//!
//! 节点上报的实际 token、GPU 时间、显存和吞吐量都不进入这里。调用方只传入
//! 协调器授权的 token 上界和不可变参考 profile，所有金额均以整数 microquota
//! 计算，并对三个分项分别向上取整。

use serde::{Deserialize, Serialize};

use crate::{
    fixed::{MicroQuota, PerformanceTier, Settlement, TrustClass},
    AccountingError, Result,
};

/// 数据库与审计收据使用的稳定计费合同标识。
pub const SERVER_REFERENCE_UPPER_BOUND_V1: &str = "server_reference_upper_bound_v1";

const TOKENS_PER_RATE_UNIT: i128 = 1_000;
const MICROSECONDS_PER_SECOND: i128 = 1_000_000;
const MIB_PER_GIB: i128 = 1_024;
const MIB_MICROSECONDS_PER_GIB_SECOND: i128 = MIB_PER_GIB * MICROSECONDS_PER_SECOND;

/// 协调器签发并在数据库中冻结的参考 profile 数值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerReferenceBillingProfile {
    /// 该 profile 允许协调器授权的最大输入 token。
    pub maximum_input_tokens: i64,
    /// 该 profile 允许协调器授权的最大输出 token。
    pub maximum_output_tokens: i64,
    /// 每次请求固定占用的参考 GPU 时间。
    pub fixed_gpu_time_us: i64,
    /// 每 1,000 个授权 token 增加的参考 GPU 时间。
    pub gpu_time_us_per_1k_tokens: i64,
    /// 参考显存占用，单位 MiB。
    pub reference_vram_mib: i64,
    /// 每 1,000 个授权 token 的 microquota 费率。
    pub token_rate_micro_per_1k: i64,
    /// 每参考 GPU 秒的 microquota 费率。
    pub gpu_rate_micro_per_second: i64,
    /// 每参考 GiB 秒显存积分的 microquota 费率。
    pub vram_rate_micro_per_gib_second: i64,
}

/// 三分项分别向上取整后的确定性计费结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBillingQuote {
    pub billable_tokens: i64,
    pub reference_gpu_time_us: i64,
    pub reference_vram_mib_microseconds: i64,
    pub token_cost: MicroQuota,
    pub gpu_cost: MicroQuota,
    pub vram_cost: MicroQuota,
    pub base_cost: MicroQuota,
}

impl ServerReferenceBillingProfile {
    fn validate(self) -> Result<()> {
        require_nonnegative(self.maximum_input_tokens, "maximum_input_tokens")?;
        require_positive(self.maximum_output_tokens, "maximum_output_tokens")?;
        require_nonnegative(self.fixed_gpu_time_us, "fixed_gpu_time_us")?;
        require_positive(self.gpu_time_us_per_1k_tokens, "gpu_time_us_per_1k_tokens")?;
        require_positive(self.reference_vram_mib, "reference_vram_mib")?;
        require_positive(self.token_rate_micro_per_1k, "token_rate_micro_per_1k")?;
        require_positive(self.gpu_rate_micro_per_second, "gpu_rate_micro_per_second")?;
        require_positive(
            self.vram_rate_micro_per_gib_second,
            "vram_rate_micro_per_gib_second",
        )?;

        let maximum_billable_tokens = checked_add_i64(
            self.maximum_input_tokens,
            self.maximum_output_tokens,
            "profile token 上界",
        )?;
        let maximum_variable_gpu_time_us = ceil_mul_div(
            maximum_billable_tokens,
            self.gpu_time_us_per_1k_tokens,
            TOKENS_PER_RATE_UNIT,
            "profile GPU 时间上界",
        )?;
        let maximum_gpu_time_us = checked_add_i64(
            self.fixed_gpu_time_us,
            maximum_variable_gpu_time_us,
            "profile GPU 时间上界求和",
        )?;
        let maximum_vram_integral = checked_mul_i64(
            maximum_gpu_time_us,
            self.reference_vram_mib,
            "profile 显存积分上界",
        )?;
        let maximum_token_cost = MicroQuota::new(ceil_mul_div(
            maximum_billable_tokens,
            self.token_rate_micro_per_1k,
            TOKENS_PER_RATE_UNIT,
            "profile token 成本上界",
        )?)?;
        let maximum_gpu_cost = MicroQuota::new(ceil_mul_div(
            maximum_gpu_time_us,
            self.gpu_rate_micro_per_second,
            MICROSECONDS_PER_SECOND,
            "profile GPU 成本上界",
        )?)?;
        let maximum_vram_cost = MicroQuota::new(ceil_mul_div(
            maximum_vram_integral,
            self.vram_rate_micro_per_gib_second,
            MIB_MICROSECONDS_PER_GIB_SECOND,
            "profile 显存成本上界",
        )?)?;
        let maximum_base_cost = maximum_token_cost
            .checked_add(maximum_gpu_cost)?
            .checked_add(maximum_vram_cost)?;
        Settlement::calculate(
            maximum_base_cost,
            PerformanceTier::High,
            TrustClass::Enhanced,
        )?;
        Ok(())
    }
}

/// 对协调器已确定的 billable token 上界生成物理参考报价。
///
/// 公式为：
///
/// - `G = fixed_gpu_us + ceil(tokens * gpu_us_per_1k / 1000)`
/// - `V = G * reference_vram_mib`
/// - 三个金额分项分别向上取整后再求和
pub fn quote_server_reference_upper_bound(
    profile: ServerReferenceBillingProfile,
    billable_tokens: i64,
) -> Result<PhysicalBillingQuote> {
    profile.validate()?;
    require_positive(billable_tokens, "billable_tokens")?;
    let maximum_billable_tokens = checked_add_i64(
        profile.maximum_input_tokens,
        profile.maximum_output_tokens,
        "profile token 上界",
    )?;
    if billable_tokens > maximum_billable_tokens {
        return Err(AccountingError::InvalidBilling(
            "billable_tokens 超过 profile 授权上界".to_owned(),
        ));
    }

    let variable_gpu_time_us = ceil_mul_div(
        billable_tokens,
        profile.gpu_time_us_per_1k_tokens,
        TOKENS_PER_RATE_UNIT,
        "参考 GPU 时间",
    )?;
    let reference_gpu_time_us = checked_add_i64(
        profile.fixed_gpu_time_us,
        variable_gpu_time_us,
        "参考 GPU 时间求和",
    )?;
    let reference_vram_mib_microseconds = checked_mul_i64(
        reference_gpu_time_us,
        profile.reference_vram_mib,
        "参考显存积分",
    )?;

    let token_cost = MicroQuota::new(ceil_mul_div(
        billable_tokens,
        profile.token_rate_micro_per_1k,
        TOKENS_PER_RATE_UNIT,
        "token 计费",
    )?)?;
    let gpu_cost = MicroQuota::new(ceil_mul_div(
        reference_gpu_time_us,
        profile.gpu_rate_micro_per_second,
        MICROSECONDS_PER_SECOND,
        "GPU 时间计费",
    )?)?;
    let vram_cost = MicroQuota::new(ceil_mul_div(
        reference_vram_mib_microseconds,
        profile.vram_rate_micro_per_gib_second,
        MIB_MICROSECONDS_PER_GIB_SECOND,
        "显存积分计费",
    )?)?;
    let base_cost = token_cost.checked_add(gpu_cost)?.checked_add(vram_cost)?;

    Ok(PhysicalBillingQuote {
        billable_tokens,
        reference_gpu_time_us,
        reference_vram_mib_microseconds,
        token_cost,
        gpu_cost,
        vram_cost,
        base_cost,
    })
}

/// 根据协调器授权输入上界与最大输出上界计算准备金报价。
pub fn maximum_reservation_quote(
    profile: ServerReferenceBillingProfile,
    authorized_input_tokens: i64,
    authorized_max_output_tokens: i64,
) -> Result<PhysicalBillingQuote> {
    require_nonnegative(authorized_input_tokens, "authorized_input_tokens")?;
    require_positive(authorized_max_output_tokens, "authorized_max_output_tokens")?;
    if authorized_input_tokens > profile.maximum_input_tokens
        || authorized_max_output_tokens > profile.maximum_output_tokens
    {
        return Err(AccountingError::InvalidBilling(
            "授权 token 超过 profile 上界".to_owned(),
        ));
    }
    let billable_tokens = checked_add_i64(
        authorized_input_tokens,
        authorized_max_output_tokens,
        "准备金 token 上界",
    )?;
    quote_server_reference_upper_bound(profile, billable_tokens)
}

/// 返回需要原子预留的最大 microquota。
///
/// 准备金覆盖物理参考基础成本和最高 High 表现倍率；Enhanced 信任桶传入统一
/// 结算函数以保持策略入口一致，但信任倍率不增加消费者扣费。
pub fn maximum_reservation_micro(
    profile: ServerReferenceBillingProfile,
    authorized_input_tokens: i64,
    authorized_max_output_tokens: i64,
) -> Result<MicroQuota> {
    let quote = maximum_reservation_quote(
        profile,
        authorized_input_tokens,
        authorized_max_output_tokens,
    )?;
    Ok(
        Settlement::calculate(quote.base_cost, PerformanceTier::High, TrustClass::Enhanced)?
            .user_deduction,
    )
}

fn require_nonnegative(value: i64, field: &'static str) -> Result<()> {
    if value < 0 {
        return Err(AccountingError::NegativeAmount { field });
    }
    Ok(())
}

fn require_positive(value: i64, field: &'static str) -> Result<()> {
    require_nonnegative(value, field)?;
    if value == 0 {
        return Err(AccountingError::InvalidBilling(format!(
            "{field} 必须大于零"
        )));
    }
    Ok(())
}

fn checked_add_i64(left: i64, right: i64, operation: &'static str) -> Result<i64> {
    let sum = i128::from(left)
        .checked_add(i128::from(right))
        .ok_or(AccountingError::Overflow { operation })?;
    i64::try_from(sum).map_err(|_| AccountingError::Overflow { operation })
}

fn checked_mul_i64(left: i64, right: i64, operation: &'static str) -> Result<i64> {
    let product = i128::from(left)
        .checked_mul(i128::from(right))
        .ok_or(AccountingError::Overflow { operation })?;
    i64::try_from(product).map_err(|_| AccountingError::Overflow { operation })
}

fn ceil_mul_div(left: i64, right: i64, denominator: i128, operation: &'static str) -> Result<i64> {
    require_nonnegative(left, "billing_multiplicand")?;
    require_nonnegative(right, "billing_multiplier")?;
    let product = i128::from(left)
        .checked_mul(i128::from(right))
        .ok_or(AccountingError::Overflow { operation })?;
    let adjusted = product
        .checked_add(denominator - 1)
        .ok_or(AccountingError::Overflow { operation })?;
    i64::try_from(adjusted / denominator).map_err(|_| AccountingError::Overflow { operation })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> ServerReferenceBillingProfile {
        ServerReferenceBillingProfile {
            maximum_input_tokens: 4_096,
            maximum_output_tokens: 1_024,
            fixed_gpu_time_us: 100_000,
            gpu_time_us_per_1k_tokens: 2_000_000,
            reference_vram_mib: 8_192,
            token_rate_micro_per_1k: 1_000_000,
            gpu_rate_micro_per_second: 2_000,
            vram_rate_micro_per_gib_second: 3_000,
        }
    }

    #[test]
    fn calculates_all_three_components_with_integer_units() {
        let quote = quote_server_reference_upper_bound(profile(), 1_500)
            .expect("有效参考 profile 应产生报价");
        assert_eq!(quote.reference_gpu_time_us, 3_100_000);
        assert_eq!(quote.reference_vram_mib_microseconds, 25_395_200_000);
        assert_eq!(quote.token_cost.as_i64(), 1_500_000);
        assert_eq!(quote.gpu_cost.as_i64(), 6_200);
        assert_eq!(quote.vram_cost.as_i64(), 74_400);
        assert_eq!(quote.base_cost.as_i64(), 1_580_600);
    }

    #[test]
    fn rounds_every_component_up_independently() {
        let minimal = ServerReferenceBillingProfile {
            maximum_input_tokens: 1,
            maximum_output_tokens: 1,
            fixed_gpu_time_us: 0,
            gpu_time_us_per_1k_tokens: 1,
            reference_vram_mib: 1,
            token_rate_micro_per_1k: 1,
            gpu_rate_micro_per_second: 1,
            vram_rate_micro_per_gib_second: 1,
        };
        let quote =
            quote_server_reference_upper_bound(minimal, 1).expect("最小非零用量仍应产生可审计报价");
        assert_eq!(quote.reference_gpu_time_us, 1);
        assert_eq!(quote.reference_vram_mib_microseconds, 1);
        assert_eq!(quote.token_cost.as_i64(), 1);
        assert_eq!(quote.gpu_cost.as_i64(), 1);
        assert_eq!(quote.vram_cost.as_i64(), 1);
        assert_eq!(quote.base_cost.as_i64(), 3);
        assert_eq!(
            maximum_reservation_micro(minimal, 0, 1)
                .expect("最小准备金应覆盖 High 上界")
                .as_i64(),
            5
        );
    }

    #[test]
    fn exact_division_does_not_add_an_extra_unit() {
        let exact = ServerReferenceBillingProfile {
            maximum_input_tokens: 1_000,
            maximum_output_tokens: 1,
            fixed_gpu_time_us: 0,
            gpu_time_us_per_1k_tokens: 1_000_000,
            reference_vram_mib: 1_024,
            token_rate_micro_per_1k: 1_000,
            gpu_rate_micro_per_second: 1_000,
            vram_rate_micro_per_gib_second: 1_000,
        };
        let quote = quote_server_reference_upper_bound(exact, 1_000).expect("整除边界应可报价");
        assert_eq!(quote.reference_gpu_time_us, 1_000_000);
        assert_eq!(quote.token_cost.as_i64(), 1_000);
        assert_eq!(quote.gpu_cost.as_i64(), 1_000);
        assert_eq!(quote.vram_cost.as_i64(), 1_000);
        assert_eq!(quote.base_cost.as_i64(), 3_000);
    }

    #[test]
    fn reservation_uses_the_full_authorized_upper_bound() {
        let reservation =
            maximum_reservation_quote(profile(), 800, 200).expect("合法授权上界应能预留");
        let smaller_quote =
            quote_server_reference_upper_bound(profile(), 999).expect("更小 token 上界应能报价");
        assert_eq!(reservation.billable_tokens, 1_000);
        assert_eq!(
            maximum_reservation_micro(profile(), 800, 200).expect("准备金额应可计算"),
            MicroQuota::new(1_581_900).expect("期望准备金额有效")
        );
        assert!(reservation.base_cost >= smaller_quote.base_cost);
    }

    #[test]
    fn rejects_negative_zero_and_invalid_profile_values() {
        assert!(quote_server_reference_upper_bound(profile(), 0).is_err());
        assert!(maximum_reservation_quote(profile(), -1, 1).is_err());
        assert!(maximum_reservation_quote(profile(), 1, 0).is_err());
        assert!(maximum_reservation_quote(profile(), 4_097, 1).is_err());
        assert!(maximum_reservation_quote(profile(), 1, 1_025).is_err());
        assert!(quote_server_reference_upper_bound(profile(), 5_121).is_err());

        let mut invalid = profile();
        invalid.reference_vram_mib = 0;
        assert!(quote_server_reference_upper_bound(invalid, 1).is_err());
        invalid = profile();
        invalid.fixed_gpu_time_us = -1;
        assert!(quote_server_reference_upper_bound(invalid, 1).is_err());
    }

    #[test]
    fn rejects_every_i64_storage_overflow() {
        let token_overflow = ServerReferenceBillingProfile {
            maximum_input_tokens: i64::MAX,
            maximum_output_tokens: 1,
            ..profile()
        };
        assert!(maximum_reservation_quote(token_overflow, i64::MAX, 1).is_err());

        let gpu_overflow = ServerReferenceBillingProfile {
            fixed_gpu_time_us: i64::MAX,
            gpu_time_us_per_1k_tokens: 1,
            ..profile()
        };
        assert!(quote_server_reference_upper_bound(gpu_overflow, 1).is_err());

        let vram_overflow = ServerReferenceBillingProfile {
            fixed_gpu_time_us: 1,
            gpu_time_us_per_1k_tokens: 1,
            reference_vram_mib: i64::MAX,
            ..profile()
        };
        assert!(quote_server_reference_upper_bound(vram_overflow, 1).is_err());

        let component_sum_overflow = ServerReferenceBillingProfile {
            maximum_input_tokens: 1_000,
            maximum_output_tokens: 1,
            fixed_gpu_time_us: 0,
            gpu_time_us_per_1k_tokens: 1,
            reference_vram_mib: 1,
            token_rate_micro_per_1k: i64::MAX,
            gpu_rate_micro_per_second: 1,
            vram_rate_micro_per_gib_second: 1,
        };
        assert!(quote_server_reference_upper_bound(component_sum_overflow, 1_000).is_err());
    }
}
