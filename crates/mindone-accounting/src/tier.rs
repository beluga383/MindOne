use serde::{Deserialize, Serialize};

use crate::quality::validate_unit_interval;
use crate::{AccountingError, PerformanceTier, Result};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TierPolicy {
    pub minimum_samples: u64,
    pub high_enter: f64,
    pub high_exit: f64,
    pub low_enter: f64,
    pub low_exit: f64,
    pub relative_margin: f64,
    pub high_percentile: f64,
    pub low_percentile: f64,
}

impl Default for TierPolicy {
    fn default() -> Self {
        Self {
            minimum_samples: 20,
            high_enter: 0.80,
            high_exit: 0.72,
            low_enter: 0.35,
            low_exit: 0.42,
            relative_margin: 0.03,
            high_percentile: 0.80,
            low_percentile: 0.20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierResult {
    pub tier: PerformanceTier,
    pub cold_start: bool,
    pub relative_assist_applied: bool,
}

impl TierPolicy {
    pub fn classify(
        self,
        current: PerformanceTier,
        absolute_score: f64,
        percentile: f64,
        valid_samples: u64,
    ) -> Result<TierResult> {
        self.validate()?;
        validate_unit_interval(absolute_score, "absolute_score")?;
        validate_unit_interval(percentile, "percentile")?;

        if valid_samples < self.minimum_samples {
            return Ok(TierResult {
                tier: PerformanceTier::Medium,
                cold_start: true,
                relative_assist_applied: false,
            });
        }

        let high_relative_assist = absolute_score >= self.high_enter - self.relative_margin
            && percentile >= self.high_percentile;
        let low_relative_assist = absolute_score <= self.low_enter + self.relative_margin
            && percentile <= self.low_percentile;

        let (tier, relative_assist_applied) = match current {
            PerformanceTier::High if absolute_score >= self.high_exit => {
                (PerformanceTier::High, false)
            }
            PerformanceTier::High => (PerformanceTier::Medium, false),
            PerformanceTier::Low if absolute_score <= self.low_exit => {
                (PerformanceTier::Low, false)
            }
            PerformanceTier::Low => (PerformanceTier::Medium, false),
            PerformanceTier::Medium if absolute_score >= self.high_enter => {
                (PerformanceTier::High, false)
            }
            PerformanceTier::Medium if high_relative_assist => (PerformanceTier::High, true),
            PerformanceTier::Medium if absolute_score <= self.low_enter => {
                (PerformanceTier::Low, false)
            }
            PerformanceTier::Medium if low_relative_assist => (PerformanceTier::Low, true),
            PerformanceTier::Medium => (PerformanceTier::Medium, false),
        };
        Ok(TierResult {
            tier,
            cold_start: false,
            relative_assist_applied,
        })
    }

    pub fn validate(self) -> Result<()> {
        for (value, name) in [
            (self.high_enter, "high_enter"),
            (self.high_exit, "high_exit"),
            (self.low_enter, "low_enter"),
            (self.low_exit, "low_exit"),
            (self.high_percentile, "high_percentile"),
            (self.low_percentile, "low_percentile"),
        ] {
            validate_unit_interval(value, name)
                .map_err(|error| AccountingError::InvalidTierPolicy(error.to_string()))?;
        }
        if self.minimum_samples == 0 {
            return Err(AccountingError::InvalidTierPolicy(
                "minimum_samples 必须大于零".to_owned(),
            ));
        }
        if !self.relative_margin.is_finite() || self.relative_margin < 0.0 {
            return Err(AccountingError::InvalidTierPolicy(
                "relative_margin 必须是非负有限数".to_owned(),
            ));
        }
        if !(self.low_enter < self.low_exit
            && self.low_exit < self.high_exit
            && self.high_exit < self.high_enter)
        {
            return Err(AccountingError::InvalidTierPolicy(
                "Tier 门槛必须满足 low_enter < low_exit < high_exit < high_enter".to_owned(),
            ));
        }
        if self.low_enter + self.relative_margin > self.low_exit
            || self.high_enter - self.relative_margin < self.high_exit
        {
            return Err(AccountingError::InvalidTierPolicy(
                "相对排名辅助区间不得穿过升降级滞回区间".to_owned(),
            ));
        }
        if self.low_percentile >= self.high_percentile {
            return Err(AccountingError::InvalidTierPolicy(
                "低位 percentile 必须小于高位 percentile".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_is_neutral_medium() {
        let result = TierPolicy::default()
            .classify(PerformanceTier::Low, 0.1, 0.0, 5)
            .expect("策略有效");
        assert_eq!(result.tier, PerformanceTier::Medium);
        assert!(result.cold_start);
    }

    #[test]
    fn absolute_thresholds_and_hysteresis_dominate() {
        let policy = TierPolicy::default();
        let promoted = policy
            .classify(PerformanceTier::Medium, 0.81, 0.5, 100)
            .expect("应可分类");
        assert_eq!(promoted.tier, PerformanceTier::High);
        let retained = policy
            .classify(PerformanceTier::High, 0.73, 0.1, 100)
            .expect("应可分类");
        assert_eq!(retained.tier, PerformanceTier::High);
        let demoted = policy
            .classify(PerformanceTier::High, 0.71, 0.99, 100)
            .expect("应可分类");
        assert_eq!(demoted.tier, PerformanceTier::Medium);
    }

    #[test]
    fn relative_rank_only_assists_near_absolute_gate() {
        let policy = TierPolicy::default();
        let assisted = policy
            .classify(PerformanceTier::Medium, 0.78, 0.85, 100)
            .expect("应可分类");
        assert_eq!(assisted.tier, PerformanceTier::High);
        assert!(assisted.relative_assist_applied);
        let too_far = policy
            .classify(PerformanceTier::Medium, 0.70, 1.0, 100)
            .expect("应可分类");
        assert_eq!(too_far.tier, PerformanceTier::Medium);
    }

    #[test]
    fn rejects_crossed_thresholds() {
        let policy = TierPolicy {
            high_exit: 0.9,
            ..TierPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
