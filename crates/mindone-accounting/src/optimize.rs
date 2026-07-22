use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{AccountingError, PerformanceTier, Result};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct OptimizationMetrics {
    pub measured_tps: f64,
    pub measured_ttft_ms: f64,
    pub error_rate: f64,
    pub current_tier: PerformanceTier,
    pub target_tps: f64,
    pub maximum_ttft_ms: f64,
    pub maximum_error_rate: f64,
    pub valid_samples: u64,
    pub minimum_samples: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvicePriority {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationAdvice {
    pub code: String,
    pub priority: AdvicePriority,
    pub message: String,
    pub evidence: BTreeMap<String, String>,
}

pub fn optimize(metrics: OptimizationMetrics) -> Result<Vec<OptimizationAdvice>> {
    validate_metrics(metrics)?;
    let mut advice = Vec::new();

    if metrics.error_rate > metrics.maximum_error_rate {
        advice.push(OptimizationAdvice {
            code: "reduce_error_rate".to_owned(),
            priority: AdvicePriority::High,
            message: "近期错误率超过门槛；先检查引擎日志、模型内存需求与并发上限，再增加流量。"
                .to_owned(),
            evidence: BTreeMap::from([
                (
                    "measured_error_rate".to_owned(),
                    format_decimal(metrics.error_rate),
                ),
                (
                    "maximum_error_rate".to_owned(),
                    format_decimal(metrics.maximum_error_rate),
                ),
            ]),
        });
    }
    if metrics.measured_ttft_ms > metrics.maximum_ttft_ms {
        advice.push(OptimizationAdvice {
            code: "reduce_ttft".to_owned(),
            priority: AdvicePriority::Medium,
            message:
                "首 Token TTFT 实测值超过目标；可降低最大并发、缩短上下文或选择更合适的量化模型。"
                    .to_owned(),
            evidence: BTreeMap::from([
                (
                    "measured_ttft_ms".to_owned(),
                    format_decimal(metrics.measured_ttft_ms),
                ),
                (
                    "maximum_ttft_ms".to_owned(),
                    format_decimal(metrics.maximum_ttft_ms),
                ),
            ]),
        });
    }
    if metrics.measured_tps < metrics.target_tps {
        let improvement = (metrics.target_tps - metrics.measured_tps) / metrics.target_tps;
        advice.push(OptimizationAdvice {
            code: "improve_tps".to_owned(),
            priority: AdvicePriority::Medium,
            message: "当前 TPS 低于目标；请按证据中的确定差距检查 GPU offload、线程数和量化版本。"
                .to_owned(),
            evidence: BTreeMap::from([
                (
                    "measured_tps".to_owned(),
                    format_decimal(metrics.measured_tps),
                ),
                ("target_tps".to_owned(), format_decimal(metrics.target_tps)),
                ("relative_gap".to_owned(), format_decimal(improvement)),
            ]),
        });
    }
    if metrics.current_tier == PerformanceTier::Low {
        advice.push(OptimizationAdvice {
            code: "recover_tier".to_owned(),
            priority: AdvicePriority::Low,
            message: "当前为低级表现；达到绝对性能和稳定性门槛后，表现倍率可由 0.7 提升至 1.0。"
                .to_owned(),
            evidence: BTreeMap::from([("current_tier".to_owned(), "low".to_owned())]),
        });
    }
    if metrics.valid_samples < metrics.minimum_samples {
        advice.push(OptimizationAdvice {
            code: "collect_samples".to_owned(),
            priority: AdvicePriority::Low,
            message: "有效样本不足，当前 Tier 结论尚不稳定；请保持配置并继续完成真实请求。"
                .to_owned(),
            evidence: BTreeMap::from([
                (
                    "valid_samples".to_owned(),
                    metrics.valid_samples.to_string(),
                ),
                (
                    "minimum_samples".to_owned(),
                    metrics.minimum_samples.to_string(),
                ),
            ]),
        });
    }
    if advice.is_empty() {
        advice.push(OptimizationAdvice {
            code: "performance_stable".to_owned(),
            priority: AdvicePriority::Low,
            message:
                "TPS、首 Token TTFT 实测值与错误率均在当前目标内，建议保持配置并继续积累有效样本。"
                    .to_owned(),
            evidence: BTreeMap::from([(
                "current_tier".to_owned(),
                tier_name(metrics.current_tier),
            )]),
        });
    }
    advice.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.code.cmp(&right.code))
    });
    Ok(advice)
}

fn validate_metrics(metrics: OptimizationMetrics) -> Result<()> {
    for (value, name) in [
        (metrics.measured_tps, "measured_tps"),
        (metrics.measured_ttft_ms, "measured_ttft_ms"),
        (metrics.error_rate, "error_rate"),
        (metrics.target_tps, "target_tps"),
        (metrics.maximum_ttft_ms, "maximum_ttft_ms"),
        (metrics.maximum_error_rate, "maximum_error_rate"),
    ] {
        if !value.is_finite() || value < 0.0 {
            return Err(AccountingError::InvalidScore(format!(
                "{name} 必须是非负有限数"
            )));
        }
    }
    if metrics.target_tps <= 0.0 || metrics.maximum_ttft_ms <= 0.0 {
        return Err(AccountingError::InvalidScore(
            "target_tps 与 maximum_ttft_ms 必须大于零".to_owned(),
        ));
    }
    if metrics.minimum_samples == 0 {
        return Err(AccountingError::InvalidScore(
            "minimum_samples 必须大于零".to_owned(),
        ));
    }
    if metrics.error_rate > 1.0 || metrics.maximum_error_rate > 1.0 {
        return Err(AccountingError::InvalidScore(
            "错误率必须在 0 到 1 之间".to_owned(),
        ));
    }
    Ok(())
}

fn format_decimal(value: f64) -> String {
    format!("{value:.4}")
}

fn tier_name(tier: PerformanceTier) -> String {
    match tier {
        PerformanceTier::High => "high",
        PerformanceTier::Medium => "medium",
        PerformanceTier::Low => "low",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics() -> OptimizationMetrics {
        OptimizationMetrics {
            measured_tps: 8.0,
            measured_ttft_ms: 1_500.0,
            error_rate: 0.10,
            current_tier: PerformanceTier::Low,
            target_tps: 10.0,
            maximum_ttft_ms: 1_000.0,
            maximum_error_rate: 0.05,
            valid_samples: 100,
            minimum_samples: 20,
        }
    }

    #[test]
    fn output_is_reproducible_and_evidence_based() {
        let first = optimize(metrics()).expect("指标应有效");
        let second = optimize(metrics()).expect("指标应有效");
        assert_eq!(first, second);
        let codes: Vec<&str> = first.iter().map(|item| item.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                "reduce_error_rate",
                "improve_tps",
                "reduce_ttft",
                "recover_tier"
            ]
        );
        assert!(first.iter().all(|item| !item.evidence.is_empty()));
        let ttft_advice = first
            .iter()
            .find(|item| item.code == "reduce_ttft")
            .expect("超出目标时应返回 TTFT 建议");
        assert!(ttft_advice.message.contains("实测"));
        assert!(!ttft_advice.message.contains("估算"));
    }

    #[test]
    fn stable_metrics_return_stable_advice() {
        let advice = optimize(OptimizationMetrics {
            measured_tps: 20.0,
            measured_ttft_ms: 100.0,
            error_rate: 0.0,
            current_tier: PerformanceTier::High,
            target_tps: 10.0,
            maximum_ttft_ms: 1_000.0,
            maximum_error_rate: 0.05,
            valid_samples: 100,
            minimum_samples: 20,
        })
        .expect("指标应有效");
        assert_eq!(advice.len(), 1);
        assert_eq!(advice[0].code, "performance_stable");
    }

    #[test]
    fn rejects_nan_and_invalid_targets() {
        let mut invalid = metrics();
        invalid.measured_tps = f64::NAN;
        assert!(optimize(invalid).is_err());
        invalid = metrics();
        invalid.target_tps = 0.0;
        assert!(optimize(invalid).is_err());
    }
}
