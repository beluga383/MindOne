use serde::{Deserialize, Serialize};

use crate::{AccountingError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QualityFusion {
    pub beta: f64,
    pub fused: f64,
}

/// 以样本数动态融合已归一化 benchmark 与 Glicko 分数。
pub fn fused_quality(
    benchmark_normalized: f64,
    glicko_normalized: f64,
    valid_samples: u64,
    cold_start_k: u64,
) -> Result<QualityFusion> {
    validate_unit_interval(benchmark_normalized, "benchmark_normalized")?;
    validate_unit_interval(glicko_normalized, "glicko_normalized")?;
    if cold_start_k == 0 {
        return Err(AccountingError::InvalidScore(
            "cold_start_k 必须大于零".to_owned(),
        ));
    }
    let samples = valid_samples as f64;
    let beta = samples / (samples + cold_start_k as f64);
    let fused = (1.0 - beta) * benchmark_normalized + beta * glicko_normalized;
    Ok(QualityFusion { beta, fused })
}

pub(crate) fn validate_unit_interval(value: f64, name: &str) -> Result<()> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(AccountingError::InvalidScore(format!(
            "{name} 必须是 0 到 1 之间的有限数"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_start_uses_benchmark_then_converges_to_glicko() {
        let cold = fused_quality(0.8, 0.2, 0, 10).expect("输入应有效");
        assert_eq!(cold.beta, 0.0);
        assert_eq!(cold.fused, 0.8);

        let balanced = fused_quality(0.8, 0.2, 10, 10).expect("输入应有效");
        assert!((balanced.beta - 0.5).abs() < f64::EPSILON);
        assert!((balanced.fused - 0.5).abs() < f64::EPSILON);

        let mature = fused_quality(0.8, 0.2, 10_000, 10).expect("输入应有效");
        assert!(mature.beta > 0.99);
        assert!(mature.fused < 0.21);
    }

    #[test]
    fn rejects_non_normalized_or_invalid_parameters() {
        assert!(fused_quality(-0.1, 0.5, 1, 10).is_err());
        assert!(fused_quality(0.5, f64::NAN, 1, 10).is_err());
        assert!(fused_quality(0.5, 0.5, 1, 0).is_err());
    }
}
