use serde::{Deserialize, Serialize};

use crate::{AccountingError, Result};

const GLICKO2_SCALE: f64 = 173.7178;
const DEFAULT_RATING: f64 = 1_500.0;
const PI_SQUARED: f64 = std::f64::consts::PI * std::f64::consts::PI;
const MAX_VOLATILITY_ITERATIONS: u32 = 1_000;

/// Glicko-2 rating expressed in the public Glicko scale.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Glicko2Rating {
    pub rating: f64,
    pub deviation: f64,
    pub volatility: f64,
}

impl Default for Glicko2Rating {
    fn default() -> Self {
        Self {
            rating: DEFAULT_RATING,
            deviation: 350.0,
            volatility: 0.06,
        }
    }
}

/// A result against an independently rated opponent.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Glicko2Observation {
    pub opponent_rating: f64,
    pub opponent_deviation: f64,
    pub score: Glicko2Score,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Glicko2Score {
    Loss,
    Draw,
    Win,
}

impl Glicko2Score {
    #[must_use]
    pub const fn value(self) -> f64 {
        match self {
            Self::Loss => 0.0,
            Self::Draw => 0.5,
            Self::Win => 1.0,
        }
    }

    #[must_use]
    pub const fn millionths(self) -> i32 {
        match self {
            Self::Loss => 0,
            Self::Draw => 500_000,
            Self::Win => 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Glicko2Config {
    /// Constrains volatility change. The Glicko-2 paper recommends 0.3 to 1.2.
    pub tau: f64,
    /// Root-finding convergence tolerance.
    pub convergence_tolerance: f64,
}

impl Default for Glicko2Config {
    fn default() -> Self {
        Self {
            tau: 0.5,
            convergence_tolerance: 0.000_001,
        }
    }
}

/// Applies one Glicko-2 rating period using the algorithm published by Mark Glickman.
///
/// The function contains no random input. Callers must provide the complete set of
/// independently produced observations for the rating period.
///
/// # Errors
///
/// Returns [`AccountingError::InvalidGlicko2`] when a rating, observation, or algorithm
/// parameter is outside the documented bounds, or when the bounded volatility solver cannot
/// converge.
pub fn update_glicko2(
    current: Glicko2Rating,
    observations: &[Glicko2Observation],
    config: Glicko2Config,
) -> Result<Glicko2Rating> {
    validate_rating(current)?;
    validate_config(config)?;
    if observations.is_empty() {
        return Err(AccountingError::InvalidGlicko2(
            "每个评分周期至少需要一个有效盲测结果".to_owned(),
        ));
    }
    if observations.len() > 10_000 {
        return Err(AccountingError::InvalidGlicko2(
            "单个评分周期最多接受 10000 个结果".to_owned(),
        ));
    }
    for observation in observations {
        validate_public_rating(observation.opponent_rating, "opponent_rating")?;
        validate_deviation(observation.opponent_deviation, "opponent_deviation")?;
    }

    let mu = (current.rating - DEFAULT_RATING) / GLICKO2_SCALE;
    let phi = current.deviation / GLICKO2_SCALE;
    let mut information_sum = 0.0;
    let mut outcome_sum = 0.0;

    for observation in observations {
        let opponent_mu = (observation.opponent_rating - DEFAULT_RATING) / GLICKO2_SCALE;
        let opponent_phi = observation.opponent_deviation / GLICKO2_SCALE;
        let impact = rating_impact(opponent_phi);
        let expected = expected_score(mu, opponent_mu, impact);
        information_sum = (impact * impact * expected).mul_add(1.0 - expected, information_sum);
        outcome_sum = impact.mul_add(observation.score.value() - expected, outcome_sum);
    }
    if !information_sum.is_finite() || information_sum <= 0.0 || !outcome_sum.is_finite() {
        return Err(AccountingError::InvalidGlicko2(
            "评分周期的信息量无效".to_owned(),
        ));
    }

    let variance = information_sum.recip();
    let improvement = variance * outcome_sum;
    let new_volatility = solve_volatility(phi, current.volatility, variance, improvement, config)?;
    let pre_rating_deviation = phi.hypot(new_volatility);
    let inverse_pre_deviation = pre_rating_deviation.recip();
    let new_phi = inverse_pre_deviation
        .mul_add(inverse_pre_deviation, variance.recip())
        .sqrt()
        .recip();
    let new_mu = (new_phi * new_phi).mul_add(outcome_sum, mu);
    let updated = Glicko2Rating {
        rating: new_mu.mul_add(GLICKO2_SCALE, DEFAULT_RATING),
        deviation: new_phi * GLICKO2_SCALE,
        volatility: new_volatility,
    };
    validate_rating(updated)?;
    Ok(updated)
}

/// Maps a public Glicko rating to the version-1 quality interval.
///
/// Ratings at or below 1000 map to zero; ratings at or above 2000 map to one.
///
/// # Errors
///
/// Returns [`AccountingError::InvalidGlicko2`] if `rating` is non-finite or outside the
/// accepted public Glicko range of 0 through 4000.
pub fn normalize_glicko2_rating(rating: f64) -> Result<f64> {
    validate_public_rating(rating, "rating")?;
    Ok(((rating - 1_000.0) / 1_000.0).clamp(0.0, 1.0))
}

fn rating_impact(opponent_phi: f64) -> f64 {
    (1.0 + 3.0 * opponent_phi * opponent_phi / PI_SQUARED)
        .sqrt()
        .recip()
}

fn expected_score(mu: f64, opponent_mu: f64, impact: f64) -> f64 {
    (1.0 + (-impact * (mu - opponent_mu)).exp()).recip()
}

fn solve_volatility(
    phi: f64,
    volatility: f64,
    variance: f64,
    improvement: f64,
    config: Glicko2Config,
) -> Result<f64> {
    let alpha = (volatility * volatility).ln();
    let phi_squared = phi * phi;
    let improvement_squared = improvement * improvement;
    let mut lower = alpha;
    let mut upper = if improvement_squared > phi_squared + variance {
        (improvement_squared - phi_squared - variance).ln()
    } else {
        let mut step = 1_u32;
        loop {
            let candidate = f64::from(step).mul_add(-config.tau, alpha);
            if volatility_objective(
                candidate,
                improvement_squared,
                phi_squared,
                variance,
                alpha,
                config.tau,
            ) >= 0.0
            {
                break candidate;
            }
            step = step
                .checked_add(1)
                .ok_or_else(|| AccountingError::InvalidGlicko2("波动率求解步数溢出".to_owned()))?;
            if step > MAX_VOLATILITY_ITERATIONS {
                return Err(AccountingError::InvalidGlicko2(
                    "波动率求解未收敛".to_owned(),
                ));
            }
        }
    };

    let mut lower_value = volatility_objective(
        lower,
        improvement_squared,
        phi_squared,
        variance,
        alpha,
        config.tau,
    );
    let mut upper_value = volatility_objective(
        upper,
        improvement_squared,
        phi_squared,
        variance,
        alpha,
        config.tau,
    );
    for _ in 0..MAX_VOLATILITY_ITERATIONS {
        if (upper - lower).abs() <= config.convergence_tolerance {
            let result = (lower / 2.0).exp();
            if result.is_finite() && result > 0.0 {
                return Ok(result);
            }
            return Err(AccountingError::InvalidGlicko2("波动率结果无效".to_owned()));
        }
        let denominator = upper_value - lower_value;
        if !denominator.is_finite() || denominator.abs() < f64::EPSILON {
            return Err(AccountingError::InvalidGlicko2(
                "波动率求解出现退化区间".to_owned(),
            ));
        }
        let candidate = lower + (lower - upper) * lower_value / denominator;
        let candidate_value = volatility_objective(
            candidate,
            improvement_squared,
            phi_squared,
            variance,
            alpha,
            config.tau,
        );
        if candidate_value * upper_value <= 0.0 {
            lower = upper;
            lower_value = upper_value;
        } else {
            lower_value /= 2.0;
        }
        upper = candidate;
        upper_value = candidate_value;
    }
    Err(AccountingError::InvalidGlicko2(
        "波动率求解未收敛".to_owned(),
    ))
}

fn volatility_objective(
    x: f64,
    improvement_squared: f64,
    phi_squared: f64,
    variance: f64,
    alpha: f64,
    tau: f64,
) -> f64 {
    let exponential = x.exp();
    let denominator = phi_squared + variance + exponential;
    let likelihood_term = exponential
        * (improvement_squared - phi_squared - variance - exponential)
        / (2.0 * denominator * denominator);
    let tau_squared = tau.powi(2);
    likelihood_term - (x - alpha) / tau_squared
}

fn validate_rating(rating: Glicko2Rating) -> Result<()> {
    validate_public_rating(rating.rating, "rating")?;
    validate_deviation(rating.deviation, "deviation")?;
    if !rating.volatility.is_finite() || !(0.000_001..=1.0).contains(&rating.volatility) {
        return Err(AccountingError::InvalidGlicko2(
            "volatility 必须在 0.000001 到 1 之间".to_owned(),
        ));
    }
    Ok(())
}

fn validate_public_rating(value: f64, field: &str) -> Result<()> {
    if !value.is_finite() || !(0.0..=4_000.0).contains(&value) {
        return Err(AccountingError::InvalidGlicko2(format!(
            "{field} 必须是 0 到 4000 之间的有限数"
        )));
    }
    Ok(())
}

fn validate_deviation(value: f64, field: &str) -> Result<()> {
    if !value.is_finite() || !(0.000_001..=350.0).contains(&value) {
        return Err(AccountingError::InvalidGlicko2(format!(
            "{field} 必须是 0.000001 到 350 之间的有限数"
        )));
    }
    Ok(())
}

fn validate_config(config: Glicko2Config) -> Result<()> {
    if !config.tau.is_finite() || !(0.1..=2.0).contains(&config.tau) {
        return Err(AccountingError::InvalidGlicko2(
            "tau 必须在 0.1 到 2 之间".to_owned(),
        ));
    }
    if !config.convergence_tolerance.is_finite()
        || !(0.000_000_001..=0.001).contains(&config.convergence_tolerance)
    {
        return Err(AccountingError::InvalidGlicko2(
            "convergence_tolerance 必须在 1e-9 到 1e-3 之间".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_published_glicko2_golden_example() {
        let observations = [
            Glicko2Observation {
                opponent_rating: 1_400.0,
                opponent_deviation: 30.0,
                score: Glicko2Score::Win,
            },
            Glicko2Observation {
                opponent_rating: 1_550.0,
                opponent_deviation: 100.0,
                score: Glicko2Score::Loss,
            },
            Glicko2Observation {
                opponent_rating: 1_700.0,
                opponent_deviation: 300.0,
                score: Glicko2Score::Loss,
            },
        ];
        let updated = update_glicko2(
            Glicko2Rating {
                rating: 1_500.0,
                deviation: 200.0,
                volatility: 0.06,
            },
            &observations,
            Glicko2Config::default(),
        )
        .expect("Glicko-2 官方示例应可计算");

        assert!((updated.rating - 1_464.06).abs() < 0.01);
        assert!((updated.deviation - 151.52).abs() < 0.01);
        assert!((updated.volatility - 0.059_996).abs() < 0.000_001);
    }

    #[test]
    fn identical_inputs_are_deterministic() {
        let current = Glicko2Rating::default();
        let observations = [Glicko2Observation {
            opponent_rating: 1_500.0,
            opponent_deviation: 100.0,
            score: Glicko2Score::Draw,
        }];
        let first =
            update_glicko2(current, &observations, Glicko2Config::default()).expect("输入应有效");
        let second =
            update_glicko2(current, &observations, Glicko2Config::default()).expect("输入应有效");
        assert_eq!(first, second);
    }

    #[test]
    fn rejects_empty_period_and_invalid_numeric_input() {
        assert!(update_glicko2(Glicko2Rating::default(), &[], Glicko2Config::default()).is_err());
        assert!(update_glicko2(
            Glicko2Rating::default(),
            &[Glicko2Observation {
                opponent_rating: f64::NAN,
                opponent_deviation: 30.0,
                score: Glicko2Score::Win,
            }],
            Glicko2Config::default()
        )
        .is_err());
    }

    #[test]
    fn version_one_normalization_clamps_at_documented_bounds() {
        for (rating, expected) in [
            (1_000.0, 0.0),
            (1_500.0, 0.5),
            (2_000.0, 1.0),
            (2_500.0, 1.0),
        ] {
            let actual = normalize_glicko2_rating(rating).expect("有效");
            assert!((actual - expected).abs() < f64::EPSILON);
        }
    }
}
