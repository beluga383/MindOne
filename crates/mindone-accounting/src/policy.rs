use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{AccountingError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePolicy {
    pub reject_tags: BTreeSet<String>,
    pub max_concurrent: u32,
    pub gpu_temp_limit_c: Option<u16>,
    pub vram_reserve_mib: u64,
    pub resume_temp_hysteresis_c: u16,
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self {
            reject_tags: BTreeSet::new(),
            max_concurrent: 1,
            gpu_temp_limit_c: None,
            vram_reserve_mib: 0,
            resume_temp_hysteresis_c: 5,
        }
    }
}

impl NodePolicy {
    pub fn validate(&self) -> Result<()> {
        if self.max_concurrent == 0 {
            return Err(AccountingError::InvalidPolicy(
                "max_concurrent 必须大于零".to_owned(),
            ));
        }
        if self
            .gpu_temp_limit_c
            .is_some_and(|limit| limit == 0 || self.resume_temp_hysteresis_c >= limit)
        {
            return Err(AccountingError::InvalidPolicy(
                "GPU 温度上限必须大于零且高于恢复滞回值".to_owned(),
            ));
        }
        if self.reject_tags.iter().any(|tag| {
            tag.trim().is_empty() || tag.len() > 128 || tag.chars().any(char::is_control)
        }) {
            return Err(AccountingError::InvalidPolicy(
                "拒绝标签为空或无效".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn normalized(mut self) -> Self {
        self.reject_tags = self
            .reject_tags
            .into_iter()
            .map(|tag| tag.trim().to_ascii_lowercase())
            .collect();
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeRuntime {
    pub task_tags: BTreeSet<String>,
    pub current_concurrent: u32,
    pub gpu_temp_c: Option<f64>,
    pub available_vram_mib: Option<u64>,
    pub paused_for_temperature: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceMetric {
    GpuTemperature,
    AvailableVram,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyRejection {
    RejectedTag {
        tag: String,
    },
    MaximumConcurrency {
        current: u32,
        maximum: u32,
    },
    InsufficientVram {
        available_mib: u64,
        reserved_mib: u64,
    },
    MetricUnavailable {
        metric: ResourceMetric,
    },
    InvalidMetric {
        metric: ResourceMetric,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    Accept { resumed_from_temperature: bool },
    PauseTemperature { current_c: f64, limit_c: u16 },
    Reject { reason: PolicyRejection },
}

pub fn evaluate_policy(policy: &NodePolicy, runtime: &NodeRuntime) -> Result<PolicyDecision> {
    policy.validate()?;
    let normalized_reject_tags: BTreeSet<String> = policy
        .reject_tags
        .iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .collect();
    let normalized_task_tags: BTreeSet<String> = runtime
        .task_tags
        .iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .collect();
    if let Some(tag) = normalized_reject_tags
        .intersection(&normalized_task_tags)
        .next()
    {
        return Ok(PolicyDecision::Reject {
            reason: PolicyRejection::RejectedTag { tag: tag.clone() },
        });
    }
    if runtime.current_concurrent >= policy.max_concurrent {
        return Ok(PolicyDecision::Reject {
            reason: PolicyRejection::MaximumConcurrency {
                current: runtime.current_concurrent,
                maximum: policy.max_concurrent,
            },
        });
    }

    let mut resumed_from_temperature = false;
    if let Some(limit) = policy.gpu_temp_limit_c {
        let Some(temperature) = runtime.gpu_temp_c else {
            return Ok(PolicyDecision::Reject {
                reason: PolicyRejection::MetricUnavailable {
                    metric: ResourceMetric::GpuTemperature,
                },
            });
        };
        if !temperature.is_finite() || temperature < 0.0 {
            return Ok(PolicyDecision::Reject {
                reason: PolicyRejection::InvalidMetric {
                    metric: ResourceMetric::GpuTemperature,
                },
            });
        }
        let resume_below = f64::from(limit.saturating_sub(policy.resume_temp_hysteresis_c));
        let must_pause = if runtime.paused_for_temperature {
            temperature > resume_below
        } else {
            temperature >= f64::from(limit)
        };
        if must_pause {
            return Ok(PolicyDecision::PauseTemperature {
                current_c: temperature,
                limit_c: limit,
            });
        }
        resumed_from_temperature = runtime.paused_for_temperature;
    }

    if policy.vram_reserve_mib > 0 {
        let Some(available) = runtime.available_vram_mib else {
            return Ok(PolicyDecision::Reject {
                reason: PolicyRejection::MetricUnavailable {
                    metric: ResourceMetric::AvailableVram,
                },
            });
        };
        if available < policy.vram_reserve_mib {
            return Ok(PolicyDecision::Reject {
                reason: PolicyRejection::InsufficientVram {
                    available_mib: available,
                    reserved_mib: policy.vram_reserve_mib,
                },
            });
        }
    }

    Ok(PolicyDecision::Accept {
        resumed_from_temperature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> NodeRuntime {
        NodeRuntime {
            task_tags: BTreeSet::new(),
            current_concurrent: 0,
            gpu_temp_c: Some(60.0),
            available_vram_mib: Some(8_192),
            paused_for_temperature: false,
        }
    }

    #[test]
    fn enforces_tags_and_concurrency_deterministically() {
        let policy = NodePolicy {
            reject_tags: BTreeSet::from(["private".to_owned(), "regulated".to_owned()]),
            max_concurrent: 2,
            ..NodePolicy::default()
        };
        let mut state = runtime();
        state.task_tags = BTreeSet::from(["REGULATED".to_owned(), "private".to_owned()]);
        let decision = evaluate_policy(&policy, &state).expect("策略应有效");
        assert_eq!(
            decision,
            PolicyDecision::Reject {
                reason: PolicyRejection::RejectedTag {
                    tag: "private".to_owned()
                }
            }
        );
        state.task_tags.clear();
        state.current_concurrent = 2;
        assert!(matches!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::Reject {
                reason: PolicyRejection::MaximumConcurrency { .. }
            }
        ));
    }

    #[test]
    fn pauses_and_resumes_temperature_with_hysteresis() {
        let policy = NodePolicy {
            gpu_temp_limit_c: Some(80),
            resume_temp_hysteresis_c: 5,
            ..NodePolicy::default()
        };
        let mut state = runtime();
        state.gpu_temp_c = Some(80.0);
        assert!(matches!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::PauseTemperature { .. }
        ));
        state.paused_for_temperature = true;
        state.gpu_temp_c = Some(76.0);
        assert!(matches!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::PauseTemperature { .. }
        ));
        state.gpu_temp_c = Some(75.0);
        assert_eq!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::Accept {
                resumed_from_temperature: true
            }
        );
    }

    #[test]
    fn configured_limits_fail_closed_without_metrics() {
        let policy = NodePolicy {
            gpu_temp_limit_c: Some(80),
            vram_reserve_mib: 4_096,
            ..NodePolicy::default()
        };
        let mut state = runtime();
        state.gpu_temp_c = None;
        assert!(matches!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::Reject {
                reason: PolicyRejection::MetricUnavailable { .. }
            }
        ));
        state.gpu_temp_c = Some(60.0);
        state.available_vram_mib = Some(2_048);
        assert!(matches!(
            evaluate_policy(&policy, &state).expect("策略应有效"),
            PolicyDecision::Reject {
                reason: PolicyRejection::InsufficientVram { .. }
            }
        ));
    }
}
