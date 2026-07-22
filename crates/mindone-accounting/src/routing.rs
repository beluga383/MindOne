use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::quality::validate_unit_interval;
use crate::{AccountingError, Result};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelCandidate {
    pub id: String,
    pub quality: f64,
    pub intent_match: f64,
    pub normalized_cost: f64,
    pub available: bool,
    pub context_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelWeights {
    pub quality: f64,
    pub intent_match: f64,
    pub cost: f64,
}

impl Default for ModelWeights {
    fn default() -> Self {
        Self {
            quality: 0.5,
            intent_match: 0.3,
            cost: 0.2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ModelRequirements {
    pub minimum_context_length: u32,
    pub weights: ModelWeights,
}

impl Default for ModelRequirements {
    fn default() -> Self {
        Self {
            minimum_context_length: 1,
            weights: ModelWeights::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeCandidate {
    pub id: String,
    pub model_id: String,
    pub trust: f64,
    pub health: f64,
    /// Worker 观测到的最近一次协调器心跳往返时延。
    ///
    /// `None` 表示尚无观测，不表示 0ms；未知节点保留候选资格，但网络项得分为 0。
    pub coordinator_rtt_ms: Option<u32>,
    pub capacity: f64,
    pub current_concurrent: u32,
    pub max_concurrent: u32,
    pub recent_error_rate: f64,
    pub policy_allowed: bool,
    pub circuit_open: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NodeWeights {
    pub trust: f64,
    pub health: f64,
    pub latency: f64,
    pub capacity: f64,
    pub available_load: f64,
    pub reliability: f64,
}

impl Default for NodeWeights {
    fn default() -> Self {
        Self {
            trust: 0.25,
            health: 0.20,
            latency: 0.15,
            capacity: 0.15,
            available_load: 0.15,
            reliability: 0.10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NodeRequirements {
    pub minimum_trust: f64,
    pub minimum_health: f64,
    pub weights: NodeWeights,
}

impl Default for NodeRequirements {
    fn default() -> Self {
        Self {
            minimum_trust: 0.0,
            minimum_health: 0.0,
            weights: NodeWeights::default(),
        }
    }
}

/// Phase 2 网络项采用的定点分值尺度。
pub const ROUTING_SCORE_SCALE: u32 = 1_000_000;

/// 已报告 RTT 的可路由上限；超过此值的节点会被过滤。
pub const MAX_ROUTABLE_COORDINATOR_RTT_MS: u32 = 1_000;

/// 网络拥堵时贡献优先路由的稳定协议版本。
pub const CONTRIBUTION_ROUTING_VERSION: &str = "contribution-routing-v1";

/// 只使用最近 30 天已结算 receipt 的反作弊加权贡献。
pub const CONTRIBUTION_ROUTING_WINDOW_DAYS: i64 = 30;

/// 小 cohort 不启用贡献优先，避免把稀疏样本放大为稳定排序信号。
pub const CONTRIBUTION_ROUTING_MIN_COHORT: usize = 5;

/// 贡献 midrank percentile 的定点尺度。
pub const CONTRIBUTION_ROUTING_PERCENTILE_SCALE: u32 = 1_000_000;

/// 只有基础路由分不低于最佳分 98% 的候选可以使用贡献 percentile。
pub const CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR: i64 = 98;
pub const CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR: i64 = 100;

/// 返回协调器 RTT 对应的归一化网络分值。
///
/// 外层 `None` 表示已报告的 RTT 不在 `1..=1000ms` 内，候选必须过滤。
/// 输入 `None` 表示没有 RTT 观测，候选仍可参与，但网络项为 0；这绝不表示
/// 实测 RTT 为 0ms。
pub const fn normalized_coordinator_rtt_score(coordinator_rtt_ms: Option<u32>) -> Option<u32> {
    match coordinator_rtt_ms {
        None => Some(0),
        Some(rtt_ms) if rtt_ms >= 1 && rtt_ms <= MAX_ROUTABLE_COORDINATOR_RTT_MS => {
            Some(ROUTING_SCORE_SCALE - rtt_ms * 1_000)
        }
        Some(_) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoredCandidate {
    pub id: String,
    pub score: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub model: ScoredCandidate,
    pub node: ScoredCandidate,
}

/// 已通过全部安全、策略与容量硬过滤的唯一节点候选。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionRoutingCandidate {
    pub id: String,
    pub base_score: i64,
    pub contribution_micro: i64,
}

/// `contribution-routing-v1` 的确定性排序结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributionRoutingRankedCandidate {
    pub id: String,
    pub base_score: i64,
    pub contribution_micro: i64,
    /// 仅在真实拥堵、cohort 足够且候选位于最佳分 2% 内时存在。
    pub contribution_percentile_ppm: Option<u32>,
}

/// 对一个已经完成全部硬过滤的唯一节点 cohort 应用贡献优先排序。
///
/// 拥堵只由服务端数据库中的 ready demand 与服务端计数的空闲槽位判断；调用者
/// 不得把节点自报并发量传入 `server_free_slots`。非拥堵、小 cohort 和最佳分 2%
/// 以外的候选保持原基础分排序，贡献绝不用于恢复已被过滤的节点。
pub fn rank_contribution_candidates(
    candidates: &[ContributionRoutingCandidate],
    ready_demand: u64,
    server_free_slots: u64,
) -> Result<Vec<ContributionRoutingRankedCandidate>> {
    let mut identifiers = BTreeSet::new();
    for candidate in candidates {
        validate_identifier(&candidate.id, "贡献路由候选 ID")?;
        if !identifiers.insert(candidate.id.as_str()) {
            return Err(AccountingError::InvalidRouting(
                "贡献路由候选 ID 必须唯一".to_owned(),
            ));
        }
        if candidate.base_score < 0 {
            return Err(AccountingError::InvalidRouting(
                "贡献路由基础分必须是非负整数".to_owned(),
            ));
        }
        if candidate.contribution_micro < 0 {
            return Err(AccountingError::InvalidRouting(
                "贡献路由贡献值必须是非负整数".to_owned(),
            ));
        }
    }

    let contribution_enabled =
        candidates.len() >= CONTRIBUTION_ROUTING_MIN_COHORT && ready_demand > server_free_slots;
    let best_score = candidates
        .iter()
        .map(|candidate| candidate.base_score)
        .max()
        .unwrap_or_default();
    let percentiles = if contribution_enabled {
        contribution_midrank_percentiles(candidates)
    } else {
        BTreeMap::new()
    };

    let mut ranked = candidates
        .iter()
        .map(|candidate| {
            let within_near_best = i128::from(candidate.base_score)
                * i128::from(CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR)
                >= i128::from(best_score) * i128::from(CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR);
            let contribution_percentile_ppm = if contribution_enabled && within_near_best {
                percentiles.get(&candidate.contribution_micro).copied()
            } else {
                None
            };
            ContributionRoutingRankedCandidate {
                id: candidate.id.clone(),
                base_score: candidate.base_score,
                contribution_micro: candidate.contribution_micro,
                contribution_percentile_ppm,
            }
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        right
            .contribution_percentile_ppm
            .cmp(&left.contribution_percentile_ppm)
            .then_with(|| right.base_score.cmp(&left.base_score))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(ranked)
}

fn contribution_midrank_percentiles(
    candidates: &[ContributionRoutingCandidate],
) -> BTreeMap<i64, u32> {
    let mut frequencies = BTreeMap::<i64, u64>::new();
    for candidate in candidates {
        *frequencies.entry(candidate.contribution_micro).or_default() += 1;
    }
    let cohort_size = candidates.len() as u128;
    let mut lower = 0_u128;
    frequencies
        .into_iter()
        .map(|(contribution, tied)| {
            let tied = u128::from(tied);
            let numerator =
                (2 * lower + tied - 1) * u128::from(CONTRIBUTION_ROUTING_PERCENTILE_SCALE);
            let denominator = 2 * (cohort_size - 1);
            let percentile = u32::try_from(numerator / denominator)
                .unwrap_or(CONTRIBUTION_ROUTING_PERCENTILE_SCALE);
            lower += tied;
            (contribution, percentile)
        })
        .collect()
}

pub fn route(
    models: &[ModelCandidate],
    nodes: &[NodeCandidate],
    model_requirements: ModelRequirements,
    node_requirements: NodeRequirements,
) -> Result<RoutingDecision> {
    let ranked_models = rank_models(models, model_requirements)?;
    if ranked_models.is_empty() {
        return Err(AccountingError::NoEligibleModel);
    }

    for model in ranked_models {
        let ranked_nodes = rank_nodes(nodes, &model.id, node_requirements)?;
        if let Some(node) = ranked_nodes.into_iter().next() {
            return Ok(RoutingDecision { model, node });
        }
    }
    Err(AccountingError::NoEligibleNode)
}

pub fn rank_models(
    candidates: &[ModelCandidate],
    requirements: ModelRequirements,
) -> Result<Vec<ScoredCandidate>> {
    let weight_sum = validate_model_weights(requirements.weights)?;
    let mut scored = Vec::new();
    for candidate in candidates {
        validate_identifier(&candidate.id, "模型 ID")?;
        validate_unit_interval(candidate.quality, "quality")?;
        validate_unit_interval(candidate.intent_match, "intent_match")?;
        validate_unit_interval(candidate.normalized_cost, "normalized_cost")?;
        if !candidate.available || candidate.context_length < requirements.minimum_context_length {
            continue;
        }
        let weights = requirements.weights;
        let score = (weights.quality * candidate.quality
            + weights.intent_match * candidate.intent_match
            - weights.cost * candidate.normalized_cost)
            / weight_sum;
        scored.push(ScoredCandidate {
            id: candidate.id.clone(),
            score,
        });
    }
    sort_scored(&mut scored);
    Ok(scored)
}

pub fn rank_nodes(
    candidates: &[NodeCandidate],
    model_id: &str,
    requirements: NodeRequirements,
) -> Result<Vec<ScoredCandidate>> {
    validate_identifier(model_id, "模型 ID")?;
    validate_unit_interval(requirements.minimum_trust, "minimum_trust")?;
    validate_unit_interval(requirements.minimum_health, "minimum_health")?;
    let weight_sum = validate_node_weights(requirements.weights)?;
    let mut scored = Vec::new();
    for candidate in candidates.iter().filter(|node| node.model_id == model_id) {
        validate_identifier(&candidate.id, "节点 ID")?;
        validate_unit_interval(candidate.trust, "trust")?;
        validate_unit_interval(candidate.health, "health")?;
        validate_unit_interval(candidate.capacity, "capacity")?;
        validate_unit_interval(candidate.recent_error_rate, "recent_error_rate")?;
        if !candidate.policy_allowed
            || candidate.circuit_open
            || candidate.max_concurrent == 0
            || candidate.current_concurrent >= candidate.max_concurrent
            || candidate.trust < requirements.minimum_trust
            || candidate.health < requirements.minimum_health
        {
            continue;
        }

        let Some(latency_score) = normalized_coordinator_rtt_score(candidate.coordinator_rtt_ms)
        else {
            continue;
        };
        let latency = f64::from(latency_score) / f64::from(ROUTING_SCORE_SCALE);
        let available_load =
            1.0 - f64::from(candidate.current_concurrent) / f64::from(candidate.max_concurrent);
        let reliability = 1.0 - candidate.recent_error_rate;
        let weights = requirements.weights;
        let score = (weights.trust * candidate.trust
            + weights.health * candidate.health
            + weights.latency * latency
            + weights.capacity * candidate.capacity
            + weights.available_load * available_load
            + weights.reliability * reliability)
            / weight_sum;
        scored.push(ScoredCandidate {
            id: candidate.id.clone(),
            score,
        });
    }
    sort_scored(&mut scored);
    Ok(scored)
}

fn validate_model_weights(weights: ModelWeights) -> Result<f64> {
    validate_weights(&[weights.quality, weights.intent_match, weights.cost])
}

fn validate_node_weights(weights: NodeWeights) -> Result<f64> {
    validate_weights(&[
        weights.trust,
        weights.health,
        weights.latency,
        weights.capacity,
        weights.available_load,
        weights.reliability,
    ])
}

fn validate_weights(weights: &[f64]) -> Result<f64> {
    if weights
        .iter()
        .any(|weight| !weight.is_finite() || *weight < 0.0)
    {
        return Err(AccountingError::InvalidRouting(
            "路由权重必须是非负有限数".to_owned(),
        ));
    }
    let sum: f64 = weights.iter().sum();
    if sum <= 0.0 || !sum.is_finite() {
        return Err(AccountingError::InvalidRouting(
            "路由权重之和必须大于零".to_owned(),
        ));
    }
    Ok(sum)
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(AccountingError::InvalidRouting(format!(
            "{label} 为空或无效"
        )));
    }
    Ok(())
}

fn sort_scored(scored: &mut [ScoredCandidate]) {
    scored.sort_by(|left, right| {
        right
            .score
            .total_cmp(&left.score)
            .then_with(|| left.id.cmp(&right.id))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(id: &str, quality: f64) -> ModelCandidate {
        ModelCandidate {
            id: id.to_owned(),
            quality,
            intent_match: 0.8,
            normalized_cost: 0.2,
            available: true,
            context_length: 8_192,
        }
    }

    fn node(id: &str, model_id: &str, coordinator_rtt_ms: Option<u32>) -> NodeCandidate {
        NodeCandidate {
            id: id.to_owned(),
            model_id: model_id.to_owned(),
            trust: 1.0,
            health: 0.95,
            coordinator_rtt_ms,
            capacity: 0.9,
            current_concurrent: 0,
            max_concurrent: 2,
            recent_error_rate: 0.01,
            policy_allowed: true,
            circuit_open: false,
        }
    }

    fn contribution_candidate(
        id: &str,
        base_score: i64,
        contribution_micro: i64,
    ) -> ContributionRoutingCandidate {
        ContributionRoutingCandidate {
            id: id.to_owned(),
            base_score,
            contribution_micro,
        }
    }

    #[test]
    fn routes_in_two_deterministic_phases() {
        let models = [model("model-b", 0.9), model("model-a", 0.9)];
        let nodes = [
            node("node-slow", "model-a", Some(100)),
            node("node-fast", "model-a", Some(10)),
            node("node-other", "model-b", Some(20)),
        ];
        let decision = route(
            &models,
            &nodes,
            ModelRequirements::default(),
            NodeRequirements::default(),
        )
        .expect("应找到路由");
        assert_eq!(decision.model.id, "model-a");
        assert_eq!(decision.node.id, "node-fast");
    }

    #[test]
    fn falls_back_to_next_model_when_top_has_no_node() {
        let models = [model("best", 0.95), model("fallback", 0.8)];
        let nodes = [node("available", "fallback", Some(20))];
        let decision = route(
            &models,
            &nodes,
            ModelRequirements::default(),
            NodeRequirements::default(),
        )
        .expect("应降级到可用模型");
        assert_eq!(decision.model.id, "fallback");
    }

    #[test]
    fn filters_context_policy_capacity_and_circuit_breaker() {
        let mut short = model("short", 1.0);
        short.context_length = 512;
        let models = [short, model("eligible", 0.7)];
        let mut denied = node("denied", "eligible", Some(1));
        denied.policy_allowed = false;
        let mut full = node("full", "eligible", Some(1));
        full.current_concurrent = full.max_concurrent;
        let mut open = node("open", "eligible", Some(1));
        open.circuit_open = true;
        let allowed = node("allowed", "eligible", Some(10));
        let decision = route(
            &models,
            &[denied, full, open, allowed],
            ModelRequirements {
                minimum_context_length: 4_096,
                weights: ModelWeights::default(),
            },
            NodeRequirements::default(),
        )
        .expect("应选择唯一合格路由");
        assert_eq!(decision.model.id, "eligible");
        assert_eq!(decision.node.id, "allowed");
    }

    #[test]
    fn rejects_nan_and_zero_weights() {
        let mut invalid = model("invalid", f64::NAN);
        assert!(rank_models(&[invalid.clone()], ModelRequirements::default()).is_err());
        invalid.quality = 0.5;
        assert!(rank_models(
            &[invalid],
            ModelRequirements {
                minimum_context_length: 1,
                weights: ModelWeights {
                    quality: 0.0,
                    intent_match: 0.0,
                    cost: 0.0,
                },
            },
        )
        .is_err());
    }

    #[test]
    fn coordinator_rtt_score_has_explicit_unknown_and_1000ms_boundary() {
        assert_eq!(normalized_coordinator_rtt_score(None), Some(0));
        assert_eq!(normalized_coordinator_rtt_score(Some(1)), Some(999_000));
        assert_eq!(normalized_coordinator_rtt_score(Some(1_000)), Some(0));
        assert_eq!(normalized_coordinator_rtt_score(Some(1_001)), None);
    }

    #[test]
    fn unknown_rtt_stays_eligible_but_reported_over_limit_is_filtered() {
        let ranked = rank_nodes(
            &[
                node("unknown", "model", None),
                node("over-limit", "model", Some(1_001)),
            ],
            "model",
            NodeRequirements::default(),
        )
        .expect("RTT 缺失不是输入错误");

        assert_eq!(
            ranked
                .iter()
                .map(|candidate| candidate.id.as_str())
                .collect::<Vec<_>>(),
            ["unknown"]
        );
    }

    #[test]
    fn coordinator_rtt_decides_network_order_and_ttft_is_not_an_input() {
        struct ObservedNode {
            candidate: NodeCandidate,
            ttft_ms: u32,
        }

        let rank = |observations: &[ObservedNode]| {
            let candidates = observations
                .iter()
                .map(|observation| observation.candidate.clone())
                .collect::<Vec<_>>();
            rank_nodes(&candidates, "model", NodeRequirements::default())
                .expect("节点观测应有效")
                .into_iter()
                .map(|candidate| candidate.id)
                .collect::<Vec<_>>()
        };
        let observations = [
            ObservedNode {
                candidate: node("fast-rtt", "model", Some(10)),
                ttft_ms: 9_000,
            },
            ObservedNode {
                candidate: node("slow-rtt", "model", Some(900)),
                ttft_ms: 1,
            },
        ];
        let reversed_ttft = [
            ObservedNode {
                candidate: observations[0].candidate.clone(),
                ttft_ms: observations[1].ttft_ms,
            },
            ObservedNode {
                candidate: observations[1].candidate.clone(),
                ttft_ms: observations[0].ttft_ms,
            },
        ];

        assert_eq!(rank(&observations), ["fast-rtt", "slow-rtt"]);
        assert_eq!(rank(&reversed_ttft), rank(&observations));
    }

    #[test]
    fn contribution_routing_uses_deterministic_midrank_for_ties() {
        let ranked = rank_contribution_candidates(
            &[
                contribution_candidate("zero", 1_000, 0),
                contribution_candidate("tied-a", 1_000, 10),
                contribution_candidate("tied-b", 1_000, 10),
                contribution_candidate("higher", 1_000, 20),
                contribution_candidate("highest", 1_000, 30),
            ],
            6,
            5,
        )
        .expect("合格 cohort 应可排序");

        let tied_percentiles = ranked
            .iter()
            .filter(|candidate| candidate.id.starts_with("tied-"))
            .map(|candidate| candidate.contribution_percentile_ppm)
            .collect::<Vec<_>>();
        assert_eq!(tied_percentiles, [Some(375_000), Some(375_000)]);
        assert_eq!(ranked[0].id, "highest");
        assert_eq!(ranked[1].id, "higher");
        assert_eq!(ranked[2].id, "tied-a");
        assert_eq!(ranked[3].id, "tied-b");
        assert_eq!(ranked[4].contribution_percentile_ppm, Some(0));
    }

    #[test]
    fn contribution_routing_is_disabled_without_server_counted_congestion() {
        let candidates = [
            contribution_candidate("base-best", 10_000, 0),
            contribution_candidate("contribution-best", 9_900, 10_000),
            contribution_candidate("c", 9_800, 30),
            contribution_candidate("d", 9_700, 20),
            contribution_candidate("e", 9_600, 10),
        ];
        let ranked =
            rank_contribution_candidates(&candidates, 5, 5).expect("非拥堵 cohort 应保持基础排序");

        assert_eq!(ranked[0].id, "base-best");
        assert!(ranked
            .iter()
            .all(|candidate| candidate.contribution_percentile_ppm.is_none()));
    }

    #[test]
    fn contribution_routing_is_disabled_for_small_cohort() {
        let ranked = rank_contribution_candidates(
            &[
                contribution_candidate("base-best", 10_000, 0),
                contribution_candidate("contribution-best", 9_900, 10_000),
                contribution_candidate("c", 9_800, 30),
                contribution_candidate("d", 9_700, 20),
            ],
            100,
            0,
        )
        .expect("小 cohort 应安全回退");

        assert_eq!(ranked[0].id, "base-best");
        assert!(ranked
            .iter()
            .all(|candidate| candidate.contribution_percentile_ppm.is_none()));
    }

    #[test]
    fn contribution_routing_only_reorders_candidates_within_two_percent() {
        let ranked = rank_contribution_candidates(
            &[
                contribution_candidate("base-best", 10_000, 0),
                contribution_candidate("near-high-contribution", 9_800, 900),
                contribution_candidate("near-mid", 9_900, 100),
                contribution_candidate("outside-highest", 9_799, 1_000),
                contribution_candidate("outside", 9_000, 50),
            ],
            6,
            5,
        )
        .expect("拥堵 cohort 应可排序");

        assert_eq!(ranked[0].id, "near-high-contribution");
        assert_eq!(ranked[1].id, "near-mid");
        assert_eq!(ranked[2].id, "base-best");
        assert_eq!(ranked[3].id, "outside-highest");
        assert_eq!(ranked[3].contribution_percentile_ppm, None);
        assert_eq!(ranked[4].contribution_percentile_ppm, None);
    }

    #[test]
    fn contribution_routing_handles_maximum_scores_without_overflow() {
        let ranked = rank_contribution_candidates(
            &[
                contribution_candidate("a", i64::MAX, 0),
                contribution_candidate("b", i64::MAX - 1, 5),
                contribution_candidate("c", i64::MAX - 2, 4),
                contribution_candidate("d", i64::MAX - 3, 3),
                contribution_candidate("e", i64::MAX - 4, 2),
            ],
            6,
            5,
        )
        .expect("阈值乘法必须使用足够宽的整数");

        assert_eq!(ranked[0].id, "b");
    }

    #[test]
    fn contribution_routing_rejects_invalid_or_duplicate_candidates() {
        assert!(rank_contribution_candidates(
            &[
                contribution_candidate("duplicate", 1, 0),
                contribution_candidate("duplicate", 1, 1),
            ],
            2,
            0,
        )
        .is_err());
        assert!(
            rank_contribution_candidates(&[contribution_candidate("negative", -1, 0)], 2, 0,)
                .is_err()
        );
        assert!(
            rank_contribution_candidates(&[contribution_candidate("negative", 1, -1)], 2, 0,)
                .is_err()
        );
    }
}
