//! MindOne 的确定性经济、账本、评价、路由与节点策略算法。
//!
//! 金额始终使用整数 microquota；浮点数只用于 0..=1 的评分，不参与账本金额。

pub mod billing;
pub mod fixed;
pub mod glicko2;
pub mod ledger;
pub mod optimize;
pub mod policy;
pub mod quality;
pub mod reserve;
pub mod routing;
pub mod tier;

pub use billing::{
    maximum_reservation_micro, maximum_reservation_quote, quote_server_reference_upper_bound,
    PhysicalBillingQuote, ServerReferenceBillingProfile, SERVER_REFERENCE_UPPER_BOUND_V1,
};
pub use fixed::{MicroQuota, PerformanceTier, Settlement, TrustClass, MICROQUOTA_PER_QUOTA};
pub use glicko2::{
    normalize_glicko2_rating, update_glicko2, Glicko2Config, Glicko2Observation, Glicko2Rating,
    Glicko2Score,
};
pub use ledger::{validate_chain, LedgerEntry, LedgerKind, GENESIS_HASH, LEDGER_HASH_VERSION};
pub use optimize::{optimize, AdvicePriority, OptimizationAdvice, OptimizationMetrics};
pub use policy::{
    evaluate_policy, NodePolicy, NodeRuntime, PolicyDecision, PolicyRejection, ResourceMetric,
};
pub use quality::{fused_quality, QualityFusion};
pub use reserve::{ReservePurpose, ReserveRelease, ReserveState};
pub use routing::{
    rank_contribution_candidates, rank_models, rank_nodes, route, ContributionRoutingCandidate,
    ContributionRoutingRankedCandidate, ModelCandidate, ModelRequirements, ModelWeights,
    NodeCandidate, NodeRequirements, NodeWeights, RoutingDecision, ScoredCandidate,
    CONTRIBUTION_ROUTING_MIN_COHORT, CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR,
    CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR, CONTRIBUTION_ROUTING_PERCENTILE_SCALE,
    CONTRIBUTION_ROUTING_VERSION, CONTRIBUTION_ROUTING_WINDOW_DAYS,
};
pub use tier::{TierPolicy, TierResult};

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq)]
pub enum AccountingError {
    #[error("数值必须为非负整数：{field}")]
    NegativeAmount { field: &'static str },
    #[error("整数运算溢出：{operation}")]
    Overflow { operation: &'static str },
    #[error("余额不足：需要 {required} microquota，当前 {available} microquota")]
    InsufficientBalance { required: i64, available: i64 },
    #[error("账本记录无效：{0}")]
    InvalidLedger(String),
    #[error("评分参数无效：{0}")]
    InvalidScore(String),
    #[error("路由参数无效：{0}")]
    InvalidRouting(String),
    #[error("没有符合条件的模型")]
    NoEligibleModel,
    #[error("没有符合条件的节点")]
    NoEligibleNode,
    #[error("Tier 参数无效：{0}")]
    InvalidTierPolicy(String),
    #[error("Glicko-2 参数无效：{0}")]
    InvalidGlicko2(String),
    #[error("节点策略无效：{0}")]
    InvalidPolicy(String),
    #[error("准备金释放无效：{0}")]
    InvalidReserveRelease(String),
    #[error("物理计费参数无效：{0}")]
    InvalidBilling(String),
}

pub type Result<T> = std::result::Result<T, AccountingError>;
