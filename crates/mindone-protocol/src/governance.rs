use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Public transparency report window. The coordinator rejects values outside its bounded range.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparencyReportQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_days: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyMicroDistribution {
    pub total_micro: Option<i64>,
    pub minimum_micro: Option<i64>,
    pub median_micro: Option<i64>,
    pub p90_micro: Option<i64>,
    pub maximum_micro: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContributorRewardsTransparency {
    /// Distinct receipt `node_user_id` accounts in the report window; not physical node count.
    pub contributing_accounts: i64,
    pub privacy_threshold_accounts: i64,
    /// Both value tracks are suppressed together below the shared account threshold.
    pub distribution_available: bool,
    /// Spendable quota awarded through receipt `node_quota_micro` values.
    pub spendable_quota: TransparencyMicroDistribution,
    /// Non-spendable contribution points from receipt `contribution_micro` values.
    pub contribution_points: TransparencyMicroDistribution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AntiAbuseTransparency {
    /// Server decisions with `decision=block`; no user, device, IP-prefix, or ASN identifiers.
    pub blocked_assessments: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveTransparency {
    pub balance_micro: i64,
    pub window_inflow_micro: i64,
    pub window_outflow_micro: i64,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaExclusionCategoryCounts {
    pub content_policy_refusal: i64,
    pub force_majeure: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaTransparency {
    /// Cohort admitted by the coordinator during the report window.
    pub accepted_jobs: i64,
    /// Effective v2 denominator; mirrors `included_denominator_jobs` for legacy clients.
    pub effective_terminal_jobs: i64,
    pub succeeded_jobs: i64,
    pub failed_jobs: i64,
    pub pending_jobs: i64,
    pub cancelled_jobs: i64,
    /// All terminal jobs: `succeeded + failed + cancelled`.
    #[serde(default)]
    pub total_terminal_jobs: i64,
    /// SLA denominator after subtracting audited failed-job exclusions.
    #[serde(default)]
    pub included_denominator_jobs: i64,
    /// All audited decisions, including decisions attached to already-excluded cancelled jobs.
    #[serde(default)]
    pub excluded_jobs: i64,
    /// Audited failed jobs removed from the SLA denominator.
    #[serde(default)]
    pub excluded_failed_jobs: i64,
    /// Audited decisions by stable allowlisted category; cancelled decisions are included.
    #[serde(default)]
    pub exclusions_by_category: SlaExclusionCategoryCounts,
    pub effective_task_success_rate_ppm: Option<i32>,
    pub target_success_rate_ppm: i32,
    pub target_met: Option<bool>,
    pub observation_scope: String,
    pub excluded_before_admission: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyReportResponse {
    pub generated_at: OffsetDateTime,
    pub window_start: OffsetDateTime,
    pub window_end: OffsetDateTime,
    pub contributor_rewards: ContributorRewardsTransparency,
    pub anti_abuse: AntiAbuseTransparency,
    pub reserve: ReserveTransparency,
    pub sla: SlaTransparency,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{ContributorRewardsTransparency, SlaTransparency, TransparencyMicroDistribution};

    #[test]
    fn contributor_rewards_json_keeps_spendable_quota_and_points_separate() {
        let value = serde_json::to_value(ContributorRewardsTransparency {
            contributing_accounts: 5,
            privacy_threshold_accounts: 5,
            distribution_available: true,
            spendable_quota: TransparencyMicroDistribution {
                total_micro: Some(500),
                minimum_micro: Some(20),
                median_micro: Some(80),
                p90_micro: Some(200),
                maximum_micro: Some(200),
            },
            contribution_points: TransparencyMicroDistribution {
                total_micro: Some(900),
                minimum_micro: Some(40),
                median_micro: Some(140),
                p90_micro: Some(360),
                maximum_micro: Some(360),
            },
        })
        .expect("透明度双轨 DTO 应可序列化");

        assert_eq!(
            value,
            json!({
                "contributing_accounts": 5,
                "privacy_threshold_accounts": 5,
                "distribution_available": true,
                "spendable_quota": {
                    "total_micro": 500,
                    "minimum_micro": 20,
                    "median_micro": 80,
                    "p90_micro": 200,
                    "maximum_micro": 200
                },
                "contribution_points": {
                    "total_micro": 900,
                    "minimum_micro": 40,
                    "median_micro": 140,
                    "p90_micro": 360,
                    "maximum_micro": 360
                }
            })
        );
        assert!(value.get("node_earnings").is_none());
        assert!(value.get("total_earnings_micro").is_none());
    }

    #[test]
    fn legacy_sla_json_defaults_v2_exclusion_fields() {
        let legacy = json!({
            "accepted_jobs": 8,
            "effective_terminal_jobs": 6,
            "succeeded_jobs": 5,
            "failed_jobs": 1,
            "pending_jobs": 1,
            "cancelled_jobs": 1,
            "effective_task_success_rate_ppm": 833333,
            "target_success_rate_ppm": 995000,
            "target_met": false,
            "observation_scope": "accepted_jobs_terminal_outcomes_v1",
            "excluded_before_admission": []
        });
        let decoded: SlaTransparency =
            serde_json::from_value(legacy).expect("旧 SLA JSON 应保持可解码");
        assert_eq!(decoded.total_terminal_jobs, 0);
        assert_eq!(decoded.included_denominator_jobs, 0);
        assert_eq!(decoded.excluded_jobs, 0);
        assert_eq!(decoded.excluded_failed_jobs, 0);
        assert_eq!(decoded.exclusions_by_category.content_policy_refusal, 0);
        assert_eq!(decoded.exclusions_by_category.force_majeure, 0);
    }
}
