use axum::{
    extract::{rejection::QueryRejection, Query, State},
    Json,
};
use mindone_protocol::{
    AntiAbuseTransparency, ContributorRewardsTransparency, ReserveTransparency,
    SlaExclusionCategoryCounts, SlaTransparency, TransparencyMicroDistribution,
    TransparencyReportQuery, TransparencyReportResponse,
};
use sqlx::Row;
use time::{Duration, OffsetDateTime};

use crate::{error::ApiError, AppState};

const DEFAULT_WINDOW_DAYS: u16 = 30;
const MAX_WINDOW_DAYS: u16 = 366;
const CONTRIBUTOR_PRIVACY_THRESHOLD_ACCOUNTS: i64 = 5;
const SLA_TARGET_PPM: i32 = 995_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DistributionValues {
    total_micro: i64,
    minimum_micro: Option<i64>,
    median_micro: Option<i64>,
    p90_micro: Option<i64>,
    maximum_micro: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SlaOutcomeCounts {
    succeeded_jobs: i64,
    failed_jobs: i64,
    cancelled_jobs: i64,
    excluded_failed_jobs: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CalculatedSla {
    total_terminal_jobs: i64,
    included_denominator_jobs: i64,
    success_rate_ppm: Option<i32>,
}

fn calculate_sla(counts: SlaOutcomeCounts) -> Option<CalculatedSla> {
    if counts.succeeded_jobs < 0
        || counts.failed_jobs < 0
        || counts.cancelled_jobs < 0
        || counts.excluded_failed_jobs < 0
        || counts.excluded_failed_jobs > counts.failed_jobs
    {
        return None;
    }
    let total_terminal_jobs = counts
        .succeeded_jobs
        .checked_add(counts.failed_jobs)?
        .checked_add(counts.cancelled_jobs)?;
    let included_failed_jobs = counts
        .failed_jobs
        .checked_sub(counts.excluded_failed_jobs)?;
    let included_denominator_jobs = counts.succeeded_jobs.checked_add(included_failed_jobs)?;
    let success_rate_ppm = if included_denominator_jobs == 0 {
        None
    } else {
        let rate = i128::from(counts.succeeded_jobs)
            .checked_mul(1_000_000)?
            .checked_div(i128::from(included_denominator_jobs))?;
        Some(i32::try_from(rate).ok()?)
    };
    Some(CalculatedSla {
        total_terminal_jobs,
        included_denominator_jobs,
        success_rate_ppm,
    })
}

fn contributor_distribution_available(contributing_accounts: i64) -> bool {
    contributing_accounts >= CONTRIBUTOR_PRIVACY_THRESHOLD_ACCOUNTS
}

fn privacy_gated_distribution(
    distribution_available: bool,
    values: DistributionValues,
) -> TransparencyMicroDistribution {
    if distribution_available {
        TransparencyMicroDistribution {
            total_micro: Some(values.total_micro),
            minimum_micro: values.minimum_micro,
            median_micro: values.median_micro,
            p90_micro: values.p90_micro,
            maximum_micro: values.maximum_micro,
        }
    } else {
        TransparencyMicroDistribution::default()
    }
}

pub async fn transparency_report(
    State(state): State<AppState>,
    query: Result<Query<TransparencyReportQuery>, QueryRejection>,
) -> Result<Json<TransparencyReportResponse>, ApiError> {
    let Query(query) = query.map_err(|_| {
        ApiError::bad_request(
            "invalid_report_window",
            "window_days 必须是 1 到 366 之间的整数",
        )
    })?;
    let window_days = query.window_days.unwrap_or(DEFAULT_WINDOW_DAYS);
    if !(1..=MAX_WINDOW_DAYS).contains(&window_days) {
        return Err(ApiError::bad_request(
            "invalid_report_window",
            "window_days 必须是 1 到 366 之间的整数",
        ));
    }

    let mut tx = state.pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    let window_end: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let window_start = window_end
        .checked_sub(Duration::days(i64::from(window_days)))
        .ok_or_else(ApiError::internal)?;

    let contributor_rewards_row = sqlx::query(
        r#"
        WITH per_account AS (
            SELECT node_user_id,
                   SUM(node_quota_micro::numeric)::bigint AS spendable_quota_micro,
                   SUM(contribution_micro::numeric)::bigint AS contribution_points_micro
            FROM receipts
            WHERE created_at >= $1 AND created_at < $2
            GROUP BY node_user_id
        )
        SELECT COUNT(*)::bigint AS contributing_accounts,
               COALESCE(SUM(spendable_quota_micro),0)::bigint
                   AS spendable_quota_total_micro,
               MIN(spendable_quota_micro)::bigint AS spendable_quota_minimum_micro,
               percentile_disc(0.5) WITHIN GROUP (ORDER BY spendable_quota_micro)::bigint
                   AS spendable_quota_median_micro,
               percentile_disc(0.9) WITHIN GROUP (ORDER BY spendable_quota_micro)::bigint
                   AS spendable_quota_p90_micro,
               MAX(spendable_quota_micro)::bigint AS spendable_quota_maximum_micro,
               COALESCE(SUM(contribution_points_micro),0)::bigint
                   AS contribution_points_total_micro,
               MIN(contribution_points_micro)::bigint AS contribution_points_minimum_micro,
               percentile_disc(0.5) WITHIN GROUP (ORDER BY contribution_points_micro)::bigint
                   AS contribution_points_median_micro,
               percentile_disc(0.9) WITHIN GROUP (ORDER BY contribution_points_micro)::bigint
                   AS contribution_points_p90_micro,
               MAX(contribution_points_micro)::bigint AS contribution_points_maximum_micro
        FROM per_account
        "#,
    )
    .bind(window_start)
    .bind(window_end)
    .fetch_one(&mut *tx)
    .await?;
    let contributing_accounts: i64 = contributor_rewards_row.try_get("contributing_accounts")?;
    let distribution_available = contributor_distribution_available(contributing_accounts);
    let spendable_quota = privacy_gated_distribution(
        distribution_available,
        DistributionValues {
            total_micro: contributor_rewards_row.try_get("spendable_quota_total_micro")?,
            minimum_micro: contributor_rewards_row.try_get("spendable_quota_minimum_micro")?,
            median_micro: contributor_rewards_row.try_get("spendable_quota_median_micro")?,
            p90_micro: contributor_rewards_row.try_get("spendable_quota_p90_micro")?,
            maximum_micro: contributor_rewards_row.try_get("spendable_quota_maximum_micro")?,
        },
    );
    let contribution_points = privacy_gated_distribution(
        distribution_available,
        DistributionValues {
            total_micro: contributor_rewards_row.try_get("contribution_points_total_micro")?,
            minimum_micro: contributor_rewards_row.try_get("contribution_points_minimum_micro")?,
            median_micro: contributor_rewards_row.try_get("contribution_points_median_micro")?,
            p90_micro: contributor_rewards_row.try_get("contribution_points_p90_micro")?,
            maximum_micro: contributor_rewards_row.try_get("contribution_points_maximum_micro")?,
        },
    );
    let contributor_rewards = ContributorRewardsTransparency {
        contributing_accounts,
        privacy_threshold_accounts: CONTRIBUTOR_PRIVACY_THRESHOLD_ACCOUNTS,
        distribution_available,
        spendable_quota,
        contribution_points,
    };

    let blocked_assessments: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM abuse_decisions
        WHERE decision = 'block' AND created_at >= $1 AND created_at < $2
        "#,
    )
    .bind(window_start)
    .bind(window_end)
    .fetch_one(&mut *tx)
    .await?;

    let reserve_row = sqlx::query(
        r#"
        SELECT account.balance_micro,account.updated_at,
               COALESCE((
                   SELECT SUM(delta_micro) FROM reserve_ledger
                   WHERE delta_micro > 0 AND created_at >= $1 AND created_at < $2
               ),0)::bigint AS window_inflow_micro,
               COALESCE((
                   SELECT SUM(-delta_micro::numeric) FROM reserve_ledger
                   WHERE delta_micro < 0 AND created_at >= $1 AND created_at < $2
               ),0)::bigint AS window_outflow_micro
        FROM reserve_accounts account WHERE account.id = 1
        "#,
    )
    .bind(window_start)
    .bind(window_end)
    .fetch_one(&mut *tx)
    .await?;
    let reserve = ReserveTransparency {
        balance_micro: reserve_row.try_get("balance_micro")?,
        window_inflow_micro: reserve_row.try_get("window_inflow_micro")?,
        window_outflow_micro: reserve_row.try_get("window_outflow_micro")?,
        updated_at: reserve_row.try_get("updated_at")?,
    };

    let sla_row = sqlx::query(
        r#"
        SELECT COUNT(*)::bigint AS accepted_jobs,
               COUNT(*) FILTER (WHERE job.status = 'succeeded')::bigint AS succeeded_jobs,
               COUNT(*) FILTER (WHERE job.status = 'failed')::bigint AS failed_jobs,
               COUNT(*) FILTER (WHERE job.status IN ('queued','leased','retry'))::bigint
                   AS pending_jobs,
               COUNT(*) FILTER (WHERE job.status = 'cancelled')::bigint AS cancelled_jobs,
               COUNT(exclusion.id)::bigint AS excluded_jobs,
               COUNT(exclusion.id) FILTER (WHERE job.status = 'failed')::bigint
                   AS excluded_failed_jobs,
               COUNT(exclusion.id) FILTER (
                   WHERE exclusion.category = 'content_policy_refusal'
               )::bigint AS content_policy_refusal_exclusions,
               COUNT(exclusion.id) FILTER (
                   WHERE exclusion.category = 'force_majeure'
               )::bigint AS force_majeure_exclusions
        FROM jobs AS job
        LEFT JOIN sla_exclusion_events AS exclusion ON exclusion.job_id = job.id
        WHERE job.created_at >= $1 AND job.created_at < $2
        "#,
    )
    .bind(window_start)
    .bind(window_end)
    .fetch_one(&mut *tx)
    .await?;
    let accepted_jobs: i64 = sla_row.try_get("accepted_jobs")?;
    let succeeded_jobs: i64 = sla_row.try_get("succeeded_jobs")?;
    let failed_jobs: i64 = sla_row.try_get("failed_jobs")?;
    let pending_jobs: i64 = sla_row.try_get("pending_jobs")?;
    let cancelled_jobs: i64 = sla_row.try_get("cancelled_jobs")?;
    let excluded_jobs: i64 = sla_row.try_get("excluded_jobs")?;
    let excluded_failed_jobs: i64 = sla_row.try_get("excluded_failed_jobs")?;
    let content_policy_refusal_exclusions: i64 =
        sla_row.try_get("content_policy_refusal_exclusions")?;
    let force_majeure_exclusions: i64 = sla_row.try_get("force_majeure_exclusions")?;
    let calculated = calculate_sla(SlaOutcomeCounts {
        succeeded_jobs,
        failed_jobs,
        cancelled_jobs,
        excluded_failed_jobs,
    })
    .ok_or_else(ApiError::internal)?;
    let effective_task_success_rate_ppm = calculated.success_rate_ppm;
    let sla = SlaTransparency {
        accepted_jobs,
        // v1 clients use this as their denominator; preserve the field while
        // advancing its effective meaning to the audited v2 denominator.
        effective_terminal_jobs: calculated.included_denominator_jobs,
        succeeded_jobs,
        failed_jobs,
        pending_jobs,
        cancelled_jobs,
        total_terminal_jobs: calculated.total_terminal_jobs,
        included_denominator_jobs: calculated.included_denominator_jobs,
        excluded_jobs,
        excluded_failed_jobs,
        exclusions_by_category: SlaExclusionCategoryCounts {
            content_policy_refusal: content_policy_refusal_exclusions,
            force_majeure: force_majeure_exclusions,
        },
        effective_task_success_rate_ppm,
        target_success_rate_ppm: SLA_TARGET_PPM,
        target_met: effective_task_success_rate_ppm.map(|rate| rate >= SLA_TARGET_PPM),
        observation_scope: "accepted_jobs_audited_terminal_outcomes_v2".to_owned(),
        excluded_before_admission: vec![
            "quota_exhaustion_before_admission".to_owned(),
            "malformed_request_before_admission".to_owned(),
            "unsupported_model_or_no_route_before_admission".to_owned(),
        ],
    };

    tx.commit().await?;
    Ok(Json(TransparencyReportResponse {
        generated_at: window_end,
        window_start,
        window_end,
        contributor_rewards,
        anti_abuse: AntiAbuseTransparency {
            blocked_assessments,
        },
        reserve,
        sla,
    }))
}

#[cfg(test)]
mod tests {
    use mindone_protocol::TransparencyMicroDistribution;

    use super::{
        calculate_sla, contributor_distribution_available, privacy_gated_distribution,
        DistributionValues, SlaOutcomeCounts,
    };

    const VALUES: DistributionValues = DistributionValues {
        total_micro: 100,
        minimum_micro: Some(10),
        median_micro: Some(20),
        p90_micro: Some(40),
        maximum_micro: Some(50),
    };

    #[test]
    fn privacy_gate_releases_all_statistics_together() {
        assert_eq!(
            privacy_gated_distribution(true, VALUES),
            TransparencyMicroDistribution {
                total_micro: Some(100),
                minimum_micro: Some(10),
                median_micro: Some(20),
                p90_micro: Some(40),
                maximum_micro: Some(50),
            }
        );
    }

    #[test]
    fn privacy_gate_suppresses_all_statistics_together() {
        assert_eq!(
            privacy_gated_distribution(false, VALUES),
            TransparencyMicroDistribution::default()
        );
    }

    #[test]
    fn sla_formula_excludes_only_audited_failed_jobs() {
        let calculated = calculate_sla(SlaOutcomeCounts {
            succeeded_jobs: 7,
            failed_jobs: 3,
            cancelled_jobs: 4,
            excluded_failed_jobs: 2,
        })
        .expect("合法计数应可计算");
        assert_eq!(calculated.total_terminal_jobs, 14);
        assert_eq!(calculated.included_denominator_jobs, 8);
        assert_eq!(calculated.success_rate_ppm, Some(875_000));
    }

    #[test]
    fn sla_formula_rejects_impossible_exclusion_count() {
        assert!(calculate_sla(SlaOutcomeCounts {
            succeeded_jobs: 1,
            failed_jobs: 1,
            cancelled_jobs: 0,
            excluded_failed_jobs: 2,
        })
        .is_none());
    }

    #[test]
    fn privacy_threshold_is_shared_and_inclusive_at_five_accounts() {
        assert!(!contributor_distribution_available(4));
        assert!(contributor_distribution_available(5));
    }
}
