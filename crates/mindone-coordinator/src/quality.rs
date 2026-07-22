//! Trusted, server-side model quality governance.
//!
//! This module is deliberately not mounted in the HTTP router. Its event constructors and
//! transaction entry are crate-private; production callers must enter through
//! `operator_quality`, which verifies signed evaluator evidence and a real artifact commitment.
//! Hidden prompts and model responses are never accepted or persisted here.

use mindone_accounting::{
    fused_quality, normalize_glicko2_rating, update_glicko2, Glicko2Config, Glicko2Observation,
    Glicko2Rating, Glicko2Score, PerformanceTier, TierPolicy,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

const QUALITY_POLICY_VERSION: i32 = 1;
const COLD_START_K: u64 = 20;
const MAX_SCORE_SAMPLES_PER_EVENT: i32 = 10_000;

#[derive(Debug, Error)]
pub enum QualityGovernanceError {
    #[error("质量评价输入无效：{0}")]
    InvalidInput(String),
    #[error("模型不存在或未启用")]
    ModelNotFound,
    #[error("评价幂等键已用于不同请求")]
    IdempotencyConflict,
    #[error("质量算法失败：{0}")]
    Accounting(#[from] mindone_accounting::AccountingError),
    #[error("质量状态数据库操作失败：{0}")]
    Database(#[from] sqlx::Error),
}

pub type QualityGovernanceResult<T> = Result<T, QualityGovernanceError>;

/// Result produced by the trusted hidden-benchmark evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedHiddenBenchmark {
    pub model_id: Uuid,
    pub idempotency_key: String,
    pub evidence_hash: String,
    pub score_normalized: i32,
    pub sample_count: i32,
}

/// Result produced by the trusted model-authenticity canary evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedCanaryEvaluation {
    pub model_id: Uuid,
    pub idempotency_key: String,
    pub evidence_hash: String,
    pub passed: bool,
}

/// One server-mediated blind comparison against an independently rated opponent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedBlindEvaluation {
    pub model_id: Uuid,
    pub idempotency_key: String,
    pub evidence_hash: String,
    pub opponent_rating_milli: i64,
    pub opponent_deviation_milli: i64,
    pub outcome: Glicko2Score,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QualityUpdate {
    pub event_id: Uuid,
    pub model_id: Uuid,
    pub event_kind: String,
    pub benchmark_normalized: i32,
    pub benchmark_samples: i32,
    pub glicko_normalized: i32,
    pub glicko_rating_milli: i64,
    pub glicko_deviation_milli: i64,
    pub glicko_volatility_nano: i64,
    pub evaluation_samples: i32,
    pub fusion_normalized: i32,
    pub tier: String,
    pub cold_start: bool,
    pub policy_version: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QualityEventKind {
    HiddenBenchmark,
    Canary,
    BlindEvaluation,
}

impl QualityEventKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::HiddenBenchmark => "hidden_benchmark",
            Self::Canary => "canary",
            Self::BlindEvaluation => "blind_evaluation",
        }
    }
}

#[derive(Debug, Clone)]
enum TrustedEventPayload {
    Score {
        score_normalized: i32,
        sample_count: i32,
    },
    Blind {
        opponent_rating_milli: i64,
        opponent_deviation_milli: i64,
        outcome: Glicko2Score,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct TrustedEvent {
    model_id: Uuid,
    idempotency_key: String,
    evidence_hash: String,
    kind: QualityEventKind,
    payload: TrustedEventPayload,
}

#[derive(Debug, Clone)]
struct ModelQualityState {
    id: Uuid,
    benchmark_normalized: i32,
    benchmark_samples: i32,
    glicko_normalized: i32,
    glicko_rating_milli: i64,
    glicko_deviation_milli: i64,
    glicko_volatility_nano: i64,
    evaluation_samples: i32,
    fusion_normalized: i32,
    tier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TierTransition {
    model_id: Uuid,
    old_tier: String,
    new_tier: String,
    fusion_normalized: i32,
    percentile_millionths: i32,
    evaluation_samples: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TierRecomputeOutcome {
    cohort_size: i32,
    cohort_commitment: String,
    transitions: Vec<TierTransition>,
}

pub(crate) fn hidden_benchmark_event(event: TrustedHiddenBenchmark) -> TrustedEvent {
    TrustedEvent {
        model_id: event.model_id,
        idempotency_key: event.idempotency_key,
        evidence_hash: event.evidence_hash,
        kind: QualityEventKind::HiddenBenchmark,
        payload: TrustedEventPayload::Score {
            score_normalized: event.score_normalized,
            sample_count: event.sample_count,
        },
    }
}

pub(crate) fn canary_event(event: TrustedCanaryEvaluation) -> TrustedEvent {
    TrustedEvent {
        model_id: event.model_id,
        idempotency_key: event.idempotency_key,
        evidence_hash: event.evidence_hash,
        kind: QualityEventKind::Canary,
        payload: TrustedEventPayload::Score {
            score_normalized: if event.passed { 1_000_000 } else { 0 },
            sample_count: 1,
        },
    }
}

pub(crate) fn blind_evaluation_event(event: TrustedBlindEvaluation) -> TrustedEvent {
    TrustedEvent {
        model_id: event.model_id,
        idempotency_key: event.idempotency_key,
        evidence_hash: event.evidence_hash,
        kind: QualityEventKind::BlindEvaluation,
        payload: TrustedEventPayload::Blind {
            opponent_rating_milli: event.opponent_rating_milli,
            opponent_deviation_milli: event.opponent_deviation_milli,
            outcome: event.outcome,
        },
    }
}

pub(crate) struct QualityRecordOutcome {
    pub update: QualityUpdate,
    pub idempotent_replay: bool,
}

pub(crate) async fn record_trusted_event_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    event: TrustedEvent,
) -> QualityGovernanceResult<QualityRecordOutcome> {
    validate_trusted_event(&event)?;
    let request_hash = event_request_hash(&event);
    lock_quality_event_idempotency(tx, &event.idempotency_key).await?;
    if let Some(existing) = load_existing_event(tx, &event.idempotency_key).await? {
        if existing.0 != request_hash {
            return Err(QualityGovernanceError::IdempotencyConflict);
        }
        return Ok(QualityRecordOutcome {
            update: existing.1,
            idempotent_replay: true,
        });
    }

    let model_name: Option<String> =
        sqlx::query_scalar("SELECT name FROM models WHERE id = $1 AND enabled = TRUE")
            .bind(event.model_id)
            .fetch_optional(&mut **tx)
            .await?;
    let model_name = model_name.ok_or(QualityGovernanceError::ModelNotFound)?;
    let rows = sqlx::query(
        r#"
        SELECT id,benchmark_normalized,benchmark_samples,glicko_normalized,
               glicko_rating_milli,glicko_deviation_milli,glicko_volatility_nano,
               evaluation_samples,quality_fusion_normalized,tier
        FROM models
        WHERE name = $1 AND enabled = TRUE
        ORDER BY id
        FOR UPDATE
        "#,
    )
    .bind(&model_name)
    .fetch_all(&mut **tx)
    .await?;
    let mut states = rows
        .iter()
        .map(model_state_from_row)
        .collect::<QualityGovernanceResult<Vec<_>>>()?;
    let target_index = states
        .iter()
        .position(|state| state.id == event.model_id)
        .ok_or(QualityGovernanceError::ModelNotFound)?;
    let old = states[target_index].clone();
    apply_event_to_target(tx, &mut states[target_index], &event.payload).await?;
    let tier_recompute = recompute_group(tx, &mut states, &model_name).await?;
    let new = states[target_index].clone();

    let event_id = Uuid::now_v7();
    insert_event_audit(tx, event_id, &event, &request_hash, &old, &new).await?;
    insert_tier_transition_audits(tx, event_id, &model_name, &tier_recompute).await?;
    Ok(QualityRecordOutcome {
        update: update_from_state(event_id, event.kind, &new),
        idempotent_replay: false,
    })
}

pub(crate) async fn lock_quality_event_idempotency(
    tx: &mut Transaction<'_, Postgres>,
    idempotency_key: &str,
) -> QualityGovernanceResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 764421))")
        .bind(idempotency_key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn load_existing_event(
    tx: &mut Transaction<'_, Postgres>,
    idempotency_key: &str,
) -> QualityGovernanceResult<Option<(String, QualityUpdate)>> {
    let row = sqlx::query(
        r#"
        SELECT id,model_id,event_kind,request_hash,new_benchmark_normalized,
               new_benchmark_samples,new_glicko_normalized,new_glicko_rating_milli,
               new_glicko_deviation_milli,new_glicko_volatility_nano,
               new_evaluation_samples,new_fusion_normalized,new_tier,policy_version
        FROM model_quality_events e
        WHERE e.idempotency_key = $1
        "#,
    )
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let evaluation_samples = row.try_get::<i32, _>("new_evaluation_samples")?;
        Ok::<_, sqlx::Error>((
            row.try_get("request_hash")?,
            QualityUpdate {
                event_id: row.try_get("id")?,
                model_id: row.try_get("model_id")?,
                event_kind: row.try_get("event_kind")?,
                benchmark_normalized: row.try_get("new_benchmark_normalized")?,
                benchmark_samples: row.try_get("new_benchmark_samples")?,
                glicko_normalized: row.try_get("new_glicko_normalized")?,
                glicko_rating_milli: row.try_get("new_glicko_rating_milli")?,
                glicko_deviation_milli: row.try_get("new_glicko_deviation_milli")?,
                glicko_volatility_nano: row.try_get("new_glicko_volatility_nano")?,
                evaluation_samples,
                fusion_normalized: row.try_get("new_fusion_normalized")?,
                tier: row.try_get("new_tier")?,
                cold_start: evaluation_samples
                    < i32::try_from(TierPolicy::default().minimum_samples).unwrap_or(i32::MAX),
                policy_version: row.try_get("policy_version")?,
            },
        ))
    })
    .transpose()
    .map_err(QualityGovernanceError::from)
}

fn model_state_from_row(row: &sqlx::postgres::PgRow) -> QualityGovernanceResult<ModelQualityState> {
    Ok(ModelQualityState {
        id: row.try_get("id")?,
        benchmark_normalized: row.try_get("benchmark_normalized")?,
        benchmark_samples: row.try_get("benchmark_samples")?,
        glicko_normalized: row.try_get("glicko_normalized")?,
        glicko_rating_milli: row.try_get("glicko_rating_milli")?,
        glicko_deviation_milli: row.try_get("glicko_deviation_milli")?,
        glicko_volatility_nano: row.try_get("glicko_volatility_nano")?,
        evaluation_samples: row.try_get("evaluation_samples")?,
        fusion_normalized: row.try_get("quality_fusion_normalized")?,
        tier: row.try_get("tier")?,
    })
}

async fn apply_event_to_target(
    tx: &mut Transaction<'_, Postgres>,
    target: &mut ModelQualityState,
    payload: &TrustedEventPayload,
) -> QualityGovernanceResult<()> {
    match payload {
        TrustedEventPayload::Score {
            score_normalized,
            sample_count,
        } => {
            let total_samples = target
                .benchmark_samples
                .checked_add(*sample_count)
                .ok_or_else(|| invalid("benchmark 样本数溢出"))?;
            let old_weighted = i64::from(target.benchmark_normalized)
                .checked_mul(i64::from(target.benchmark_samples))
                .ok_or_else(|| invalid("benchmark 累计分数溢出"))?;
            let new_weighted = i64::from(*score_normalized)
                .checked_mul(i64::from(*sample_count))
                .ok_or_else(|| invalid("benchmark 评价分数溢出"))?;
            let weighted = old_weighted
                .checked_add(new_weighted)
                .ok_or_else(|| invalid("benchmark 总分溢出"))?;
            let rounded = weighted
                .checked_add(i64::from(total_samples) / 2)
                .ok_or_else(|| invalid("benchmark 舍入溢出"))?
                / i64::from(total_samples);
            target.benchmark_normalized =
                i32::try_from(rounded).map_err(|_| invalid("benchmark 归一化结果超出范围"))?;
            target.benchmark_samples = total_samples;
            sqlx::query(
                "UPDATE models SET benchmark_normalized=$2,benchmark_samples=$3 WHERE id=$1",
            )
            .bind(target.id)
            .bind(target.benchmark_normalized)
            .bind(target.benchmark_samples)
            .execute(&mut **tx)
            .await?;
        }
        TrustedEventPayload::Blind {
            opponent_rating_milli,
            opponent_deviation_milli,
            outcome,
        } => {
            let current = stored_glicko_rating(target)?;
            let updated = update_glicko2(
                current,
                &[Glicko2Observation {
                    opponent_rating: stored_milli_to_f64(*opponent_rating_milli)?,
                    opponent_deviation: stored_milli_to_f64(*opponent_deviation_milli)?,
                    score: *outcome,
                }],
                Glicko2Config::default(),
            )?;
            target.glicko_rating_milli = rounded_i64(updated.rating * 1_000.0)?;
            target.glicko_deviation_milli = rounded_i64(updated.deviation * 1_000.0)?.max(1);
            target.glicko_volatility_nano =
                rounded_i64(updated.volatility * 1_000_000_000.0)?.max(1_000);
            target.evaluation_samples = target
                .evaluation_samples
                .checked_add(1)
                .ok_or_else(|| invalid("Glicko-2 样本数溢出"))?;
            target.glicko_normalized = normalized_glicko_millionths(updated.rating)?;
            sqlx::query(
                r#"
                UPDATE models
                SET glicko_normalized=$2,glicko_rating_milli=$3,
                    glicko_deviation_milli=$4,glicko_volatility_nano=$5,
                    evaluation_samples=$6
                WHERE id=$1
                "#,
            )
            .bind(target.id)
            .bind(target.glicko_normalized)
            .bind(target.glicko_rating_milli)
            .bind(target.glicko_deviation_milli)
            .bind(target.glicko_volatility_nano)
            .bind(target.evaluation_samples)
            .execute(&mut **tx)
            .await?;
        }
    }
    Ok(())
}

async fn recompute_group(
    tx: &mut Transaction<'_, Postgres>,
    states: &mut [ModelQualityState],
    cohort_name: &str,
) -> QualityGovernanceResult<TierRecomputeOutcome> {
    if states.is_empty() {
        return Err(invalid("Tier 相对排名集合不能为空"));
    }
    let old_tiers = states
        .iter()
        .map(|state| state.tier.clone())
        .collect::<Vec<_>>();
    let mut fused_scores = Vec::with_capacity(states.len());
    for state in states.iter_mut() {
        state.glicko_normalized =
            normalized_glicko_millionths(stored_milli_to_f64(state.glicko_rating_milli)?)?;
        let samples =
            u64::try_from(state.evaluation_samples).map_err(|_| invalid("评价样本数不得为负"))?;
        let fusion = fused_quality(
            f64::from(state.benchmark_normalized) / 1_000_000.0,
            f64::from(state.glicko_normalized) / 1_000_000.0,
            samples,
            COLD_START_K,
        )?;
        state.fusion_normalized = normalized_f64_to_millionths(fusion.fused)?;
        fused_scores.push(state.fusion_normalized);
    }

    let mut percentiles = Vec::with_capacity(states.len());
    for (state, old_tier) in states.iter_mut().zip(&old_tiers) {
        let percentile = score_percentile(state.fusion_normalized, &fused_scores)?;
        let percentile_millionths = normalized_f64_to_millionths(percentile)?;
        let samples =
            u64::try_from(state.evaluation_samples).map_err(|_| invalid("评价样本数不得为负"))?;
        let tier = TierPolicy::default().classify(
            parse_tier(old_tier)?,
            f64::from(state.fusion_normalized) / 1_000_000.0,
            percentile,
            samples,
        )?;
        state.tier = tier_name(tier.tier).to_owned();
        percentiles.push(percentile_millionths);
    }

    let cohort_size = i32::try_from(states.len()).map_err(|_| invalid("Tier 排名集合过大"))?;
    let cohort_commitment = tier_cohort_commitment(cohort_name, states, &old_tiers, &percentiles)?;
    let mut transitions = Vec::new();
    for ((state, old_tier), percentile_millionths) in
        states.iter().zip(&old_tiers).zip(&percentiles)
    {
        sqlx::query(
            r#"
            UPDATE models
            SET glicko_normalized=$2,quality_fusion_normalized=$3,tier=$4,
                quality_policy_version=$5,quality_updated_at=now(),updated_at=now()
            WHERE id=$1
            "#,
        )
        .bind(state.id)
        .bind(state.glicko_normalized)
        .bind(state.fusion_normalized)
        .bind(&state.tier)
        .bind(QUALITY_POLICY_VERSION)
        .execute(&mut **tx)
        .await?;
        if old_tier != &state.tier {
            transitions.push(TierTransition {
                model_id: state.id,
                old_tier: old_tier.clone(),
                new_tier: state.tier.clone(),
                fusion_normalized: state.fusion_normalized,
                percentile_millionths: *percentile_millionths,
                evaluation_samples: state.evaluation_samples,
            });
        }
    }
    Ok(TierRecomputeOutcome {
        cohort_size,
        cohort_commitment,
        transitions,
    })
}

async fn insert_tier_transition_audits(
    tx: &mut Transaction<'_, Postgres>,
    source_quality_event_id: Uuid,
    cohort_name: &str,
    outcome: &TierRecomputeOutcome,
) -> QualityGovernanceResult<()> {
    for transition in &outcome.transitions {
        sqlx::query(
            r#"
            INSERT INTO model_tier_transition_events
                (id,source_quality_event_id,model_id,cohort_name,cohort_size,
                 cohort_commitment,old_tier,new_tier,fusion_normalized,
                 percentile_millionths,evaluation_samples,policy_version)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(source_quality_event_id)
        .bind(transition.model_id)
        .bind(cohort_name)
        .bind(outcome.cohort_size)
        .bind(&outcome.cohort_commitment)
        .bind(&transition.old_tier)
        .bind(&transition.new_tier)
        .bind(transition.fusion_normalized)
        .bind(transition.percentile_millionths)
        .bind(transition.evaluation_samples)
        .bind(QUALITY_POLICY_VERSION)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

fn tier_cohort_commitment(
    cohort_name: &str,
    states: &[ModelQualityState],
    old_tiers: &[String],
    percentiles: &[i32],
) -> QualityGovernanceResult<String> {
    if states.len() != old_tiers.len() || states.len() != percentiles.len() {
        return Err(invalid("Tier cohort commitment 输入长度不一致"));
    }
    let mut digest = Sha256::new();
    digest.update(b"mindone:tier-cohort:v1\0");
    digest.update(QUALITY_POLICY_VERSION.to_be_bytes());
    update_hash_field(&mut digest, cohort_name.as_bytes());
    digest.update(
        u64::try_from(states.len())
            .map_err(|_| invalid("Tier 排名集合过大"))?
            .to_be_bytes(),
    );
    for ((state, old_tier), percentile) in states.iter().zip(old_tiers).zip(percentiles) {
        digest.update(state.id.as_bytes());
        digest.update(state.fusion_normalized.to_be_bytes());
        digest.update(state.evaluation_samples.to_be_bytes());
        digest.update(percentile.to_be_bytes());
        update_hash_field(&mut digest, old_tier.as_bytes());
        update_hash_field(&mut digest, state.tier.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

async fn insert_event_audit(
    tx: &mut Transaction<'_, Postgres>,
    event_id: Uuid,
    event: &TrustedEvent,
    request_hash: &str,
    old: &ModelQualityState,
    new: &ModelQualityState,
) -> QualityGovernanceResult<()> {
    let (score, samples, opponent_rating, opponent_deviation, outcome) = match event.payload {
        TrustedEventPayload::Score {
            score_normalized,
            sample_count,
        } => (Some(score_normalized), sample_count, None, None, None),
        TrustedEventPayload::Blind {
            opponent_rating_milli,
            opponent_deviation_milli,
            outcome,
        } => (
            None,
            1,
            Some(opponent_rating_milli),
            Some(opponent_deviation_milli),
            Some(outcome.millionths()),
        ),
    };
    sqlx::query(
        r#"
        INSERT INTO model_quality_events
            (id,model_id,event_kind,idempotency_key,request_hash,evidence_hash,
             score_normalized,sample_count,opponent_rating_milli,
             opponent_deviation_milli,outcome_millionths,
             old_benchmark_normalized,new_benchmark_normalized,
             old_benchmark_samples,new_benchmark_samples,
             old_glicko_normalized,new_glicko_normalized,
             old_glicko_rating_milli,new_glicko_rating_milli,
             old_glicko_deviation_milli,new_glicko_deviation_milli,
             old_glicko_volatility_nano,new_glicko_volatility_nano,
             old_evaluation_samples,new_evaluation_samples,
             old_fusion_normalized,new_fusion_normalized,old_tier,new_tier,policy_version)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,
             $20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)
        "#,
    )
    .bind(event_id)
    .bind(event.model_id)
    .bind(event.kind.as_str())
    .bind(&event.idempotency_key)
    .bind(request_hash)
    .bind(&event.evidence_hash)
    .bind(score)
    .bind(samples)
    .bind(opponent_rating)
    .bind(opponent_deviation)
    .bind(outcome)
    .bind(old.benchmark_normalized)
    .bind(new.benchmark_normalized)
    .bind(old.benchmark_samples)
    .bind(new.benchmark_samples)
    .bind(old.glicko_normalized)
    .bind(new.glicko_normalized)
    .bind(old.glicko_rating_milli)
    .bind(new.glicko_rating_milli)
    .bind(old.glicko_deviation_milli)
    .bind(new.glicko_deviation_milli)
    .bind(old.glicko_volatility_nano)
    .bind(new.glicko_volatility_nano)
    .bind(old.evaluation_samples)
    .bind(new.evaluation_samples)
    .bind(old.fusion_normalized)
    .bind(new.fusion_normalized)
    .bind(&old.tier)
    .bind(&new.tier)
    .bind(QUALITY_POLICY_VERSION)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) fn validate_trusted_event(event: &TrustedEvent) -> QualityGovernanceResult<()> {
    let key = event.idempotency_key.as_bytes();
    if key.is_empty()
        || key.len() > 128
        || !key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(byte))
    {
        return Err(invalid(
            "idempotency_key 只允许 1 到 128 字节的 ASCII 字母、数字及 -_.:",
        ));
    }
    validate_sha256(&event.evidence_hash, "evidence_hash")?;
    match event.payload {
        TrustedEventPayload::Score {
            score_normalized,
            sample_count,
        } => {
            if !(0..=1_000_000).contains(&score_normalized) {
                return Err(invalid("score_normalized 必须在 0 到 1000000 之间"));
            }
            if !(1..=MAX_SCORE_SAMPLES_PER_EVENT).contains(&sample_count) {
                return Err(invalid("sample_count 必须在 1 到 10000 之间"));
            }
        }
        TrustedEventPayload::Blind {
            opponent_rating_milli,
            opponent_deviation_milli,
            ..
        } => {
            if !(0..=4_000_000).contains(&opponent_rating_milli) {
                return Err(invalid("opponent_rating_milli 必须在 0 到 4000000 之间"));
            }
            if !(1..=350_000).contains(&opponent_deviation_milli) {
                return Err(invalid("opponent_deviation_milli 必须在 1 到 350000 之间"));
            }
        }
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> QualityGovernanceResult<()> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(invalid(&format!(
            "{field} 必须是 64 位小写 SHA-256 十六进制值"
        )));
    }
    Ok(())
}

fn event_request_hash(event: &TrustedEvent) -> String {
    let mut digest = Sha256::new();
    digest.update(b"mindone:model-quality-event:v1\0");
    digest.update(event.model_id.as_bytes());
    update_hash_field(&mut digest, event.kind.as_str().as_bytes());
    update_hash_field(&mut digest, event.idempotency_key.as_bytes());
    update_hash_field(&mut digest, event.evidence_hash.as_bytes());
    match event.payload {
        TrustedEventPayload::Score {
            score_normalized,
            sample_count,
        } => {
            digest.update([0]);
            digest.update(score_normalized.to_be_bytes());
            digest.update(sample_count.to_be_bytes());
        }
        TrustedEventPayload::Blind {
            opponent_rating_milli,
            opponent_deviation_milli,
            outcome,
        } => {
            digest.update([1]);
            digest.update(opponent_rating_milli.to_be_bytes());
            digest.update(opponent_deviation_milli.to_be_bytes());
            digest.update(outcome.millionths().to_be_bytes());
        }
    }
    hex::encode(digest.finalize())
}

fn update_hash_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

fn stored_glicko_rating(state: &ModelQualityState) -> QualityGovernanceResult<Glicko2Rating> {
    Ok(Glicko2Rating {
        rating: stored_milli_to_f64(state.glicko_rating_milli)?,
        deviation: stored_milli_to_f64(state.glicko_deviation_milli)?,
        volatility: stored_nano_to_f64(state.glicko_volatility_nano)?,
    })
}

fn stored_milli_to_f64(value: i64) -> QualityGovernanceResult<f64> {
    let value = i32::try_from(value).map_err(|_| invalid("milli 状态超出内部范围"))?;
    Ok(f64::from(value) / 1_000.0)
}

fn stored_nano_to_f64(value: i64) -> QualityGovernanceResult<f64> {
    let value = i32::try_from(value).map_err(|_| invalid("nano 状态超出内部范围"))?;
    Ok(f64::from(value) / 1_000_000_000.0)
}

fn rounded_i64(value: f64) -> QualityGovernanceResult<i64> {
    if !value.is_finite() || !(0.0..=4_000_000_000.0).contains(&value) {
        return Err(invalid("浮点评分结果超出可持久化范围"));
    }
    value
        .round()
        .to_string()
        .parse()
        .map_err(|_| invalid("浮点评分结果无法转换为整数"))
}

fn normalized_glicko_millionths(rating: f64) -> QualityGovernanceResult<i32> {
    normalized_f64_to_millionths(normalize_glicko2_rating(rating)?)
}

fn normalized_f64_to_millionths(value: f64) -> QualityGovernanceResult<i32> {
    let scaled = rounded_i64(value * 1_000_000.0)?;
    let normalized = i32::try_from(scaled).map_err(|_| invalid("归一化分数超出整数范围"))?;
    if !(0..=1_000_000).contains(&normalized) {
        return Err(invalid("归一化分数超出 0 到 1000000"));
    }
    Ok(normalized)
}

fn score_percentile(score: i32, all_scores: &[i32]) -> QualityGovernanceResult<f64> {
    if all_scores.is_empty() {
        return Err(invalid("Tier 相对排名集合不能为空"));
    }
    if all_scores.len() == 1 {
        return Ok(0.5);
    }
    let lower = all_scores
        .iter()
        .filter(|candidate| **candidate < score)
        .count();
    let equal_peers = all_scores
        .iter()
        .filter(|candidate| **candidate == score)
        .count()
        .saturating_sub(1);
    let lower = u32::try_from(lower).map_err(|_| invalid("Tier 排名集合过大"))?;
    let equal_peers = u32::try_from(equal_peers).map_err(|_| invalid("Tier 排名集合过大"))?;
    let denominator =
        u32::try_from(all_scores.len() - 1).map_err(|_| invalid("Tier 排名集合过大"))?;
    Ok((f64::from(lower) + f64::from(equal_peers) / 2.0) / f64::from(denominator))
}

fn parse_tier(value: &str) -> QualityGovernanceResult<PerformanceTier> {
    match value {
        "high" => Ok(PerformanceTier::High),
        "medium" => Ok(PerformanceTier::Medium),
        "low" => Ok(PerformanceTier::Low),
        _ => Err(invalid("数据库包含未知 Tier")),
    }
}

const fn tier_name(value: PerformanceTier) -> &'static str {
    match value {
        PerformanceTier::High => "high",
        PerformanceTier::Medium => "medium",
        PerformanceTier::Low => "low",
    }
}

fn update_from_state(
    event_id: Uuid,
    kind: QualityEventKind,
    state: &ModelQualityState,
) -> QualityUpdate {
    QualityUpdate {
        event_id,
        model_id: state.id,
        event_kind: kind.as_str().to_owned(),
        benchmark_normalized: state.benchmark_normalized,
        benchmark_samples: state.benchmark_samples,
        glicko_normalized: state.glicko_normalized,
        glicko_rating_milli: state.glicko_rating_milli,
        glicko_deviation_milli: state.glicko_deviation_milli,
        glicko_volatility_nano: state.glicko_volatility_nano,
        evaluation_samples: state.evaluation_samples,
        fusion_normalized: state.fusion_normalized,
        tier: state.tier.clone(),
        cold_start: u64::try_from(state.evaluation_samples).map_or(true, |samples| {
            samples < TierPolicy::default().minimum_samples
        }),
        policy_version: QUALITY_POLICY_VERSION,
    }
}

fn invalid(message: &str) -> QualityGovernanceError {
    QualityGovernanceError::InvalidInput(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_is_deterministic_and_ties_use_midrank() {
        assert_eq!(score_percentile(10, &[10]).expect("有效"), 0.5);
        assert_eq!(score_percentile(20, &[10, 20]).expect("有效"), 1.0);
        assert_eq!(score_percentile(10, &[10, 20]).expect("有效"), 0.0);
        assert_eq!(score_percentile(10, &[10, 10, 20]).expect("有效"), 0.25);
    }

    #[test]
    fn request_hash_binds_all_security_relevant_fields() {
        let base = TrustedEvent {
            model_id: Uuid::from_u128(1),
            idempotency_key: "evaluation-1".to_owned(),
            evidence_hash: "a".repeat(64),
            kind: QualityEventKind::HiddenBenchmark,
            payload: TrustedEventPayload::Score {
                score_normalized: 800_000,
                sample_count: 10,
            },
        };
        let mut changed = base.clone();
        changed.payload = TrustedEventPayload::Score {
            score_normalized: 800_001,
            sample_count: 10,
        };
        assert_ne!(event_request_hash(&base), event_request_hash(&changed));
    }

    #[test]
    fn strictly_rejects_noncanonical_evidence_hash_and_key() {
        let event = TrustedEvent {
            model_id: Uuid::from_u128(1),
            idempotency_key: "contains whitespace".to_owned(),
            evidence_hash: "A".repeat(64),
            kind: QualityEventKind::Canary,
            payload: TrustedEventPayload::Score {
                score_normalized: 1_000_000,
                sample_count: 1,
            },
        };
        assert!(validate_trusted_event(&event).is_err());
    }
}
