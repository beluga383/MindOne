use mindone_protocol::{ExecutionTelemetryVerdict, HardwareProfile, JobExecutionTelemetry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::error::ApiError;

pub(crate) const ASSESSMENT_VERSION: &str = "latency-vram-fingerprint-v1";
const HISTORICAL_MIN_SAMPLES: i64 = 10;
const HISTORICAL_OUTLIER_FACTOR: i64 = 16;

#[derive(Clone, Debug)]
pub(crate) struct FingerprintContext {
    pub job_id: Uuid,
    pub node_id: Uuid,
    pub model_id: Uuid,
    pub model_instance_id: Option<Uuid>,
    pub attempt_number: i32,
    pub result_idempotency_key: String,
    pub confidentiality: String,
    pub trust_level: String,
    pub model_size_bytes: i64,
    pub hardware_profile: Value,
}

#[derive(Clone, Debug)]
pub(crate) struct FingerprintOutcome {
    pub verdict: ExecutionTelemetryVerdict,
    pub alert_count: u32,
    pub evidence_kind: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Severity {
    Warning,
    Critical,
}

impl Severity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug)]
struct Alert {
    severity: Severity,
    code: &'static str,
    explanation: &'static str,
    observed: Value,
    expected: Value,
}

#[derive(Clone, Copy, Debug)]
struct HistoricalBaseline {
    sample_count: i64,
    ttft_median_ms: Option<i64>,
    tps_median_milli: Option<i64>,
}

#[derive(Clone, Debug)]
struct Assessment {
    declared_vram_total_mib: Option<i64>,
    model_soft_min_peak_mib: i64,
    model_critical_min_peak_mib: i64,
    incomplete: bool,
    alerts: Vec<Alert>,
}

pub(crate) fn telemetry_fingerprint(
    context: &FingerprintContext,
    telemetry: &JobExecutionTelemetry,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(telemetry).map_err(|error| {
        tracing::error!(error = %error, "任务遥测无法编码");
        ApiError::internal()
    })?;
    let mut digest = Sha256::new();
    digest.update(b"MindOne job execution telemetry v1\0");
    digest.update(context.job_id.as_bytes());
    digest.update(context.node_id.as_bytes());
    digest.update(context.model_id.as_bytes());
    if let Some(model_instance_id) = context.model_instance_id {
        digest.update(model_instance_id.as_bytes());
    }
    digest.update(context.attempt_number.to_be_bytes());
    digest.update(context.result_idempotency_key.as_bytes());
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

pub(crate) async fn append_execution_fingerprint(
    tx: &mut Transaction<'_, Postgres>,
    context: FingerprintContext,
    telemetry: &JobExecutionTelemetry,
    fingerprint: &str,
) -> Result<FingerprintOutcome, ApiError> {
    let hardware_cohort_key = hardware_cohort_key(&context.hardware_profile)?;
    let history = historical_baseline(tx, context.model_id, &hardware_cohort_key).await?;
    let assessment = assess(&context, telemetry, history)?;
    let evidence_kind = evidence_kind(&context).to_owned();
    let verdict = verdict(&assessment.alerts, assessment.incomplete);
    let telemetry_id = Uuid::now_v7();
    let vram_sample_count =
        i32::try_from(telemetry.vram_sample_count).map_err(|_| ApiError::internal())?;

    sqlx::query(
        r#"
        INSERT INTO job_execution_telemetry
            (id,job_id,node_id,model_id,model_instance_id,attempt_number,
             result_idempotency_key,evidence_kind,ttft_ms,tps_milli,peak_vram_mib,
             vram_sample_count,declared_vram_total_mib,model_size_bytes,
             model_soft_min_peak_mib,model_critical_min_peak_mib,
             historical_ttft_median_ms,historical_tps_median_milli,
             historical_sample_count,hardware_cohort_key,verdict,assessment_version,
             telemetry_fingerprint)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
        "#,
    )
    .bind(telemetry_id)
    .bind(context.job_id)
    .bind(context.node_id)
    .bind(context.model_id)
    .bind(context.model_instance_id)
    .bind(context.attempt_number)
    .bind(&context.result_idempotency_key)
    .bind(&evidence_kind)
    .bind(telemetry.ttft_ms)
    .bind(telemetry.tps_milli)
    .bind(telemetry.peak_vram_mib)
    .bind(vram_sample_count)
    .bind(assessment.declared_vram_total_mib)
    .bind(context.model_size_bytes)
    .bind(assessment.model_soft_min_peak_mib)
    .bind(assessment.model_critical_min_peak_mib)
    .bind(history.ttft_median_ms)
    .bind(history.tps_median_milli)
    .bind(history.sample_count)
    .bind(&hardware_cohort_key)
    .bind(verdict_key(verdict))
    .bind(ASSESSMENT_VERSION)
    .bind(fingerprint)
    .execute(&mut **tx)
    .await?;

    for alert in &assessment.alerts {
        sqlx::query(
            r#"
            INSERT INTO execution_anomaly_ledger
                (id,telemetry_id,job_id,node_id,severity,code,explanation,
                 observed,expected,idempotency_key)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(telemetry_id)
        .bind(context.job_id)
        .bind(context.node_id)
        .bind(alert.severity.as_str())
        .bind(alert.code)
        .bind(alert.explanation)
        .bind(&alert.observed)
        .bind(&alert.expected)
        .bind(format!(
            "job:{}:execution-fingerprint:{}",
            context.job_id, alert.code
        ))
        .execute(&mut **tx)
        .await?;
    }

    let alert_count = u32::try_from(assessment.alerts.len()).map_err(|_| ApiError::internal())?;
    Ok(FingerprintOutcome {
        verdict,
        alert_count,
        evidence_kind,
    })
}

async fn historical_baseline(
    tx: &mut Transaction<'_, Postgres>,
    model_id: Uuid,
    hardware_cohort_key: &str,
) -> Result<HistoricalBaseline, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE ttft_ms IS NOT NULL AND tps_milli IS NOT NULL)::bigint
                AS sample_count,
            percentile_disc(0.5) WITHIN GROUP (ORDER BY ttft_ms)
                FILTER (WHERE ttft_ms IS NOT NULL) AS ttft_median_ms,
            percentile_disc(0.5) WITHIN GROUP (ORDER BY tps_milli)
                FILTER (WHERE tps_milli IS NOT NULL) AS tps_median_milli
        FROM job_execution_telemetry
        WHERE model_id=$1 AND hardware_cohort_key=$2
        "#,
    )
    .bind(model_id)
    .bind(hardware_cohort_key)
    .fetch_one(&mut **tx)
    .await?;
    Ok(HistoricalBaseline {
        sample_count: row.try_get("sample_count")?,
        ttft_median_ms: row.try_get("ttft_median_ms")?,
        tps_median_milli: row.try_get("tps_median_milli")?,
    })
}

fn assess(
    context: &FingerprintContext,
    telemetry: &JobExecutionTelemetry,
    history: HistoricalBaseline,
) -> Result<Assessment, ApiError> {
    if context.model_size_bytes <= 0 {
        return Err(ApiError::internal());
    }
    let model_size_mib = ceil_div_positive(context.model_size_bytes, 1_048_576)?;
    // GGUF 可以 mmap、分层 offload，因而不能假定峰值显存等于文件大小。1/16
    // 只作为弱偏差线，1/128 才是“规模明显不符”的严重线，并把小模型下限保持很低。
    let model_soft_min_peak_mib = ceil_div_positive(model_size_mib, 16)?.max(32);
    let model_critical_min_peak_mib = ceil_div_positive(model_size_mib, 128)?.max(8);
    let declared_vram_total_mib = declared_vram_total_mib(&context.hardware_profile)?;
    let mut alerts = Vec::new();
    let incomplete = telemetry.ttft_ms.is_none()
        || telemetry.tps_milli.is_none()
        || telemetry.peak_vram_mib.is_none();

    if let Some(peak) = telemetry.peak_vram_mib {
        if let Some(total) = declared_vram_total_mib {
            if peak > total {
                alerts.push(Alert {
                    severity: Severity::Critical,
                    code: "peak_exceeds_declared_total",
                    explanation: "任务峰值显存超过节点注册时声明的总显存",
                    observed: json!({"peak_vram_mib": peak}),
                    expected: json!({"maximum_peak_vram_mib": total}),
                });
            }
        }
        if peak < model_critical_min_peak_mib {
            alerts.push(Alert {
                severity: Severity::Critical,
                code: "model_vram_severe_mismatch",
                explanation: "任务峰值显存低于模型文件规模的保守 1/128 严重偏差线",
                observed: json!({"peak_vram_mib": peak, "model_size_bytes": context.model_size_bytes}),
                expected: json!({"minimum_peak_vram_mib": model_critical_min_peak_mib, "ratio": "model_size_mib/128"}),
            });
        } else if peak < model_soft_min_peak_mib {
            alerts.push(Alert {
                severity: Severity::Warning,
                code: "model_vram_weak_mismatch",
                explanation: "任务峰值显存低于模型文件规模的保守 1/16 弱偏差线",
                observed: json!({"peak_vram_mib": peak, "model_size_bytes": context.model_size_bytes}),
                expected: json!({"minimum_peak_vram_mib": model_soft_min_peak_mib, "ratio": "model_size_mib/16"}),
            });
        }
    }

    if let Some(total) = declared_vram_total_mib {
        let severe_capacity_bytes = i128::from(total)
            .checked_mul(1_048_576)
            .and_then(|value| value.checked_mul(16))
            .ok_or_else(ApiError::internal)?;
        if i128::from(context.model_size_bytes) > severe_capacity_bytes {
            alerts.push(Alert {
                severity: Severity::Critical,
                code: "model_declared_capacity_severe_mismatch",
                explanation: "发布模型文件规模超过节点声明总显存的 16 倍，形成严重容量异常",
                observed: json!({"model_size_bytes": context.model_size_bytes, "declared_vram_total_mib": total}),
                expected: json!({"maximum_model_to_declared_vram_ratio": 16}),
            });
        }
    }

    if history.sample_count >= HISTORICAL_MIN_SAMPLES {
        compare_latency_history(telemetry, history, &mut alerts);
    }

    Ok(Assessment {
        declared_vram_total_mib,
        model_soft_min_peak_mib,
        model_critical_min_peak_mib,
        incomplete,
        alerts,
    })
}

fn compare_latency_history(
    telemetry: &JobExecutionTelemetry,
    history: HistoricalBaseline,
    alerts: &mut Vec<Alert>,
) {
    if let (Some(observed), Some(median)) = (telemetry.ttft_ms, history.ttft_median_ms) {
        if ratio_outlier(observed, median) {
            alerts.push(Alert {
                severity: Severity::Warning,
                code: "ttft_historical_outlier",
                explanation: "本次 TTFT 与同模型、同硬件声明 cohort 的服务端历史中位数相差超过 16 倍",
                observed: json!({"ttft_ms": observed}),
                expected: json!({"historical_median_ms": median, "factor": HISTORICAL_OUTLIER_FACTOR, "samples": history.sample_count}),
            });
        }
    }
    if let (Some(observed), Some(median)) = (telemetry.tps_milli, history.tps_median_milli) {
        if ratio_outlier(observed, median) {
            alerts.push(Alert {
                severity: Severity::Warning,
                code: "tps_historical_outlier",
                explanation: "本次 TPS 与同模型、同硬件声明 cohort 的服务端历史中位数相差超过 16 倍",
                observed: json!({"tps_milli": observed}),
                expected: json!({"historical_median_milli": median, "factor": HISTORICAL_OUTLIER_FACTOR, "samples": history.sample_count}),
            });
        }
    }
}

fn ratio_outlier(observed: i64, baseline: i64) -> bool {
    if observed <= 0 || baseline <= 0 {
        return false;
    }
    i128::from(observed) > i128::from(baseline) * i128::from(HISTORICAL_OUTLIER_FACTOR)
        || i128::from(baseline) > i128::from(observed) * i128::from(HISTORICAL_OUTLIER_FACTOR)
}

fn declared_vram_total_mib(profile: &Value) -> Result<Option<i64>, ApiError> {
    let profile: HardwareProfile = serde_json::from_value(profile.clone()).map_err(|error| {
        tracing::error!(error = %error, "数据库中的硬件声明无法解析");
        ApiError::internal()
    })?;
    let mut total = 0_u64;
    let mut observed = false;
    for gpu in profile.gpus {
        if let Some(vram) = gpu.vram_total_mib {
            total = total.checked_add(vram).ok_or_else(ApiError::internal)?;
            observed = true;
        }
    }
    if !observed {
        return Ok(None);
    }
    i64::try_from(total)
        .map(Some)
        .map_err(|_| ApiError::internal())
}

fn hardware_cohort_key(profile: &Value) -> Result<String, ApiError> {
    let profile: HardwareProfile = serde_json::from_value(profile.clone()).map_err(|error| {
        tracing::error!(error = %error, "数据库中的硬件声明无法形成指纹 cohort");
        ApiError::internal()
    })?;
    let mut gpus = profile
        .gpus
        .into_iter()
        .map(|gpu| {
            (
                gpu.name,
                gpu.vendor,
                gpu.vram_total_mib,
                gpu.compute_capability,
            )
        })
        .collect::<Vec<_>>();
    gpus.sort();
    let encoded = serde_json::to_vec(&json!({
        "operating_system": profile.operating_system,
        "architecture": profile.architecture,
        "cuda_available": profile.cuda_available,
        "metal_available": profile.metal_available,
        "gpus": gpus,
    }))
    .map_err(|_| ApiError::internal())?;
    let mut digest = Sha256::new();
    digest.update(b"MindOne self-reported hardware cohort v1\0");
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn evidence_kind(context: &FingerprintContext) -> &'static str {
    if context.confidentiality == "standard" || context.trust_level != "enhanced" {
        "standard_self_reported_risk_signal"
    } else {
        // 当前 TEE envelope 绑定结果内容，但遥测字段仍由节点侧 adapter 上报，不能称作证明。
        "enhanced_node_reported_risk_signal"
    }
}

fn verdict(alerts: &[Alert], incomplete: bool) -> ExecutionTelemetryVerdict {
    if alerts
        .iter()
        .any(|alert| alert.severity == Severity::Critical)
    {
        ExecutionTelemetryVerdict::Critical
    } else if !alerts.is_empty() {
        ExecutionTelemetryVerdict::Warning
    } else if incomplete {
        ExecutionTelemetryVerdict::InsufficientEvidence
    } else {
        ExecutionTelemetryVerdict::NoAnomalyObserved
    }
}

const fn verdict_key(verdict: ExecutionTelemetryVerdict) -> &'static str {
    match verdict {
        ExecutionTelemetryVerdict::InsufficientEvidence => "insufficient_evidence",
        ExecutionTelemetryVerdict::NoAnomalyObserved => "no_anomaly_observed",
        ExecutionTelemetryVerdict::Warning => "warning",
        ExecutionTelemetryVerdict::Critical => "critical",
    }
}

fn ceil_div_positive(value: i64, divisor: i64) -> Result<i64, ApiError> {
    if value <= 0 || divisor <= 0 {
        return Err(ApiError::internal());
    }
    value
        .checked_add(divisor - 1)
        .map(|sum| sum / divisor)
        .ok_or_else(ApiError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(model_size_mib: i64, declared_total_mib: Option<u64>) -> FingerprintContext {
        let hardware = json!({
            "operating_system": "linux",
            "operating_system_version": "1",
            "architecture": "x86_64",
            "cpu_model": "test",
            "cpu_logical_cores": 4,
            "ram_total_mib": 16384,
            "gpus": [{
                "name": "test-gpu",
                "vram_total_mib": declared_total_mib
            }],
            "cuda_available": true,
            "metal_available": false,
            "sandbox_mechanisms": []
        });
        FingerprintContext {
            job_id: Uuid::from_u128(1),
            node_id: Uuid::from_u128(2),
            model_id: Uuid::from_u128(3),
            model_instance_id: Some(Uuid::from_u128(4)),
            attempt_number: 1,
            result_idempotency_key: "result-1".to_owned(),
            confidentiality: "standard".to_owned(),
            trust_level: "standard".to_owned(),
            model_size_bytes: model_size_mib * 1_048_576,
            hardware_profile: hardware,
        }
    }

    fn history() -> HistoricalBaseline {
        HistoricalBaseline {
            sample_count: 0,
            ttft_median_ms: None,
            tps_median_milli: None,
        }
    }

    #[test]
    fn impossible_peak_and_model_scale_are_server_critical() {
        let assessment = assess(
            &context(8_192, Some(4_096)),
            &JobExecutionTelemetry {
                ttft_ms: Some(100),
                tps_milli: Some(10_000),
                peak_vram_mib: Some(5_000),
                vram_sample_count: 10,
            },
            history(),
        )
        .expect("服务端应生成风险判定");
        assert!(assessment.alerts.iter().any(|alert| {
            alert.code == "peak_exceeds_declared_total" && alert.severity == Severity::Critical
        }));
        assert_eq!(
            verdict(&assessment.alerts, assessment.incomplete),
            ExecutionTelemetryVerdict::Critical
        );
    }

    #[test]
    fn conservative_model_floor_has_weak_and_critical_bands() {
        let weak = assess(
            &context(8_192, Some(24_576)),
            &JobExecutionTelemetry {
                ttft_ms: Some(100),
                tps_milli: Some(10_000),
                peak_vram_mib: Some(256),
                vram_sample_count: 2,
            },
            history(),
        )
        .expect("弱偏差应可判定");
        assert!(weak
            .alerts
            .iter()
            .any(|alert| alert.code == "model_vram_weak_mismatch"));

        let critical = assess(
            &context(8_192, Some(24_576)),
            &JobExecutionTelemetry {
                ttft_ms: Some(100),
                tps_milli: Some(10_000),
                peak_vram_mib: Some(32),
                vram_sample_count: 2,
            },
            history(),
        )
        .expect("严重偏差应可判定");
        assert!(critical
            .alerts
            .iter()
            .any(|alert| alert.code == "model_vram_severe_mismatch"));
    }

    #[test]
    fn historical_latency_outliers_require_server_sample_floor() {
        let telemetry = JobExecutionTelemetry {
            ttft_ms: Some(1),
            tps_milli: Some(900_000),
            peak_vram_mib: Some(1_024),
            vram_sample_count: 4,
        };
        let baseline = HistoricalBaseline {
            sample_count: 10,
            ttft_median_ms: Some(100),
            tps_median_milli: Some(10_000),
        };
        let assessment =
            assess(&context(1_024, Some(8_192)), &telemetry, baseline).expect("历史偏差应可判定");
        assert!(assessment
            .alerts
            .iter()
            .any(|alert| alert.code == "ttft_historical_outlier"));
        assert!(assessment
            .alerts
            .iter()
            .any(|alert| alert.code == "tps_historical_outlier"));
    }

    #[test]
    fn standard_evidence_never_claims_execution_proof() {
        let context = context(1_024, Some(8_192));
        assert_eq!(
            evidence_kind(&context),
            "standard_self_reported_risk_signal"
        );
    }

    #[test]
    fn telemetry_hash_binds_every_reported_value() {
        let telemetry = JobExecutionTelemetry {
            ttft_ms: Some(10),
            tps_milli: Some(20),
            peak_vram_mib: Some(30),
            vram_sample_count: 2,
        };
        let context = context(1_024, Some(8_192));
        let first = telemetry_fingerprint(&context, &telemetry).expect("遥测应可哈希");
        let mut changed = telemetry.clone();
        changed.peak_vram_mib = Some(31);
        let second = telemetry_fingerprint(&context, &changed).expect("变化遥测应可哈希");
        assert_ne!(first, second);

        let mut other_job = context;
        other_job.job_id = Uuid::from_u128(99);
        let moved = telemetry_fingerprint(&other_job, &telemetry).expect("另一任务应可哈希");
        assert_ne!(first, moved, "同值遥测 commitment 不得跨任务移植");
    }

    #[test]
    fn missing_platform_counter_is_insufficient_evidence_not_anomaly() {
        let assessment = assess(
            &context(1_024, None),
            &JobExecutionTelemetry {
                ttft_ms: Some(100),
                tps_milli: Some(10_000),
                peak_vram_mib: None,
                vram_sample_count: 0,
            },
            history(),
        )
        .expect("缺平台计数器仍应保留记录");
        assert!(assessment.alerts.is_empty());
        assert_eq!(
            verdict(&assessment.alerts, assessment.incomplete),
            ExecutionTelemetryVerdict::InsufficientEvidence
        );
    }
}
