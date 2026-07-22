use std::{collections::BTreeMap, env, fs, net::SocketAddr, path::Path, sync::Arc};

use axum::{
    body::Body,
    http::{header::AUTHORIZATION, HeaderMap, Method, Request, StatusCode},
};
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use mindone_accounting::routing::{
    normalized_coordinator_rtt_score, CONTRIBUTION_ROUTING_MIN_COHORT,
    CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR, CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR,
    CONTRIBUTION_ROUTING_PERCENTILE_SCALE, CONTRIBUTION_ROUTING_VERSION,
    CONTRIBUTION_ROUTING_WINDOW_DAYS, MAX_ROUTABLE_COORDINATOR_RTT_MS,
};
use mindone_accounting::{
    maximum_reservation_micro, maximum_reservation_quote, Glicko2Score, LedgerEntry, LedgerKind,
    ReservePurpose, ServerReferenceBillingProfile, LEDGER_HASH_VERSION,
    SERVER_REFERENCE_UPPER_BOUND_V1,
};
use mindone_coordinator::{
    anti_abuse::{
        assess_before_create, record_settled_edge, settlement_contribution_weight, AntiAbuseError,
        NoAsnResolver, TrafficClass, TrustedNetworkSignal,
    },
    auth::LocalDevelopmentProvider,
    config::{Config, PrivateEvaluationBudgetConfig, RuntimeEnvironment},
    db::{connect, migrate, prepare_private_evaluation_runtime},
    operator_grant::{grant_operator_quota, OperatorQuotaGrantError, OperatorQuotaGrantRequest},
    operator_quality::{
        quality_evidence_signing_message, record_operator_quality_evidence, OperatorQualityError,
        OperatorQualityRecordRequest, QualityEvidenceMeasurement, QualityEvidenceStatement,
        SignedQualityEvidence, QUALITY_EVIDENCE_SCHEMA,
    },
    private_evaluation_catalog::{
        private_evaluation_catalog_signing_message, PrivateEvaluationCatalogEntry,
        PrivateEvaluationCatalogStatement, SignedPrivateEvaluationCatalog,
        PRIVATE_EVALUATION_CATALOG_FILE, PRIVATE_EVALUATION_CATALOG_SCHEMA,
        PRIVATE_EVALUATION_NORMALIZATION,
    },
    quality::QualityGovernanceError,
    router,
    settlement::{release_reserve, ReserveReleaseCommand},
    standard_data::{
        encrypt_for_storage, StandardDataMigrationError, StorageDirection, ENVELOPE_PREFIX,
    },
    sweep_expired_hidden_jobs, sweep_expired_hidden_jobs_prepared, AppState,
};
use mindone_protocol::{LedgerEntryResponse, LedgerNamespace, LedgerRecomputationStatus};
use serde_json::{json, Value};
use serial_test::serial;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tower::ServiceExt;
use uuid::Uuid;

const REQUIRE_POSTGRES_TESTS_ENV: &str = "MINDONE_REQUIRE_POSTGRES_TESTS";

macro_rules! bind_test_billing_snapshot {
    ($query:expr, $snapshot:ident) => {{
        $query
            .bind(&$snapshot.contract_version)
            .bind($snapshot.profile_id)
            .bind($snapshot.profile_version)
            .bind(&$snapshot.profile_fingerprint)
            .bind(&$snapshot.model_weights_hash)
            .bind(&$snapshot.reference_hardware_class)
            .bind(&$snapshot.profile_evidence_hash)
            .bind($snapshot.profile_valid_from)
            .bind($snapshot.profile_valid_until)
            .bind($snapshot.profile_max_input_tokens)
            .bind($snapshot.profile_max_output_tokens)
            .bind($snapshot.fixed_gpu_time_us)
            .bind($snapshot.gpu_time_us_per_1k_tokens)
            .bind($snapshot.reference_vram_mib)
            .bind($snapshot.token_rate_micro_per_1k)
            .bind($snapshot.gpu_rate_micro_per_second)
            .bind($snapshot.vram_rate_micro_per_gib_second)
            .bind($snapshot.authorized_input_tokens)
            .bind($snapshot.authorized_max_output_tokens)
            .bind($snapshot.billable_tokens)
            .bind($snapshot.reference_gpu_time_us)
            .bind($snapshot.reference_vram_mib_microseconds)
            .bind($snapshot.token_cost_micro)
            .bind($snapshot.gpu_cost_micro)
            .bind($snapshot.vram_cost_micro)
            .bind($snapshot.base_cost_micro)
    }};
}

fn database_url_or_skip(test_name: &str) -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(database_url) => Some(database_url),
        Err(error) if env::var(REQUIRE_POSTGRES_TESTS_ENV).as_deref() == Ok("1") => {
            panic!(
                "{test_name} 要求真实 PostgreSQL，但 DATABASE_URL 不可用：{error}；required CI 不得静默跳过"
            );
        }
        Err(_) => {
            eprintln!("跳过 {test_name}：未设置 DATABASE_URL");
            None
        }
    }
}

fn signed_quality_request(
    directory: &Path,
    keys_directory: &Path,
    signing_key: &SigningKey,
    evaluator_id: &str,
    model_id: Uuid,
    idempotency_key: String,
    measurement: QualityEvidenceMeasurement,
) -> OperatorQualityRecordRequest {
    signed_quality_request_with_validity(
        directory,
        keys_directory,
        signing_key,
        evaluator_id,
        model_id,
        idempotency_key,
        measurement,
        Duration::hours(1),
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_quality_request_with_validity(
    directory: &Path,
    keys_directory: &Path,
    signing_key: &SigningKey,
    evaluator_id: &str,
    model_id: Uuid,
    idempotency_key: String,
    measurement: QualityEvidenceMeasurement,
    validity: Duration,
) -> OperatorQualityRecordRequest {
    let artifact = serde_json::to_vec(&json!({
        "source": "independent-integration-evaluator",
        "model_id": model_id,
        "idempotency_key": &idempotency_key,
        "measurement": &measurement,
    }))
    .expect("应编码独立 evaluator artifact");
    let artifact_sha256 = hex::encode(Sha256::digest(&artifact));
    let now = OffsetDateTime::now_utc();
    let statement = QualityEvidenceStatement {
        schema: QUALITY_EVIDENCE_SCHEMA.to_owned(),
        evaluator_id: evaluator_id.to_owned(),
        model_id,
        idempotency_key: idempotency_key.clone(),
        observed_at: now.format(&Rfc3339).expect("应格式化 observed_at"),
        valid_until: (now + validity)
            .format(&Rfc3339)
            .expect("应格式化 valid_until"),
        artifact_sha256,
        measurement,
    };
    let signature = signing_key.sign(
        &quality_evidence_signing_message(&statement).expect("应生成 quality evidence 签名消息"),
    );
    let envelope = SignedQualityEvidence {
        statement,
        signature: hex::encode(signature.to_bytes()),
    };
    let artifact_path = directory.join(format!("{idempotency_key}.artifact.json"));
    let evidence_path = directory.join(format!("{idempotency_key}.evidence.json"));
    fs::write(&artifact_path, artifact).expect("应写入 evaluator artifact");
    fs::write(
        &evidence_path,
        serde_json::to_vec(&envelope).expect("应编码签名 evidence"),
    )
    .expect("应写入签名 evidence");
    OperatorQualityRecordRequest {
        evidence_path,
        artifact_path,
        trusted_keys_dir: keys_directory.to_owned(),
        operator_id: "ops/quality@example.com".to_owned(),
        reason: "导入独立 evaluator 已签名且 artifact 匹配的质量证据".to_owned(),
    }
}

fn write_test_private_evaluation_catalog(
    directory: &Path,
    entries: Vec<PrivateEvaluationCatalogEntry>,
) {
    write_test_private_evaluation_catalog_with_id(
        directory,
        &format!("private-integration-{}", Uuid::now_v7()),
        entries,
    );
}

fn write_test_private_evaluation_catalog_with_id(
    directory: &Path,
    catalog_id: &str,
    entries: Vec<PrivateEvaluationCatalogEntry>,
) {
    let signing_key = SigningKey::from_bytes(&[0x39_u8; 32]);
    let evaluator_id = "private-integration-evaluator";
    fs::write(
        directory.join(format!("{evaluator_id}.pub")),
        hex::encode(signing_key.verifying_key().to_bytes()),
    )
    .expect("应写入私有 evaluator 测试公钥");
    let now = OffsetDateTime::now_utc();
    let statement = PrivateEvaluationCatalogStatement {
        schema: PRIVATE_EVALUATION_CATALOG_SCHEMA.to_owned(),
        catalog_id: catalog_id.to_owned(),
        evaluator_id: evaluator_id.to_owned(),
        issued_at: now.format(&Rfc3339).expect("应格式化 catalog issued_at"),
        valid_until: (now + Duration::hours(1))
            .format(&Rfc3339)
            .expect("应格式化 catalog valid_until"),
        behavior_normalization: PRIVATE_EVALUATION_NORMALIZATION.to_owned(),
        entries,
    };
    let signature = signing_key.sign(
        &private_evaluation_catalog_signing_message(&statement)
            .expect("应生成私有 catalog 签名消息"),
    );
    let envelope = SignedPrivateEvaluationCatalog {
        statement,
        signature: hex::encode(signature.to_bytes()),
    };
    fs::write(
        directory.join(PRIVATE_EVALUATION_CATALOG_FILE),
        serde_json::to_vec(&envelope).expect("应编码签名私有 catalog"),
    )
    .expect("应写入签名私有 catalog");
}

#[tokio::test]
#[serial]
async fn operator_quota_grant_is_transactional_audited_and_idempotent() {
    let Some(database_url) = database_url_or_skip("运维赠额 PostgreSQL 集成测试") else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接赠额集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("运维赠额迁移应成功");
    let suffix = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id,provider,provider_subject,username)
        VALUES ($1,'integration-test',$2,$3)
        "#,
    )
    .bind(user_id)
    .bind(format!("operator-grant-{suffix}"))
    .bind(format!("赠额测试-{suffix}"))
    .execute(&pool)
    .await
    .expect("应能建立零余额生产语义账户");
    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应能建立默认零余额额度账户");

    let request = OperatorQuotaGrantRequest {
        user_id,
        amount_micro: 1_000_000,
        idempotency_key: format!("launch-{suffix}"),
        operator_id: "ops/oncall@example.com".to_owned(),
        reason: "生产网络首批供应启动额度".to_owned(),
    };
    let granted = grant_operator_quota(&pool, &request)
        .await
        .expect("首次赠额应提交");
    assert!(!granted.idempotent_replay);
    assert_eq!(granted.balance_before_micro, 0);
    assert_eq!(granted.balance_after_micro, 1_000_000);

    let replay = grant_operator_quota(&pool, &request)
        .await
        .expect("相同请求重试应返回原记录");
    assert!(replay.idempotent_replay);
    assert_eq!(replay.grant_id, granted.grant_id);
    assert_eq!(replay.quota_ledger_id, granted.quota_ledger_id);
    assert_eq!(replay.balance_after_micro, granted.balance_after_micro);

    let mut changed = request.clone();
    changed.amount_micro += 1;
    assert!(matches!(
        grant_operator_quota(&pool, &changed).await,
        Err(OperatorQuotaGrantError::IdempotencyConflict)
    ));
    let missing = OperatorQuotaGrantRequest {
        user_id: Uuid::now_v7(),
        idempotency_key: format!("missing-{suffix}"),
        ..request.clone()
    };
    assert!(matches!(
        grant_operator_quota(&pool, &missing).await,
        Err(OperatorQuotaGrantError::UserNotFound(_))
    ));

    let account_balance: i64 =
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("应能读取赠额后余额");
    assert_eq!(account_balance, 1_000_000);
    let ledger = sqlx::query(
        r#"
        SELECT entry_type,request_id,delta_micro,balance_before_micro,balance_after_micro,
               idempotency_key,prev_hash,entry_hash
        FROM quota_ledger WHERE id=$1
        "#,
    )
    .bind(granted.quota_ledger_id)
    .fetch_one(&pool)
    .await
    .expect("赠额必须写入 quota ledger");
    assert_eq!(ledger.get::<String, _>("entry_type"), "operator_grant");
    assert_eq!(ledger.get::<Option<Uuid>, _>("request_id"), None);
    assert_eq!(ledger.get::<i64, _>("delta_micro"), 1_000_000);
    assert_eq!(ledger.get::<i64, _>("balance_before_micro"), 0);
    assert_eq!(ledger.get::<i64, _>("balance_after_micro"), 1_000_000);
    assert_eq!(
        ledger.get::<String, _>("idempotency_key"),
        format!("operator-grant:{}", request.idempotency_key)
    );
    assert_eq!(ledger.get::<String, _>("prev_hash"), "0".repeat(64));
    assert_eq!(
        ledger.get::<String, _>("entry_hash"),
        granted.quota_ledger_entry_hash
    );

    let audit = sqlx::query(
        r#"
        SELECT user_id,operator_id,reason,amount_micro,idempotency_key,
               quota_ledger_id,quota_ledger_entry_hash
        FROM operator_quota_grants WHERE id=$1
        "#,
    )
    .bind(granted.grant_id)
    .fetch_one(&pool)
    .await
    .expect("赠额必须写入独立审计记录");
    assert_eq!(audit.get::<Uuid, _>("user_id"), user_id);
    assert_eq!(audit.get::<String, _>("operator_id"), request.operator_id);
    assert_eq!(audit.get::<String, _>("reason"), request.reason);
    assert_eq!(audit.get::<i64, _>("amount_micro"), 1_000_000);
    assert_eq!(
        audit.get::<String, _>("idempotency_key"),
        request.idempotency_key
    );
    assert_eq!(
        audit.get::<Uuid, _>("quota_ledger_id"),
        granted.quota_ledger_id
    );
    assert_eq!(
        audit.get::<String, _>("quota_ledger_entry_hash"),
        granted.quota_ledger_entry_hash
    );

    assert!(sqlx::query(
        "UPDATE operator_quota_grants SET reason='这条审计记录不应被修改' WHERE id=$1"
    )
    .bind(granted.grant_id)
    .execute(&pool)
    .await
    .is_err());
    assert!(sqlx::query("DELETE FROM operator_quota_grants WHERE id=$1")
        .bind(granted.grant_id)
        .execute(&pool)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM quota_ledger WHERE id=$1")
        .bind(granted.quota_ledger_id)
        .execute(&pool)
        .await
        .is_err());
}

#[tokio::test]
#[serial]
async fn postgres_standard_and_regulated_routing_use_coordinator_rtt_contract() {
    let Some(database_url) = database_url_or_skip("协调器 RTT 路由 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("RTT-路由-集成测试-{suffix}");
    let pool = connect(&config)
        .await
        .expect("应能连接协调器 RTT 路由集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("协调器 RTT 路由数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");

    // 先钉住 accounting helper 的边界合同；后面的真实 HTTP + PostgreSQL 路由必须给出
    // 同样的保留/过滤结论，避免 SQL 与纯函数实现悄然分叉。
    assert_eq!(MAX_ROUTABLE_COORDINATOR_RTT_MS, 1_000);
    assert_eq!(normalized_coordinator_rtt_score(None), Some(0));
    assert_eq!(
        normalized_coordinator_rtt_score(Some(MAX_ROUTABLE_COORDINATOR_RTT_MS)),
        Some(0)
    );
    assert_eq!(
        normalized_coordinator_rtt_score(Some(MAX_ROUTABLE_COORDINATOR_RTT_MS + 1)),
        None
    );
    assert!(
        normalized_coordinator_rtt_score(Some(10)) > normalized_coordinator_rtt_score(Some(900)),
        "较低 coordinator RTT 必须得到较高网络项得分"
    );

    let (consumer_token, _, _) =
        login(&app, &format!("rtt-routing-consumer-public-key-{suffix}")).await;
    let (fast_rtt_token, _, _) = login(&app, &format!("fast-rtt-node-public-key-{suffix}")).await;
    let (slow_rtt_token, _, _) = login(&app, &format!("slow-rtt-node-public-key-{suffix}")).await;
    let fast_rtt_node =
        register_test_node(&app, &fast_rtt_token, &format!("fast-rtt-node-{suffix}")).await;
    let slow_rtt_node =
        register_test_node(&app, &slow_rtt_token, &format!("slow-rtt-node-{suffix}")).await;

    // TTFT 故意与 coordinator RTT 给出相反结论；TPS、负载、可靠性和策略保持一致。
    heartbeat_test_node_with_rtt(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        30_000,
        9_000,
        Some(10),
        &[],
    )
    .await;
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        1,
        Some(900),
        &[],
    )
    .await;
    assert_latest_routing_metrics(&pool, &fast_rtt_node, 9_000, Some(10)).await;
    assert_latest_routing_metrics(&pool, &slow_rtt_node, 1, Some(900)).await;

    let fast_model = publish_test_model(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    let slow_model = publish_test_model(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    assert_eq!(
        value_str(&fast_model, "/model_id"),
        value_str(&slow_model, "/model_id")
    );
    let fast_instance = value_str(&fast_model, "/model_instance_id");
    let slow_instance = value_str(&slow_model, "/model_instance_id");
    let model_name = format!("model-{suffix}");

    let standard_inverse_job = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["rtt-inverse"],
        &format!("standard-rtt-inverse-{suffix}"),
    )
    .await;
    let (slow_inverse_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": slow_rtt_node,
            "model_instance_id": slow_instance
        })),
        Some(&slow_rtt_token),
    )
    .await;
    assert_eq!(
        slow_inverse_status,
        StatusCode::NO_CONTENT,
        "Standard 路由不得把较好 TTFT 当成网络时延项"
    );
    let (_, fast_inverse_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": fast_rtt_node,
            "model_instance_id": fast_instance
        })),
        Some(&fast_rtt_token),
    )
    .await;
    assert_eq!(
        value_str(&fast_inverse_claim, "/job_id"),
        standard_inverse_job
    );
    fail_test_job(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        &standard_inverse_job,
        &format!("standard-rtt-inverse-fail-{suffix}"),
    )
    .await;

    // 两台节点都超过上限时，真实 Standard claim 必须没有候选；这证明 1001ms
    // 是过滤而不只是一个较低分。随后同一排队任务在 1000ms 边界立即可领取。
    heartbeat_test_node_with_rtt(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        30_000,
        1,
        Some(1_001),
        &[],
    )
    .await;
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        Some(1_001),
        &[],
    )
    .await;
    let standard_boundary_job = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["rtt-boundary"],
        &format!("standard-rtt-boundary-{suffix}"),
    )
    .await;
    for (node_id, instance_id, token) in [
        (&fast_rtt_node, &fast_instance, &fast_rtt_token),
        (&slow_rtt_node, &slow_instance, &slow_rtt_token),
    ] {
        let (status, _) = call(
            &app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({"node_id": node_id, "model_instance_id": instance_id})),
            Some(token.as_str()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "1001ms 节点必须被过滤");
    }
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        Some(1_000),
        &[],
    )
    .await;
    assert_latest_routing_metrics(&pool, &slow_rtt_node, 9_000, Some(1_000)).await;
    let (_, boundary_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": slow_rtt_node,
            "model_instance_id": slow_instance
        })),
        Some(&slow_rtt_token),
    )
    .await;
    assert_eq!(value_str(&boundary_claim, "/job_id"), standard_boundary_job);
    fail_test_job(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        &standard_boundary_job,
        &format!("standard-rtt-boundary-fail-{suffix}"),
    )
    .await;

    // 省略新字段写入 NULL，证明升级前 worker 不会被误当成 0ms，也不会被剔除。
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        None,
        &[],
    )
    .await;
    assert_latest_routing_metrics(&pool, &slow_rtt_node, 9_000, None).await;
    let standard_null_job = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["rtt-null"],
        &format!("standard-rtt-null-{suffix}"),
    )
    .await;
    let (_, null_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": slow_rtt_node,
            "model_instance_id": slow_instance
        })),
        Some(&slow_rtt_token),
    )
    .await;
    assert_eq!(value_str(&null_claim, "/job_id"), standard_null_job);
    fail_test_job(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        &standard_null_job,
        &format!("standard-rtt-null-fail-{suffix}"),
    )
    .await;

    let fast_report = install_verified_tee_report(
        &pool,
        parse_uuid(&fast_rtt_node, "低 RTT 节点"),
        parse_uuid(&fast_instance, "低 RTT 模型实例"),
        "88".repeat(32),
    )
    .await;
    let slow_report = install_verified_tee_report(
        &pool,
        parse_uuid(&slow_rtt_node, "高 RTT 节点"),
        parse_uuid(&slow_instance, "高 RTT 模型实例"),
        "99".repeat(32),
    )
    .await;

    heartbeat_test_node_with_rtt(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        30_000,
        9_000,
        Some(10),
        &[],
    )
    .await;
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        1,
        Some(900),
        &[],
    )
    .await;
    let (_, regulated_inverse) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("regulated-rtt-inverse-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(
        value_str(&regulated_inverse, "/node_id"),
        fast_rtt_node,
        "Regulated 路由不得把较好 TTFT 当成网络时延项"
    );
    assert_eq!(
        value_str(&regulated_inverse, "/attestation/report_id"),
        fast_report.to_string()
    );
    expire_prepared_route(&pool, &value_str(&regulated_inverse, "/route_id")).await;

    heartbeat_test_node_with_rtt(
        &app,
        &fast_rtt_token,
        &fast_rtt_node,
        30_000,
        1,
        Some(1_001),
        &[],
    )
    .await;
    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        Some(1_001),
        &[],
    )
    .await;
    let (regulated_over_status, regulated_over_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("regulated-rtt-over-limit-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(regulated_over_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        regulated_over_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("attestation_failed"),
        "两台 1001ms Enhanced 节点都必须在 Regulated SQL 中被过滤"
    );

    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        Some(1_000),
        &[],
    )
    .await;
    let (_, regulated_boundary) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("regulated-rtt-boundary-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(value_str(&regulated_boundary, "/node_id"), slow_rtt_node);
    assert_eq!(
        value_str(&regulated_boundary, "/attestation/report_id"),
        slow_report.to_string()
    );
    expire_prepared_route(&pool, &value_str(&regulated_boundary, "/route_id")).await;

    heartbeat_test_node_with_rtt(
        &app,
        &slow_rtt_token,
        &slow_rtt_node,
        30_000,
        9_000,
        None,
        &[],
    )
    .await;
    let (_, regulated_null) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("regulated-rtt-null-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(value_str(&regulated_null, "/node_id"), slow_rtt_node);
    assert_eq!(
        value_str(&regulated_null, "/attestation/report_id"),
        slow_report.to_string()
    );
}

#[tokio::test]
#[serial]
async fn postgres_speed_classes_choose_fast_pack_safely_and_queue_when_full() {
    let Some(database_url) = database_url_or_skip("三档速度调度 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("三档速度调度-集成测试-{suffix}");
    let pool = connect(&config)
        .await
        .expect("应能连接三档速度调度集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("三档速度调度数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");

    let (consumer_token, _, _) = login(&app, &format!("speed-consumer-public-key-{suffix}")).await;
    let (burst_token, _, _) = login(&app, &format!("speed-burst-public-key-{suffix}")).await;
    let (packed_token, _, _) = login(&app, &format!("speed-packed-public-key-{suffix}")).await;
    let burst_node = register_test_node(&app, &burst_token, &format!("speed-burst-{suffix}")).await;
    let packed_node =
        register_test_node(&app, &packed_token, &format!("speed-packed-{suffix}")).await;

    heartbeat_test_node_with_rtt(&app, &burst_token, &burst_node, 90_000, 100, Some(20), &[]).await;
    heartbeat_test_node_with_rtt(
        &app,
        &packed_token,
        &packed_node,
        20_000,
        100,
        Some(20),
        &[],
    )
    .await;
    let burst_model = publish_test_model(
        &app,
        &burst_token,
        &burst_node,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    let packed_model = publish_test_model(
        &app,
        &packed_token,
        &packed_node,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    assert_eq!(
        value_str(&burst_model, "/model_id"),
        value_str(&packed_model, "/model_id")
    );
    let burst_instance = value_str(&burst_model, "/model_instance_id");
    let packed_instance = value_str(&packed_model, "/model_instance_id");
    let model_name = format!("model-{suffix}");

    // 两台都空闲时，fast 先看真实 TPS；低 TPS 节点即使主动轮询也不能抢走任务。
    let fast_job = create_test_job(
        &app,
        &consumer_token,
        &format!("{model_name}-fast"),
        &["speed-fast"],
        &format!("speed-fast-{suffix}"),
    )
    .await;
    let (wrong_fast_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(wrong_fast_status, StatusCode::NO_CONTENT);
    let (_, fast_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(value_str(&fast_claim, "/job_id"), fast_job);
    fail_test_job(
        &app,
        &burst_token,
        &burst_node,
        &fast_job,
        &format!("speed-fast-fail-{suffix}"),
    )
    .await;

    // 高 TPS 节点已有真实租约时，fast 必须优先整台空闲节点，不能只按历史 TPS
    // 把新请求塞进已有并发。两台都有负载时，即使各自仍有第二个物理 slot，fast
    // 也必须保持 queued；只有 slow 可以用这些并发 slot。
    let burst_blocker = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["occupy-fastest"],
        &format!("occupy-fastest-{suffix}"),
    )
    .await;
    let (_, burst_blocker_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(value_str(&burst_blocker_claim, "/job_id"), burst_blocker);
    let idle_fast_job = create_test_job(
        &app,
        &consumer_token,
        &format!("{model_name}-fast"),
        &["fast-idle-first"],
        &format!("fast-idle-first-{suffix}"),
    )
    .await;
    let (busy_fast_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(busy_fast_status, StatusCode::NO_CONTENT);
    let (_, idle_fast_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(value_str(&idle_fast_claim, "/job_id"), idle_fast_job);
    let both_busy_fast_job = create_test_job(
        &app,
        &consumer_token,
        &format!("{model_name}-fast"),
        &["fast-all-busy"],
        &format!("fast-all-busy-{suffix}"),
    )
    .await;
    for (node_id, instance_id, token) in [
        (&burst_node, &burst_instance, &burst_token),
        (&packed_node, &packed_instance, &packed_token),
    ] {
        let (status, _) = call(
            &app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({
                "node_id": node_id,
                "model_instance_id": instance_id
            })),
            Some(token.as_str()),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let busy_fast_status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id=$1")
        .bind(parse_uuid(&both_busy_fast_job, "fast 全忙排队任务"))
        .fetch_one(&pool)
        .await
        .expect("应能读取 fast 全忙排队任务");
    assert_eq!(busy_fast_status, "queued");
    fail_test_job(
        &app,
        &packed_token,
        &packed_node,
        &idle_fast_job,
        &format!("fast-idle-first-fail-{suffix}"),
    )
    .await;
    fail_test_job(
        &app,
        &burst_token,
        &burst_node,
        &burst_blocker,
        &format!("occupy-fastest-fail-{suffix}"),
    )
    .await;
    let (wrong_released_fast_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(wrong_released_fast_status, StatusCode::NO_CONTENT);
    let (_, released_fast_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(
        value_str(&released_fast_claim, "/job_id"),
        both_busy_fast_job
    );
    fail_test_job(
        &app,
        &burst_token,
        &burst_node,
        &both_busy_fast_job,
        &format!("fast-all-busy-release-fail-{suffix}"),
    )
    .await;

    // 先让 packed 节点拥有一个真实有效租约，再确认 slow 会在它仍有第二个服务端
    // 计数空槽时优先合并；不是根据 worker 自报 current_concurrent 虚构容量。
    heartbeat_test_node_with_rtt(
        &app,
        &packed_token,
        &packed_node,
        90_000,
        100,
        Some(10),
        &[],
    )
    .await;
    heartbeat_test_node_with_rtt(&app, &burst_token, &burst_node, 60_000, 100, Some(900), &[])
        .await;
    let packed_blocker = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["occupy-packed"],
        &format!("occupy-packed-{suffix}"),
    )
    .await;
    let (_, blocker_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(value_str(&blocker_claim, "/job_id"), packed_blocker);

    let packed_slow_job = create_test_job(
        &app,
        &consumer_token,
        &format!("{model_name}-slow"),
        &["pack-while-safe"],
        &format!("pack-while-safe-{suffix}"),
    )
    .await;
    let (wrong_slow_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(wrong_slow_status, StatusCode::NO_CONTENT);
    let (_, packed_slow_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(value_str(&packed_slow_claim, "/job_id"), packed_slow_job);
    fail_test_job(
        &app,
        &packed_token,
        &packed_node,
        &packed_slow_job,
        &format!("packed-slow-fail-{suffix}"),
    )
    .await;

    // 将 packed 的策略收紧为一个 slot 后，它的既有租约使其立即失去资格；slow
    // 必须回退到空闲节点。随后两个节点都满载时，新任务只能保持 queued。
    sqlx::query("UPDATE node_policies SET max_concurrent=1 WHERE node_id=$1")
        .bind(parse_uuid(&packed_node, "packed 节点"))
        .execute(&pool)
        .await
        .expect("应能收紧 packed 节点并发策略");
    let fallback_slow_job = create_test_job(
        &app,
        &consumer_token,
        &format!("{model_name}-slow"),
        &["slow-fallback"],
        &format!("slow-fallback-{suffix}"),
    )
    .await;
    let (full_packed_status, full_packed_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": packed_node,
            "model_instance_id": packed_instance
        })),
        Some(&packed_token),
    )
    .await;
    assert_eq!(full_packed_status, StatusCode::FORBIDDEN);
    assert_eq!(
        full_packed_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("node_policy_rejected")
    );
    let (_, fallback_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": burst_node, "model_instance_id": burst_instance})),
        Some(&burst_token),
    )
    .await;
    assert_eq!(value_str(&fallback_claim, "/job_id"), fallback_slow_job);
    sqlx::query("UPDATE node_policies SET max_concurrent=1 WHERE node_id=$1")
        .bind(parse_uuid(&burst_node, "burst 节点"))
        .execute(&pool)
        .await
        .expect("应能收紧 burst 节点并发策略");

    let queued_job = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["all-busy"],
        &format!("all-busy-{suffix}"),
    )
    .await;
    for (node_id, instance_id, token) in [
        (&packed_node, &packed_instance, &packed_token),
        (&burst_node, &burst_instance, &burst_token),
    ] {
        let (status, error) = call_unchecked(
            &app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({"node_id": node_id, "model_instance_id": instance_id})),
            Some(token.as_str()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "满载节点不得超卖 slot");
        assert_eq!(
            error.pointer("/error/type").and_then(Value::as_str),
            Some("node_policy_rejected")
        );
    }
    let queued_status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id=$1")
        .bind(parse_uuid(&queued_job, "满载排队任务"))
        .fetch_one(&pool)
        .await
        .expect("应能读取满载排队任务");
    assert_eq!(queued_status, "queued");
}

#[tokio::test]
#[serial]
async fn postgres_contribution_routing_only_breaks_congested_near_ties() {
    let Some(database_url) = database_url_or_skip("贡献优先路由 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("贡献路由集成测试-{suffix}");
    config.dev_initial_quota_micro = 100_000_000;
    let standard_data_key = config.standard_data_key.clone();
    let pool = connect(&config)
        .await
        .expect("应能连接贡献优先路由集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("贡献优先路由数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");

    assert_eq!(CONTRIBUTION_ROUTING_VERSION, "contribution-routing-v1");
    assert_eq!(CONTRIBUTION_ROUTING_WINDOW_DAYS, 30);
    assert_eq!(CONTRIBUTION_ROUTING_MIN_COHORT, 5);
    assert_eq!(CONTRIBUTION_ROUTING_PERCENTILE_SCALE, 1_000_000);
    assert_eq!(CONTRIBUTION_ROUTING_NEAR_BEST_NUMERATOR, 98);
    assert_eq!(CONTRIBUTION_ROUTING_NEAR_BEST_DENOMINATOR, 100);

    struct RoutingNode {
        token: String,
        user_id: Uuid,
        node_id: String,
        model_instance_id: String,
    }

    let (consumer_token, _, consumer_user_id) = login(
        &app,
        &format!("contribution-routing-consumer-public-key-{suffix}"),
    )
    .await;
    let consumer_user_id = parse_uuid(&consumer_user_id, "贡献路由消费者");
    let model_name = format!("model-{suffix}");
    let coordinator_rtts = [10_i64, 20, 30, 40, 50];
    let contributions = [0_i64, 120_000, 1_200, 2_400, 3_600];
    let mut routing_nodes = Vec::new();
    let mut common_model_id = None;
    for (index, coordinator_rtt) in coordinator_rtts.into_iter().enumerate() {
        let (token, _, user_id) =
            login(&app, &format!("contribution-routing-node-{suffix}-{index}")).await;
        let node_id = register_test_node(
            &app,
            &token,
            &format!("contribution-routing-node-{suffix}-{index}"),
        )
        .await;
        heartbeat_test_node_with_rtt(
            &app,
            &token,
            &node_id,
            30_000,
            100,
            Some(coordinator_rtt),
            &[],
        )
        .await;
        let published =
            publish_test_model(&app, &token, &node_id, &suffix.to_string(), 1_000_000).await;
        let model_id = parse_uuid(&value_str(&published, "/model_id"), "贡献路由模型");
        if let Some(expected_model_id) = common_model_id {
            assert_eq!(model_id, expected_model_id, "测试节点必须发布同一模型");
        } else {
            common_model_id = Some(model_id);
        }
        routing_nodes.push(RoutingNode {
            token,
            user_id: parse_uuid(&user_id, "贡献路由节点用户"),
            node_id,
            model_instance_id: value_str(&published, "/model_instance_id"),
        });
    }
    let model_id = common_model_id.expect("贡献路由测试必须发布模型");
    let physical_node_ids = routing_nodes
        .iter()
        .map(|node| parse_uuid(&node.node_id, "贡献路由节点"))
        .collect::<Vec<_>>();
    sqlx::query("UPDATE nodes SET last_seen_at=now() WHERE id=ANY($1)")
        .bind(&physical_node_ids)
        .execute(&pool)
        .await
        .expect("应能统一贡献路由节点健康时间");

    for (index, node) in routing_nodes.iter().enumerate() {
        insert_test_settled_node_contribution(
            &pool,
            &standard_data_key,
            consumer_user_id,
            model_id,
            parse_uuid(&node.node_id, "贡献 receipt 节点"),
            node.user_id,
            &model_name,
            contributions[index],
            &format!("{suffix}-{index}"),
        )
        .await;
    }
    sqlx::query("UPDATE node_metrics SET current_concurrent=1 WHERE node_id=ANY($1)")
        .bind(&physical_node_ids)
        .execute(&pool)
        .await
        .expect("应能设置不参与拥堵判定的节点自报并发夹具");

    // 节点都自报 current_concurrent=1，但服务端实际空闲槽位仍为 10；ready
    // demand=6 不拥堵。若错误信任节点自报量会得到 5 个槽位并提前启用贡献。
    let mut noncongested_jobs = Vec::new();
    for index in 0..6 {
        noncongested_jobs.push(
            create_test_job(
                &app,
                &consumer_token,
                &model_name,
                &["contribution-routing"],
                &format!("contribution-routing-noncongested-{suffix}-{index}"),
            )
            .await,
        );
    }
    let high_contribution_node = &routing_nodes[1];
    let base_best_node = &routing_nodes[0];
    let (noncongested_high_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": high_contribution_node.node_id,
            "model_instance_id": high_contribution_node.model_instance_id
        })),
        Some(&high_contribution_node.token),
    )
    .await;
    assert_eq!(noncongested_high_status, StatusCode::NO_CONTENT);
    let (_, noncongested_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": base_best_node.node_id,
            "model_instance_id": base_best_node.model_instance_id
        })),
        Some(&base_best_node.token),
    )
    .await;
    let noncongested_job = value_str(&noncongested_claim, "/job_id");
    assert!(noncongested_jobs.contains(&noncongested_job));
    fail_test_job(
        &app,
        &base_best_node.token,
        &base_best_node.node_id,
        &noncongested_job,
        &format!("contribution-routing-noncongested-fail-{suffix}"),
    )
    .await;

    // 上一步终结一项后还剩 5 项，再加入 6 项得到 ready demand=11 > 服务端
    // 空闲槽位=10。最高贡献节点只比最佳基础分差一个 10ms RTT，处于 2% 近同分
    // 窗口，因此 Standard 应由贡献 percentile 决胜。
    let mut congested_jobs = noncongested_jobs
        .into_iter()
        .filter(|job_id| job_id != &noncongested_job)
        .collect::<Vec<_>>();
    for index in 0..6 {
        congested_jobs.push(
            create_test_job(
                &app,
                &consumer_token,
                &model_name,
                &["contribution-routing"],
                &format!("contribution-routing-congested-{suffix}-{index}"),
            )
            .await,
        );
    }
    let (_, congested_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": high_contribution_node.node_id,
            "model_instance_id": high_contribution_node.model_instance_id
        })),
        Some(&high_contribution_node.token),
    )
    .await;
    let congested_job_id = value_str(&congested_claim, "/job_id");
    assert!(
        congested_jobs.contains(&congested_job_id),
        "拥堵任务必须由最高贡献的近同分节点领取"
    );
    fail_test_job(
        &app,
        &high_contribution_node.token,
        &high_contribution_node.node_id,
        &congested_job_id,
        &format!("contribution-routing-congested-fail-{suffix}"),
    )
    .await;

    let mut report_ids = Vec::new();
    for (index, node) in routing_nodes.iter().enumerate() {
        report_ids.push(
            install_verified_tee_report(
                &pool,
                parse_uuid(&node.node_id, "贡献路由 Enhanced 节点"),
                parse_uuid(&node.model_instance_id, "贡献路由模型实例"),
                format!("{:02x}", 128 + index).repeat(32),
            )
            .await,
        );
    }
    sqlx::query("UPDATE nodes SET last_seen_at=now() WHERE id=ANY($1)")
        .bind(&physical_node_ids)
        .execute(&pool)
        .await
        .expect("应能统一 Enhanced 节点健康时间");

    // Regulated prepare 自身在选路前不持久化；无同模型同标签 DB backlog 时必须
    // 保持原基础排序，不能把内存中的当前请求伪装为 ready demand。
    let (_, regulated_noncongested) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("contribution-regulated-noncongested-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(
        value_str(&regulated_noncongested, "/node_id"),
        base_best_node.node_id
    );
    assert_eq!(
        value_str(&regulated_noncongested, "/attestation/report_id"),
        report_ids[0].to_string()
    );
    expire_prepared_route(&pool, &value_str(&regulated_noncongested, "/route_id")).await;

    // 实际写入 PostgreSQL 的同模型/同标签 ready backlog 可以证明网络拥堵，并
    // 让 Regulated 的同一贡献合同生效；不使用 node current_concurrent。
    for index in 0..11 {
        create_test_job(
            &app,
            &consumer_token,
            &model_name,
            &["regulated"],
            &format!("contribution-regulated-backlog-{suffix}-{index}"),
        )
        .await;
    }
    let (_, regulated_congested) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &model_name,
            &format!("contribution-regulated-congested-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(
        value_str(&regulated_congested, "/node_id"),
        high_contribution_node.node_id
    );
    assert_eq!(
        value_str(&regulated_congested, "/attestation/report_id"),
        report_ids[1].to_string()
    );
}

#[tokio::test]
#[serial]
async fn development_physical_billing_profiles_fail_closed_and_freeze_route_snapshots() {
    let Some(database_url) = database_url_or_skip("物理计费 route writer PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.environment = RuntimeEnvironment::Development;
    config.dev_username = format!("物理计费 route writer 集成测试-{suffix}");
    config.dev_initial_quota_micro = 100_000_000;
    let pool = connect(&config)
        .await
        .expect("应能连接物理计费 route writer 集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("物理计费 route writer 数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("Development 测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");

    let (consumer_token, _, consumer_user_id) =
        login(&app, &format!("billing-consumer-public-key-{suffix}")).await;
    let consumer_user_id = parse_uuid(&consumer_user_id, "物理计费消费者");
    let (node_token, _, _) = login(&app, &format!("billing-node-public-key-{suffix}")).await;
    let node_id = register_test_node(&app, &node_token, &format!("billing-node-{suffix}")).await;
    heartbeat_test_node(&app, &node_token, &node_id, 30_000, 25, &[]).await;
    sqlx::query("UPDATE node_policies SET max_concurrent=10 WHERE node_id=$1")
        .bind(parse_uuid(&node_id, "物理计费节点"))
        .execute(&pool)
        .await
        .expect("应能设置物理计费测试节点容量");

    // Development 发布路径绝不能像 RuntimeEnvironment::Test 一样隐式生成 profile。
    let invalid_suffix = format!("billing-invalid-{suffix}");
    let invalid_model =
        publish_test_model(&app, &node_token, &node_id, &invalid_suffix, 1_000_000).await;
    let invalid_model_id = parse_uuid(&value_str(&invalid_model, "/model_id"), "缺失 profile 模型");
    let invalid_instance_id = parse_uuid(
        &value_str(&invalid_model, "/model_instance_id"),
        "缺失 profile 模型实例",
    );
    let invalid_model_name = format!("model-{invalid_suffix}");
    install_verified_tee_report(
        &pool,
        parse_uuid(&node_id, "物理计费节点"),
        invalid_instance_id,
        "91".repeat(32),
    )
    .await;
    let implicit_profile_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM billing_profiles WHERE model_id=$1")
            .bind(invalid_model_id)
            .fetch_one(&pool)
            .await
            .expect("应能确认 Development 发布没有隐式计费 profile");
    assert_eq!(implicit_profile_count, 0);
    assert_billing_route_rejected_without_writes(
        &app,
        &pool,
        &consumer_token,
        consumer_user_id,
        invalid_model_id,
        &invalid_model_name,
        &format!("missing-{suffix}"),
    )
    .await;

    // 数据库必须硬拒绝与 canonical model weights 不一致的 profile；失败后两个 writer
    // 仍然不得创建任何任务或 route。
    let now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("测试时间必须可截断到秒");
    let mismatch_error = try_insert_test_billing_profile(
        &pool,
        invalid_model_id,
        &"f".repeat(64),
        1,
        1_000,
        1_000,
        1,
        now - Duration::hours(1),
        now + Duration::hours(1),
    )
    .await
    .expect_err("weights mismatch profile 必须被数据库拒绝");
    assert!(
        mismatch_error
            .as_database_error()
            .is_some_and(|error| error.message().contains("canonical model weights")),
        "weights mismatch 必须由 canonical weights 约束拒绝：{mismatch_error}"
    );
    assert_billing_route_rejected_without_writes(
        &app,
        &pool,
        &consumer_token,
        consumer_user_id,
        invalid_model_id,
        &invalid_model_name,
        &format!("weights-mismatch-{suffix}"),
    )
    .await;

    insert_test_billing_profile(
        &pool,
        invalid_model_id,
        &"0".repeat(64),
        1,
        1_000,
        1_000,
        1,
        now - Duration::hours(2),
        now - Duration::hours(1),
    )
    .await;
    assert_billing_route_rejected_without_writes(
        &app,
        &pool,
        &consumer_token,
        consumer_user_id,
        invalid_model_id,
        &invalid_model_name,
        &format!("expired-{suffix}"),
    )
    .await;

    // 单独模型用于 v1 -> v2 轮换，避免过期 profile 占用 immutable version 1。
    let rotation_suffix = format!("billing-rotation-{suffix}");
    let rotation_model =
        publish_test_model(&app, &node_token, &node_id, &rotation_suffix, 1_000_000).await;
    let rotation_model_id = parse_uuid(&value_str(&rotation_model, "/model_id"), "计费轮换模型");
    let rotation_instance_id = parse_uuid(
        &value_str(&rotation_model, "/model_instance_id"),
        "计费轮换模型实例",
    );
    let rotation_model_name = format!("model-{rotation_suffix}");
    let rotation_report_id = install_verified_tee_report(
        &pool,
        parse_uuid(&node_id, "物理计费节点"),
        rotation_instance_id,
        "92".repeat(32),
    )
    .await;
    let profile_v1 = insert_test_billing_profile(
        &pool,
        rotation_model_id,
        &"0".repeat(64),
        1,
        4_096,
        1_000,
        1,
        now - Duration::hours(1),
        now + Duration::days(1),
    )
    .await;

    let standard_job_v1 = create_test_job(
        &app,
        &consumer_token,
        &rotation_model_name,
        &["test"],
        &format!("billing-standard-v1-{suffix}"),
    )
    .await;
    let (_, regulated_route_v1) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &rotation_model_name,
            &format!("billing-regulated-v1-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    let route_v1 = parse_uuid(
        &value_str(&regulated_route_v1, "/route_id"),
        "计费 v1 Regulated route",
    );
    let job_v1_snapshot =
        frozen_job_billing_snapshot(&pool, parse_uuid(&standard_job_v1, "计费 v1 Standard job"))
            .await;
    let route_v1_snapshot = frozen_route_billing_snapshot(&pool, route_v1).await;
    assert_eq!(value_i64(&job_v1_snapshot, "/billing_profile_version"), 1);
    assert_eq!(
        value_str(&job_v1_snapshot, "/billing_profile_id"),
        profile_v1.to_string()
    );
    assert_eq!(value_i64(&route_v1_snapshot, "/billing_profile_version"), 1);
    assert_eq!(
        value_str(&route_v1_snapshot, "/billing_profile_id"),
        profile_v1.to_string()
    );

    let profile_v2 = insert_test_billing_profile(
        &pool,
        rotation_model_id,
        &"0".repeat(64),
        2,
        4_096,
        1_000,
        2,
        now - Duration::minutes(30),
        now + Duration::days(1),
    )
    .await;
    assert_eq!(
        frozen_job_billing_snapshot(
            &pool,
            parse_uuid(&standard_job_v1, "轮换后的计费 v1 Standard job"),
        )
        .await,
        job_v1_snapshot,
        "插入 v2 后旧 Standard job 的全部 billing_* 字段必须逐字冻结"
    );
    assert_eq!(
        frozen_route_billing_snapshot(&pool, route_v1).await,
        route_v1_snapshot,
        "插入 v2 后已 prepared route 的全部 billing_* 字段必须逐字冻结"
    );

    let standard_job_v2 = create_test_job(
        &app,
        &consumer_token,
        &rotation_model_name,
        &["test"],
        &format!("billing-standard-v2-{suffix}"),
    )
    .await;
    let (_, regulated_route_v2) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            &rotation_model_name,
            &format!("billing-regulated-v2-{suffix}"),
        )),
        Some(&consumer_token),
    )
    .await;
    let route_v2 = parse_uuid(
        &value_str(&regulated_route_v2, "/route_id"),
        "计费 v2 Regulated route",
    );
    let job_v2_snapshot =
        frozen_job_billing_snapshot(&pool, parse_uuid(&standard_job_v2, "计费 v2 Standard job"))
            .await;
    let route_v2_snapshot = frozen_route_billing_snapshot(&pool, route_v2).await;
    for snapshot in [&job_v2_snapshot, &route_v2_snapshot] {
        assert_eq!(value_i64(snapshot, "/billing_profile_version"), 2);
        assert_eq!(
            value_str(snapshot, "/billing_profile_id"),
            profile_v2.to_string()
        );
        assert_eq!(
            value_i64(snapshot, "/billing_token_rate_micro_per_1k"),
            6_000
        );
    }
    assert_ne!(job_v2_snapshot, job_v1_snapshot);
    assert_ne!(route_v2_snapshot, route_v1_snapshot);

    // route v1 即使在 v2 生效后才消费，Regulated job 仍必须逐字段复制 route v1。
    let (_, regulated_job_v1) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": route_v1,
            "envelope": regulated_envelope(
                route_v1,
                rotation_report_id,
                rotation_instance_id,
                "request",
                &"93".repeat(32),
                31,
            ),
            "idempotency_key": format!("billing-regulated-create-v1-{suffix}")
        })),
        Some(&consumer_token),
    )
    .await;
    let regulated_job_v1_snapshot = frozen_job_billing_snapshot(
        &pool,
        parse_uuid(
            &value_str(&regulated_job_v1, "/job_id"),
            "从 v1 route 创建的 Regulated job",
        ),
    )
    .await;
    assert_eq!(
        regulated_job_v1_snapshot, route_v1_snapshot,
        "Regulated create 必须完整复制 prepared route 的冻结计费快照"
    );

    // 当前最高 active v3 的输出上界不足。writer 必须 fail closed，不能为了接受请求
    // 回退到仍 active 且上界充足的 v2。
    insert_test_billing_profile(
        &pool,
        rotation_model_id,
        &"0".repeat(64),
        3,
        4_096,
        1,
        3,
        now - Duration::minutes(10),
        now + Duration::days(1),
    )
    .await;
    assert_billing_route_rejected_without_writes(
        &app,
        &pool,
        &consumer_token,
        consumer_user_id,
        rotation_model_id,
        &rotation_model_name,
        &format!("newest-bounds-no-fallback-{suffix}"),
    )
    .await;
}

#[tokio::test]
#[serial]
async fn real_postgres_job_settlement_and_failure_no_charge() {
    let Some(database_url) = database_url_or_skip("PostgreSQL 集成测试") else {
        return;
    };
    let mut config = Config::development_for_tests(database_url);
    let anti_abuse_pepper = config.token_pepper.clone();
    let standard_data_key = config.standard_data_key.clone();
    let suffix = Uuid::now_v7();
    config.dev_username = format!("集成测试-{suffix}");
    let pool = match connect(&config).await {
        Ok(pool) => pool,
        Err(error) => {
            panic!("无法连接集成测试数据库：{error}");
        }
    };
    if let Err(error) = migrate(&pool, &config.standard_data_key).await {
        panic!("数据库迁移失败：{error}");
    }
    if let Err(error) = migrate(&pool, &config.standard_data_key).await {
        panic!("数据库迁移无法重复执行：{error}");
    }
    let key_commitment_before: String = sqlx::query_scalar(
        "SELECT key_commitment FROM standard_data_key_state WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("应能读取已绑定且不泄露原始密钥的 commitment");
    let wrong_key_error = migrate(&pool, &[0xa5; 32])
        .await
        .expect_err("已绑定数据库必须在监听前拒绝错误的 Standard 数据密钥");
    assert!(matches!(
        wrong_key_error,
        StandardDataMigrationError::Protection(_)
    ));
    let key_commitment_after: String = sqlx::query_scalar(
        "SELECT key_commitment FROM standard_data_key_state WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("错误密钥失败后应能复核 commitment");
    assert_eq!(key_commitment_after, key_commitment_before);
    assert!(
        sqlx::query("UPDATE standard_data_key_state SET key_commitment=$1 WHERE singleton=TRUE")
            .bind("0".repeat(64))
            .execute(&pool)
            .await
            .is_err(),
        "Standard key commitment 不得 UPDATE"
    );
    assert!(
        sqlx::query("DELETE FROM standard_data_key_state WHERE singleton=TRUE")
            .execute(&pool)
            .await
            .is_err(),
        "Standard key commitment 不得 DELETE"
    );
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("错误密钥失败后，正确密钥必须仍可幂等重跑");
    let key_commitment_after_retry: String = sqlx::query_scalar(
        "SELECT key_commitment FROM standard_data_key_state WHERE singleton=TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("正确密钥重跑后应能复核 commitment");
    assert_eq!(key_commitment_after_retry, key_commitment_before);
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let database_pool = pool.clone();
    let app = router(AppState::new(pool, config, provider)).expect("测试路由配置应有效");

    let consumer_key = format!("mindone-integration-consumer-public-key-{suffix}");
    let node_key = format!("mindone-integration-node-public-key-{suffix}");
    let (_initial_access_token, mut consumer_refresh_token, consumer_user_id) =
        login(&app, &consumer_key).await;
    let consumer_uuid = Uuid::parse_str(&consumer_user_id).expect("消费者 ID 必须是 UUID");
    let initial_refresh_challenge: String = sqlx::query_scalar(
        "SELECT refresh_challenge FROM sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(consumer_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("设备绑定会话必须保存 refresh challenge");
    let (token_only_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/refresh",
        Some(json!({"refresh_token": consumer_refresh_token.clone()})),
        None,
    )
    .await;
    assert_eq!(token_only_status, StatusCode::UNAUTHORIZED);
    let wrong_signature = sign_refresh_proof(
        "另一台设备",
        &initial_refresh_challenge,
        &consumer_refresh_token,
    );
    let (wrong_key_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/refresh",
        Some(json!({
            "refresh_token": consumer_refresh_token.clone(),
            "device_key_signature": wrong_signature
        })),
        None,
    )
    .await;
    assert_eq!(wrong_key_status, StatusCode::UNAUTHORIZED);
    let valid_signature = sign_refresh_proof(
        &consumer_key,
        &initial_refresh_challenge,
        &consumer_refresh_token,
    );
    let (_, refreshed) = call(
        &app,
        Method::POST,
        "/v1/auth/refresh",
        Some(json!({
            "refresh_token": consumer_refresh_token.clone(),
            "device_key_signature": valid_signature.clone()
        })),
        None,
    )
    .await;
    let rotated_access_token = value_str(&refreshed, "/access_token");
    let rotated_refresh_token = value_str(&refreshed, "/refresh_token");
    let next_refresh_challenge = value_str(&refreshed, "/refresh_challenge");
    assert_ne!(initial_refresh_challenge, next_refresh_challenge);
    let (replay_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/refresh",
        Some(json!({
            "refresh_token": consumer_refresh_token.clone(),
            "device_key_signature": valid_signature
        })),
        None,
    )
    .await;
    assert_eq!(replay_status, StatusCode::UNAUTHORIZED);
    let access_token = rotated_access_token;
    consumer_refresh_token = rotated_refresh_token;
    let (_, initial_history) = call(
        &app,
        Method::GET,
        "/v1/quota/history",
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(count_entry_type(&initial_history, "bootstrap_grant"), 1);
    let initial_bootstrap = initial_history
        .pointer("/entries")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.pointer("/entry_type").and_then(Value::as_str) == Some("bootstrap_grant")
            })
        })
        .expect("初始 history 应返回 bootstrap_grant 完整行");
    assert_history_entry_locally_recomputes(initial_bootstrap);
    let (second_access_token, _, repeated_consumer_id) = login(&app, &consumer_key).await;
    assert_eq!(consumer_user_id, repeated_consumer_id);
    let (_, second_history) = call(
        &app,
        Method::GET,
        "/v1/quota/history",
        None,
        Some(&second_access_token),
    )
    .await;
    assert_eq!(count_entry_type(&second_history, "bootstrap_grant"), 1);
    let (node_access_token, _, node_user_id) = login(&app, &node_key).await;
    assert_ne!(consumer_user_id, node_user_id);
    let (_, node_initial_history) = call(
        &app,
        Method::GET,
        "/v1/quota/history",
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        count_entry_type(&node_initial_history, "bootstrap_grant"),
        1
    );
    let node_user_uuid = Uuid::parse_str(&node_user_id).expect("节点用户 ID 必须是 UUID");
    let consumer_session_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(consumer_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能定位消费者设备绑定会话");
    let network = TrustedNetworkSignal::from_connection(
        Some(SocketAddr::from(([198, 51, 100, 7], 443))),
        &HeaderMap::new(),
        &anti_abuse_pepper,
        &NoAsnResolver,
        &std::collections::BTreeSet::new(),
    )
    .expect("服务端应能派生最小化网络信号")
    .expect("直接 peer 应产生网络信号");
    let assessment_key = format!("create-risk-{suffix}");
    let clean_decision = assess_before_create(
        &database_pool,
        &anti_abuse_pepper,
        consumer_uuid,
        consumer_session_id,
        &assessment_key,
        Some(&network),
        true,
    )
    .await
    .expect("干净的服务端信号应完成反滥用评估");
    assert!(clean_decision.allowed());
    let repeated_decision = assess_before_create(
        &database_pool,
        &anti_abuse_pepper,
        consumer_uuid,
        consumer_session_id,
        &assessment_key,
        Some(&network),
        true,
    )
    .await
    .expect("相同反滥用评估必须幂等");
    assert_eq!(repeated_decision, clean_decision);
    let node_session_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1",
    )
    .bind(node_user_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能定位节点账户设备绑定会话");
    let node_network = TrustedNetworkSignal::from_connection(
        Some(SocketAddr::from(([192, 0, 2, 9], 443))),
        &HeaderMap::new(),
        &anti_abuse_pepper,
        &NoAsnResolver,
        &std::collections::BTreeSet::new(),
    )
    .expect("服务端应能派生另一账户网络信号")
    .expect("直接 peer 应产生网络信号");
    let second_user_same_key = assess_before_create(
        &database_pool,
        &anti_abuse_pepper,
        node_user_uuid,
        node_session_id,
        &assessment_key,
        Some(&node_network),
        true,
    )
    .await
    .expect("不同账户必须能独立使用相同 assessment_key");
    assert!(second_user_same_key.allowed());
    let same_key_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT user_id)::bigint FROM abuse_decisions WHERE assessment_key=$1",
    )
    .bind(&assessment_key)
    .fetch_one(&database_pool)
    .await
    .expect("应能验证账户内幂等作用域");
    assert_eq!(same_key_users, 2);
    let changed_network = TrustedNetworkSignal::from_connection(
        Some(SocketAddr::from(([203, 0, 113, 7], 443))),
        &HeaderMap::new(),
        &anti_abuse_pepper,
        &NoAsnResolver,
        &std::collections::BTreeSet::new(),
    )
    .expect("服务端应能派生第二个网络信号")
    .expect("直接 peer 应产生网络信号");
    let conflicting_decision = assess_before_create(
        &database_pool,
        &anti_abuse_pepper,
        consumer_uuid,
        consumer_session_id,
        &assessment_key,
        Some(&changed_network),
        true,
    )
    .await;
    assert!(matches!(
        conflicting_decision,
        Err(AntiAbuseError::IdempotencyConflict)
    ));
    let missing_network_decision = assess_before_create(
        &database_pool,
        &anti_abuse_pepper,
        consumer_uuid,
        consumer_session_id,
        &format!("missing-network-{suffix}"),
        None,
        true,
    )
    .await
    .expect("缺失网络信号应形成可审计拒绝决定");
    assert!(!missing_network_decision.allowed());
    assert!(missing_network_decision
        .reason_codes
        .contains(&"missing_network_signal".to_owned()));
    let stored_network_hash: String = sqlx::query_scalar(
        "SELECT ip_prefix_hash FROM abuse_network_observations WHERE user_id=$1 ORDER BY observed_at DESC LIMIT 1",
    )
    .bind(consumer_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能读取最小化网络观察");
    assert_eq!(stored_network_hash.len(), 64);
    assert!(!stored_network_hash.contains("198.51.100"));

    let mut abuse_tx = database_pool.begin().await.expect("应开始调用图事务");
    for _ in 0..10 {
        record_settled_edge(
            &mut abuse_tx,
            consumer_uuid,
            node_user_uuid,
            TrafficClass::Normal,
        )
        .await
        .expect("应累计消费者到节点的调用边");
        record_settled_edge(
            &mut abuse_tx,
            node_user_uuid,
            consumer_uuid,
            TrafficClass::Normal,
        )
        .await
        .expect("应累计反向调用边");
    }
    let loop_weight = settlement_contribution_weight(
        &mut abuse_tx,
        consumer_uuid,
        node_user_uuid,
        TrafficClass::Normal,
    )
    .await
    .expect("应计算闭环调用权重");
    assert_eq!(loop_weight, 100_000);
    let verification_weight = settlement_contribution_weight(
        &mut abuse_tx,
        consumer_uuid,
        node_user_uuid,
        TrafficClass::Verification,
    )
    .await
    .expect("应计算测试流量权重");
    assert_eq!(verification_weight, 100_000);
    let self_dealing_weight = settlement_contribution_weight(
        &mut abuse_tx,
        consumer_uuid,
        consumer_uuid,
        TrafficClass::Normal,
    )
    .await
    .expect("应计算自成交权重");
    assert_eq!(self_dealing_weight, 0);
    abuse_tx
        .rollback()
        .await
        .expect("调用图权重夹具不应污染后续真实创建链路");

    let (_, node) = call(
        &app,
        Method::POST,
        "/v1/nodes/register",
        Some(json!({
            "alias": format!("node-{suffix}"),
            "hardware_profile": {
                "operating_system":"macos",
                "operating_system_version":"15",
                "architecture":"aarch64",
                "cpu_model":"Apple Silicon",
                "cpu_logical_cores":10,
                "ram_total_mib":32768,
                "gpus":[],
                "cuda_available":false,
                "metal_available":true,
                "sandbox_mechanisms":["seatbelt"]
            },
            "max_concurrent": 2,
            "gpu_temp_limit_c": 85,
            "vram_reserve_mib": 512
        })),
        Some(&node_access_token),
    )
    .await;
    let node_id = value_str(&node, "/node_id");
    assert_eq!(
        node.pointer("/trust_level").and_then(Value::as_str),
        Some("standard_limited")
    );
    let (_, authoritative_auth_status) = call(
        &app,
        Method::GET,
        "/v1/auth/status",
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        authoritative_auth_status
            .pointer("/user/id")
            .and_then(Value::as_str),
        Some(node_user_id.as_str())
    );
    assert_eq!(
        authoritative_auth_status
            .pointer("/trust_level")
            .and_then(Value::as_str),
        Some("unverified")
    );
    assert_eq!(
        authoritative_auth_status
            .pointer("/best_node_trust_level")
            .and_then(Value::as_str),
        Some("standard_limited")
    );
    assert_eq!(
        authoritative_auth_status
            .pointer("/registered_nodes")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(authoritative_auth_status
        .pointer("/device_key_fingerprint")
        .and_then(Value::as_str)
        .is_some());
    assert_eq!(
        authoritative_auth_status
            .pointer("/device_key_revoked")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(authoritative_auth_status
        .pointer("/logged_in_at")
        .is_some_and(|value| !value.is_null()));
    assert!(authoritative_auth_status
        .pointer("/last_used_at")
        .is_some_and(|value| !value.is_null()));
    let heartbeat_path = format!("/v1/nodes/{node_id}/heartbeat");
    let (heartbeat_status, _) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "tps_milli": 12000,
            "ttft_ms": 100,
            "current_concurrent": 0,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "error_rate_ppm": 0
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(heartbeat_status, StatusCode::OK);
    let legacy_coordinator_rtt_ms: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT coordinator_rtt_ms FROM node_metrics
        WHERE node_id = $1 ORDER BY measured_at DESC, id DESC LIMIT 1
        "#,
    )
    .bind(parse_uuid(&node_id, "旧版心跳节点"))
    .fetch_one(&database_pool)
    .await
    .expect("旧版心跳应写入 NULL coordinator RTT");
    assert_eq!(legacy_coordinator_rtt_ms, None);

    let (rtt_heartbeat_status, _) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "tps_milli": 12000,
            "ttft_ms": 100,
            "current_concurrent": 0,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "error_rate_ppm": 0,
            "coordinator_rtt_ms": 37
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(rtt_heartbeat_status, StatusCode::OK);
    let stored_coordinator_rtt_ms: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT coordinator_rtt_ms FROM node_metrics
        WHERE node_id = $1 ORDER BY measured_at DESC, id DESC LIMIT 1
        "#,
    )
    .bind(parse_uuid(&node_id, "RTT 心跳节点"))
    .fetch_one(&database_pool)
    .await
    .expect("应读取客户端实测 coordinator RTT");
    assert_eq!(stored_coordinator_rtt_ms, Some(37));
    let (_, rtt_stats) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        rtt_stats
            .pointer("/metrics/coordinator_rtt_ms")
            .and_then(Value::as_i64),
        Some(37)
    );
    let metrics_before_invalid_rtt: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM node_metrics WHERE node_id=$1")
            .bind(parse_uuid(&node_id, "RTT 零写入节点"))
            .fetch_one(&database_pool)
            .await
            .expect("应读取非法 RTT 前的指标数量");
    let (zero_rtt_status, _) = call_unchecked(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({"coordinator_rtt_ms": 0})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(zero_rtt_status, StatusCode::BAD_REQUEST);
    let metrics_after_invalid_rtt: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM node_metrics WHERE node_id=$1")
            .bind(parse_uuid(&node_id, "RTT 零写入节点"))
            .fetch_one(&database_pool)
            .await
            .expect("应读取非法 RTT 后的指标数量");
    assert_eq!(
        metrics_after_invalid_rtt, metrics_before_invalid_rtt,
        "协议拒绝的 coordinator RTT 不得写入任何指标行"
    );
    let invalid_rtt_insert =
        sqlx::query("INSERT INTO node_metrics (id,node_id,coordinator_rtt_ms) VALUES ($1,$2,0)")
            .bind(Uuid::now_v7())
            .bind(parse_uuid(&node_id, "RTT 约束节点"))
            .execute(&database_pool)
            .await;
    assert!(
        invalid_rtt_insert.is_err(),
        "数据库约束必须独立拒绝零毫秒 coordinator RTT"
    );
    for (temperature, expected_status) in [(90, "paused"), (82, "paused"), (80, "online")] {
        let (_, heartbeat) = call(
            &app,
            Method::POST,
            &heartbeat_path,
            Some(json!({
                "tps_milli": 12000,
                "ttft_ms": 100,
                "current_concurrent": 0,
                "gpu_temp_c": temperature,
                "vram_used_mib": 1024,
                "vram_total_mib": 8192,
                "error_rate_ppm": 0
            })),
            Some(&node_access_token),
        )
        .await;
        assert_eq!(
            heartbeat.pointer("/status").and_then(Value::as_str),
            Some(expected_status),
            "温度 {temperature}°C 的节点状态不符合 5°C 滞回规则"
        );
    }
    let (_, recovered_node) = call(
        &app,
        Method::POST,
        "/v1/nodes/register",
        Some(json!({
            "alias": format!("node-{suffix}"),
            "hardware_profile": {
                "operating_system":"macos",
                "operating_system_version":"15",
                "architecture":"aarch64",
                "cpu_model":"Apple Silicon",
                "cpu_logical_cores":10,
                "ram_total_mib":32768,
                "gpus":[],
                "cuda_available":false,
                "metal_available":true,
                "sandbox_mechanisms":["seatbelt"],
                "restart":true
            },
            "max_concurrent": 1,
            "gpu_temp_limit_c": 85,
            "vram_reserve_mib": 512
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_str(&recovered_node, "/node_id"), node_id);
    let (_, sensorless_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "tps_milli": 12000,
            "ttft_ms": 100,
            "current_concurrent": 0,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "error_rate_ppm": 0
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        sensorless_heartbeat
            .pointer("/status")
            .and_then(Value::as_str),
        Some("paused")
    );
    assert_eq!(
        sensorless_heartbeat
            .pointer("/pause_reason")
            .and_then(Value::as_str),
        Some("gpu_temperature_limit")
    );
    let (_, recovered_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "tps_milli": 12000,
            "ttft_ms": 100,
            "current_concurrent": 0,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "error_rate_ppm": 0
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        recovered_heartbeat
            .pointer("/status")
            .and_then(Value::as_str),
        Some("online")
    );

    let (self_rated_status, self_rated_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("self-rated-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "benchmark_normalized": 1000000,
            "glicko_normalized": 1000000,
            "evaluation_samples": 1000,
            "base_cost_per_1k_micro": 1_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(self_rated_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        self_rated_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("client_quality_forbidden")
    );

    let (_, model) = call(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("instance-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "benchmark_normalized": 0,
            "glicko_normalized": 0,
            "evaluation_samples": 0,
            "base_cost_per_1k_micro": 1_000_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    let model_id = value_str(&model, "/model_id");
    let model_instance_id = value_str(&model, "/model_instance_id");
    assert_eq!(
        model.pointer("/tier").and_then(Value::as_str),
        Some("medium")
    );
    let model_uuid = Uuid::parse_str(&model_id).expect("模型 ID 必须是 UUID");
    let (legacy_evaluation_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/evaluations/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(legacy_evaluation_status, StatusCode::NOT_FOUND);
    let challenge_plaintext_columns: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM information_schema.columns
        WHERE table_schema='public' AND table_name IN
            ('model_evaluation_challenges','model_evaluation_challenge_events')
          AND column_name IN ('prompt','output','response','expected_answer')
        "#,
    )
    .fetch_one(&database_pool)
    .await
    .expect("应能检查评价表最小化字段");
    assert_eq!(challenge_plaintext_columns, 0);

    let quality_parent = fs::canonicalize(env::current_dir().expect("应读取当前工作目录"))
        .expect("当前工作目录应可规范化");
    let quality_temp = tempfile::Builder::new()
        .prefix(".mindone-quality-integration-")
        .tempdir_in(quality_parent)
        .expect("应在受控目录创建 quality evidence 临时目录");
    let quality_root = fs::canonicalize(quality_temp.path()).expect("quality 临时目录应可规范化");
    let quality_keys = quality_root.join("trusted-keys");
    fs::create_dir(&quality_keys).expect("应创建受信 evaluator key 目录");
    let evaluator_id = "integration-evaluator-1";
    let evaluator_signing_key = SigningKey::from_bytes(&[42_u8; 32]);
    fs::write(
        quality_keys.join(format!("{evaluator_id}.pub")),
        hex::encode(evaluator_signing_key.verifying_key().to_bytes()),
    )
    .expect("应写入受信 evaluator 公钥");
    let benchmark_idempotency = format!("hidden-benchmark-{suffix}");
    let benchmark_request = signed_quality_request(
        &quality_root,
        &quality_keys,
        &evaluator_signing_key,
        evaluator_id,
        model_uuid,
        benchmark_idempotency.clone(),
        QualityEvidenceMeasurement::HiddenBenchmark {
            score_normalized: 700_000,
            sample_count: 30,
        },
    );
    let benchmark_result = record_operator_quality_evidence(&database_pool, &benchmark_request)
        .await
        .expect("签名且 artifact 匹配的 benchmark 应更新质量状态");
    assert!(!benchmark_result.idempotent_replay);
    let benchmark_update = benchmark_result.quality.clone();
    assert!(benchmark_update.cold_start);
    assert_eq!(benchmark_update.tier, "medium");
    let duplicate_benchmark = record_operator_quality_evidence(&database_pool, &benchmark_request)
        .await
        .expect("相同签名评价重试必须幂等");
    assert!(duplicate_benchmark.idempotent_replay);
    assert_eq!(duplicate_benchmark.quality, benchmark_update);
    assert_eq!(
        duplicate_benchmark.evidence_audit_id,
        benchmark_result.evidence_audit_id
    );
    let conflicting_request = signed_quality_request(
        &quality_root,
        &quality_keys,
        &evaluator_signing_key,
        evaluator_id,
        model_uuid,
        benchmark_idempotency.clone(),
        QualityEvidenceMeasurement::HiddenBenchmark {
            score_normalized: 700_001,
            sample_count: 30,
        },
    );
    let conflicting_benchmark =
        record_operator_quality_evidence(&database_pool, &conflicting_request).await;
    assert!(matches!(
        conflicting_benchmark,
        Err(OperatorQualityError::Quality(
            QualityGovernanceError::IdempotencyConflict
        ))
    ));
    let invalid_signature_idempotency = format!("invalid-signature-{suffix}");
    let invalid_signature_request = signed_quality_request(
        &quality_root,
        &quality_keys,
        &evaluator_signing_key,
        evaluator_id,
        model_uuid,
        invalid_signature_idempotency.clone(),
        QualityEvidenceMeasurement::Canary { passed: true },
    );
    let mut invalid_envelope: SignedQualityEvidence = serde_json::from_slice(
        &fs::read(&invalid_signature_request.evidence_path).expect("应读取待篡改 evidence"),
    )
    .expect("测试 evidence 应可解析");
    let replacement = if invalid_envelope.signature.starts_with("00") {
        "ff"
    } else {
        "00"
    };
    invalid_envelope.signature.replace_range(0..2, replacement);
    fs::write(
        &invalid_signature_request.evidence_path,
        serde_json::to_vec(&invalid_envelope).expect("应编码篡改 evidence"),
    )
    .expect("应写入篡改 evidence");
    assert!(matches!(
        record_operator_quality_evidence(&database_pool, &invalid_signature_request).await,
        Err(OperatorQualityError::SignatureInvalid)
    ));
    let invalid_event_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM model_quality_events WHERE idempotency_key=$1)",
    )
    .bind(&invalid_signature_idempotency)
    .fetch_one(&database_pool)
    .await
    .expect("应检查无签名事件未落库");
    assert!(!invalid_event_exists);
    assert_eq!(benchmark_update.benchmark_samples, 30);
    let mut final_quality = benchmark_update;
    for sample_index in 0..20 {
        let blind_request = signed_quality_request(
            &quality_root,
            &quality_keys,
            &evaluator_signing_key,
            evaluator_id,
            model_uuid,
            format!("blind-{suffix}-{sample_index}"),
            QualityEvidenceMeasurement::BlindEvaluation {
                opponent_rating_milli: 1_500_000,
                opponent_deviation_milli: 100_000,
                outcome: Glicko2Score::Draw,
            },
        );
        final_quality = record_operator_quality_evidence(&database_pool, &blind_request)
            .await
            .expect("受信签名盲测应执行 Glicko-2 更新")
            .quality;
    }
    assert!(!final_quality.cold_start);
    assert_eq!(final_quality.evaluation_samples, 20);
    assert_eq!(final_quality.tier, "medium");
    let quality_event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM model_quality_events WHERE model_id=$1")
            .bind(model_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("应能审计模型质量事件");
    assert_eq!(quality_event_count, 21);
    let signed_evidence_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM quality_evidence_audits WHERE model_id=$1",
    )
    .bind(model_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能审计签名质量 evidence");
    assert_eq!(signed_evidence_count, 21);
    let audit_event_id: Uuid =
        sqlx::query_scalar("SELECT id FROM model_quality_events WHERE idempotency_key=$1")
            .bind(format!("hidden-benchmark-{suffix}"))
            .fetch_one(&database_pool)
            .await
            .expect("应能定位 benchmark 审计事件");
    let audit_mutation = sqlx::query("DELETE FROM model_quality_events WHERE id=$1")
        .bind(audit_event_id)
        .execute(&database_pool)
        .await;
    assert!(audit_mutation.is_err(), "质量审计事件必须只追加");
    let evidence_audit_mutation = sqlx::query(
        "UPDATE quality_evidence_audits SET reason='不应修改' WHERE quality_event_id=$1",
    )
    .bind(audit_event_id)
    .execute(&database_pool)
    .await;
    assert!(
        evidence_audit_mutation.is_err(),
        "签名 evidence 审计必须只追加"
    );

    let peer_model_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO models
            (id,owner_user_id,name,format,weights_hash,size_bytes,context_length,
             benchmark_normalized,glicko_normalized,evaluation_samples,tier,
             base_cost_per_1k_micro,benchmark_samples,glicko_rating_milli,
             glicko_deviation_milli,glicko_volatility_nano,
             quality_fusion_normalized,quality_policy_version,quality_updated_at)
        SELECT $2,owner_user_id,name,format,$3,size_bytes,context_length,
               790000,780000,20,'medium',base_cost_per_1k_micro,100,1780000,
               100000,60000000,785000,1,now()
        FROM models WHERE id=$1
        "#,
    )
    .bind(model_uuid)
    .bind(peer_model_id)
    .bind("1".repeat(64))
    .execute(&database_pool)
    .await
    .expect("应创建同名 peer 模型以验证全 cohort Tier 重算");
    let cohort_request = signed_quality_request(
        &quality_root,
        &quality_keys,
        &evaluator_signing_key,
        evaluator_id,
        model_uuid,
        format!("cohort-recompute-{suffix}"),
        QualityEvidenceMeasurement::Canary { passed: true },
    );
    let cohort_result = record_operator_quality_evidence(&database_pool, &cohort_request)
        .await
        .expect("目标模型事件应重算同名 cohort 的全部 Tier");
    let peer_tier: String = sqlx::query_scalar("SELECT tier FROM models WHERE id=$1")
        .bind(peer_model_id)
        .fetch_one(&database_pool)
        .await
        .expect("应读取 peer Tier");
    assert_eq!(peer_tier, "high");
    let transition = sqlx::query(
        r#"
        SELECT old_tier,new_tier,cohort_size,fusion_normalized,
               percentile_millionths,cohort_commitment
        FROM model_tier_transition_events
        WHERE source_quality_event_id=$1 AND model_id=$2
        "#,
    )
    .bind(cohort_result.quality.event_id)
    .bind(peer_model_id)
    .fetch_one(&database_pool)
    .await
    .expect("peer Tier 变化必须追加源事件绑定审计");
    assert_eq!(transition.get::<String, _>("old_tier"), "medium");
    assert_eq!(transition.get::<String, _>("new_tier"), "high");
    assert_eq!(transition.get::<i32, _>("cohort_size"), 2);
    assert_eq!(transition.get::<i32, _>("fusion_normalized"), 785_000);
    assert_eq!(transition.get::<i32, _>("percentile_millionths"), 1_000_000);
    assert_eq!(transition.get::<String, _>("cohort_commitment").len(), 64);
    let transition_mutation = sqlx::query(
        "UPDATE model_tier_transition_events SET new_tier='low' WHERE source_quality_event_id=$1 AND model_id=$2",
    )
    .bind(cohort_result.quality.event_id)
    .bind(peer_model_id)
    .execute(&database_pool)
    .await;
    assert!(transition_mutation.is_err(), "Tier 转换审计必须只追加");
    sqlx::query("UPDATE models SET enabled=FALSE,updated_at=now() WHERE id=$1")
        .bind(peer_model_id)
        .execute(&database_pool)
        .await
        .expect("定向 cohort 测试后应停用无实例 peer，避免影响后续路由场景");

    let durable_request = signed_quality_request_with_validity(
        &quality_root,
        &quality_keys,
        &evaluator_signing_key,
        evaluator_id,
        model_uuid,
        format!("durable-replay-{suffix}"),
        QualityEvidenceMeasurement::Canary { passed: false },
        Duration::seconds(5),
    );
    let durable_result = record_operator_quality_evidence(&database_pool, &durable_request)
        .await
        .expect("短期签名 evidence 首次提交时应有效");
    let durable_envelope: SignedQualityEvidence = serde_json::from_slice(
        &fs::read(&durable_request.evidence_path).expect("应读取 durable replay evidence"),
    )
    .expect("durable replay evidence 应可解析");
    let durable_expiry = OffsetDateTime::parse(&durable_envelope.statement.valid_until, &Rfc3339)
        .expect("durable replay 有效期应可解析");
    let rotated_key = SigningKey::from_bytes(&[43_u8; 32]);
    fs::write(
        quality_keys.join(format!("{evaluator_id}.pub")),
        hex::encode(rotated_key.verifying_key().to_bytes()),
    )
    .expect("应模拟 evaluator 公钥轮换");
    let wait_millis = (durable_expiry - OffsetDateTime::now_utc())
        .whole_milliseconds()
        .max(0)
        + 100;
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from(wait_millis).expect("测试等待时长应可表示"),
    ))
    .await;
    assert!(OffsetDateTime::now_utc() >= durable_expiry);
    let durable_replay = record_operator_quality_evidence(&database_pool, &durable_request)
        .await
        .expect("已提交的精确 evidence 在过期和公钥轮换后仍应幂等重放");
    assert!(durable_replay.idempotent_replay);
    assert_eq!(durable_replay.quality, durable_result.quality);
    assert_eq!(
        durable_replay.evidence_audit_id,
        durable_result.evidence_audit_id
    );

    let invalid_payload_key = format!("create-invalid-payload-{suffix}");
    let mut invalid_payload = standard_job_body(
        &format!("model-{suffix}"),
        &["test"],
        &invalid_payload_key,
        10,
    );
    invalid_payload["encrypted_payload"] = Value::String("%%%".to_owned());
    let (invalid_payload_status, invalid_payload_response) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(invalid_payload),
        Some(&access_token),
    )
    .await;
    assert_eq!(invalid_payload_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_payload_response
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("invalid_standard_payload")
    );

    let underauthorized_key = format!("create-underauthorized-{suffix}");
    let mut underauthorized = standard_job_body(
        &format!("model-{suffix}"),
        &["test"],
        &underauthorized_key,
        10,
    );
    underauthorized["estimated_input_tokens"] = Value::from(1);
    let (underauthorized_status, underauthorized_response) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(underauthorized),
        Some(&access_token),
    )
    .await;
    assert_eq!(underauthorized_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        underauthorized_response
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("usage_authorization_too_small")
    );

    let create_key = format!("create-{suffix}");
    let create_body = standard_job_body(&format!("model-{suffix}"), &["test"], &create_key, 10);
    let typed_create: mindone_protocol::CreateJobRequest =
        serde_json::from_value(create_body.clone()).expect("测试创建请求应符合协议");
    let mut legacy_fingerprint_digest = Sha256::new();
    legacy_fingerprint_digest.update(b"MindOne Standard create idempotency fingerprint v1\0");
    legacy_fingerprint_digest
        .update(serde_json::to_vec(&typed_create).expect("应能编码测试创建请求用于 legacy 指纹"));
    let legacy_create_fingerprint = hex::encode(legacy_fingerprint_digest.finalize());
    let wire_payload = create_body["encrypted_payload"]
        .as_str()
        .expect("测试 Standard payload 应为字符串")
        .to_owned();
    let (_, created) = call(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(create_body.clone()),
        Some(&access_token),
    )
    .await;
    let job_id = value_str(&created, "/job_id");
    let stored_create = sqlx::query(
        "SELECT encrypted_payload,standard_payload_storage_version,standard_request_fingerprint FROM jobs WHERE id=$1",
    )
    .bind(parse_uuid(&job_id, "Standard job"))
    .fetch_one(&database_pool)
    .await
    .expect("应能检查 Standard payload 静态保护");
    let stored_payload: String = stored_create.get("encrypted_payload");
    assert!(stored_payload.starts_with(ENVELOPE_PREFIX));
    assert_ne!(stored_payload, wire_payload);
    assert_eq!(
        stored_create.get::<i16, _>("standard_payload_storage_version"),
        1
    );
    assert!(stored_create
        .get::<String, _>("standard_request_fingerprint")
        .starts_with("mindone-standard-hmac-v1:"));
    let (_, replayed_create) = call(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(create_body.clone()),
        Some(&access_token),
    )
    .await;
    assert_eq!(value_str(&replayed_create, "/job_id"), job_id);
    assert_eq!(
        replayed_create
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let reserved_after_create: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(consumer_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("应能读取 Standard 创建后的 reservation");
    let mut altered_create = create_body.clone();
    altered_create["tags"] = json!(["altered"]);
    let (altered_create_status, altered_create_response) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(altered_create),
        Some(&access_token),
    )
    .await;
    assert_eq!(altered_create_status, StatusCode::CONFLICT);
    assert_eq!(
        altered_create_response
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );
    let create_job_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM jobs WHERE user_id=$1 AND idempotency_key=$2",
    )
    .bind(consumer_uuid)
    .bind(&create_key)
    .fetch_one(&database_pool)
    .await
    .expect("同一 Standard 幂等键只能创建一个任务");
    assert_eq!(create_job_count, 1);
    let reserved_after_conflict: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(consumer_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("应能读取冲突后的 reservation");
    assert_eq!(reserved_after_conflict, reserved_after_create);
    let (_, claimed) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_str(&claimed, "/job_id"), job_id);
    assert_eq!(value_str(&claimed, "/encrypted_payload"), wire_payload);
    let capacity_probe_job_id = Uuid::now_v7();
    let capacity_probe_payload = encrypt_for_storage(
        &standard_data_key,
        capacity_probe_job_id,
        StorageDirection::Payload,
        b"e30=",
    )
    .expect("应能构造受保护的容量探测 payload");
    let capacity_model_id = Uuid::parse_str(&model_id).expect("模型 ID 必须是 UUID");
    let capacity_billing =
        load_test_billing_snapshot(&database_pool, capacity_model_id, 1, 1).await;
    let capacity_insert = sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             tags,estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             priority,max_attempts,standard_request_fingerprint,
             standard_payload_storage_version,
             billing_contract_version,billing_profile_id,billing_profile_version,
             billing_profile_fingerprint,billing_model_weights_hash,
             billing_reference_hardware_class,billing_profile_evidence_hash,
             billing_profile_valid_from,billing_profile_valid_until,
             billing_profile_max_input_tokens,billing_profile_max_output_tokens,
             billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
             billing_reference_vram_mib,billing_token_rate_micro_per_1k,
             billing_gpu_rate_micro_per_second,
             billing_vram_rate_micro_per_gib_second,
             billing_authorized_input_tokens,billing_authorized_max_output_tokens,
             billing_billable_tokens,billing_reference_gpu_time_us,
             billing_reference_vram_mib_microseconds,billing_token_cost_micro,
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        VALUES ($1,$2,$3,$4,$5,'base64','{}',1,1,$7,0,3,$6,1,
                $8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
                $23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33)
        "#,
    )
    .bind(capacity_probe_job_id)
    .bind(Uuid::parse_str(&consumer_user_id).expect("消费者 ID 必须是 UUID"))
    .bind(capacity_model_id)
    .bind(format!("capacity-probe-{suffix}"))
    .bind(capacity_probe_payload)
    .bind(format!("mindone-standard-hmac-v1:{}", "0".repeat(64)))
    .bind(capacity_billing.reservation_micro);
    bind_test_billing_snapshot!(capacity_insert, capacity_billing)
        .execute(&database_pool)
        .await
        .expect("应插入仅用于路由容量测试的排队任务");
    let (_, capacity_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 1,
                "gpu_temp_limit_c": 85,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        capacity_heartbeat
            .pointer("/status")
            .and_then(Value::as_str),
        Some("paused")
    );
    assert_eq!(
        capacity_heartbeat
            .pointer("/pause_reason")
            .and_then(Value::as_str),
        Some("max_concurrent")
    );
    let renew_path = format!("/v1/jobs/{job_id}/renew");
    let (renew_status, _) = call(
        &app,
        Method::POST,
        &renew_path,
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(renew_status, StatusCode::OK);
    let (capacity_claim_status, capacity_claim) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(capacity_claim_status, StatusCode::FORBIDDEN);
    assert_eq!(
        capacity_claim.pointer("/code").and_then(Value::as_i64),
        Some(50)
    );
    let _ = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "gpu_temp_c": 90,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 1,
                "gpu_temp_limit_c": 85,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    let (hot_renew_status, hot_renew) = call_unchecked(
        &app,
        Method::POST,
        &renew_path,
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(hot_renew_status, StatusCode::FORBIDDEN);
    assert_eq!(hot_renew.pointer("/code").and_then(Value::as_i64), Some(50));
    let _ = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 1,
                "gpu_temp_limit_c": 85,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    let unpublish_path = format!("/v1/models/{model_instance_id}");
    let (_, draining) = call(
        &app,
        Method::DELETE,
        &unpublish_path,
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    assert_eq!(
        draining.pointer("/active_jobs").and_then(Value::as_i64),
        Some(1)
    );
    let (_, draining_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "gpu_temp_c": 50,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "draining": true,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 1,
                "gpu_temp_limit_c": 85,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        draining_heartbeat
            .pointer("/status")
            .and_then(Value::as_str),
        Some("draining")
    );
    let (draining_renew_status, _) = call(
        &app,
        Method::POST,
        &renew_path,
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(draining_renew_status, StatusCode::OK);
    let (draining_claim_status, draining_claim) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(draining_claim_status, StatusCode::FORBIDDEN);
    assert_eq!(
        draining_claim.pointer("/code").and_then(Value::as_i64),
        Some(50)
    );
    sqlx::query("DELETE FROM jobs WHERE id = $1")
        .bind(capacity_probe_job_id)
        .execute(&database_pool)
        .await
        .expect("应清理容量路由测试任务");
    let result_path = format!("/v1/jobs/{job_id}/result");
    let (invalid_result_status, invalid_result) = call_unchecked(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": "x".repeat(201),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 10, 5),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(invalid_result_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_result
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("invalid_job_result")
    );
    let (usage_mismatch_status, usage_mismatch) = call_unchecked(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("usage-mismatch-{suffix}"),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 9, 5),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(usage_mismatch_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        usage_mismatch
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("usage_binding_mismatch")
    );
    let status_after_usage_mismatch: String =
        sqlx::query_scalar("SELECT status FROM jobs WHERE id=$1")
            .bind(parse_uuid(&job_id, "Standard job"))
            .fetch_one(&database_pool)
            .await
            .expect("usage 不一致不得改变任务状态");
    assert_eq!(status_after_usage_mismatch, "leased");
    let premature_receipts: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM receipts WHERE job_id=$1")
            .bind(parse_uuid(&job_id, "Standard job"))
            .fetch_one(&database_pool)
            .await
            .expect("usage 不一致不得生成账单");
    assert_eq!(premature_receipts, 0);
    let wire_result = standard_result_ciphertext(&format!("model-{suffix}"), 10, 5);
    let (result_status, settled) = call(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("result-{suffix}"),
            "result_ciphertext": wire_result.clone(),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(result_status, StatusCode::OK);
    let settled_job_uuid = parse_uuid(&job_id, "Standard job");
    let stored_result = sqlx::query(
        "SELECT result_ciphertext,standard_result_storage_version FROM jobs WHERE id=$1",
    )
    .bind(settled_job_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能检查 Standard result 静态保护");
    let stored_result_ciphertext: String = stored_result.get("result_ciphertext");
    assert!(stored_result_ciphertext.starts_with(ENVELOPE_PREFIX));
    assert_ne!(stored_result_ciphertext, wire_result);
    assert_eq!(
        stored_result.get::<i16, _>("standard_result_storage_version"),
        1
    );
    let telemetry_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM job_execution_telemetry WHERE job_id=$1")
            .bind(settled_job_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("结算事务必须原子追加一条任务指纹");
    assert_eq!(telemetry_count, 1);
    let telemetry_evidence_kind: String =
        sqlx::query_scalar("SELECT evidence_kind FROM job_execution_telemetry WHERE job_id=$1")
            .bind(settled_job_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("Standard 任务必须保留自报风险信号边界");
    assert_eq!(
        telemetry_evidence_kind,
        "standard_self_reported_risk_signal"
    );
    let anomaly_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM execution_anomaly_ledger WHERE job_id=$1")
            .bind(settled_job_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("严重显存规模偏差必须写入异常账本");
    assert!(anomaly_count >= 1);
    assert_eq!(
        settled.pointer("/status").and_then(Value::as_str),
        Some("succeeded")
    );
    assert!(settled.pointer("/receipt_id").is_none());
    assert!(settled.pointer("/reserve_micro").is_none());
    let finalized_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id = $1")
            .bind(Uuid::parse_str(&model_instance_id).expect("模型实例 ID 必须是 UUID"))
            .fetch_one(&database_pool)
            .await
            .expect("应能读取自动收尾后的模型实例");
    assert_eq!(finalized_status, "unpublished");
    let (replay_status, replayed) = call(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 10, 5),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(
        replayed
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let telemetry_count_after_replay: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM job_execution_telemetry WHERE job_id=$1")
            .bind(settled_job_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("幂等重放后应仍只有一个任务指纹");
    let anomaly_count_after_replay: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM execution_anomaly_ledger WHERE job_id=$1")
            .bind(settled_job_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("幂等重放后异常账本不得重复");
    assert_eq!(telemetry_count_after_replay, 1);
    assert_eq!(anomaly_count_after_replay, anomaly_count);
    let (altered_telemetry_status, altered_telemetry) = call_unchecked(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 10, 5),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": {
                "ttft_ms": 101,
                "tps_milli": 10_000,
                "peak_vram_mib": 1,
                "vram_sample_count": 4
            }
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(altered_telemetry_status, StatusCode::CONFLICT);
    assert_eq!(
        altered_telemetry
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );
    let (altered_result_replay_status, altered_result_replay) = call_unchecked(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 10, 4),
            "actual_input_tokens": 10,
            "actual_output_tokens": 4,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(altered_result_replay_status, StatusCode::CONFLICT);
    assert_eq!(
        altered_result_replay
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );
    let settled_edge_count: i64 = sqlx::query_scalar(
        "SELECT normal_requests FROM abuse_call_edges WHERE consumer_user_id=$1 AND node_user_id=$2",
    )
    .bind(consumer_uuid)
    .bind(node_user_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("成功结算应记录一次最小化调用边");
    assert_eq!(settled_edge_count, 1, "结果回放不得重复累计调用边");
    let (_, completed_job) = call(
        &app,
        Method::GET,
        &format!("/v1/jobs/{job_id}"),
        None,
        Some(&access_token),
    )
    .await;
    let receipt_id = value_str(&completed_job, "/receipt_id");
    assert_eq!(value_str(&completed_job, "/result_ciphertext"), wire_result);
    let mut legacy_tx = database_pool
        .begin()
        .await
        .expect("应能开始 legacy Standard 回填夹具事务");
    sqlx::query("ALTER TABLE jobs DISABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(&mut *legacy_tx)
        .await
        .expect("测试夹具应能暂时关闭 Standard 新写门禁");
    sqlx::query(
        r#"
        UPDATE jobs
        SET encrypted_payload=$2,standard_payload_storage_version=0,
            result_ciphertext=$3,standard_result_storage_version=0,
            standard_request_fingerprint=$4
        WHERE id=$1
        "#,
    )
    .bind(settled_job_uuid)
    .bind(&wire_payload)
    .bind(&wire_result)
    .bind(&legacy_create_fingerprint)
    .execute(&mut *legacy_tx)
    .await
    .expect("应能构造真实 legacy Standard 行");
    sqlx::query("ALTER TABLE jobs ENABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(&mut *legacy_tx)
        .await
        .expect("测试夹具必须恢复 Standard 新写门禁");
    legacy_tx
        .commit()
        .await
        .expect("应能提交 legacy Standard 回填夹具");
    migrate(&database_pool, &standard_data_key)
        .await
        .expect("第二次启动应分批回填 legacy Standard 行");
    let migrated_storage = sqlx::query(
        "SELECT encrypted_payload,result_ciphertext,standard_payload_storage_version,standard_result_storage_version,standard_request_fingerprint FROM jobs WHERE id=$1",
    )
    .bind(settled_job_uuid)
    .fetch_one(&database_pool)
    .await
    .expect("应能检查 legacy Standard 回填结果");
    assert!(migrated_storage
        .get::<String, _>("encrypted_payload")
        .starts_with(ENVELOPE_PREFIX));
    assert!(migrated_storage
        .get::<String, _>("result_ciphertext")
        .starts_with(ENVELOPE_PREFIX));
    assert_eq!(
        migrated_storage.get::<i16, _>("standard_payload_storage_version"),
        1
    );
    assert_eq!(
        migrated_storage.get::<i16, _>("standard_result_storage_version"),
        1
    );
    assert!(migrated_storage
        .get::<String, _>("standard_request_fingerprint")
        .starts_with("mindone-standard-hmac-v1:"));
    assert!(
        sqlx::query("UPDATE jobs SET standard_request_fingerprint=NULL WHERE id=$1")
            .bind(settled_job_uuid)
            .execute(&database_pool)
            .await
            .is_err(),
        "Standard fingerprint 的 NULL 不得借 CHECK UNKNOWN 绕过触发器"
    );
    assert!(
        sqlx::query("UPDATE jobs SET standard_payload_storage_version=NULL WHERE id=$1")
            .bind(settled_job_uuid)
            .execute(&database_pool)
            .await
            .is_err(),
        "Standard payload version 的 NULL 不得借三值逻辑绕过触发器"
    );
    assert!(
        sqlx::query("UPDATE jobs SET standard_result_storage_version=NULL WHERE id=$1")
            .bind(settled_job_uuid)
            .execute(&database_pool)
            .await
            .is_err(),
        "非空 Standard result 的 NULL version 不得借三值逻辑绕过触发器"
    );
    let (_, migrated_replay) = call(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(create_body.clone()),
        Some(&access_token),
    )
    .await;
    assert_eq!(value_str(&migrated_replay, "/job_id"), job_id);
    assert_eq!(
        migrated_replay
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );

    let mut rollback_fixture_ids = [Uuid::new_v4(), Uuid::new_v4()];
    rollback_fixture_ids.sort_unstable();
    let migratable_job_id = rollback_fixture_ids[0];
    let null_fingerprint_job_id = rollback_fixture_ids[1];
    let rollback_model_id = Uuid::parse_str(&model_id).expect("模型 ID 必须是 UUID");
    let rollback_billing =
        load_test_billing_snapshot(&database_pool, rollback_model_id, 1, 1).await;
    assert!(migratable_job_id < null_fingerprint_job_id);
    let mut null_fingerprint_tx = database_pool
        .begin()
        .await
        .expect("应能开始 NULL fingerprint 升级夹具事务");
    sqlx::query("ALTER TABLE jobs DISABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(&mut *null_fingerprint_tx)
        .await
        .expect("测试夹具应能暂时关闭 Standard 新写门禁");
    let rollback_insert = sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             tags,estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             priority,max_attempts,standard_request_fingerprint,
             standard_payload_storage_version,
             billing_contract_version,billing_profile_id,billing_profile_version,
             billing_profile_fingerprint,billing_model_weights_hash,
             billing_reference_hardware_class,billing_profile_evidence_hash,
             billing_profile_valid_from,billing_profile_valid_until,
             billing_profile_max_input_tokens,billing_profile_max_output_tokens,
             billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
             billing_reference_vram_mib,billing_token_rate_micro_per_1k,
             billing_gpu_rate_micro_per_second,
             billing_vram_rate_micro_per_gib_second,
             billing_authorized_input_tokens,billing_authorized_max_output_tokens,
             billing_billable_tokens,billing_reference_gpu_time_us,
             billing_reference_vram_mib_microseconds,billing_token_cost_micro,
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        VALUES
            ($1,$3,$4,$5,$7,'base64','{}',1,1,$9,0,3,$8,0,
             $10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,
             $25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35),
            ($2,$3,$4,$6,$7,'base64','{}',1,1,$9,0,3,NULL,0,
             $10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,
             $25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)
        "#,
    )
    .bind(migratable_job_id)
    .bind(null_fingerprint_job_id)
    .bind(consumer_uuid)
    .bind(rollback_model_id)
    .bind(format!("rollback-migratable-{suffix}"))
    .bind(format!("rollback-null-fingerprint-{suffix}"))
    .bind(&wire_payload)
    .bind(&legacy_create_fingerprint)
    .bind(rollback_billing.reservation_micro);
    bind_test_billing_snapshot!(rollback_insert, rollback_billing)
        .execute(&mut *null_fingerprint_tx)
        .await
        .expect("应构造一行可迁移及一行不可重建指纹的 legacy Standard 数据");
    sqlx::query("ALTER TABLE jobs ENABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(&mut *null_fingerprint_tx)
        .await
        .expect("测试夹具必须恢复 Standard 新写门禁");
    null_fingerprint_tx
        .commit()
        .await
        .expect("应提交 NULL fingerprint 升级夹具");

    let null_fingerprint_error = migrate(&database_pool, &standard_data_key)
        .await
        .expect_err("legacy NULL fingerprint 必须令监听前升级失败");
    assert!(matches!(
        null_fingerprint_error,
        StandardDataMigrationError::Protection(_)
    ));
    let rollback_rows = sqlx::query(
        r#"
        SELECT id,encrypted_payload,standard_payload_storage_version,
               standard_request_fingerprint
        FROM jobs WHERE id IN ($1,$2) ORDER BY id
        "#,
    )
    .bind(migratable_job_id)
    .bind(null_fingerprint_job_id)
    .fetch_all(&database_pool)
    .await
    .expect("失败升级后应能复核整批 legacy 行");
    assert_eq!(rollback_rows.len(), 2);
    assert_eq!(rollback_rows[0].get::<Uuid, _>("id"), migratable_job_id);
    assert_eq!(
        rollback_rows[0].get::<String, _>("encrypted_payload"),
        wire_payload
    );
    assert_eq!(
        rollback_rows[0].get::<i16, _>("standard_payload_storage_version"),
        0
    );
    assert_eq!(
        rollback_rows[0].get::<Option<String>, _>("standard_request_fingerprint"),
        Some(legacy_create_fingerprint.clone())
    );
    assert_eq!(
        rollback_rows[1].get::<Uuid, _>("id"),
        null_fingerprint_job_id
    );
    assert_eq!(
        rollback_rows[1].get::<String, _>("encrypted_payload"),
        wire_payload
    );
    assert_eq!(
        rollback_rows[1].get::<i16, _>("standard_payload_storage_version"),
        0
    );
    assert_eq!(
        rollback_rows[1].get::<Option<String>, _>("standard_request_fingerprint"),
        None
    );
    sqlx::query("DELETE FROM jobs WHERE id IN ($1,$2)")
        .bind(migratable_job_id)
        .bind(null_fingerprint_job_id)
        .execute(&database_pool)
        .await
        .expect("应清理 NULL fingerprint 升级夹具");
    migrate(&database_pool, &standard_data_key)
        .await
        .expect("清理不可恢复 legacy 行后，正确密钥必须可幂等重跑");

    assert_eq!(
        completed_job.pointer("/receipt_id").and_then(Value::as_str),
        Some(receipt_id.as_str())
    );
    let (_, settled_history) = call(
        &app,
        Method::GET,
        "/v1/quota/history",
        None,
        Some(&access_token),
    )
    .await;
    let settled_entry = settled_history
        .pointer("/entries")
        .and_then(Value::as_array)
        .and_then(|entries| {
            entries.iter().find(|entry| {
                entry.pointer("/request_id").and_then(Value::as_str) == Some(job_id.as_str())
            })
        })
        .expect("结算账本应该能由 job_id 发现");
    assert_eq!(
        settled_entry.pointer("/receipt_id").and_then(Value::as_str),
        Some(receipt_id.as_str())
    );
    assert!(settled_entry
        .pointer("/prev_hash")
        .and_then(Value::as_str)
        .is_some());
    assert!(settled_entry
        .pointer("/entry_hash")
        .and_then(Value::as_str)
        .is_some());
    assert_history_entry_locally_recomputes(settled_entry);
    let (_, receipt) = call(
        &app,
        Method::GET,
        &format!("/v1/quota/receipts/{receipt_id}"),
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(
        receipt.pointer("/job_id").and_then(Value::as_str),
        Some(job_id.as_str())
    );
    assert!(value_i64(&receipt, "/reserve_micro") > 0);
    assert_eq!(
        receipt
            .pointer("/contribution_weight_ppm")
            .and_then(Value::as_i64),
        Some(1_000_000)
    );

    let reserve_release = release_reserve(
        &database_pool,
        ReserveReleaseCommand {
            purpose: ReservePurpose::ResultValidation,
            amount_micro: 1,
            reference_id: format!("integration-verification:{job_id}"),
            idempotency_key: format!("reserve-release-{suffix}"),
            operator_id: "ops/reserve@example.com".to_owned(),
            reason: "支付独立结果验证任务成本".to_owned(),
        },
    )
    .await
    .expect("受控准备金释放应该成功");
    assert_eq!(
        reserve_release.balance_before_micro - reserve_release.balance_after_micro,
        1
    );
    let replayed_release = release_reserve(
        &database_pool,
        ReserveReleaseCommand {
            purpose: ReservePurpose::ResultValidation,
            amount_micro: 1,
            reference_id: format!("integration-verification:{job_id}"),
            idempotency_key: format!("reserve-release-{suffix}"),
            operator_id: "ops/reserve@example.com".to_owned(),
            reason: "支付独立结果验证任务成本".to_owned(),
        },
    )
    .await
    .expect("同一准备金释放幂等键应该可安全重放");
    assert!(replayed_release.idempotent_replay);
    assert_eq!(replayed_release.release_id, reserve_release.release_id);
    assert_eq!(
        replayed_release.operator_audit_id,
        reserve_release.operator_audit_id
    );
    let changed_release = release_reserve(
        &database_pool,
        ReserveReleaseCommand {
            purpose: ReservePurpose::ResultValidation,
            amount_micro: 1,
            reference_id: format!("integration-verification:{job_id}"),
            idempotency_key: format!("reserve-release-{suffix}"),
            operator_id: "ops/reserve@example.com".to_owned(),
            reason: "同一幂等键不得改写准备金释放理由".to_owned(),
        },
    )
    .await;
    assert!(matches!(
        changed_release,
        Err(ref error) if error.to_string() == "准备金幂等键已经用于不同释放请求"
    ));
    let reserve_operator_audit = sqlx::query(
        r#"
        SELECT reserve_ledger_id,purpose,operator_id,reason,amount_micro,
               reference_id,idempotency_key,reserve_ledger_entry_hash
        FROM operator_reserve_releases WHERE id=$1
        "#,
    )
    .bind(reserve_release.operator_audit_id)
    .fetch_one(&database_pool)
    .await
    .expect("准备金释放必须写入 operator 审计");
    assert_eq!(
        reserve_operator_audit.get::<Uuid, _>("reserve_ledger_id"),
        reserve_release.release_id
    );
    assert_eq!(
        reserve_operator_audit.get::<String, _>("purpose"),
        "verification"
    );
    assert_eq!(
        reserve_operator_audit.get::<String, _>("operator_id"),
        "ops/reserve@example.com"
    );
    assert_eq!(reserve_operator_audit.get::<i64, _>("amount_micro"), 1);
    assert_eq!(
        reserve_operator_audit.get::<String, _>("reserve_ledger_entry_hash"),
        reserve_release.entry_hash
    );
    assert!(
        sqlx::query("DELETE FROM operator_reserve_releases WHERE id=$1")
            .bind(reserve_release.operator_audit_id)
            .execute(&database_pool)
            .await
            .is_err(),
        "准备金 operator 审计必须只追加"
    );
    let excessive_release = release_reserve(
        &database_pool,
        ReserveReleaseCommand {
            purpose: ReservePurpose::PeakGuarantee,
            amount_micro: reserve_release.balance_after_micro.saturating_add(1),
            reference_id: format!("integration-overdraw:{job_id}"),
            idempotency_key: format!("reserve-overdraw-{suffix}"),
            operator_id: "ops/reserve@example.com".to_owned(),
            reason: "高峰保障容量预留测试".to_owned(),
        },
    )
    .await;
    assert!(excessive_release.is_err());
    let reserve_balance_after_rejection: i64 =
        sqlx::query_scalar("SELECT balance_micro FROM reserve_accounts WHERE id = 1")
            .fetch_one(&database_pool)
            .await
            .expect("应能读取准备金余额");
    assert_eq!(
        reserve_balance_after_rejection,
        reserve_release.balance_after_micro
    );

    let quality_before_republish: (i32, i32, String) =
        sqlx::query_as("SELECT benchmark_samples,evaluation_samples,tier FROM models WHERE id=$1")
            .bind(model_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("重复发布前应能读取服务端质量状态");
    let (_, republished) = call(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("instance-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "benchmark_normalized": 0,
            "glicko_normalized": 0,
            "evaluation_samples": 0,
            "base_cost_per_1k_micro": 1_000_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_str(&republished, "/model_id"), model_id);
    assert_eq!(
        value_str(&republished, "/model_instance_id"),
        model_instance_id
    );
    let (cost_change_status, cost_change_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("instance-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "base_cost_per_1k_micro": 1_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(cost_change_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        cost_change_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("client_base_cost_forbidden")
    );
    let preserved_quality =
        sqlx::query("SELECT benchmark_samples,evaluation_samples,tier FROM models WHERE id=$1")
            .bind(model_uuid)
            .fetch_one(&database_pool)
            .await
            .expect("重复发布后应能读取服务端质量状态");
    assert_eq!(
        preserved_quality
            .try_get::<i32, _>("benchmark_samples")
            .expect("benchmark_samples 应存在"),
        quality_before_republish.0
    );
    assert_eq!(
        preserved_quality
            .try_get::<i32, _>("evaluation_samples")
            .expect("evaluation_samples 应存在"),
        quality_before_republish.1
    );
    assert_eq!(
        preserved_quality
            .try_get::<String, _>("tier")
            .expect("tier 应存在"),
        quality_before_republish.2
    );
    let (_, republished_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 0,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "draining": false,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 2,
                "gpu_temp_limit_c": null,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        republished_heartbeat
            .pointer("/status")
            .and_then(Value::as_str),
        Some("online")
    );

    let (_, balance_before_failure) = call(
        &app,
        Method::GET,
        "/v1/quota/balance",
        None,
        Some(&access_token),
    )
    .await;
    let spendable_before = value_i64(&balance_before_failure, "/spendable_micro");
    let (_, second) = call(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(standard_job_body_with_encoding(
            &format!("model-{suffix}"),
            &["blocked"],
            &format!("create-fail-{suffix}"),
            10,
            "base64url",
        )),
        Some(&access_token),
    )
    .await;
    let failed_job_id = value_str(&second, "/job_id");
    let (_, rejected_policy_heartbeat) = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 0,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": ["blocked"],
                "max_concurrent": 2,
                "gpu_temp_limit_c": null,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        rejected_policy_heartbeat
            .pointer("/policy_updated")
            .and_then(Value::as_bool),
        Some(true)
    );
    let (rejected_claim_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(rejected_claim_status, StatusCode::NO_CONTENT);
    let _ = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 0,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 2,
                "gpu_temp_limit_c": null,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    let (_, claimed_failure) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_str(&claimed_failure, "/job_id"), failed_job_id);
    let _ = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": ["blocked"],
                "max_concurrent": 2,
                "gpu_temp_limit_c": null,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    let (renew_rejected_status, renew_rejected) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{failed_job_id}/renew"),
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(renew_rejected_status, StatusCode::FORBIDDEN);
    assert_eq!(
        renew_rejected.pointer("/code").and_then(Value::as_i64),
        Some(50)
    );
    let _ = call(
        &app,
        Method::POST,
        &heartbeat_path,
        Some(json!({
            "current_concurrent": 1,
            "vram_used_mib": 1024,
            "vram_total_mib": 8192,
            "policy": {
                "reject_tags": [],
                "max_concurrent": 2,
                "gpu_temp_limit_c": null,
                "vram_reserve_mib": 512
            }
        })),
        Some(&node_access_token),
    )
    .await;
    let (_, failure_draining) = call(
        &app,
        Method::DELETE,
        &unpublish_path,
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        failure_draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    let fail_path = format!("/v1/jobs/{failed_job_id}/fail");
    let (invalid_fail_status, invalid_fail) = call_unchecked(
        &app,
        Method::POST,
        &fail_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("invalid-fail-{suffix}"),
            "error_class": "policy",
            "error_message": "故".repeat(1001),
            "retryable": false
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(invalid_fail_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_fail.pointer("/error/type").and_then(Value::as_str),
        Some("invalid_failure_report")
    );
    let (fail_status, failed) = call(
        &app,
        Method::POST,
        &fail_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("fail-{suffix}"),
            "error_class": "policy",
            "error_message": "测试故障",
            "retryable": false
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(fail_status, StatusCode::OK);
    assert_eq!(
        sorted_object_keys(&failed),
        vec!["accepted", "idempotent_replay", "job_id"]
    );
    assert_eq!(
        failed.pointer("/accepted").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        failed
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(false)
    );
    let (_, replayed_failure) = call(
        &app,
        Method::POST,
        &fail_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("fail-{suffix}"),
            "error_class": "policy",
            "error_message": "测试故障",
            "retryable": false
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        replayed_failure
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let (altered_failure_status, altered_failure) = call_unchecked(
        &app,
        Method::POST,
        &fail_path,
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("fail-{suffix}"),
            "error_class": "policy",
            "error_message": "篡改后的故障",
            "retryable": true
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(altered_failure_status, StatusCode::CONFLICT);
    assert_eq!(
        altered_failure
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );
    let (_, failed_job) = call(
        &app,
        Method::GET,
        &format!("/v1/jobs/{failed_job_id}"),
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(
        failed_job.pointer("/error_class").and_then(Value::as_str),
        Some("policy")
    );
    assert_eq!(
        failed_job.pointer("/error_message").and_then(Value::as_str),
        Some("测试故障")
    );
    let (_, balance_after_failure) = call(
        &app,
        Method::GET,
        "/v1/quota/balance",
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(
        value_i64(&balance_after_failure, "/spendable_micro"),
        spendable_before
    );
    assert_eq!(value_i64(&balance_after_failure, "/reserved_micro"), 0);
    let failure_finalized_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id = $1")
            .bind(Uuid::parse_str(&model_instance_id).expect("模型实例 ID 必须是 UUID"))
            .fetch_one(&database_pool)
            .await
            .expect("应能读取失败任务收尾后的模型实例");
    assert_eq!(failure_finalized_status, "unpublished");

    let reaper_model = publish_test_model(
        &app,
        &node_access_token,
        &node_id,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    assert_eq!(
        value_str(&reaper_model, "/model_instance_id"),
        model_instance_id
    );
    let (_, balance_before_expired_lease) = call(
        &app,
        Method::GET,
        "/v1/quota/balance",
        None,
        Some(&access_token),
    )
    .await;
    let spendable_before_expired_lease =
        value_i64(&balance_before_expired_lease, "/spendable_micro");
    let (_, expiring_job) = call(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(standard_job_body(
            &format!("model-{suffix}"),
            &["test"],
            &format!("create-expiring-{suffix}"),
            10,
        )),
        Some(&access_token),
    )
    .await;
    let expiring_job_id = value_str(&expiring_job, "/job_id");
    let (_, claimed_expiring_job) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_str(&claimed_expiring_job, "/job_id"), expiring_job_id);
    let (_, expiring_draining) = call(
        &app,
        Method::DELETE,
        &unpublish_path,
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        expiring_draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    sqlx::query(
        r#"
        UPDATE jobs
        SET max_attempts = attempt_count,
            lease_expires_at = now() - interval '1 second'
        WHERE id = $1
        "#,
    )
    .bind(Uuid::parse_str(&expiring_job_id).expect("任务 ID 必须是 UUID"))
    .execute(&database_pool)
    .await
    .expect("应能模拟最后一次租约过期");
    let (expired_fail_status, expired_fail) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{expiring_job_id}/fail"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("expired-fail-{suffix}"),
            "error_class": "timeout",
            "error_message": "租约过期后的迟到报告",
            "retryable": false
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(expired_fail_status, StatusCode::CONFLICT);
    assert_eq!(
        expired_fail.pointer("/error/type").and_then(Value::as_str),
        Some("lease_expired")
    );
    let (reaper_poll_status, reaper_poll) = call(
        &app,
        Method::GET,
        &format!("/v1/jobs/{expiring_job_id}"),
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(reaper_poll_status, StatusCode::OK);
    assert_eq!(
        reaper_poll.pointer("/status").and_then(Value::as_str),
        Some("failed")
    );
    assert_eq!(
        reaper_poll.pointer("/error_class").and_then(Value::as_str),
        Some("timeout")
    );
    let reaped_job_status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = $1")
        .bind(Uuid::parse_str(&expiring_job_id).expect("任务 ID 必须是 UUID"))
        .fetch_one(&database_pool)
        .await
        .expect("应能读取 reaper 收口后的任务");
    assert_eq!(reaped_job_status, "failed");
    let reaped_attempt_status: String = sqlx::query_scalar(
        "SELECT status FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(Uuid::parse_str(&expiring_job_id).expect("任务 ID 必须是 UUID"))
    .fetch_one(&database_pool)
    .await
    .expect("应能读取 reaper 收口后的 attempt");
    assert_eq!(reaped_attempt_status, "expired");
    let reaped_instance_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id = $1")
            .bind(Uuid::parse_str(&model_instance_id).expect("模型实例 ID 必须是 UUID"))
            .fetch_one(&database_pool)
            .await
            .expect("应能读取 reaper 收口后的模型实例");
    assert_eq!(reaped_instance_status, "unpublished");
    let (_, balance_after_expired_lease) = call(
        &app,
        Method::GET,
        "/v1/quota/balance",
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(
        value_i64(&balance_after_expired_lease, "/spendable_micro"),
        spendable_before_expired_lease
    );
    assert_eq!(
        value_i64(&balance_after_expired_lease, "/reserved_micro"),
        0
    );

    let routed_model = publish_test_model(
        &app,
        &node_access_token,
        &node_id,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    assert_eq!(value_str(&routed_model, "/model_id"), model_id);
    let better_node_key = format!("mindone-integration-better-node-public-key-{suffix}");
    let (better_node_token, _, better_node_user_id) = login(&app, &better_node_key).await;
    assert_ne!(better_node_user_id, node_user_id);
    let better_node_id =
        register_test_node(&app, &better_node_token, &format!("better-node-{suffix}")).await;
    heartbeat_test_node(&app, &better_node_token, &better_node_id, 40_000, 50, &[]).await;
    let (foreign_result_replay_status, foreign_result_replay) = call_unchecked(
        &app,
        Method::POST,
        &result_path,
        Some(json!({
            "node_id": better_node_id,
            "idempotency_key": format!("result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext(&format!("model-{suffix}"), 10, 5),
            "actual_input_tokens": 10,
            "actual_output_tokens": 5,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(foreign_result_replay_status, StatusCode::FORBIDDEN);
    assert_eq!(
        foreign_result_replay
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("forbidden")
    );
    let (foreign_failure_replay_status, foreign_failure_replay) = call_unchecked(
        &app,
        Method::POST,
        &fail_path,
        Some(json!({
            "node_id": better_node_id,
            "idempotency_key": format!("fail-{suffix}"),
            "error_class": "policy",
            "error_message": "测试故障",
            "retryable": false
        })),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(foreign_failure_replay_status, StatusCode::FORBIDDEN);
    assert_eq!(
        foreign_failure_replay
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("forbidden")
    );
    sqlx::query("UPDATE nodes SET trust_level = 'enhanced' WHERE id = $1")
        .bind(Uuid::parse_str(&better_node_id).expect("节点 ID 必须是 UUID"))
        .execute(&database_pool)
        .await
        .expect("应能模拟受控 attestation 提升节点信任");
    let (arbitrary_cost_status, arbitrary_cost_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": better_node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("instance-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "base_cost_per_1k_micro": 9_999_999,
            "tags": ["test"]
        })),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(arbitrary_cost_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        arbitrary_cost_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("client_base_cost_forbidden")
    );
    let better_model = publish_test_model(
        &app,
        &better_node_token,
        &better_node_id,
        &suffix.to_string(),
        1_000_000,
    )
    .await;
    let better_model_instance_id = value_str(&better_model, "/model_instance_id");
    assert_eq!(value_str(&better_model, "/model_id"), model_id);
    assert_ne!(
        value_str(&better_model, "/model_instance_id"),
        model_instance_id
    );
    let canonical_cost: i64 =
        sqlx::query_scalar("SELECT base_cost_per_1k_micro FROM models WHERE id = $1")
            .bind(Uuid::parse_str(&model_id).expect("模型 ID 必须是 UUID"))
            .fetch_one(&database_pool)
            .await
            .expect("应能读取 canonical 模型费率");
    assert_eq!(
        canonical_cost, 1_000_000,
        "数据库只能保存协调器 v1 固定费率"
    );

    let best_route_job = create_test_job(
        &app,
        &access_token,
        &format!("model-{suffix}"),
        &["test"],
        &format!("route-best-{suffix}"),
    )
    .await;
    let (worse_claim_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(worse_claim_status, StatusCode::NO_CONTENT);
    let (_, best_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": better_node_id, "model_instance_id": better_model_instance_id})),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(value_str(&best_claim, "/job_id"), best_route_job);
    fail_test_job(
        &app,
        &better_node_token,
        &better_node_id,
        &best_route_job,
        &format!("route-best-fail-{suffix}"),
    )
    .await;

    sqlx::query("UPDATE nodes SET last_seen_at = now() - interval '5 minutes' WHERE id = $1")
        .bind(Uuid::parse_str(&better_node_id).expect("节点 ID 必须是 UUID"))
        .execute(&database_pool)
        .await
        .expect("应能模拟优选节点心跳过期");
    let stale_fallback_job = create_test_job(
        &app,
        &access_token,
        &format!("model-{suffix}"),
        &["test"],
        &format!("route-stale-fallback-{suffix}"),
    )
    .await;
    let (stale_node_claim_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": better_node_id, "model_instance_id": better_model_instance_id})),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(stale_node_claim_status, StatusCode::NO_CONTENT);
    let (_, stale_fallback_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        value_str(&stale_fallback_claim, "/job_id"),
        stale_fallback_job
    );
    fail_test_job(
        &app,
        &node_access_token,
        &node_id,
        &stale_fallback_job,
        &format!("route-stale-fail-{suffix}"),
    )
    .await;

    heartbeat_test_node(
        &app,
        &better_node_token,
        &better_node_id,
        40_000,
        50,
        &["blocked"],
    )
    .await;
    let policy_fallback_job = create_test_job(
        &app,
        &access_token,
        &format!("model-{suffix}"),
        &["BLOCKED"],
        &format!("route-policy-fallback-{suffix}"),
    )
    .await;
    let (vetoed_node_claim_status, _) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": better_node_id, "model_instance_id": better_model_instance_id})),
        Some(&better_node_token),
    )
    .await;
    assert_eq!(vetoed_node_claim_status, StatusCode::NO_CONTENT);
    let (_, policy_fallback_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        value_str(&policy_fallback_claim, "/job_id"),
        policy_fallback_job
    );
    fail_test_job(
        &app,
        &node_access_token,
        &node_id,
        &policy_fallback_job,
        &format!("route-policy-fail-{suffix}"),
    )
    .await;

    let (over_cap_status, over_cap_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-over-cap-{suffix}"),
            "alias": format!("instance-over-cap-{suffix}"),
            "format": "gguf",
            "weights_hash": "77".repeat(32),
            "size_bytes": 1024,
            "context_length": 4096,
            "base_cost_per_1k_micro": 100_000_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(over_cap_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        over_cap_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("client_base_cost_forbidden")
    );
    let (_, expensive_model) = call(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-expensive-{suffix}"),
            "alias": format!("instance-expensive-{suffix}"),
            "format": "gguf",
            "weights_hash": "88".repeat(32),
            "size_bytes": 1024,
            "context_length": 1_000_000,
            "base_cost_per_1k_micro": 1_000_000,
            "tags": ["test"]
        })),
        Some(&node_access_token),
    )
    .await;
    assert_ne!(
        value_str(&expensive_model, "/model_instance_id"),
        model_instance_id
    );
    let expensive_model_id = parse_uuid(
        &value_str(&expensive_model, "/model_id"),
        "高费率物理计费模型",
    );
    let expensive_profile_now = OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .expect("高费率 profile 时间必须可截断到秒");
    insert_test_billing_profile(
        &database_pool,
        expensive_model_id,
        &"88".repeat(32),
        2,
        1_000_000,
        1_000_000,
        1_000,
        expensive_profile_now - Duration::hours(1),
        expensive_profile_now + Duration::days(1),
    )
    .await;
    let (insufficient_status, insufficient) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs",
        Some(standard_job_body(
            &format!("model-expensive-{suffix}"),
            &["test"],
            &format!("create-insufficient-{suffix}"),
            10_000,
        )),
        Some(&access_token),
    )
    .await;
    assert_eq!(insufficient_status, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        insufficient.pointer("/code").and_then(Value::as_i64),
        Some(40)
    );
    let (_, balance_after_insufficient) = call(
        &app,
        Method::GET,
        "/v1/quota/balance",
        None,
        Some(&access_token),
    )
    .await;
    assert_eq!(value_i64(&balance_after_insufficient, "/reserved_micro"), 0);

    let (_, logout) = call(
        &app,
        Method::POST,
        "/v1/auth/logout",
        Some(json!({"refresh_token": consumer_refresh_token})),
        None,
    )
    .await;
    assert_eq!(
        logout
            .pointer("/device_key_revoked")
            .and_then(Value::as_bool),
        Some(true)
    );
    for revoked_access_token in [&access_token, &second_access_token] {
        let (revoked_status, _) = call_unchecked(
            &app,
            Method::GET,
            "/v1/quota/balance",
            None,
            Some(revoked_access_token),
        )
        .await;
        assert_eq!(revoked_status, StatusCode::UNAUTHORIZED);
    }
    let (revoked_refresh_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/refresh",
        Some(json!({"refresh_token": consumer_refresh_token})),
        None,
    )
    .await;
    assert_eq!(revoked_refresh_status, StatusCode::UNAUTHORIZED);
    let (repeated_logout_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/logout",
        Some(json!({"refresh_token": consumer_refresh_token})),
        None,
    )
    .await;
    assert_eq!(repeated_logout_status, StatusCode::OK);
    let (random_logout_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/auth/logout",
        Some(json!({"refresh_token": "mnr_not-a-real-refresh-token"})),
        None,
    )
    .await;
    assert_eq!(random_logout_status, StatusCode::UNAUTHORIZED);
    let device_key_revoked: bool = sqlx::query_scalar(
        "SELECT COALESCE(bool_and(revoked_at IS NOT NULL),FALSE) FROM device_keys WHERE user_id = $1",
    )
    .bind(Uuid::parse_str(&consumer_user_id).expect("用户 ID 必须是 UUID"))
    .fetch_one(&database_pool)
    .await
    .expect("应能检查设备公钥撤销状态");
    assert!(device_key_revoked);
    let target_contribution: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(r.contribution_micro),0)::bigint
        FROM receipts r JOIN jobs j ON j.id = r.job_id
        WHERE j.leased_to_node_id = $1
        "#,
    )
    .bind(parse_uuid(&node_id, "贡献节点"))
    .fetch_one(&database_pool)
    .await
    .expect("应能读取目标节点累计贡献");
    assert!(target_contribution > 0);
    let cohort_billing = load_test_billing_snapshot(&database_pool, model_uuid, 0, 1).await;
    for index in 1_i64..=5 {
        let cohort_user_id = if index == 1 {
            node_user_uuid
        } else {
            let cohort_user_id = Uuid::now_v7();
            sqlx::query(
                r#"
                INSERT INTO users (id,provider,provider_subject,username)
                VALUES ($1,'local-development',$2,$3)
                "#,
            )
            .bind(cohort_user_id)
            .bind(format!("transparency-cohort-{suffix}-{index}"))
            .bind(format!("透明度贡献账户-{suffix}-{index}"))
            .execute(&database_pool)
            .await
            .expect("应能创建透明度分布测试的独立贡献账户");
            sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
                .bind(cohort_user_id)
                .execute(&database_pool)
                .await
                .expect("透明度贡献账户应有独立额度账户");
            cohort_user_id
        };
        let cohort_device_key_id = Uuid::now_v7();
        let cohort_device_marker =
            char::from_digit(u32::try_from(index).expect("索引应为 u32"), 16)
                .expect("1..=5 应是合法 hex")
                .to_string()
                .repeat(64);
        sqlx::query(
            r#"
            INSERT INTO device_keys (id,user_id,fingerprint,public_key,algorithm)
            VALUES ($1,$2,$3,$3,'ed25519')
            "#,
        )
        .bind(cohort_device_key_id)
        .bind(cohort_user_id)
        .bind(cohort_device_marker)
        .execute(&database_pool)
        .await
        .expect("应能为贡献 percentile 测试节点创建设备密钥");
        let cohort_node_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO nodes (id,user_id,alias,hardware_profile,device_key_id)
            VALUES ($1,$2,$3,'{}'::jsonb,$4)
            "#,
        )
        .bind(cohort_node_id)
        .bind(cohort_user_id)
        .bind(format!("rank-cohort-{suffix}-{index}"))
        .bind(cohort_device_key_id)
        .execute(&database_pool)
        .await
        .expect("应能创建贡献 percentile 测试 cohort 节点");
        let cohort_job_id = Uuid::now_v7();
        let cohort_payload = encrypt_for_storage(
            &standard_data_key,
            cohort_job_id,
            StorageDirection::Payload,
            b"dGVzdA==",
        )
        .expect("应能构造受保护的 cohort payload");
        let cohort_job_insert = sqlx::query(
            r#"
            INSERT INTO jobs
                (id,user_id,model_id,idempotency_key,status,encrypted_payload,
                 estimated_input_tokens,max_output_tokens,reserved_cost_micro,
                 leased_to_node_id,actual_input_tokens,actual_output_tokens,completed_at,
                 standard_request_fingerprint,standard_payload_storage_version,
                 billing_contract_version,billing_profile_id,billing_profile_version,
                 billing_profile_fingerprint,billing_model_weights_hash,
                 billing_reference_hardware_class,billing_profile_evidence_hash,
                 billing_profile_valid_from,billing_profile_valid_until,
                 billing_profile_max_input_tokens,billing_profile_max_output_tokens,
                 billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
                 billing_reference_vram_mib,billing_token_rate_micro_per_1k,
                 billing_gpu_rate_micro_per_second,
                 billing_vram_rate_micro_per_gib_second,
                 billing_authorized_input_tokens,billing_authorized_max_output_tokens,
                 billing_billable_tokens,billing_reference_gpu_time_us,
                 billing_reference_vram_mib_microseconds,billing_token_cost_micro,
                 billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
            VALUES ($1,$2,$3,$4,'succeeded',$5,0,1,$8,$6,0,1,now(),$7,1,
                    $9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
                    $23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34)
            "#,
        )
        .bind(cohort_job_id)
        .bind(consumer_uuid)
        .bind(model_uuid)
        .bind(format!("rank-cohort-job-{suffix}-{index}"))
        .bind(cohort_payload)
        .bind(cohort_node_id)
        .bind(format!("mindone-standard-hmac-v1:{}", "0".repeat(64)))
        .bind(cohort_billing.reservation_micro);
        bind_test_billing_snapshot!(cohort_job_insert, cohort_billing)
            .execute(&database_pool)
            .await
            .expect("应能创建贡献 percentile 测试 cohort 任务");
        sqlx::query(
            r#"
            INSERT INTO receipts
                (id,job_id,consumer_user_id,node_user_id,model_name,tier,trust_level,
                 base_cost_micro,user_deduction_micro,node_quota_micro,
                 contribution_micro,reserve_micro,settlement_hash,
                 billing_contract_version,billing_profile_id,billing_profile_version,
                 billing_profile_fingerprint,billing_model_weights_hash,
                 billing_reference_hardware_class,billing_profile_evidence_hash,
                 billing_profile_valid_from,billing_profile_valid_until,
                 billing_profile_max_input_tokens,billing_profile_max_output_tokens,
                 billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
                 billing_reference_vram_mib,billing_token_rate_micro_per_1k,
                 billing_gpu_rate_micro_per_second,
                 billing_vram_rate_micro_per_gib_second,
                 billing_authorized_input_tokens,billing_authorized_max_output_tokens,
                 billing_billable_tokens,billing_reference_gpu_time_us,
                 billing_reference_vram_mib_microseconds,billing_token_cost_micro,
                 billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
            SELECT $1,j.id,$3,$4,$5,'medium','standard-limited',
                   j.billing_base_cost_micro,j.billing_base_cost_micro,
                   j.billing_base_cost_micro * 4 / 5,$6,
                   j.billing_base_cost_micro - j.billing_base_cost_micro * 4 / 5,$7,
                   j.billing_contract_version,j.billing_profile_id,
                   j.billing_profile_version,j.billing_profile_fingerprint,
                   j.billing_model_weights_hash,j.billing_reference_hardware_class,
                   j.billing_profile_evidence_hash,j.billing_profile_valid_from,
                   j.billing_profile_valid_until,j.billing_profile_max_input_tokens,
                   j.billing_profile_max_output_tokens,j.billing_fixed_gpu_time_us,
                   j.billing_gpu_time_us_per_1k_tokens,j.billing_reference_vram_mib,
                   j.billing_token_rate_micro_per_1k,
                   j.billing_gpu_rate_micro_per_second,
                   j.billing_vram_rate_micro_per_gib_second,
                   j.billing_authorized_input_tokens,
                   j.billing_authorized_max_output_tokens,j.billing_billable_tokens,
                   j.billing_reference_gpu_time_us,
                   j.billing_reference_vram_mib_microseconds,
                   j.billing_token_cost_micro,j.billing_gpu_cost_micro,
                   j.billing_vram_cost_micro,j.billing_base_cost_micro
            FROM jobs j WHERE j.id=$2
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(cohort_job_id)
        .bind(consumer_uuid)
        .bind(cohort_user_id)
        .bind(format!("model-{suffix}"))
        .bind(
            index
                .saturating_mul(target_contribution)
                .saturating_div(5)
                .max(1),
        )
        .bind(hex::encode(Sha256::digest(
            format!("rank-cohort-receipt-{suffix}-{index}").as_bytes(),
        )))
        .execute(&database_pool)
        .await
        .expect("应能创建贡献 percentile 测试 cohort 账单");
    }
    let verified_uptime_before: i64 =
        sqlx::query_scalar("SELECT verified_uptime_seconds FROM nodes WHERE id = $1")
            .bind(parse_uuid(&node_id, "uptime 节点"))
            .fetch_one(&database_pool)
            .await
            .expect("应能读取服务端累计的已验证 uptime");
    sqlx::query(
        r#"
        UPDATE nodes
        SET created_at = now() - interval '10 years',
            last_verified_heartbeat_at = now() - interval '10 minutes'
        WHERE id = $1
        "#,
    )
    .bind(parse_uuid(&node_id, "uptime 节点"))
    .execute(&database_pool)
    .await
    .expect("应能模拟节点离线而不改变累计 uptime");
    let (_, node_stats) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_access_token),
    )
    .await;
    assert_eq!(value_i64(&node_stats, "/requests"), 5);
    assert_eq!(value_i64(&node_stats, "/succeeded"), 1);
    assert_eq!(value_i64(&node_stats, "/failed"), 4);
    assert_eq!(
        node_stats.pointer("/trust_level").and_then(Value::as_str),
        Some("standard_limited")
    );
    serde_json::from_value::<mindone_protocol::NodeStatsResponse>(node_stats.clone())
        .expect("Standard-Limited 节点统计必须符合协议 DTO");
    assert_eq!(
        value_i64(&node_stats, "/uptime_seconds"),
        verified_uptime_before,
        "uptime 只能来自相邻已验证心跳，不能按 now-created_at 离线增长"
    );
    assert_eq!(
        node_stats.pointer("/tier").and_then(Value::as_str),
        Some("medium")
    );
    assert!(value_i64(&node_stats, "/spendable_earned_micro") > 0);
    assert!(value_i64(&node_stats, "/contribution_earned_micro") > 0);
    assert_eq!(
        node_stats
            .pointer("/honor/aggregation_version")
            .and_then(Value::as_str),
        Some("node-honor-v2")
    );
    assert!(value_i64(&node_stats, "/honor/contribution_rank_cohort_nodes") >= 5);
    let percentile = node_stats
        .pointer("/honor/contribution_rank_percentile")
        .and_then(Value::as_f64)
        .expect("满足五节点隐私阈值后必须返回真实 percentile");
    assert!((0.0..=1.0).contains(&percentile));
    assert_eq!(
        value_i64(&node_stats, "/honor/zero_failure_streak_days"),
        0,
        "当天存在真实失败时连续零故障天数必须为零"
    );
    assert!(
        value_i64(&node_stats, "/honor/next_contribution_milestone_micro")
            > value_i64(&node_stats, "/contribution_earned_micro")
    );
    assert!(
        value_i64(&node_stats, "/honor/previous_contribution_milestone_micro")
            <= value_i64(&node_stats, "/contribution_earned_micro")
    );
    let leaderboard = node_stats
        .pointer("/honor/network_leaderboard")
        .expect("应返回隐私安全的全网榜");
    assert_eq!(
        leaderboard.pointer("/suppressed").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        leaderboard.pointer("/tie_policy").and_then(Value::as_str),
        Some("midrank_shared_band")
    );
    assert_eq!(value_i64(leaderboard, "/count_granularity"), 5);
    let entries = leaderboard["entries"].as_array().expect("匿名榜应为数组");
    assert!(entries.iter().any(|entry| {
        entry.pointer("/label").and_then(Value::as_str) == Some("contributor")
            && value_i64(entry, "/qualifying_nodes_lower_bound") >= 5
    }));
    for entry in entries {
        let lower_bound = value_i64(entry, "/qualifying_nodes_lower_bound");
        assert_eq!(lower_bound % 5, 0);
        let object = entry.as_object().expect("榜单档位应为对象");
        for forbidden in [
            "user_id",
            "device_id",
            "device_key_id",
            "node_id",
            "model_id",
            "model_instance_id",
            "contribution_micro",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "匿名榜不得包含 {forbidden}"
            );
        }
    }
    let (_, better_node_stats) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{better_node_id}/stats"),
        None,
        Some(&better_node_token),
    )
    .await;
    assert_eq!(value_i64(&better_node_stats, "/requests"), 1);
    assert_eq!(value_i64(&better_node_stats, "/failed"), 1);
    assert_eq!(
        better_node_stats
            .pointer("/trust_level")
            .and_then(Value::as_str),
        Some("enhanced")
    );

    let (_, transparency) = call(
        &app,
        Method::GET,
        "/v1/transparency/report?window_days=30",
        None,
        None,
    )
    .await;
    let transparency_dto = serde_json::from_value::<mindone_protocol::TransparencyReportResponse>(
        transparency.clone(),
    )
    .expect("透明度报告必须符合双轨协议 DTO");
    assert!(value_i64(&transparency, "/sla/accepted_jobs") > 0);
    assert_eq!(
        value_i64(&transparency, "/sla/effective_terminal_jobs"),
        value_i64(&transparency, "/sla/included_denominator_jobs")
    );
    assert_eq!(
        value_i64(&transparency, "/sla/total_terminal_jobs"),
        value_i64(&transparency, "/sla/succeeded_jobs")
            + value_i64(&transparency, "/sla/failed_jobs")
            + value_i64(&transparency, "/sla/cancelled_jobs")
    );
    assert_eq!(
        value_i64(&transparency, "/sla/included_denominator_jobs"),
        value_i64(&transparency, "/sla/succeeded_jobs")
            + value_i64(&transparency, "/sla/failed_jobs")
            - value_i64(&transparency, "/sla/excluded_failed_jobs")
    );
    let terminal_jobs = value_i64(&transparency, "/sla/effective_terminal_jobs");
    let succeeded_jobs = value_i64(&transparency, "/sla/succeeded_jobs");
    assert_eq!(
        value_i64(&transparency, "/sla/effective_task_success_rate_ppm"),
        succeeded_jobs * 1_000_000 / terminal_jobs
    );
    assert_eq!(value_i64(&transparency, "/sla/excluded_jobs"), 0);
    assert_eq!(
        value_i64(
            &transparency,
            "/sla/exclusions_by_category/content_policy_refusal"
        ),
        0
    );
    assert_eq!(
        value_i64(&transparency, "/sla/exclusions_by_category/force_majeure"),
        0
    );
    assert_eq!(
        transparency
            .pointer("/sla/observation_scope")
            .and_then(Value::as_str),
        Some("accepted_jobs_audited_terminal_outcomes_v2")
    );
    assert!(value_i64(&transparency, "/anti_abuse/blocked_assessments") > 0);
    assert!(value_i64(&transparency, "/reserve/balance_micro") >= 0);
    assert!(value_i64(&transparency, "/reserve/window_inflow_micro") >= 0);
    assert!(value_i64(&transparency, "/reserve/window_outflow_micro") >= 0);
    let contributing_accounts =
        value_i64(&transparency, "/contributor_rewards/contributing_accounts");
    let privacy_threshold = value_i64(
        &transparency,
        "/contributor_rewards/privacy_threshold_accounts",
    );
    let distribution_available = transparency
        .pointer("/contributor_rewards/distribution_available")
        .and_then(Value::as_bool)
        .expect("透明度报告应说明双轨分布是否可用");
    assert_eq!(
        distribution_available,
        contributing_accounts >= privacy_threshold
    );
    assert!(
        contributing_accounts >= privacy_threshold,
        "测试夹具必须达到统一的五贡献账户隐私阈值：实际 {contributing_accounts}，阈值 {privacy_threshold}，响应 {transparency}"
    );
    assert!(distribution_available);
    assert_eq!(
        sorted_object_keys(
            transparency
                .pointer("/contributor_rewards")
                .expect("透明度报告应包含贡献账户双轨分布")
        ),
        vec![
            "contributing_accounts",
            "contribution_points",
            "distribution_available",
            "privacy_threshold_accounts",
            "spendable_quota",
        ]
    );
    for track in ["spendable_quota", "contribution_points"] {
        assert_eq!(
            sorted_object_keys(
                transparency
                    .pointer(&format!("/contributor_rewards/{track}"))
                    .expect("透明度报告应包含完整的双轨统计")
            ),
            vec![
                "maximum_micro",
                "median_micro",
                "minimum_micro",
                "p90_micro",
                "total_micro",
            ]
        );
    }
    let expected_rewards = sqlx::query(
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
    .bind(transparency_dto.window_start)
    .bind(transparency_dto.window_end)
    .fetch_one(&database_pool)
    .await
    .expect("应能从权威 receipts 分别重算透明度双轨分布");
    assert_eq!(
        contributing_accounts,
        expected_rewards
            .try_get::<i64, _>("contributing_accounts")
            .expect("应返回贡献账户数")
    );
    let settled_physical_nodes: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(DISTINCT j.leased_to_node_id)::bigint
        FROM receipts r
        JOIN jobs j ON j.id = r.job_id
        WHERE r.created_at >= $1 AND r.created_at < $2
          AND j.leased_to_node_id IS NOT NULL
        "#,
    )
    .bind(transparency_dto.window_start)
    .bind(transparency_dto.window_end)
    .fetch_one(&database_pool)
    .await
    .expect("应能独立统计窗口内已结算物理节点数");
    assert!(
        settled_physical_nodes > contributing_accounts,
        "测试夹具应证明 contributing_accounts 是 receipt 的贡献账户数，不能冒充物理节点数"
    );
    for (pointer, column) in [
        (
            "/contributor_rewards/spendable_quota/total_micro",
            "spendable_quota_total_micro",
        ),
        (
            "/contributor_rewards/spendable_quota/minimum_micro",
            "spendable_quota_minimum_micro",
        ),
        (
            "/contributor_rewards/spendable_quota/median_micro",
            "spendable_quota_median_micro",
        ),
        (
            "/contributor_rewards/spendable_quota/p90_micro",
            "spendable_quota_p90_micro",
        ),
        (
            "/contributor_rewards/spendable_quota/maximum_micro",
            "spendable_quota_maximum_micro",
        ),
        (
            "/contributor_rewards/contribution_points/total_micro",
            "contribution_points_total_micro",
        ),
        (
            "/contributor_rewards/contribution_points/minimum_micro",
            "contribution_points_minimum_micro",
        ),
        (
            "/contributor_rewards/contribution_points/median_micro",
            "contribution_points_median_micro",
        ),
        (
            "/contributor_rewards/contribution_points/p90_micro",
            "contribution_points_p90_micro",
        ),
        (
            "/contributor_rewards/contribution_points/maximum_micro",
            "contribution_points_maximum_micro",
        ),
    ] {
        assert_eq!(
            value_i64(&transparency, pointer),
            expected_rewards
                .try_get::<i64, _>(column)
                .unwrap_or_else(|error| panic!("应返回 {column}: {error}")),
            "透明度字段 {pointer} 必须独立来自 {column}"
        );
    }
    assert!(transparency.pointer("/node_earnings").is_none());
    assert!(!transparency.to_string().contains("total_earnings_micro"));
    let serialized_transparency = transparency.to_string();
    for private_key in [
        "user_id",
        "node_id",
        "device_hash",
        "ip_prefix_hash",
        "asn_hash",
    ] {
        assert!(!serialized_transparency.contains(private_key));
    }
    let (invalid_window_status, invalid_window) = call_unchecked(
        &app,
        Method::GET,
        "/v1/transparency/report?window_days=0",
        None,
        None,
    )
    .await;
    assert_eq!(invalid_window_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid_window
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("invalid_report_window")
    );

    let (_, full_linux) = call(
        &app,
        Method::POST,
        "/v1/nodes/register",
        Some(json!({
            "alias": format!("full-linux-{suffix}"),
            "hardware_profile": {
                "operating_system":"linux",
                "operating_system_version":"test",
                "architecture":"x86_64",
                "cpu_model":"Integration CPU",
                "cpu_logical_cores":16,
                "ram_total_mib":65536,
                "gpus":[],
                "cuda_available":true,
                "metal_available":false,
                "sandbox_mechanisms":["namespaces","seccomp_bpf","landlock"]
            },
            "reject_tags": [],
            "max_concurrent": 1,
            "gpu_temp_limit_c": null,
            "vram_reserve_mib": 0
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        full_linux.pointer("/trust_level").and_then(Value::as_str),
        Some("standard")
    );
    let (_, windows) = call(
        &app,
        Method::POST,
        "/v1/nodes/register",
        Some(json!({
            "alias": format!("windows-{suffix}"),
            "hardware_profile": {
                "operating_system":"windows",
                "operating_system_version":"test",
                "architecture":"x86_64",
                "cpu_model":"Integration CPU",
                "cpu_logical_cores":16,
                "ram_total_mib":65536,
                "gpus":[],
                "cuda_available":false,
                "metal_available":false,
                "sandbox_mechanisms":["job_objects"]
            },
            "reject_tags": [],
            "max_concurrent": 1,
            "gpu_temp_limit_c": null,
            "vram_reserve_mib": 0
        })),
        Some(&node_access_token),
    )
    .await;
    assert_eq!(
        windows.pointer("/trust_level").and_then(Value::as_str),
        Some("experimental")
    );
}

#[tokio::test]
#[serial]
async fn hidden_work_uses_only_ordinary_worker_routes_and_zero_financial_settlement() {
    let Some(database_url) = database_url_or_skip("隐藏评价普通数据流 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("Hidden-Work-集成测试-{suffix}");
    config.evaluation_draw_denominator = 1;
    let mut ordinary_config = config.clone();
    ordinary_config.evaluation_draw_denominator = 0;
    let pool = connect(&config).await.expect("应能连接隐藏评价测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("隐藏评价迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试认证配置有效"),
    );
    let app =
        router(AppState::new(pool.clone(), config, provider.clone())).expect("测试路由配置应有效");
    let ordinary_app =
        router(AppState::new(pool.clone(), ordinary_config, provider)).expect("测试路由配置应有效");
    let (node_token, _, _) = login(&app, &format!("hidden-node-key-{suffix}")).await;
    let node_id = register_test_node(&app, &node_token, &format!("hidden-node-{suffix}")).await;
    heartbeat_test_node(&app, &node_token, &node_id, 20_000, 80, &[]).await;
    let probe_node_id =
        register_test_node(&app, &node_token, &format!("hidden-probe-node-{suffix}")).await;
    heartbeat_test_node(&app, &node_token, &probe_node_id, 20_000, 80, &[]).await;
    let model =
        publish_test_model(&app, &node_token, &node_id, &suffix.to_string(), 1_000_000).await;
    let model_instance_id = value_str(&model, "/model_instance_id");
    let model_id = parse_uuid(&value_str(&model, "/model_id"), "隐藏评价模型");
    let model_name = format!("model-{suffix}");

    // 同一账户的第二节点主动探测普通/隐藏任务时，外部可观察的授权、状态与结果校验
    // 顺序必须一致。普通路由使用独立的 denominator=0 state，共享同一真实数据库和认证。
    let ordinary_id = create_test_job(
        &ordinary_app,
        &node_token,
        &model_name,
        &["probe"],
        &format!("ordinary-probe-{suffix}"),
    )
    .await;
    let (_, ordinary_claim) = call(
        &ordinary_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(value_str(&ordinary_claim, "/job_id"), ordinary_id);

    let (legacy_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/evaluations/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(legacy_status, StatusCode::NOT_FOUND);
    let (_, stats_before) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_token),
    )
    .await;
    let (_, hidden_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let hidden_id = value_str(&hidden_claim, "/job_id");
    assert_eq!(parse_uuid(&hidden_id, "隐藏任务").get_version_num(), 4);
    for forbidden in ["evaluation", "benchmark", "canary", "challenge", "kind"] {
        assert!(!hidden_claim
            .to_string()
            .to_ascii_lowercase()
            .contains(forbidden));
    }
    let payload_bytes = BASE64_STANDARD
        .decode(value_str(&hidden_claim, "/encrypted_payload"))
        .expect("隐藏任务应使用普通 Base64 Standard payload");
    let payload: Value =
        serde_json::from_slice(&payload_bytes).expect("隐藏任务 payload 应为 JSON");
    assert_eq!(
        payload.pointer("/request/model").and_then(Value::as_str),
        Some("auto")
    );
    let prompt = payload
        .pointer("/request/messages/0/content")
        .and_then(Value::as_str)
        .expect("应含自然语言请求");
    let prompt_lower = prompt.to_ascii_lowercase();
    for forbidden in [
        "mindone",
        "evaluation",
        "benchmark",
        "canary",
        "评价",
        "评测",
    ] {
        assert!(!prompt_lower.contains(forbidden));
    }
    let (_, stats_after_claim) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        stats_before.pointer("/requests"),
        stats_after_claim.pointer("/requests")
    );

    let issued_at: time::OffsetDateTime =
        sqlx::query_scalar("SELECT issued_at FROM model_evaluation_challenges WHERE id=$1")
            .bind(parse_uuid(&hidden_id, "隐藏任务"))
            .fetch_one(&pool)
            .await
            .expect("应能读取隐藏任务真实签发时间");
    let (_, hidden_status) = call(
        &app,
        Method::GET,
        &format!("/v1/jobs/{hidden_id}"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        hidden_status.pointer("/created_at"),
        Some(&serde_json::to_value(issued_at).expect("签发时间可序列化")),
        "隐藏任务 created_at 必须来自真实 issued_at，不能由 prompt hash 伪造"
    );

    let wrong_node_renew = json!({"node_id": probe_node_id});
    let (ordinary_renew_status, ordinary_renew_error) = call_unchecked(
        &ordinary_app,
        Method::POST,
        &format!("/v1/jobs/{ordinary_id}/renew"),
        Some(wrong_node_renew.clone()),
        Some(&node_token),
    )
    .await;
    let (hidden_renew_status, hidden_renew_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/renew"),
        Some(wrong_node_renew),
        Some(&node_token),
    )
    .await;
    assert_eq!(ordinary_renew_status, StatusCode::CONFLICT);
    assert_eq!(hidden_renew_status, ordinary_renew_status);
    assert_eq!(hidden_renew_error, ordinary_renew_error);
    assert_eq!(
        hidden_renew_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("lease_not_renewable")
    );

    let malformed_result = |node: &str, key: String| {
        json!({
            "node_id": node,
            "idempotency_key": key,
            "result_ciphertext": "%",
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })
    };
    let (ordinary_malformed_status, ordinary_malformed_error) = call_unchecked(
        &ordinary_app,
        Method::POST,
        &format!("/v1/jobs/{ordinary_id}/result"),
        Some(malformed_result(
            &probe_node_id,
            format!("ordinary-malformed-{suffix}"),
        )),
        Some(&node_token),
    )
    .await;
    let (hidden_malformed_status, hidden_malformed_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/result"),
        Some(malformed_result(
            &probe_node_id,
            format!("hidden-malformed-{suffix}"),
        )),
        Some(&node_token),
    )
    .await;
    assert_eq!(ordinary_malformed_status, StatusCode::BAD_REQUEST);
    assert_eq!(hidden_malformed_status, ordinary_malformed_status);
    assert_eq!(hidden_malformed_error, ordinary_malformed_error);

    let overflow_token_value = i32::MAX as u32 + 1;
    let overflow_result = |model: &str, key: String, prompt_tokens: u32, completion_tokens: u32| {
        json!({
            "node_id": node_id,
            "idempotency_key": key,
            "result_ciphertext": standard_result_ciphertext(model, prompt_tokens, completion_tokens),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })
    };
    let (ordinary_overflow_status, ordinary_overflow_error) = call_unchecked(
        &ordinary_app,
        Method::POST,
        &format!("/v1/jobs/{ordinary_id}/result"),
        Some(overflow_result(
            &model_name,
            format!("ordinary-overflow-{suffix}"),
            overflow_token_value,
            1,
        )),
        Some(&node_token),
    )
    .await;
    let (hidden_overflow_status, hidden_overflow_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/result"),
        Some(overflow_result(
            "auto",
            format!("hidden-overflow-{suffix}"),
            overflow_token_value,
            1,
        )),
        Some(&node_token),
    )
    .await;
    assert_eq!(ordinary_overflow_status, StatusCode::BAD_REQUEST);
    assert_eq!(hidden_overflow_status, ordinary_overflow_status);
    assert_eq!(hidden_overflow_error, ordinary_overflow_error);
    assert_eq!(
        hidden_overflow_error
            .pointer("/error/message")
            .and_then(Value::as_str),
        Some("prompt_tokens 超出范围")
    );

    let (ordinary_completion_overflow_status, ordinary_completion_overflow_error) = call_unchecked(
        &ordinary_app,
        Method::POST,
        &format!("/v1/jobs/{ordinary_id}/result"),
        Some(overflow_result(
            &model_name,
            format!("ordinary-completion-overflow-{suffix}"),
            1,
            overflow_token_value,
        )),
        Some(&node_token),
    )
    .await;
    let (hidden_completion_overflow_status, hidden_completion_overflow_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/result"),
        Some(overflow_result(
            "auto",
            format!("hidden-completion-overflow-{suffix}"),
            1,
            overflow_token_value,
        )),
        Some(&node_token),
    )
    .await;
    assert_eq!(ordinary_completion_overflow_status, StatusCode::BAD_REQUEST);
    assert_eq!(
        hidden_completion_overflow_status,
        ordinary_completion_overflow_status
    );
    assert_eq!(
        hidden_completion_overflow_error,
        ordinary_completion_overflow_error
    );
    assert_eq!(
        hidden_completion_overflow_error
            .pointer("/error/message")
            .and_then(Value::as_str),
        Some("completion_tokens 超出范围")
    );

    fail_test_job(
        &ordinary_app,
        &node_token,
        &node_id,
        &ordinary_id,
        &format!("ordinary-probe-cleanup-{suffix}"),
    )
    .await;

    let (_, renewed) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/renew"),
        Some(json!({"node_id": node_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(value_str(&renewed, "/job_id"), hidden_id);
    let fail_body = json!({
        "node_id": node_id,
        "idempotency_key": format!("hidden-fail-{suffix}"),
        "error_class": "engine",
        "error_message": "受控测试失败",
        "retryable": true
    });
    let (_, failed) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/fail"),
        Some(fail_body.clone()),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        failed,
        json!({"job_id": hidden_id, "accepted": true, "idempotent_replay": false})
    );
    let (_, failed_replay) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/fail"),
        Some(fail_body),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        failed_replay
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let (ordinary_terminal_renew_status, ordinary_terminal_renew_error) = call_unchecked(
        &ordinary_app,
        Method::POST,
        &format!("/v1/jobs/{ordinary_id}/renew"),
        Some(json!({"node_id": node_id})),
        Some(&node_token),
    )
    .await;
    let (hidden_terminal_renew_status, hidden_terminal_renew_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{hidden_id}/renew"),
        Some(json!({"node_id": node_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(ordinary_terminal_renew_status, StatusCode::CONFLICT);
    assert_eq!(hidden_terminal_renew_status, ordinary_terminal_renew_status);
    assert_eq!(hidden_terminal_renew_error, ordinary_terminal_renew_error);

    sqlx::query(
        "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
    )
    .bind(parse_uuid(&hidden_id, "隐藏任务"))
    .execute(&pool)
    .await
    .expect("应能推进隐藏评价冷却时间");
    let (_, result_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let result_id = value_str(&result_claim, "/job_id");
    let result_body = json!({
        "node_id": node_id,
        "idempotency_key": format!("hidden-result-{suffix}"),
        "result_ciphertext": standard_result_ciphertext("auto", 10, 1),
        "actual_input_tokens": 10,
        "actual_output_tokens": 1,
        "execution_telemetry": test_execution_telemetry()
    });
    let (_, result_ack) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{result_id}/result"),
        Some(result_body.clone()),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        result_ack,
        json!({"job_id": result_id, "status": "succeeded", "idempotent_replay": false})
    );
    let (_, result_replay) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{result_id}/result"),
        Some(result_body),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        result_replay
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );

    // 两次失败尚不隔离；先排入一个普通消费者任务，再制造第三个连续失败。
    let queued_before_quarantine = create_test_job(
        &ordinary_app,
        &node_token,
        &model_name,
        &["quarantine-probe"],
        &format!("ordinary-before-quarantine-{suffix}"),
    )
    .await;
    sqlx::query(
        "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
    )
    .bind(parse_uuid(&result_id, "第二个隐藏任务"))
    .execute(&pool)
    .await
    .expect("应能推进第二个隐藏评价冷却时间");
    let (_, third_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let third_id = value_str(&third_claim, "/job_id");
    let (_, third_failed) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{third_id}/fail"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("hidden-third-fail-{suffix}"),
            "error_class": "engine",
            "error_message": "受控连续失败",
            "retryable": false
        })),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        third_failed.pointer("/accepted").and_then(Value::as_bool),
        Some(true)
    );
    let quarantine_state: (i32, i32, bool) = sqlx::query_as(
        r#"
        SELECT consecutive_failures,recovery_passes,quarantined
        FROM model_instance_canary_state WHERE model_instance_id=$1
        "#,
    )
    .bind(parse_uuid(&model_instance_id, "隐藏评价模型实例"))
    .fetch_one(&pool)
    .await
    .expect("第三次连续失败必须生成实例隔离状态");
    assert_eq!(quarantine_state, (3, 0, true));
    let (_, quarantined_stats) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        quarantined_stats.pointer("/instance_canary_risk/0/quarantined"),
        Some(&Value::Bool(true))
    );
    assert_eq!(
        quarantined_stats.pointer("/tier").and_then(Value::as_str),
        None,
        "节点最佳 Tier 必须排除已隔离实例"
    );
    let quarantined_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_instance_canary_events WHERE model_instance_id=$1 AND event_kind='quarantined'",
    )
    .bind(parse_uuid(&model_instance_id, "隐藏评价模型实例"))
    .fetch_one(&pool)
    .await
    .expect("隔离转换必须有只追加事件");
    assert_eq!(quarantined_events, 1);
    let (quarantined_claim_status, quarantined_claim_body) = call_unchecked(
        &ordinary_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(quarantined_claim_status, StatusCode::NO_CONTENT);
    assert_eq!(quarantined_claim_body, Value::Null);

    // 隔离实例仍能收到 ordinary-wire canary；两个连续正确结果后自动恢复路由。
    let mut previous_id = third_id;
    for recovery_index in 0..2 {
        sqlx::query(
            "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
        )
        .bind(parse_uuid(&previous_id, "恢复前隐藏任务"))
        .execute(&pool)
        .await
        .expect("应能推进恢复 canary 冷却时间");
        let (_, recovery_claim) = call(
            &app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
            Some(&node_token),
        )
        .await;
        let recovery_id = value_str(&recovery_claim, "/job_id");
        let (kind, seed): (String, Vec<u8>) = sqlx::query_as(
            "SELECT challenge_kind,challenge_seed FROM model_evaluation_challenges WHERE id=$1",
        )
        .bind(parse_uuid(&recovery_id, "恢复 canary"))
        .fetch_one(&pool)
        .await
        .expect("恢复 canary 必须保留事务内 seed");
        let expected = hidden_expected_from_seed(&kind, &seed);
        let (_, recovered_ack) = call(
            &app,
            Method::POST,
            &format!("/v1/jobs/{recovery_id}/result"),
            Some(json!({
                "node_id": node_id,
                "idempotency_key": format!("hidden-recovery-{recovery_index}-{suffix}"),
                "result_ciphertext": standard_result_ciphertext_with_content(
                    "auto", 1, 1, &expected
                ),
                "actual_input_tokens": 1,
                "actual_output_tokens": 1,
                "execution_telemetry": test_execution_telemetry()
            })),
            Some(&node_token),
        )
        .await;
        assert_eq!(
            recovered_ack.pointer("/status").and_then(Value::as_str),
            Some("succeeded")
        );
        previous_id = recovery_id;
    }
    let recovered_state: (i32, i32, bool) = sqlx::query_as(
        r#"
        SELECT consecutive_failures,recovery_passes,quarantined
        FROM model_instance_canary_state WHERE model_instance_id=$1
        "#,
    )
    .bind(parse_uuid(&model_instance_id, "隐藏评价模型实例"))
    .fetch_one(&pool)
    .await
    .expect("连续成功后必须保留恢复状态");
    assert_eq!(recovered_state, (0, 0, false));
    let (_, recovered_stats) = call(
        &app,
        Method::GET,
        &format!("/v1/nodes/{node_id}/stats"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        recovered_stats.pointer("/instance_canary_risk/0/quarantined"),
        Some(&Value::Bool(false))
    );
    assert_eq!(
        recovered_stats.pointer("/tier").and_then(Value::as_str),
        Some("medium"),
        "恢复后的 published 实例应重新参与节点最佳 Tier"
    );
    let (_, ordinary_after_recovery) = call(
        &ordinary_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        value_str(&ordinary_after_recovery, "/job_id"),
        queued_before_quarantine
    );
    fail_test_job(
        &ordinary_app,
        &node_token,
        &node_id,
        &queued_before_quarantine,
        &format!("ordinary-after-recovery-cleanup-{suffix}"),
    )
    .await;

    // 候选读取后、租约写入前的并发 unpublish 必须由最终实例行锁线性化。先在独立
    // 事务持有实例更新锁，再启动真实 claim；仅在 PostgreSQL 明确报告该 claim 被本
    // 事务阻塞后才提交，避免用固定 sleep 猜测竞态时序。
    let unpublish_race_job = create_test_job(
        &ordinary_app,
        &node_token,
        &model_name,
        &["unpublish-race"],
        &format!("ordinary-unpublish-race-{suffix}"),
    )
    .await;
    let instance_uuid = parse_uuid(&model_instance_id, "并发取消发布模型实例");
    let mut unpublish_tx = pool.begin().await.expect("应能开始并发取消发布事务");
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *unpublish_tx)
        .await
        .expect("应能读取取消发布事务 backend pid");
    sqlx::query("SELECT status FROM model_instances WHERE id=$1 FOR UPDATE")
        .bind(instance_uuid)
        .fetch_one(&mut *unpublish_tx)
        .await
        .expect("取消发布事务应锁定精确实例");
    sqlx::query("UPDATE model_instances SET status='unpublished',unpublished_at=now() WHERE id=$1")
        .bind(instance_uuid)
        .execute(&mut *unpublish_tx)
        .await
        .expect("取消发布事务应写入未提交终态");
    let race_app = ordinary_app.clone();
    let race_node_id = node_id.clone();
    let race_instance_id = model_instance_id.clone();
    let race_node_token = node_token.clone();
    let claim_task = tokio::spawn(async move {
        call_unchecked(
            &race_app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({
                "node_id": race_node_id,
                "model_instance_id": race_instance_id
            })),
            Some(&race_node_token),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let claim_waits_for_unpublish: bool = sqlx::query_scalar(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity activity
                    WHERE activity.pid <> pg_backend_pid()
                      AND $1 = ANY(pg_blocking_pids(activity.pid))
                )
                "#,
            )
            .bind(blocker_pid)
            .fetch_one(&pool)
            .await
            .expect("应能检查 claim 的数据库锁等待");
            if claim_waits_for_unpublish {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("真实 claim 应在最终 published 复核处等待并发 unpublish");
    unpublish_tx.commit().await.expect("并发取消发布事务应提交");
    let (race_claim_status, race_claim_body) =
        claim_task.await.expect("并发 claim 任务不应异常退出");
    assert_eq!(race_claim_status, StatusCode::NO_CONTENT);
    assert_eq!(race_claim_body, Value::Null);
    let race_job_state: (String, Option<Uuid>) =
        sqlx::query_as("SELECT status,leased_to_node_id FROM jobs WHERE id=$1")
            .bind(parse_uuid(&unpublish_race_job, "并发取消发布普通任务"))
            .fetch_one(&pool)
            .await
            .expect("应能读取被拒绝 claim 后的任务状态");
    assert_eq!(race_job_state, ("queued".to_owned(), None));
    let race_republished =
        publish_test_model(&app, &node_token, &node_id, &suffix.to_string(), 1_000_000).await;
    assert_eq!(
        value_str(&race_republished, "/model_instance_id"),
        model_instance_id
    );
    let (_, race_cleanup_claim) = call(
        &ordinary_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        value_str(&race_cleanup_claim, "/job_id"),
        unpublish_race_job
    );
    fail_test_job(
        &ordinary_app,
        &node_token,
        &node_id,
        &unpublish_race_job,
        &format!("ordinary-unpublish-race-cleanup-{suffix}"),
    )
    .await;

    // 后台 sweep 不依赖节点再次 claim。强制取消发布会先进入 draining；租约到期后，
    // challenge 终态、风险事件和实例 unpublished 必须在同一事务提交，重复 sweep 为零。
    sqlx::query(
        "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
    )
    .bind(parse_uuid(&previous_id, "后台过期前隐藏任务"))
    .execute(&pool)
    .await
    .expect("应能推进后台过期测试冷却时间");
    let (_, expiry_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let expiry_id = value_str(&expiry_claim, "/job_id");
    let expiry_uuid = parse_uuid(&expiry_id, "后台过期隐藏任务");
    let (_, expiry_draining) = call(
        &app,
        Method::DELETE,
        &format!("/v1/models/{model_instance_id}"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        expiry_draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    sqlx::query(
        "UPDATE model_evaluation_challenges SET lease_expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(expiry_uuid)
    .execute(&pool)
    .await
    .expect("应能确定性推进隐藏租约到期边界");
    let expiry_events_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events WHERE challenge_id=$1",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能记录目标隐藏任务 sweep 前的事件数");
    let expiry_risk_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_instance_canary_events WHERE challenge_id=$1 AND reason_code='lease_expired'",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能确认目标隐藏任务 sweep 前没有过期风险事件");
    assert_eq!(expiry_risk_before, 0);

    let first_sweep_count = sweep_expired_hidden_jobs(&pool)
        .await
        .expect("后台过期扫描应提交");
    assert!(
        first_sweep_count >= 1,
        "后台扫描必须至少收口本测试创建的目标隐藏租约"
    );
    let expired_state: (String, Option<Vec<u8>>, Option<String>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT status,challenge_seed,result_hash,completed_at FROM model_evaluation_challenges WHERE id=$1",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能读取后台收口后的隐藏任务");
    assert_eq!(expired_state.0, "failed");
    assert!(expired_state.1.is_none(), "终态必须销毁 challenge seed");
    assert!(expired_state.2.is_some(), "终态必须记录结果 commitment");
    assert!(expired_state.3.is_some(), "终态必须记录完成时间");
    let expiry_events_after_first: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events WHERE challenge_id=$1",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能读取首次 sweep 后的目标事件数");
    assert_eq!(
        expiry_events_after_first,
        expiry_events_before + 2,
        "目标租约过期必须精确追加 expired 与 completed 两个事件"
    );
    let expiry_risk_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_instance_canary_events WHERE challenge_id=$1 AND reason_code='lease_expired'",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("租约过期必须生成一次精确实例风险事件");
    assert_eq!(expiry_risk_events, 1);
    let _second_sweep_count = sweep_expired_hidden_jobs(&pool)
        .await
        .expect("重复后台过期扫描应安全");
    let expired_state_after_repeat: (String, Option<Vec<u8>>, Option<String>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT status,challenge_seed,result_hash,completed_at FROM model_evaluation_challenges WHERE id=$1",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能读取重复 sweep 后的目标隐藏任务");
    assert_eq!(
        expired_state_after_repeat, expired_state,
        "重复 sweep 不得改写目标隐藏任务终态"
    );
    let expiry_events_after_repeat: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events WHERE challenge_id=$1",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能读取重复 sweep 后的目标事件数");
    let expiry_risk_after_repeat: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_instance_canary_events WHERE challenge_id=$1 AND reason_code='lease_expired'",
    )
    .bind(expiry_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能读取重复 sweep 后的目标风险事件数");
    assert_eq!(expiry_events_after_repeat, expiry_events_after_first);
    assert_eq!(expiry_risk_after_repeat, expiry_risk_events);
    let expired_instance_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id=$1")
            .bind(parse_uuid(&model_instance_id, "后台过期模型实例"))
            .fetch_one(&pool)
            .await
            .expect("应能读取后台过期后的实例状态");
    assert_eq!(expired_instance_status, "unpublished");
    let (late_submit_status, late_submit_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{expiry_id}/fail"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("hidden-after-sweep-{suffix}"),
            "error_class": "engine",
            "error_message": "后台扫描后到达的迟交",
            "retryable": false
        })),
        Some(&node_token),
    )
    .await;
    assert_eq!(late_submit_status, StatusCode::CONFLICT);
    assert_eq!(
        late_submit_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("lease_expired"),
        "后台 sweep 先获锁时迟交仍应稳定返回 lease_expired"
    );

    // result 与显式 fail 也必须在自己的终态事务中完成 draining 收口。
    let republished_after_expiry =
        publish_test_model(&app, &node_token, &node_id, &suffix.to_string(), 1_000_000).await;
    assert_eq!(
        value_str(&republished_after_expiry, "/model_instance_id"),
        model_instance_id
    );
    sqlx::query(
        "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
    )
    .bind(expiry_uuid)
    .execute(&pool)
    .await
    .expect("应能推进 result 收口测试冷却时间");
    let (_, draining_result_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let draining_result_id = value_str(&draining_result_claim, "/job_id");
    let draining_result_uuid = parse_uuid(&draining_result_id, "draining result 隐藏任务");
    let (_, result_draining) = call(
        &app,
        Method::DELETE,
        &format!("/v1/models/{model_instance_id}"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        result_draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    let (_, draining_result_ack) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{draining_result_id}/result"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("hidden-draining-result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext("auto", 10, 1),
            "actual_input_tokens": 10,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        draining_result_ack
            .pointer("/status")
            .and_then(Value::as_str),
        Some("succeeded")
    );
    let result_instance_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id=$1")
            .bind(parse_uuid(&model_instance_id, "result 收口模型实例"))
            .fetch_one(&pool)
            .await
            .expect("result 终态后应能读取实例状态");
    assert_eq!(result_instance_status, "unpublished");

    let republished_after_result =
        publish_test_model(&app, &node_token, &node_id, &suffix.to_string(), 1_000_000).await;
    assert_eq!(
        value_str(&republished_after_result, "/model_instance_id"),
        model_instance_id
    );
    sqlx::query(
        "UPDATE model_evaluation_challenges SET issued_at=now()-interval '2 minutes' WHERE id=$1",
    )
    .bind(draining_result_uuid)
    .execute(&pool)
    .await
    .expect("应能推进 fail 收口测试冷却时间");
    let (_, draining_fail_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(&node_token),
    )
    .await;
    let draining_fail_id = value_str(&draining_fail_claim, "/job_id");
    let draining_fail_uuid = parse_uuid(&draining_fail_id, "draining fail 隐藏任务");
    let (_, fail_draining) = call(
        &app,
        Method::DELETE,
        &format!("/v1/models/{model_instance_id}"),
        None,
        Some(&node_token),
    )
    .await;
    assert_eq!(
        fail_draining.pointer("/status").and_then(Value::as_str),
        Some("draining")
    );
    let (_, draining_fail_ack) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{draining_fail_id}/fail"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("hidden-draining-fail-{suffix}"),
            "error_class": "engine",
            "error_message": "受控 draining 收口失败",
            "retryable": false
        })),
        Some(&node_token),
    )
    .await;
    assert_eq!(
        draining_fail_ack
            .pointer("/accepted")
            .and_then(Value::as_bool),
        Some(true)
    );
    let fail_instance_status: String =
        sqlx::query_scalar("SELECT status FROM model_instances WHERE id=$1")
            .bind(parse_uuid(&model_instance_id, "fail 收口模型实例"))
            .fetch_one(&pool)
            .await
            .expect("fail 终态后应能读取实例状态");
    assert_eq!(fail_instance_status, "unpublished");

    let risk_event_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM model_instance_canary_events WHERE model_instance_id=$1 ORDER BY created_at,id LIMIT 1",
    )
    .bind(parse_uuid(&model_instance_id, "隐藏评价模型实例"))
    .fetch_one(&pool)
    .await
    .expect("应存在 canary 风险事件");
    assert!(
        sqlx::query(
            "UPDATE model_instance_canary_events SET reason_code='answer_match' WHERE id=$1"
        )
        .bind(risk_event_id)
        .execute(&pool)
        .await
        .is_err(),
        "风险事件必须拒绝 UPDATE"
    );

    let hidden_uuid = parse_uuid(&hidden_id, "隐藏任务");
    let result_uuid = parse_uuid(&result_id, "隐藏任务结果");
    let financial_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM jobs WHERE id IN ($1,$2,$3,$4,$5)) + (SELECT COUNT(*) FROM receipts WHERE job_id IN ($1,$2,$3,$4,$5))",
    )
    .bind(hidden_uuid)
    .bind(result_uuid)
    .bind(expiry_uuid)
    .bind(draining_result_uuid)
    .bind(draining_fail_uuid)
    .fetch_one(&pool)
    .await
    .expect("应能确认隐藏任务不进入 jobs/receipts");
    assert_eq!(financial_rows, 0);
    let immutable_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events WHERE challenge_id IN ($1,$2,$3,$4,$5)",
    )
    .bind(hidden_uuid)
    .bind(result_uuid)
    .bind(expiry_uuid)
    .bind(draining_result_uuid)
    .bind(draining_fail_uuid)
    .fetch_one(&pool)
    .await
    .expect("隐藏结果必须有追加式审计");
    assert!(immutable_events >= 5);
    let global_samples: i32 =
        sqlx::query_scalar("SELECT evaluation_samples FROM models WHERE id=$1")
            .bind(model_id)
            .fetch_one(&pool)
            .await
            .expect("应能确认单实例自报不污染全局质量");
    assert_eq!(global_samples, 0);
}

#[tokio::test]
#[serial]
async fn private_hidden_benchmark_binds_model_rejects_replay_and_arbitrates_instances() {
    let Some(database_url) = database_url_or_skip("私有 Hidden Benchmark PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let private_directory = tempfile::Builder::new()
        .prefix(".mindone-private-catalog-integration-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应在受控 crate 目录创建私有 catalog 临时目录");
    let private_directory_path =
        fs::canonicalize(private_directory.path()).expect("私有 catalog 目录应可规范化");
    let mut expected_by_prompt = BTreeMap::new();
    let mut private_prompts = Vec::new();
    let mut catalog_entries = Vec::new();
    for index in 0..8_u32 {
        let entry_id = format!("private-entry-{suffix}-{index}");
        let prompt = format!("TEST-ONLY private model behavior probe {suffix} / {index}");
        let expected = format!("TEST-ONLY-EXPECTED-{suffix}-{index}");
        expected_by_prompt.insert(prompt.clone(), expected.clone());
        private_prompts.push(prompt.clone());
        catalog_entries.push(PrivateEvaluationCatalogEntry {
            entry_id,
            case_family: format!("private-family-{suffix}"),
            model_weights_sha256: "0".repeat(64),
            prompt,
            expected_behavior_sha256: hex::encode(Sha256::digest(expected.as_bytes())),
            inference_seed: 10_000 + index,
            max_output_tokens: 32,
        });
    }
    write_test_private_evaluation_catalog(&private_directory_path, catalog_entries);

    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("Private-Hidden-集成测试-{suffix}");
    config.evaluation_draw_denominator = 1;
    config.quality_evaluator_keys_dir = Some(private_directory_path);
    let pool = connect(&config)
        .await
        .expect("应能连接私有 Hidden Benchmark 测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("私有 Hidden Benchmark migration 应成功");
    let private_security = prepare_private_evaluation_runtime(&pool, &config)
        .await
        .expect("私有 Hidden Benchmark 启动期 key-state 应验证")
        .expect("有效签名 catalog、HMAC key 与显式预算应签发 runtime capability");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试认证配置有效"),
    );
    let state = AppState::new(pool.clone(), config, provider)
        .with_private_evaluation_security(Some(private_security));
    let app = router(state.clone()).expect("测试路由配置应有效");
    let (node_token, _, _) = login(&app, &format!("private-hidden-key-{suffix}")).await;
    let node_a = register_test_node(&app, &node_token, &format!("private-a-{suffix}")).await;
    let node_b = register_test_node(&app, &node_token, &format!("private-b-{suffix}")).await;
    heartbeat_test_node(&app, &node_token, &node_a, 20_000, 80, &[]).await;
    heartbeat_test_node(&app, &node_token, &node_b, 20_000, 80, &[]).await;
    let model_a =
        publish_test_model(&app, &node_token, &node_a, &suffix.to_string(), 1_000_000).await;
    let model_b =
        publish_test_model(&app, &node_token, &node_b, &suffix.to_string(), 1_000_000).await;
    assert_eq!(model_a.pointer("/model_id"), model_b.pointer("/model_id"));
    let model_id = parse_uuid(&value_str(&model_a, "/model_id"), "私有模型");
    let instance_a = value_str(&model_a, "/model_instance_id");
    let instance_b = value_str(&model_b, "/model_instance_id");

    let (wrong_instance_status, wrong_instance_body) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_a, "model_instance_id": instance_b})),
        Some(&node_token),
    )
    .await;
    assert_eq!(wrong_instance_status, StatusCode::NO_CONTENT);
    assert_eq!(wrong_instance_body, Value::Null);

    let first = claim_private_challenge(&app, &pool, &node_token, &node_a, &instance_a).await;
    assert!(private_prompts.contains(&first.prompt));
    let first_expected = expected_by_prompt
        .get(&first.prompt)
        .expect("私有 Prompt 必须来自签名测试 catalog")
        .clone();

    // 领取后若 canonical 模型权重被替换，原挑战必须拒绝提交；恢复原 hash 后同一
    // challenge 才能继续，证明绑定校验不是只看 worker 自报字段。
    sqlx::query("UPDATE models SET weights_hash=$2 WHERE id=$1")
        .bind(model_id)
        .bind("1".repeat(64))
        .execute(&pool)
        .await
        .expect("应能模拟领取后的模型权重替换");
    let (wrong_weights_status, wrong_weights_body) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_a,
        &first.job_id,
        &first_expected,
        format!("private-wrong-weights-{suffix}"),
    )
    .await;
    assert_eq!(wrong_weights_status, StatusCode::CONFLICT);
    assert_eq!(
        wrong_weights_body
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("model_binding_mismatch")
    );
    sqlx::query("UPDATE models SET weights_hash=$2 WHERE id=$1")
        .bind(model_id)
        .bind("0".repeat(64))
        .execute(&pool)
        .await
        .expect("应恢复测试模型 canonical 权重 hash");

    // 同账号另一节点也不能替代精确实例提交结果。
    let (wrong_submit_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_b,
        &first.job_id,
        &first_expected,
        format!("private-wrong-instance-{suffix}"),
    )
    .await;
    assert_eq!(wrong_submit_status, StatusCode::FORBIDDEN);
    let (first_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_a,
        &first.job_id,
        &first_expected,
        format!("private-correct-first-{suffix}"),
    )
    .await;
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(
        private_challenge_status(&pool, &first.job_id).await,
        "succeeded"
    );
    wait_private_challenge_cooldown().await;

    let fixed = claim_private_challenge(&app, &pool, &node_token, &node_a, &instance_a).await;
    assert_ne!(fixed.entry_commitment, first.entry_commitment);
    let fixed_expected = expected_by_prompt
        .get(&fixed.prompt)
        .expect("固定响应测试 Prompt 必须来自签名 catalog")
        .clone();
    let (fixed_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_a,
        &fixed.job_id,
        "FIXED-RESPONSE-MUST-NOT-PASS",
        format!("private-fixed-{suffix}"),
    )
    .await;
    assert_eq!(fixed_status, StatusCode::OK);
    assert_eq!(
        private_challenge_status(&pool, &fixed.job_id).await,
        "failed"
    );
    wait_private_challenge_cooldown().await;

    let replay = claim_private_challenge(&app, &pool, &node_token, &node_a, &instance_a).await;
    assert_ne!(replay.entry_commitment, first.entry_commitment);
    let (replay_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_a,
        &replay.job_id,
        &first_expected,
        format!("private-replay-{suffix}"),
    )
    .await;
    assert_eq!(replay_status, StatusCode::OK);
    assert_eq!(
        private_challenge_status(&pool, &replay.job_id).await,
        "failed"
    );

    // cooldown 对 account/device/node 任一近期领取生效；即使切换到同账号另一设备，
    // 也必须等待同一个权威 PostgreSQL 窗口，不能借换节点绕过。
    wait_private_challenge_cooldown().await;
    let peer = claim_private_challenge(&app, &pool, &node_token, &node_b, &instance_b).await;
    let peer_expected = expected_by_prompt
        .get(&peer.prompt)
        .expect("peer Prompt 必须来自签名 catalog");
    let (peer_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_b,
        &peer.job_id,
        peer_expected,
        format!("private-peer-{suffix}"),
    )
    .await;
    assert_eq!(peer_status, StatusCode::OK);
    let peer_verdict: String = sqlx::query_scalar(
        "SELECT verdict FROM model_authenticity_arbitration_events WHERE challenge_id=$1",
    )
    .bind(parse_uuid(&peer.job_id, "peer 私有挑战"))
    .fetch_one(&pool)
    .await
    .expect("跨实例不一致必须生成仲裁事件");
    assert_eq!(peer_verdict, "disputed");

    wait_private_challenge_cooldown().await;
    let corroborating =
        claim_private_challenge(&app, &pool, &node_token, &node_a, &instance_a).await;
    let corroborating_expected = expected_by_prompt
        .get(&corroborating.prompt)
        .expect("corroborating Prompt 必须来自签名 catalog");
    let (corroborating_status, _) = submit_private_challenge_result(
        &app,
        &node_token,
        &node_a,
        &corroborating.job_id,
        corroborating_expected,
        format!("private-corroborating-{suffix}"),
    )
    .await;
    assert_eq!(corroborating_status, StatusCode::OK);
    let corroborated: (String, i32, i32, i32) = sqlx::query_as(
        r#"
        SELECT verdict,observed_distinct_instances,
               passed_distinct_instances,failed_distinct_instances
        FROM model_authenticity_arbitration_events WHERE challenge_id=$1
        "#,
    )
    .bind(parse_uuid(&corroborating.job_id, "corroborated 私有挑战"))
    .fetch_one(&pool)
    .await
    .expect("两个正确实例必须形成可审计仲裁");
    assert_eq!(corroborated, ("corroborated".to_owned(), 2, 2, 0));

    // worker 主动报错和沉默超时都必须作为真实性失败进入同一个只追加仲裁流，
    // 不能通过选择 /fail 或不提交来逃避跨实例判断。
    wait_private_challenge_cooldown().await;
    let worker_failed =
        claim_private_challenge(&app, &pool, &node_token, &node_a, &instance_a).await;
    fail_test_job(
        &app,
        &node_token,
        &node_a,
        &worker_failed.job_id,
        &format!("private-worker-fail-{suffix}"),
    )
    .await;
    let worker_failure_passed: bool = sqlx::query_scalar(
        "SELECT passed FROM model_authenticity_arbitration_events WHERE challenge_id=$1",
    )
    .bind(parse_uuid(&worker_failed.job_id, "worker fail 私有挑战"))
    .fetch_one(&pool)
    .await
    .expect("worker fail 必须生成真实性仲裁事件");
    assert!(!worker_failure_passed);

    wait_private_challenge_cooldown().await;
    let timed_out = claim_private_challenge(&app, &pool, &node_token, &node_b, &instance_b).await;
    sqlx::query(
        "UPDATE model_evaluation_challenges SET lease_expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(parse_uuid(&timed_out.job_id, "超时私有挑战"))
    .execute(&pool)
    .await
    .expect("应能推进私有挑战到超时边界");
    assert!(
        sweep_expired_hidden_jobs_prepared(&state)
            .await
            .expect("超时扫描应成功")
            >= 1
    );
    let timeout_passed: bool = sqlx::query_scalar(
        "SELECT passed FROM model_authenticity_arbitration_events WHERE challenge_id=$1",
    )
    .bind(parse_uuid(&timed_out.job_id, "超时私有挑战"))
    .fetch_one(&pool)
    .await
    .expect("沉默超时必须生成真实性仲裁事件");
    assert!(!timeout_passed);

    let challenge_ids = [
        &first.job_id,
        &fixed.job_id,
        &replay.job_id,
        &peer.job_id,
        &corroborating.job_id,
        &worker_failed.job_id,
        &timed_out.job_id,
    ]
    .into_iter()
    .map(|value| parse_uuid(value, "私有挑战集合"))
    .collect::<Vec<_>>();
    let consumed_entries: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint,
               COUNT(DISTINCT private_catalog_entry_commitment)::bigint,
               COUNT(*) FILTER (WHERE private_catalog_id IS NULL
                                  AND private_catalog_entry_id IS NULL
                                  AND private_case_family IS NULL
                                  AND private_catalog_commitment IS NULL
                                  AND private_evaluator_id IS NULL
                                  AND private_evaluator_key_fingerprint IS NULL
                                  AND prompt_hash IS NULL
                                  AND expected_hash IS NULL)::bigint
        FROM model_evaluation_challenges WHERE id=ANY($1)
        "#,
    )
    .bind(&challenge_ids)
    .fetch_one(&pool)
    .await
    .expect("应能验证私有 entry 一次性消费");
    assert_eq!(consumed_entries, (7, 7, 7));
    let persisted_rows = sqlx::query_scalar::<_, String>(
        "SELECT string_agg(to_jsonb(challenge)::text, '') FROM model_evaluation_challenges challenge WHERE id=ANY($1)",
    )
    .bind(&challenge_ids)
    .fetch_one(&pool)
    .await
    .expect("应能读取私有 challenge commitment 行");
    for prompt in &private_prompts {
        assert!(
            !persisted_rows.contains(prompt),
            "数据库不得持久化私有 Prompt 明文"
        );
    }
    let financial_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM jobs WHERE id=ANY($1)) + (SELECT COUNT(*) FROM receipts WHERE job_id=ANY($1))",
    )
    .bind(&challenge_ids)
    .fetch_one(&pool)
    .await
    .expect("应能验证私有挑战零财务结算");
    assert_eq!(financial_rows, 0);
    let arbitration_event_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM model_authenticity_arbitration_events WHERE challenge_id=$1",
    )
    .bind(parse_uuid(&first.job_id, "首个私有挑战"))
    .fetch_one(&pool)
    .await
    .expect("首个私有挑战必须有仲裁事件");
    assert!(
        sqlx::query(
            "UPDATE model_authenticity_arbitration_events SET verdict='disputed' WHERE id=$1"
        )
        .bind(arbitration_event_id)
        .execute(&pool)
        .await
        .is_err(),
        "真实性仲裁事件必须拒绝 UPDATE"
    );
    let global_samples: i32 =
        sqlx::query_scalar("SELECT evaluation_samples FROM models WHERE id=$1")
            .bind(model_id)
            .fetch_one(&pool)
            .await
            .expect("应能确认私有在线挑战不直接改写 canonical 质量");
    assert_eq!(global_samples, 0);

    // 即使受信 evaluator 轮换 catalog ID、时间和签名，已经暴露过的 Prompt 或
    // expected behavior 也不能重新签发；两个旋转条目都冲突后必须明确退回 canary。
    wait_private_challenge_cooldown().await;
    write_test_private_evaluation_catalog(
        private_directory.path(),
        vec![
            PrivateEvaluationCatalogEntry {
                entry_id: format!("rotated-first-{suffix}"),
                case_family: format!("rotated-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt: first.prompt,
                expected_behavior_sha256: hex::encode(Sha256::digest(first_expected.as_bytes())),
                inference_seed: 30_001,
                max_output_tokens: 32,
            },
            PrivateEvaluationCatalogEntry {
                entry_id: format!("rotated-fixed-{suffix}"),
                case_family: format!("rotated-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt: fixed.prompt,
                expected_behavior_sha256: hex::encode(Sha256::digest(fixed_expected.as_bytes())),
                inference_seed: 30_002,
                max_output_tokens: 32,
            },
        ],
    );
    let (_, rotated_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_a, "model_instance_id": instance_a})),
        Some(&node_token),
    )
    .await;
    let rotated_job_id = parse_uuid(&value_str(&rotated_claim, "/job_id"), "轮换 catalog claim");
    let rotated_kind: String =
        sqlx::query_scalar("SELECT challenge_kind FROM model_evaluation_challenges WHERE id=$1")
            .bind(rotated_job_id)
            .fetch_one(&pool)
            .await
            .expect("轮换 catalog claim 必须有服务端挑战记录");
    assert_eq!(rotated_kind, "canary");
}

#[tokio::test]
#[serial]
async fn private_global_reserve_counts_cross_catalog_conflicts_across_two_pools() {
    let Some(database_url) =
        database_url_or_skip("private-hidden 跨 catalog reserve 双 pool PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let seed_directory = tempfile::Builder::new()
        .prefix(".mindone-private-reserve-seed-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应在受控 crate 目录创建 reserve seed catalog");
    let seed_directory_path =
        fs::canonicalize(seed_directory.path()).expect("reserve seed catalog 路径应可规范化");
    let reserve_directory = tempfile::Builder::new()
        .prefix(".mindone-private-reserve-target-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应在受控 crate 目录创建 reserve target catalog");
    let reserve_directory_path =
        fs::canonicalize(reserve_directory.path()).expect("reserve target catalog 路径应可规范化");

    let mut seed_expected_by_prompt = BTreeMap::new();
    let seed_entries = (0..2_u32)
        .map(|index| {
            let prompt = format!("TEST-ONLY reserve seed probe {suffix} / {index}");
            let expected = format!("RESERVE-SEED-EXPECTED-{suffix}-{index}");
            let expected_behavior_sha256 = hex::encode(Sha256::digest(expected.as_bytes()));
            seed_expected_by_prompt.insert(prompt.clone(), expected_behavior_sha256.clone());
            PrivateEvaluationCatalogEntry {
                entry_id: format!("reserve-seed-entry-{suffix}-{index}"),
                case_family: format!("reserve-seed-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt,
                expected_behavior_sha256,
                inference_seed: 50_000 + index,
                max_output_tokens: 32,
            }
        })
        .collect();
    write_test_private_evaluation_catalog(&seed_directory_path, seed_entries);

    let budget = PrivateEvaluationBudgetConfig {
        catalog_hourly_limit: 100,
        account_hourly_limit: 100,
        device_hourly_limit: 100,
        node_hourly_limit: 100,
        cooldown: std::time::Duration::from_secs(1),
        global_reserve_entries: 1,
    };
    let mut seed_config = Config::development_for_tests(database_url.clone());
    seed_config.dev_username = format!("Private-Reserve-Seed-集成测试-{suffix}");
    seed_config.evaluation_draw_denominator = 1;
    seed_config.quality_evaluator_keys_dir = Some(seed_directory_path);
    seed_config.private_evaluation_budget = Some(budget.clone());
    let seed_pool = connect(&seed_config)
        .await
        .expect("seed coordinator 应连接 reserve 测试数据库");
    migrate(&seed_pool, &seed_config.standard_data_key)
        .await
        .expect("reserve 测试 migration 应成功");
    let seed_security = prepare_private_evaluation_runtime(&seed_pool, &seed_config)
        .await
        .expect("seed coordinator 应通过 private runtime prepare")
        .expect("seed coordinator 应获得 issuance capability");
    let seed_provider = Arc::new(
        LocalDevelopmentProvider::new(seed_config.dev_username.clone(), seed_config.bind_addr)
            .expect("seed coordinator 测试认证配置应有效"),
    );
    let seed_app = router(
        AppState::new(seed_pool.clone(), seed_config, seed_provider)
            .with_private_evaluation_security(Some(seed_security)),
    )
    .expect("测试路由配置应有效");
    let (seed_token, _, _) = login(&seed_app, &format!("reserve-seed-device-{suffix}")).await;
    let seed_node = register_test_node(
        &seed_app,
        &seed_token,
        &format!("reserve-seed-node-{suffix}"),
    )
    .await;
    heartbeat_test_node(&seed_app, &seed_token, &seed_node, 20_000, 80, &[]).await;
    let seed_model = publish_test_model(
        &seed_app,
        &seed_token,
        &seed_node,
        &format!("reserve-seed-{suffix}"),
        1_000_000,
    )
    .await;
    let seed_claim = claim_private_challenge(
        &seed_app,
        &seed_pool,
        &seed_token,
        &seed_node,
        &value_str(&seed_model, "/model_instance_id"),
    )
    .await;
    let reused_expected = seed_expected_by_prompt
        .get(&seed_claim.prompt)
        .expect("seed claim 必须来自受信 catalog")
        .clone();

    let fresh_prompts = [
        format!("TEST-ONLY reserve fresh probe {suffix} / 1"),
        format!("TEST-ONLY reserve fresh probe {suffix} / 2"),
    ];
    write_test_private_evaluation_catalog(
        &reserve_directory_path,
        vec![
            PrivateEvaluationCatalogEntry {
                entry_id: format!("reserve-reused-entry-{suffix}"),
                case_family: format!("reserve-target-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt: seed_claim.prompt,
                expected_behavior_sha256: reused_expected,
                inference_seed: 51_000,
                max_output_tokens: 32,
            },
            PrivateEvaluationCatalogEntry {
                entry_id: format!("reserve-fresh-entry-{suffix}-1"),
                case_family: format!("reserve-target-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt: fresh_prompts[0].clone(),
                expected_behavior_sha256: hex::encode(Sha256::digest(
                    format!("RESERVE-FRESH-EXPECTED-{suffix}-1").as_bytes(),
                )),
                inference_seed: 51_001,
                max_output_tokens: 32,
            },
            PrivateEvaluationCatalogEntry {
                entry_id: format!("reserve-fresh-entry-{suffix}-2"),
                case_family: format!("reserve-target-family-{suffix}"),
                model_weights_sha256: "0".repeat(64),
                prompt: fresh_prompts[1].clone(),
                expected_behavior_sha256: hex::encode(Sha256::digest(
                    format!("RESERVE-FRESH-EXPECTED-{suffix}-2").as_bytes(),
                )),
                inference_seed: 51_002,
                max_output_tokens: 32,
            },
        ],
    );

    let mut reserve_config = Config::development_for_tests(database_url);
    reserve_config.dev_username = format!("Private-Reserve-Target-集成测试-{suffix}");
    reserve_config.evaluation_draw_denominator = 1;
    reserve_config.quality_evaluator_keys_dir = Some(reserve_directory_path);
    reserve_config.private_evaluation_budget = Some(budget);
    let reserve_pool = connect(&reserve_config)
        .await
        .expect("target coordinator 应建立独立 reserve 测试连接池");
    let reserve_security = prepare_private_evaluation_runtime(&reserve_pool, &reserve_config)
        .await
        .expect("target coordinator 应通过相同 HMAC key-state prepare")
        .expect("target coordinator 应获得 issuance capability");
    let reserve_provider = Arc::new(
        LocalDevelopmentProvider::new(
            reserve_config.dev_username.clone(),
            reserve_config.bind_addr,
        )
        .expect("target coordinator 测试认证配置应有效"),
    );
    let reserve_app = router(
        AppState::new(reserve_pool.clone(), reserve_config, reserve_provider)
            .with_private_evaluation_security(Some(reserve_security)),
    )
    .expect("测试路由配置应有效");

    let (returning_token, _, _) =
        login(&reserve_app, &format!("reserve-returning-device-{suffix}")).await;
    let returning_node = register_test_node(
        &reserve_app,
        &returning_token,
        &format!("reserve-returning-node-{suffix}"),
    )
    .await;
    heartbeat_test_node(
        &reserve_app,
        &returning_token,
        &returning_node,
        20_000,
        80,
        &[],
    )
    .await;
    let returning_model = publish_test_model(
        &reserve_app,
        &returning_token,
        &returning_node,
        &format!("reserve-returning-{suffix}"),
        1_000_000,
    )
    .await;
    let returning_instance = value_str(&returning_model, "/model_instance_id");
    let (_, first_claim) = call(
        &reserve_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": returning_node,
            "model_instance_id": returning_instance
        })),
        Some(&returning_token),
    )
    .await;
    let first_job_id = value_str(&first_claim, "/job_id");
    let first_kind: String =
        sqlx::query_scalar("SELECT challenge_kind FROM model_evaluation_challenges WHERE id=$1")
            .bind(parse_uuid(
                &first_job_id,
                "returning identity 首次 reserve claim",
            ))
            .fetch_one(&reserve_pool)
            .await
            .expect("returning identity 首次必须有 challenge 行");
    assert_eq!(first_kind, "hidden_benchmark");
    fail_test_job(
        &reserve_app,
        &returning_token,
        &returning_node,
        &first_job_id,
        &format!("reserve-returning-first-fail-{suffix}"),
    )
    .await;
    wait_private_challenge_cooldown().await;

    let issued_before_denial: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events \
         WHERE private_commitment_version=2 AND event_kind='issued'",
    )
    .fetch_one(&reserve_pool)
    .await
    .expect("应读取 reserve 拒绝前的 v2 issued 总数");
    let (_, denied_claim) = call(
        &reserve_app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": returning_node,
            "model_instance_id": returning_instance
        })),
        Some(&returning_token),
    )
    .await;
    assert_eq!(
        sorted_object_keys(&denied_claim),
        sorted_object_keys(&first_claim),
        "reserve 拒绝后的 canary 与 hidden 必须保持相同公开字段形状"
    );
    let denied_rendered = denied_claim.to_string();
    assert!(!denied_rendered.contains("reserve-target-family"));
    assert!(!denied_rendered.contains("reserve-fresh-entry"));
    for prompt in &fresh_prompts {
        assert!(!denied_rendered.contains(prompt));
    }
    let denied_job_id = value_str(&denied_claim, "/job_id");
    let denied_kind: String =
        sqlx::query_scalar("SELECT challenge_kind FROM model_evaluation_challenges WHERE id=$1")
            .bind(parse_uuid(&denied_job_id, "reserve 边界 canary claim"))
            .fetch_one(&reserve_pool)
            .await
            .expect("reserve 边界 fallback 必须有 challenge 行");
    assert_eq!(denied_kind, "canary");
    let issued_after_denial: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events \
         WHERE private_commitment_version=2 AND event_kind='issued'",
    )
    .fetch_one(&reserve_pool)
    .await
    .expect("应读取 reserve 拒绝后的 v2 issued 总数");
    assert_eq!(
        issued_after_denial, issued_before_denial,
        "returning identity 不得消费最后一个全局可发行 reserve entry"
    );

    let (fresh_token, _, _) = login(&reserve_app, &format!("reserve-fresh-device-{suffix}")).await;
    let fresh_node = register_test_node(
        &reserve_app,
        &fresh_token,
        &format!("reserve-fresh-node-{suffix}"),
    )
    .await;
    heartbeat_test_node(&reserve_app, &fresh_token, &fresh_node, 20_000, 80, &[]).await;
    let fresh_model = publish_test_model(
        &reserve_app,
        &fresh_token,
        &fresh_node,
        &format!("reserve-fresh-{suffix}"),
        1_000_000,
    )
    .await;
    let fresh_claim = claim_private_challenge(
        &reserve_app,
        &reserve_pool,
        &fresh_token,
        &fresh_node,
        &value_str(&fresh_model, "/model_instance_id"),
    )
    .await;
    assert!(
        fresh_prompts.contains(&fresh_claim.prompt),
        "全新 account/device/node 必须仍能取得为其保留的 private entry"
    );
    let issued_after_fresh_identity: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events \
         WHERE private_commitment_version=2 AND event_kind='issued'",
    )
    .fetch_one(&reserve_pool)
    .await
    .expect("应读取全新身份 claim 后的 v2 issued 总数");
    assert_eq!(issued_after_fresh_identity, issued_after_denial + 1);
}

#[tokio::test]
#[serial]
async fn private_global_reserve_serializes_overlapping_catalogs_across_two_pools() {
    let Some(database_url) = database_url_or_skip(
        "private-hidden 重叠 catalog 并发 reserve 双 pool PostgreSQL 集成测试",
    ) else {
        return;
    };
    let suffix = Uuid::now_v7();
    let catalog_b_id = format!("reserve-concurrent-b-{suffix}");
    let catalog_c_id = format!("reserve-concurrent-c-{suffix}");
    let directory_b = tempfile::Builder::new()
        .prefix(".mindone-private-reserve-concurrent-b-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应创建 concurrent reserve catalog B");
    let directory_c = tempfile::Builder::new()
        .prefix(".mindone-private-reserve-concurrent-c-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应创建 concurrent reserve catalog C");
    let directory_b_path =
        fs::canonicalize(directory_b.path()).expect("concurrent catalog B 路径应可规范化");
    let directory_c_path =
        fs::canonicalize(directory_c.path()).expect("concurrent catalog C 路径应可规范化");

    let old_entries_b = (0..2_u32)
        .map(|index| PrivateEvaluationCatalogEntry {
            entry_id: format!("reserve-concurrent-old-b-{suffix}-{index}"),
            case_family: format!("reserve-concurrent-old-family-b-{suffix}"),
            model_weights_sha256: "0".repeat(64),
            prompt: format!("TEST-ONLY concurrent old B probe {suffix} / {index}"),
            expected_behavior_sha256: hex::encode(Sha256::digest(
                format!("CONCURRENT-OLD-B-EXPECTED-{suffix}-{index}").as_bytes(),
            )),
            inference_seed: 52_000 + index,
            max_output_tokens: 32,
        })
        .collect();
    let old_entries_c = (0..2_u32)
        .map(|index| PrivateEvaluationCatalogEntry {
            entry_id: format!("reserve-concurrent-old-c-{suffix}-{index}"),
            case_family: format!("reserve-concurrent-old-family-c-{suffix}"),
            model_weights_sha256: "0".repeat(64),
            prompt: format!("TEST-ONLY concurrent old C probe {suffix} / {index}"),
            expected_behavior_sha256: hex::encode(Sha256::digest(
                format!("CONCURRENT-OLD-C-EXPECTED-{suffix}-{index}").as_bytes(),
            )),
            inference_seed: 52_100 + index,
            max_output_tokens: 32,
        })
        .collect();
    write_test_private_evaluation_catalog_with_id(&directory_b_path, &catalog_b_id, old_entries_b);
    write_test_private_evaluation_catalog_with_id(&directory_c_path, &catalog_c_id, old_entries_c);

    let budget = PrivateEvaluationBudgetConfig {
        catalog_hourly_limit: 100,
        account_hourly_limit: 100,
        device_hourly_limit: 100,
        node_hourly_limit: 100,
        cooldown: std::time::Duration::from_secs(1),
        global_reserve_entries: 1,
    };
    let mut config_b = Config::development_for_tests(database_url.clone());
    config_b.dev_username = format!("Private-Reserve-Concurrent-B-{suffix}");
    config_b.evaluation_draw_denominator = 1;
    config_b.quality_evaluator_keys_dir = Some(directory_b_path.clone());
    config_b.private_evaluation_budget = Some(budget.clone());
    let mut config_c = Config::development_for_tests(database_url);
    config_c.dev_username = format!("Private-Reserve-Concurrent-C-{suffix}");
    config_c.evaluation_draw_denominator = 1;
    config_c.quality_evaluator_keys_dir = Some(directory_c_path.clone());
    config_c.private_evaluation_budget = Some(budget);

    let pool_b = connect(&config_b)
        .await
        .expect("concurrent coordinator B 应连接测试数据库");
    migrate(&pool_b, &config_b.standard_data_key)
        .await
        .expect("concurrent reserve 测试 migration 应成功");
    let pool_c = connect(&config_c)
        .await
        .expect("concurrent coordinator C 应建立独立 PgPool");
    let security_b = prepare_private_evaluation_runtime(&pool_b, &config_b)
        .await
        .expect("concurrent coordinator B 应通过 runtime prepare")
        .expect("concurrent coordinator B 应获得 issuance capability");
    let security_c = prepare_private_evaluation_runtime(&pool_c, &config_c)
        .await
        .expect("concurrent coordinator C 应通过相同 HMAC key-state prepare")
        .expect("concurrent coordinator C 应获得 issuance capability");
    let provider_b = Arc::new(
        LocalDevelopmentProvider::new(config_b.dev_username.clone(), config_b.bind_addr)
            .expect("concurrent coordinator B 认证配置应有效"),
    );
    let provider_c = Arc::new(
        LocalDevelopmentProvider::new(config_c.dev_username.clone(), config_c.bind_addr)
            .expect("concurrent coordinator C 认证配置应有效"),
    );
    let app_b = router(
        AppState::new(pool_b.clone(), config_b, provider_b)
            .with_private_evaluation_security(Some(security_b)),
    )
    .expect("测试路由配置应有效");
    let app_c = router(
        AppState::new(pool_c.clone(), config_c, provider_c)
            .with_private_evaluation_security(Some(security_c)),
    )
    .expect("测试路由配置应有效");

    let (token_b, _, _) = login(&app_b, &format!("reserve-concurrent-device-b-{suffix}")).await;
    let (token_c, _, _) = login(&app_c, &format!("reserve-concurrent-device-c-{suffix}")).await;
    let node_b = register_test_node(
        &app_b,
        &token_b,
        &format!("reserve-concurrent-node-b-{suffix}"),
    )
    .await;
    let node_c = register_test_node(
        &app_c,
        &token_c,
        &format!("reserve-concurrent-node-c-{suffix}"),
    )
    .await;
    heartbeat_test_node(&app_b, &token_b, &node_b, 20_000, 80, &[]).await;
    heartbeat_test_node(&app_c, &token_c, &node_c, 20_000, 80, &[]).await;
    let model_b = publish_test_model(
        &app_b,
        &token_b,
        &node_b,
        &format!("rcb-{suffix}"),
        1_000_000,
    )
    .await;
    let model_c = publish_test_model(
        &app_c,
        &token_c,
        &node_c,
        &format!("rcc-{suffix}"),
        1_000_000,
    )
    .await;
    let instance_b = value_str(&model_b, "/model_instance_id");
    let instance_c = value_str(&model_c, "/model_instance_id");

    // 先在各自稳定 catalog ID 的旧 statement 下真实发行一次，使两边身份都成为
    // returning identity；随后轮换 entries 时，旧 entry 不属于新 catalog 的可用集合。
    let old_claim_b =
        claim_private_challenge(&app_b, &pool_b, &token_b, &node_b, &instance_b).await;
    let old_claim_c =
        claim_private_challenge(&app_c, &pool_c, &token_c, &node_c, &instance_c).await;
    fail_test_job(
        &app_b,
        &token_b,
        &node_b,
        &old_claim_b.job_id,
        &format!("reserve-concurrent-old-fail-b-{suffix}"),
    )
    .await;
    fail_test_job(
        &app_c,
        &token_c,
        &node_c,
        &old_claim_c.job_id,
        &format!("reserve-concurrent-old-fail-c-{suffix}"),
    )
    .await;
    wait_private_challenge_cooldown().await;

    let overlap_prompts = [
        format!("TEST-ONLY concurrent overlap probe {suffix} / 0"),
        format!("TEST-ONLY concurrent overlap probe {suffix} / 1"),
    ];
    let overlap_expected = [
        hex::encode(Sha256::digest(
            format!("CONCURRENT-OVERLAP-EXPECTED-{suffix}-0").as_bytes(),
        )),
        hex::encode(Sha256::digest(
            format!("CONCURRENT-OVERLAP-EXPECTED-{suffix}-1").as_bytes(),
        )),
    ];
    let target_entries_b = (0..2_u32)
        .map(|index| PrivateEvaluationCatalogEntry {
            entry_id: format!("reserve-concurrent-target-b-{suffix}-{index}"),
            case_family: format!("reserve-concurrent-target-family-b-{suffix}"),
            model_weights_sha256: "0".repeat(64),
            prompt: overlap_prompts[index as usize].clone(),
            expected_behavior_sha256: overlap_expected[index as usize].clone(),
            inference_seed: 53_000 + index,
            max_output_tokens: 32,
        })
        .collect();
    let target_entries_c = (0..2_u32)
        .map(|index| PrivateEvaluationCatalogEntry {
            entry_id: format!("reserve-concurrent-target-c-{suffix}-{index}"),
            case_family: format!("reserve-concurrent-target-family-c-{suffix}"),
            model_weights_sha256: "0".repeat(64),
            prompt: overlap_prompts[index as usize].clone(),
            expected_behavior_sha256: overlap_expected[index as usize].clone(),
            inference_seed: 53_100 + index,
            max_output_tokens: 32,
        })
        .collect();
    write_test_private_evaluation_catalog_with_id(
        &directory_b_path,
        &catalog_b_id,
        target_entries_b,
    );
    write_test_private_evaluation_catalog_with_id(
        &directory_c_path,
        &catalog_c_id,
        target_entries_c,
    );

    let issued_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events \
         WHERE private_commitment_version=2 AND event_kind='issued'",
    )
    .fetch_one(&pool_b)
    .await
    .expect("应读取并发 claim 前的 v2 issued 总数");

    // 先由测试事务占住生产使用的同一 advisory key，再启动两个真实 HTTP claim。
    // 只有 pg_blocking_pids 明确观察到两个 backend 都在等待该事务后才释放，避免用
    // tokio::join! 的调度巧合冒充并发证据；若生产锁 key/位置漂移，本测试会超时失败。
    const TEST_PRIVATE_RESERVE_LOCK_NAMESPACE: i32 = 0x4d4f_5052;
    const TEST_PRIVATE_RESERVE_LOCK_KEY: i32 = 0x5253_5632;
    let mut reserve_lock_tx = pool_b
        .begin()
        .await
        .expect("应开始 concurrent reserve advisory blocker 事务");
    let reserve_lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *reserve_lock_tx)
        .await
        .expect("应读取 reserve advisory blocker backend pid");
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(TEST_PRIVATE_RESERVE_LOCK_NAMESPACE)
        .bind(TEST_PRIVATE_RESERVE_LOCK_KEY)
        .execute(&mut *reserve_lock_tx)
        .await
        .expect("测试事务应持有生产 private reserve advisory key");

    let concurrent_app_b = app_b.clone();
    let concurrent_node_b = node_b.clone();
    let concurrent_instance_b = instance_b.clone();
    let concurrent_token_b = token_b.clone();
    let claim_task_b = tokio::spawn(async move {
        call_unchecked(
            &concurrent_app_b,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({
                "node_id": concurrent_node_b,
                "model_instance_id": concurrent_instance_b
            })),
            Some(&concurrent_token_b),
        )
        .await
    });
    let concurrent_app_c = app_c.clone();
    let concurrent_node_c = node_c.clone();
    let concurrent_instance_c = instance_c.clone();
    let concurrent_token_c = token_c.clone();
    let claim_task_c = tokio::spawn(async move {
        call_unchecked(
            &concurrent_app_c,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({
                "node_id": concurrent_node_c,
                "model_instance_id": concurrent_instance_c
            })),
            Some(&concurrent_token_c),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked_claims: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)::bigint
                FROM pg_stat_activity activity
                WHERE activity.pid <> pg_backend_pid()
                  AND $1 = ANY(pg_blocking_pids(activity.pid))
                "#,
            )
            .bind(reserve_lock_pid)
            .fetch_one(&pool_b)
            .await
            .expect("应检查两个 claim 的 advisory lock 等待");
            if blocked_claims >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("两个独立 PgPool 的 claim 都必须等待同一 private reserve advisory lock");
    reserve_lock_tx
        .commit()
        .await
        .expect("应释放 concurrent reserve advisory blocker");
    let (joined_b, joined_c) = tokio::join!(claim_task_b, claim_task_c);
    let (status_b, body_b) = joined_b.expect("concurrent reserve claim B 不得 panic");
    let (status_c, body_c) = joined_c.expect("concurrent reserve claim C 不得 panic");
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(status_c, StatusCode::OK);
    assert!(body_b.pointer("/error").is_none());
    assert!(body_c.pointer("/error").is_none());
    assert_eq!(
        sorted_object_keys(&body_b),
        sorted_object_keys(&body_c),
        "全局 reserve 串行化后的 hidden 与 canary 必须保持相同公开字段形状"
    );
    let rendered_b = body_b.to_string();
    let rendered_c = body_c.to_string();
    for private_value in [
        catalog_b_id.as_str(),
        catalog_c_id.as_str(),
        overlap_prompts[0].as_str(),
        overlap_prompts[1].as_str(),
    ] {
        assert!(!rendered_b.contains(private_value));
        assert!(!rendered_c.contains(private_value));
    }

    let challenge_ids = vec![
        parse_uuid(&value_str(&body_b, "/job_id"), "concurrent reserve claim B"),
        parse_uuid(&value_str(&body_c, "/job_id"), "concurrent reserve claim C"),
    ];
    let kinds: (i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FILTER (WHERE challenge_kind='hidden_benchmark')::bigint,
               COUNT(*) FILTER (WHERE challenge_kind='canary')::bigint
        FROM model_evaluation_challenges WHERE id=ANY($1)
        "#,
    )
    .bind(&challenge_ids)
    .fetch_one(&pool_c)
    .await
    .expect("应统计并发重叠 catalog 的 challenge 类型");
    assert_eq!(
        kinds,
        (1, 1),
        "remaining=2 且 reserve=1 时两个 returning identities 最多只能签发一个 hidden"
    );
    let issued_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenge_events \
         WHERE private_commitment_version=2 AND event_kind='issued'",
    )
    .fetch_one(&pool_c)
    .await
    .expect("应读取并发 claim 后的 v2 issued 总数");
    assert_eq!(
        issued_after,
        issued_before + 1,
        "全局 advisory xact lock 必须阻止第二个 pool 超发 reserve"
    );

    let persisted: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(DISTINCT challenge.id)::bigint,
               COUNT(event.id) FILTER (WHERE event.event_kind='issued')::bigint,
               COUNT(*) FILTER (
                   WHERE challenge.private_commitment_version=2
                     AND challenge.private_catalog_id IS NULL
                     AND challenge.private_catalog_entry_id IS NULL
                     AND challenge.private_case_family IS NULL
                     AND challenge.private_catalog_commitment IS NULL
                     AND challenge.private_evaluator_id IS NULL
                     AND challenge.private_evaluator_key_fingerprint IS NULL
                     AND challenge.prompt_hash IS NULL
                     AND challenge.expected_hash IS NULL
               )::bigint,
               COUNT(event.id) FILTER (
                   WHERE challenge.private_commitment_version=2
                     AND event.private_commitment_version=2
                     AND event.event_kind='issued'
               )::bigint,
               COUNT(*) FILTER (
                   WHERE challenge.challenge_kind='canary'
                     AND challenge.private_commitment_version IS NULL
                     AND challenge.private_catalog_id_commitment IS NULL
                     AND challenge.private_catalog_entry_commitment IS NULL
                     AND challenge.private_prompt_commitment IS NULL
                     AND challenge.private_expected_commitment IS NULL
               )::bigint
        FROM model_evaluation_challenges challenge
        LEFT JOIN model_evaluation_challenge_events event
          ON event.challenge_id=challenge.id AND event.event_kind='issued'
        WHERE challenge.id=ANY($1)
        "#,
    )
    .bind(&challenge_ids)
    .fetch_one(&pool_b)
    .await
    .expect("应验证并发 claim 没有 challenge/event 或 commitment 残留");
    assert_eq!(
        persisted,
        (2, 2, 1, 1, 1),
        "两个成功响应必须各有 issued event，且只有 hidden 行携带一套 v2 commitments"
    );
    let financial_rows: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM jobs WHERE id=ANY($1)) \
              + (SELECT COUNT(*) FROM receipts WHERE job_id=ANY($1))",
    )
    .bind(&challenge_ids)
    .fetch_one(&pool_c)
    .await
    .expect("应验证并发 private/canary claim 零财务副作用");
    assert_eq!(financial_rows, 0);
}

#[tokio::test]
#[serial]
async fn private_hidden_budget_serializes_two_pools_and_rolls_back_failed_issuance() {
    let Some(database_url) =
        database_url_or_skip("private-hidden 双 coordinator 预算 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let private_directory = tempfile::Builder::new()
        .prefix(".mindone-private-budget-integration-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("应在受控 crate 目录创建预算测试 catalog");
    let private_directory_path =
        fs::canonicalize(private_directory.path()).expect("预算测试 catalog 路径应可规范化");
    write_test_private_evaluation_catalog(
        &private_directory_path,
        (0..4_u32)
            .map(|index| {
                let expected = format!("BUDGET-EXPECTED-{suffix}-{index}");
                PrivateEvaluationCatalogEntry {
                    entry_id: format!("budget-entry-{suffix}-{index}"),
                    case_family: format!("budget-family-{suffix}"),
                    model_weights_sha256: "0".repeat(64),
                    prompt: format!("TEST-ONLY budget probe {suffix} / {index}"),
                    expected_behavior_sha256: hex::encode(Sha256::digest(expected.as_bytes())),
                    inference_seed: 40_000 + index,
                    max_output_tokens: 32,
                }
            })
            .collect(),
    );

    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("Private-Budget-集成测试-{suffix}");
    config.evaluation_draw_denominator = 1;
    config.quality_evaluator_keys_dir = Some(private_directory_path);
    config.private_evaluation_budget = Some(PrivateEvaluationBudgetConfig {
        catalog_hourly_limit: 100,
        account_hourly_limit: 1,
        device_hourly_limit: 100,
        node_hourly_limit: 100,
        cooldown: std::time::Duration::from_secs(1),
        global_reserve_entries: 0,
    });
    let pool_a = connect(&config)
        .await
        .expect("coordinator A 应连接预算测试数据库");
    migrate(&pool_a, &config.standard_data_key)
        .await
        .expect("预算测试 migration 应成功");
    let pool_b = connect(&config)
        .await
        .expect("coordinator B 应建立独立连接池");
    let security_a = prepare_private_evaluation_runtime(&pool_a, &config)
        .await
        .expect("coordinator A 应通过 private runtime prepare")
        .expect("coordinator A 应获得 issuance capability");
    let security_b = prepare_private_evaluation_runtime(&pool_b, &config)
        .await
        .expect("coordinator B 应通过相同 key-state prepare")
        .expect("coordinator B 应获得 issuance capability");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("预算测试认证配置应有效"),
    );
    let app_a = router(
        AppState::new(pool_a.clone(), config.clone(), provider.clone())
            .with_private_evaluation_security(Some(security_a)),
    )
    .expect("测试路由配置应有效");
    let app_b = router(
        AppState::new(pool_b.clone(), config, provider)
            .with_private_evaluation_security(Some(security_b)),
    )
    .expect("测试路由配置应有效");

    let (token_a, _, user_a) = login(&app_a, &format!("budget-device-a-{suffix}")).await;
    let (token_b, _, user_b) = login(&app_b, &format!("budget-device-b-{suffix}")).await;
    assert_ne!(user_a, user_b, "本地开发 provider 默认按设备隔离账号");
    // GitHub production provider 会把同一主体的多台设备归到同一账号；本地开发
    // provider 为测试隔离故意按设备建账号。此处在任何节点注册前，把第二个已证明
    // 私钥持有的 device/session 原子关联到账号 A，构造真实的“同账号、不同设备”。
    let user_a_uuid = parse_uuid(&user_a, "预算账号 A");
    let user_b_uuid = parse_uuid(&user_b, "预算账号 B");
    let mut device_link = pool_a.begin().await.expect("应开始同账号第二设备关联事务");
    sqlx::query("UPDATE device_keys SET user_id=$1 WHERE user_id=$2")
        .bind(user_a_uuid)
        .bind(user_b_uuid)
        .execute(&mut *device_link)
        .await
        .expect("应把第二设备关联到预算账号 A");
    sqlx::query("UPDATE sessions SET user_id=$1 WHERE user_id=$2")
        .bind(user_a_uuid)
        .bind(user_b_uuid)
        .execute(&mut *device_link)
        .await
        .expect("应把第二设备 session 关联到预算账号 A");
    device_link
        .commit()
        .await
        .expect("同账号第二设备关联事务应提交");
    let node_a = register_test_node(&app_a, &token_a, &format!("budget-node-a-{suffix}")).await;
    let node_b = register_test_node(&app_b, &token_b, &format!("budget-node-b-{suffix}")).await;
    heartbeat_test_node(&app_a, &token_a, &node_a, 20_000, 80, &[]).await;
    heartbeat_test_node(&app_b, &token_b, &node_b, 20_000, 80, &[]).await;
    let model_a =
        publish_test_model(&app_a, &token_a, &node_a, &suffix.to_string(), 1_000_000).await;
    let model_b =
        publish_test_model(&app_b, &token_b, &node_b, &suffix.to_string(), 1_000_000).await;
    assert_eq!(model_a.pointer("/model_id"), model_b.pointer("/model_id"));
    let instance_a = value_str(&model_a, "/model_instance_id");
    let instance_b = value_str(&model_b, "/model_instance_id");
    let node_a_uuid = parse_uuid(&node_a, "预算 rollback 节点");
    let node_b_uuid = parse_uuid(&node_b, "预算并发节点");

    // 测试专用 trigger 只匹配本测试 node A。它在 challenge 已插入、issued event
    // 即将写入时失败，证明 scope lock、challenge 与 event 位于同一回滚边界。
    let identifier = suffix.simple().to_string();
    let function_name = format!("test_private_fail_{}", &identifier[..16]);
    let trigger_name = format!("test_private_fail_trigger_{}", &identifier[..12]);
    let create_function = format!(
        r#"
        CREATE FUNCTION {function_name}() RETURNS trigger AS $$
        BEGIN
            IF NEW.private_commitment_version=2 AND EXISTS (
                SELECT 1 FROM model_evaluation_challenges
                WHERE id=NEW.challenge_id AND node_id='{node_a_uuid}'::uuid
            ) THEN
                RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='test private issued rollback';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        "#,
    );
    sqlx::query(&create_function)
        .execute(&pool_a)
        .await
        .expect("应创建范围受限的 rollback 测试函数");
    let create_trigger = format!(
        "CREATE TRIGGER {trigger_name} BEFORE INSERT ON model_evaluation_challenge_events \
         FOR EACH ROW EXECUTE FUNCTION {function_name}()"
    );
    sqlx::query(&create_trigger)
        .execute(&pool_a)
        .await
        .expect("应创建 rollback 测试 trigger");
    let scopes_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM private_evaluation_budget_scopes")
            .fetch_one(&pool_a)
            .await
            .expect("应读取 rollback 前 scope 数量");
    let (rollback_status, rollback_body) = call_unchecked(
        &app_a,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_a, "model_instance_id": instance_a})),
        Some(&token_a),
    )
    .await;
    let drop_trigger =
        format!("DROP TRIGGER IF EXISTS {trigger_name} ON model_evaluation_challenge_events");
    sqlx::query(&drop_trigger)
        .execute(&pool_a)
        .await
        .expect("应移除 rollback 测试 trigger");
    let drop_function = format!("DROP FUNCTION IF EXISTS {function_name}()");
    sqlx::query(&drop_function)
        .execute(&pool_a)
        .await
        .expect("应移除 rollback 测试函数");
    assert_eq!(rollback_status, StatusCode::INTERNAL_SERVER_ERROR);
    let rollback_rendered = rollback_body.to_string();
    assert!(!rollback_rendered.contains("test private issued rollback"));
    assert!(!rollback_rendered.contains("budget-entry"));
    assert!(!rollback_rendered.contains("TEST-ONLY budget probe"));
    let rollback_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM model_evaluation_challenges WHERE node_id=$1",
    )
    .bind(node_a_uuid)
    .fetch_one(&pool_a)
    .await
    .expect("应检查失败 issuance 的 challenge 回滚");
    assert_eq!(rollback_rows, 0);
    let scopes_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM private_evaluation_budget_scopes")
            .fetch_one(&pool_a)
            .await
            .expect("应读取 rollback 后 scope 数量");
    assert_eq!(
        scopes_after, scopes_before,
        "失败 issuance 不得遗留 scope lock 行"
    );

    let claim_a = call_unchecked(
        &app_a,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_a, "model_instance_id": instance_a})),
        Some(&token_a),
    );
    let claim_b = call_unchecked(
        &app_b,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_b, "model_instance_id": instance_b})),
        Some(&token_b),
    );
    let ((status_a, body_a), (status_b, body_b)) = tokio::join!(claim_a, claim_b);
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(
        body_a
            .as_object()
            .map(|value| value.keys().collect::<Vec<_>>()),
        body_b
            .as_object()
            .map(|value| value.keys().collect::<Vec<_>>()),
        "hidden 与预算拒绝后的 canary 必须保持相同公开字段形状"
    );

    let nodes = vec![node_a_uuid, node_b_uuid];
    let kinds: (i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FILTER (WHERE challenge_kind='hidden_benchmark')::bigint,
               COUNT(*) FILTER (WHERE challenge_kind='canary')::bigint
        FROM model_evaluation_challenges WHERE node_id=ANY($1)
        "#,
    )
    .bind(&nodes)
    .fetch_one(&pool_a)
    .await
    .expect("应统计双 pool 并发 challenge 类型");
    assert_eq!(
        kinds,
        (1, 1),
        "account cap=1 必须精确签发一个 private hidden"
    );
    let issued_v2: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM model_evaluation_challenge_events event
        JOIN model_evaluation_challenges challenge ON challenge.id=event.challenge_id
        WHERE challenge.node_id=ANY($1) AND event.event_kind='issued'
          AND event.private_commitment_version=2
        "#,
    )
    .bind(&nodes)
    .fetch_one(&pool_b)
    .await
    .expect("应从独立 pool 读取权威 issued event 数量");
    assert_eq!(
        issued_v2, 1,
        "并发 coordinator 不得超发第二个 issued v2 event"
    );
    let private_shape: (i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint,
               COUNT(*) FILTER (
                   WHERE private_catalog_id IS NULL
                     AND private_catalog_entry_id IS NULL
                     AND private_case_family IS NULL
                     AND private_catalog_commitment IS NULL
                     AND private_evaluator_id IS NULL
                     AND private_evaluator_key_fingerprint IS NULL
                     AND prompt_hash IS NULL AND expected_hash IS NULL
                     AND private_catalog_valid_until IS NOT NULL
               )::bigint
        FROM model_evaluation_challenges
        WHERE node_id=ANY($1) AND private_commitment_version=2
        "#,
    )
    .bind(&nodes)
    .fetch_one(&pool_a)
    .await
    .expect("应验证并发 private row 不落 raw identifier 或 bare SHA");
    assert_eq!(private_shape, (1, 1));
}

#[tokio::test]
#[serial]
async fn regulated_e2ee_route_is_one_time_bound_opaque_and_capacity_safe() {
    let Some(database_url) = database_url_or_skip("Regulated E2EE PostgreSQL 集成测试") else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("Regulated-E2EE-集成测试-{suffix}");
    let pool = connect(&config)
        .await
        .expect("应能连接 Regulated E2EE 集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("Regulated E2EE 数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");

    let (consumer_token, _, consumer_user_id) =
        login(&app, &format!("regulated-consumer-public-key-{suffix}")).await;
    let (full_node_token, _, _) =
        login(&app, &format!("regulated-full-node-public-key-{suffix}")).await;
    let full_node_id =
        register_test_node(&app, &full_node_token, &format!("regulated-full-{suffix}")).await;
    heartbeat_test_node(&app, &full_node_token, &full_node_id, 20_000, 80, &[]).await;
    sqlx::query("UPDATE node_policies SET max_concurrent = 1 WHERE node_id = $1")
        .bind(parse_uuid(&full_node_id, "满载节点"))
        .execute(&pool)
        .await
        .expect("应能把满载测试节点容量设为一");
    let full_model = publish_test_model(
        &app,
        &full_node_token,
        &full_node_id,
        &format!("regulated-{suffix}"),
        1_000_000,
    )
    .await;
    let model_name = format!("model-regulated-{suffix}");
    let model_id = value_str(&full_model, "/model_id");
    let full_model_instance_id = value_str(&full_model, "/model_instance_id");
    let full_report_id = install_verified_tee_report(
        &pool,
        parse_uuid(&full_node_id, "满载节点"),
        parse_uuid(&full_model_instance_id, "满载模型实例"),
        "22".repeat(32),
    )
    .await;
    let reregistered_full_node =
        register_test_node(&app, &full_node_token, &format!("regulated-full-{suffix}")).await;
    assert_eq!(reregistered_full_node, full_node_id);
    let preserved_trust =
        sqlx::query("SELECT trust_level,attestation_report_id FROM nodes WHERE id = $1")
            .bind(parse_uuid(&full_node_id, "满载节点"))
            .fetch_one(&pool)
            .await
            .expect("应能检查重复注册后的硬件信任");
    assert_eq!(
        preserved_trust
            .try_get::<String, _>("trust_level")
            .expect("应包含信任等级"),
        "enhanced"
    );
    assert_eq!(
        preserved_trust
            .try_get::<Option<Uuid>, _>("attestation_report_id")
            .expect("应包含证明绑定"),
        Some(full_report_id)
    );
    heartbeat_test_node(&app, &full_node_token, &full_node_id, 20_000, 80, &[]).await;
    sqlx::query("UPDATE node_policies SET max_concurrent = 1 WHERE node_id = $1")
        .bind(parse_uuid(&full_node_id, "满载节点"))
        .execute(&pool)
        .await
        .expect("重复注册后应能恢复满载测试容量策略");

    // 先真实领取一个 Standard 任务占满节点，证明 prepare 会把 leased 任务计入容量，
    // 而不会因为节点是 Enhanced 就超额承诺 Regulated route。
    let capacity_job_id = create_test_job(
        &app,
        &consumer_token,
        &model_name,
        &["capacity"],
        &format!("regulated-capacity-{suffix}"),
    )
    .await;
    let (_, capacity_claim) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": full_node_id, "model_instance_id": full_model_instance_id})),
        Some(&full_node_token),
    )
    .await;
    assert_eq!(value_str(&capacity_claim, "/job_id"), capacity_job_id);
    let prepare_body = json!({
        "virtual_model": model_name,
        "tags": ["regulated"],
        "estimated_input_tokens": 8,
        "max_output_tokens": 8,
        "idempotency_key": format!("regulated-prepare-{suffix}"),
        "priority": 0
    });
    let (full_status, full_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body.clone()),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(full_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        full_error.pointer("/code").and_then(Value::as_i64),
        Some(30)
    );
    assert_eq!(
        full_error.pointer("/error/type").and_then(Value::as_str),
        Some("attestation_failed")
    );

    let (free_node_token, _, _) =
        login(&app, &format!("regulated-free-node-public-key-{suffix}")).await;
    let free_node_id =
        register_test_node(&app, &free_node_token, &format!("regulated-free-{suffix}")).await;
    heartbeat_test_node(&app, &free_node_token, &free_node_id, 30_000, 40, &[]).await;
    sqlx::query("UPDATE node_policies SET max_concurrent = 1 WHERE node_id = $1")
        .bind(parse_uuid(&free_node_id, "空闲节点"))
        .execute(&pool)
        .await
        .expect("应能把空闲测试节点容量设为一");
    let (free_arbitrary_cost_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": free_node_id,
            "name": format!("model-regulated-{suffix}"),
            "alias": format!("instance-regulated-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "base_cost_per_1k_micro": 9_999_999,
            "tags": ["test"]
        })),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(free_arbitrary_cost_status, StatusCode::BAD_REQUEST);
    let free_model = publish_test_model(
        &app,
        &free_node_token,
        &free_node_id,
        &format!("regulated-{suffix}"),
        1_000_000,
    )
    .await;
    assert_eq!(value_str(&free_model, "/model_id"), model_id);
    let free_model_instance_id = value_str(&free_model, "/model_instance_id");
    let free_report_id = install_verified_tee_report(
        &pool,
        parse_uuid(&free_node_id, "空闲节点"),
        parse_uuid(&free_model_instance_id, "空闲模型实例"),
        "33".repeat(32),
    )
    .await;

    let (_, prepared) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body.clone()),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(value_str(&prepared, "/node_id"), free_node_id);
    assert_eq!(
        value_str(&prepared, "/model_instance_id"),
        free_model_instance_id
    );
    assert_eq!(
        value_str(&prepared, "/attestation/report_id"),
        free_report_id.to_string()
    );
    assert_eq!(
        prepared
            .pointer("/attestation/ephemeral_public_key")
            .and_then(Value::as_str),
        Some("3333333333333333333333333333333333333333333333333333333333333333")
    );
    let route_id = value_str(&prepared, "/route_id");
    let (_, prepared_replay) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(value_str(&prepared_replay, "/route_id"), route_id);
    assert_eq!(
        prepared_replay
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let mut changed_prepare =
        prepare_body_for_fingerprint_test(&model_name, &format!("regulated-prepare-{suffix}"));
    changed_prepare["tags"] = json!(["regulated", "changed"]);
    let (changed_prepare_status, changed_prepare_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(changed_prepare),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(changed_prepare_status, StatusCode::CONFLICT);
    assert_eq!(
        changed_prepare_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );

    // prepare 只预留路由槽位，不预留额度。先清掉用于满载验证的 Standard 任务。
    fail_test_job(
        &app,
        &full_node_token,
        &full_node_id,
        &capacity_job_id,
        &format!("regulated-capacity-fail-{suffix}"),
    )
    .await;
    let reserved_before_create: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(parse_uuid(&consumer_user_id, "消费者"))
            .fetch_one(&pool)
            .await
            .expect("应能读取创建前 reservation");
    assert_eq!(reserved_before_create, 0);

    let route_uuid = parse_uuid(&route_id, "Regulated route");
    let instance_uuid = parse_uuid(&free_model_instance_id, "空闲模型实例");
    let request_envelope = regulated_envelope(
        route_uuid,
        free_report_id,
        instance_uuid,
        "request",
        &"11".repeat(32),
        7,
    );
    let (report_mismatch_status, report_mismatch) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": route_uuid,
            "envelope": regulated_envelope(
                route_uuid,
                Uuid::now_v7(),
                instance_uuid,
                "request",
                &"11".repeat(32),
                8,
            ),
            "idempotency_key": format!("regulated-report-mismatch-{suffix}")
        })),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(report_mismatch_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        report_mismatch.pointer("/code").and_then(Value::as_i64),
        Some(30)
    );
    let reserved_after_mismatch: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(parse_uuid(&consumer_user_id, "消费者"))
            .fetch_one(&pool)
            .await
            .expect("应能读取报告不匹配后的 reservation");
    assert_eq!(reserved_after_mismatch, reserved_before_create);

    let create_body = json!({
        "route_id": route_uuid,
        "envelope": request_envelope,
        "idempotency_key": format!("regulated-create-{suffix}")
    });
    let (_, created) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(create_body.clone()),
        Some(&consumer_token),
    )
    .await;
    let job_id = value_str(&created, "/job_id");
    assert_eq!(
        created
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(false)
    );
    let (_, create_replay) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(create_body),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(value_str(&create_replay, "/job_id"), job_id);
    assert_eq!(
        create_replay
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(true)
    );
    let (changed_create_status, changed_create_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": route_uuid,
            "envelope": regulated_envelope(
                route_uuid,
                free_report_id,
                instance_uuid,
                "request",
                &"11".repeat(32),
                99,
            ),
            "idempotency_key": format!("regulated-create-{suffix}")
        })),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(changed_create_status, StatusCode::CONFLICT);
    assert_eq!(
        changed_create_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("idempotency_binding_mismatch")
    );
    let (route_replay_status, route_replay) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": route_uuid,
            "envelope": regulated_envelope(
                route_uuid,
                free_report_id,
                instance_uuid,
                "request",
                &"44".repeat(32),
                9,
            ),
            "idempotency_key": format!("regulated-route-replay-{suffix}")
        })),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(route_replay_status, StatusCode::CONFLICT);
    assert_eq!(
        route_replay.pointer("/error/type").and_then(Value::as_str),
        Some("regulated_route_replay")
    );
    let route_job_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM jobs WHERE regulated_route_id = $1")
            .bind(route_uuid)
            .fetch_one(&pool)
            .await
            .expect("应能统计 route 对应任务数");
    assert_eq!(route_job_count, 1, "一次性 route 不得创建第二个任务");

    let sentinel = format!("绝不能进入协调器数据库的明文-{suffix}");
    let stored_payload: String =
        sqlx::query_scalar("SELECT encrypted_payload FROM jobs WHERE id = $1")
            .bind(parse_uuid(&job_id, "Regulated 任务"))
            .fetch_one(&pool)
            .await
            .expect("应能读取 opaque envelope");
    assert!(!stored_payload.contains(&sentinel));
    let stored: Value =
        serde_json::from_str(&stored_payload).expect("数据库只应保存严格 envelope JSON");
    assert!(stored.get("ciphertext").is_some());
    assert!(stored.get("prompt").is_none());
    assert!(stored.get("messages").is_none());

    let (wrong_node_status, _) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": full_node_id, "model_instance_id": full_model_instance_id})),
        Some(&full_node_token),
    )
    .await;
    assert_eq!(wrong_node_status, StatusCode::NO_CONTENT);
    let (_, claimed) = call(
        &app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": free_node_id, "model_instance_id": free_model_instance_id})),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(value_str(&claimed, "/job_id"), job_id);
    assert_eq!(
        claimed.pointer("/confidentiality").and_then(Value::as_str),
        Some("regulated")
    );
    assert_eq!(value_str(&claimed, "/regulated_route_id"), route_id);
    assert_eq!(
        claimed.pointer("/tee_public_key").and_then(Value::as_str),
        Some("3333333333333333333333333333333333333333333333333333333333333333")
    );

    let (wrong_result_status, wrong_result) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{job_id}/result"),
        Some(json!({
            "node_id": free_node_id,
            "idempotency_key": format!("regulated-wrong-result-{suffix}"),
            "result_ciphertext": regulated_envelope(
                Uuid::now_v7(),
                free_report_id,
                instance_uuid,
                "result",
                &"33".repeat(32),
                10,
            ).to_string(),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(wrong_result_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        wrong_result.pointer("/code").and_then(Value::as_i64),
        Some(30)
    );

    let result_envelope = regulated_envelope(
        route_uuid,
        free_report_id,
        instance_uuid,
        "result",
        &"33".repeat(32),
        11,
    );
    let (_, settled) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{job_id}/result"),
        Some(json!({
            "node_id": free_node_id,
            "idempotency_key": format!("regulated-result-{suffix}"),
            "result_ciphertext": result_envelope.to_string(),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(value_str(&settled, "/job_id"), job_id);
    let (_, completed) = call(
        &app,
        Method::GET,
        &format!("/v1/jobs/{job_id}"),
        None,
        Some(&consumer_token),
    )
    .await;
    assert_eq!(
        completed.pointer("/status").and_then(Value::as_str),
        Some("succeeded")
    );
    let returned_envelope: Value = serde_json::from_str(
        completed
            .pointer("/result_ciphertext")
            .and_then(Value::as_str)
            .expect("消费者应收到仍为 opaque 的结果 envelope"),
    )
    .expect("结果应为严格 envelope JSON");
    assert_eq!(returned_envelope, result_envelope);

    // Regulated 任务领取后若硬件信任过期，续租必须在同一事务内终止任务、
    // 释放 reservation，且不得扣款或生成 receipt。
    let consumer_uuid = parse_uuid(&consumer_user_id, "消费者");
    let spendable_before_renew_failure: i64 =
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id = $1")
            .bind(consumer_uuid)
            .fetch_one(&pool)
            .await
            .expect("应能读取续租信任失效前余额");
    let (renew_failure_job_id, _, _, _) = prepare_create_claim_regulated_job(
        &app,
        &consumer_token,
        &free_node_token,
        &free_node_id,
        &model_name,
        &format!("regulated-renew-failure-{suffix}"),
        31,
    )
    .await;
    let reserved_during_renew_failure: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(consumer_uuid)
            .fetch_one(&pool)
            .await
            .expect("应能读取续租信任失效前 reservation");
    assert!(reserved_during_renew_failure > 0);
    sqlx::query("UPDATE nodes SET trust_expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(parse_uuid(&free_node_id, "空闲节点"))
        .execute(&pool)
        .await
        .expect("应能模拟租约领取后硬件信任过期");
    let (renew_failure_status, renew_failure_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{renew_failure_job_id}/renew"),
        Some(json!({"node_id": free_node_id})),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(renew_failure_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        renew_failure_error.pointer("/code").and_then(Value::as_i64),
        Some(30)
    );
    assert_regulated_attestation_failure_is_atomic(
        &pool,
        consumer_uuid,
        parse_uuid(&renew_failure_job_id, "续租信任失效任务"),
        spendable_before_renew_failure,
    )
    .await;

    // 恢复一个新的已验证报告，再证明结果提交路径也执行相同的原子失败语义。
    install_verified_tee_report(
        &pool,
        parse_uuid(&free_node_id, "空闲节点"),
        instance_uuid,
        "33".repeat(32),
    )
    .await;
    let spendable_before_result_failure: i64 =
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id = $1")
            .bind(consumer_uuid)
            .fetch_one(&pool)
            .await
            .expect("应能读取结果信任失效前余额");
    let (
        result_failure_job_id,
        result_failure_route,
        result_failure_report,
        result_failure_instance,
    ) = prepare_create_claim_regulated_job(
        &app,
        &consumer_token,
        &free_node_token,
        &free_node_id,
        &model_name,
        &format!("regulated-result-failure-{suffix}"),
        41,
    )
    .await;
    sqlx::query("UPDATE nodes SET attestation_report_id = NULL WHERE id = $1")
        .bind(parse_uuid(&free_node_id, "空闲节点"))
        .execute(&pool)
        .await
        .expect("应能模拟租约领取后节点报告解绑");
    let (result_failure_status, result_failure_error) = call_unchecked(
        &app,
        Method::POST,
        &format!("/v1/jobs/{result_failure_job_id}/result"),
        Some(json!({
            "node_id": free_node_id,
            "idempotency_key": format!("regulated-result-attestation-failure-{suffix}"),
            "result_ciphertext": regulated_envelope(
                result_failure_route,
                result_failure_report,
                result_failure_instance,
                "result",
                &"33".repeat(32),
                42,
            ).to_string(),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&free_node_token),
    )
    .await;
    assert_eq!(result_failure_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        result_failure_error
            .pointer("/code")
            .and_then(Value::as_i64),
        Some(30)
    );
    assert_regulated_attestation_failure_is_atomic(
        &pool,
        consumer_uuid,
        parse_uuid(&result_failure_job_id, "结果信任失效任务"),
        spendable_before_result_failure,
    )
    .await;

    // 后续过期 route 场景仍需要一个当前有效的节点报告。
    sqlx::query(
        "UPDATE nodes SET attestation_report_id = $2,trust_expires_at = now() + interval '1 hour' WHERE id = $1",
    )
    .bind(parse_uuid(&free_node_id, "空闲节点"))
    .bind(result_failure_report)
    .execute(&pool)
    .await
    .expect("应能恢复节点当前报告用于后续 route 过期测试");

    // 已过期 route 必须 fail closed，且在创建 jobs/reservation 之前结束。
    let expiry_prepare_body = json!({
        "virtual_model": model_name,
        "tags": ["regulated"],
        "estimated_input_tokens": 4,
        "max_output_tokens": 4,
        "idempotency_key": format!("regulated-expiry-prepare-{suffix}"),
        "priority": 0
    });
    let (_, expiry_prepared) = call(
        &app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(expiry_prepare_body),
        Some(&consumer_token),
    )
    .await;
    let expiry_route = parse_uuid(&value_str(&expiry_prepared, "/route_id"), "过期 route");
    let expiry_report = parse_uuid(
        &value_str(&expiry_prepared, "/attestation/report_id"),
        "过期 route 报告",
    );
    let expiry_instance = parse_uuid(
        &value_str(&expiry_prepared, "/model_instance_id"),
        "过期 route 模型实例",
    );
    sqlx::query(
        "UPDATE regulated_routes SET prepared_at = now() - interval '5 minutes', expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(expiry_route)
    .execute(&pool)
    .await
    .expect("应能模拟 prepared route 过期");
    let reserved_before_expired_create: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(parse_uuid(&consumer_user_id, "消费者"))
            .fetch_one(&pool)
            .await
            .expect("应能读取过期创建前 reservation");
    let (expired_status, expired_error) = call_unchecked(
        &app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": expiry_route,
            "envelope": regulated_envelope(
                expiry_route,
                expiry_report,
                expiry_instance,
                "request",
                &"55".repeat(32),
                12,
            ),
            "idempotency_key": format!("regulated-expired-create-{suffix}")
        })),
        Some(&consumer_token),
    )
    .await;
    assert_eq!(expired_status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        expired_error.pointer("/code").and_then(Value::as_i64),
        Some(30)
    );
    let expired_job_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM jobs WHERE regulated_route_id = $1")
            .bind(expiry_route)
            .fetch_one(&pool)
            .await
            .expect("应能确认过期 route 没有任务");
    assert_eq!(expired_job_count, 0);
    let reserved_after_expired_create: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(parse_uuid(&consumer_user_id, "消费者"))
            .fetch_one(&pool)
            .await
            .expect("应能读取过期创建后的 reservation");
    assert_eq!(
        reserved_after_expired_create,
        reserved_before_expired_create
    );
}

#[tokio::test]
#[serial]
async fn inference_api_key_and_openai_gateway_complete_real_standard_job() {
    let Some(database_url) = database_url_or_skip("API Key 与 OpenAI 网关 PostgreSQL 集成测试")
    else {
        return;
    };
    let suffix = Uuid::now_v7();
    let mut config = Config::development_for_tests(database_url);
    config.dev_username = format!("OpenAI-Gateway-集成测试-{suffix}");
    let pool = connect(&config)
        .await
        .expect("应能连接 OpenAI 网关集成测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("OpenAI 网关数据库迁移应成功");
    let provider = Arc::new(
        LocalDevelopmentProvider::new(config.dev_username.clone(), config.bind_addr)
            .expect("测试配置必须使用 loopback 本地认证"),
    );
    let app = router(AppState::new(pool.clone(), config, provider)).expect("测试路由配置应有效");
    let (session_token, _, _) = login(&app, &format!("gateway-user-{suffix}")).await;
    let node_id = register_test_node(&app, &session_token, &format!("gateway-{suffix}")).await;
    heartbeat_test_node(&app, &session_token, &node_id, 20_000, 80, &[]).await;
    let published = publish_test_model(
        &app,
        &session_token,
        &node_id,
        &format!("gateway-{suffix}"),
        1_000_000,
    )
    .await;
    let model_instance_id = value_str(&published, "/model_instance_id");
    let model_name = format!("model-gateway-{suffix}");

    let (_, created_key) = call(
        &app,
        Method::POST,
        "/v1/api-keys",
        Some(json!({"name": format!("gateway-{suffix}")})),
        Some(&session_token),
    )
    .await;
    let api_key = value_str(&created_key, "/api_key");
    let api_key_id = value_str(&created_key, "/record/id");
    assert!(api_key.starts_with("mok_"));

    let (_, listed) = call(
        &app,
        Method::GET,
        "/v1/api-keys",
        None,
        Some(&session_token),
    )
    .await;
    assert_eq!(
        listed.pointer("/data/0/id").and_then(Value::as_str),
        Some(api_key_id.as_str())
    );
    assert!(listed.pointer("/data/0/api_key").is_none());
    let (management_status, _) =
        call_unchecked(&app, Method::GET, "/v1/quota/balance", None, Some(&api_key)).await;
    assert_eq!(management_status, StatusCode::UNAUTHORIZED);

    let (_, models) = call(&app, Method::GET, "/v1/models", None, Some(&api_key)).await;
    let identifiers = models
        .pointer("/data")
        .and_then(Value::as_array)
        .expect("OpenAI models.data 应为数组")
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert!(identifiers.contains(&model_name.as_str()));
    assert!(identifiers.contains(&format!("{model_name}-fast").as_str()));
    assert!(identifiers.contains(&format!("{model_name}-slow").as_str()));

    let stream_app = app.clone();
    let stream_api_key = api_key.clone();
    let stream_model = model_name.clone();
    let stream_call = tokio::spawn(async move {
        call_sse_unchecked(
            &stream_app,
            "/v1/chat/completions",
            json!({
                "model": stream_model,
                "messages": [{"role": "user", "content": "real gateway stream"}],
                "max_tokens": 8,
                "stream": true
            }),
            &stream_api_key,
        )
        .await
    });
    let stream_claimed =
        claim_gateway_job(&app, &session_token, &node_id, &model_instance_id).await;
    let stream_job_id = value_str(&stream_claimed, "/job_id");
    let stream_data = json!({
        "id": "chatcmpl-public-gateway",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": model_name,
        "choices": [{
            "index": 0,
            "delta": {"content": "stream-ok"},
            "finish_reason": null
        }]
    })
    .to_string();
    call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{stream_job_id}/stream"),
        Some(json!({
            "node_id": node_id,
            "attempt": 1,
            "sequence": 0,
            "idempotency_key": format!("gateway-stream-data-{suffix}"),
            "kind": "data",
            "event_data": stream_data
        })),
        Some(&session_token),
    )
    .await;
    call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{stream_job_id}/stream"),
        Some(json!({
            "node_id": node_id,
            "attempt": 1,
            "sequence": 1,
            "idempotency_key": format!("gateway-stream-done-{suffix}"),
            "kind": "upstream_done"
        })),
        Some(&session_token),
    )
    .await;
    call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{stream_job_id}/result"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("gateway-stream-result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext_with_content(
                &model_name,
                1,
                1,
                "stream-ok"
            ),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&session_token),
    )
    .await;
    let (stream_status, stream_headers, stream_body) =
        stream_call.await.expect("流式网关任务不应 panic");
    assert_eq!(stream_status, StatusCode::OK);
    assert_eq!(
        stream_headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream; charset=utf-8")
    );
    assert!(stream_body.contains(&format!("id: 0\ndata: {stream_data}\n\n")));
    assert_eq!(stream_body.matches("data: [DONE]").count(), 1);
    assert!(
        stream_body.find("stream-ok").expect("SSE 应包含真实增量")
            < stream_body.find("data: [DONE]").expect("SSE 应终止")
    );
    let stream_ciphertext: String = sqlx::query_scalar(
        "SELECT event_ciphertext FROM job_stream_events WHERE job_id=$1 AND event_kind='data'",
    )
    .bind(parse_uuid(&stream_job_id, "流式网关任务"))
    .fetch_one(&pool)
    .await
    .expect("应读取流式网关密文事件");
    assert!(stream_ciphertext.starts_with(ENVELOPE_PREFIX));
    assert!(!stream_ciphertext.contains("stream-ok"));

    let gateway_app = app.clone();
    let gateway_api_key = api_key.clone();
    let gateway_model = model_name.clone();
    let gateway_call = tokio::spawn(async move {
        call_unchecked(
            &gateway_app,
            Method::POST,
            "/v1/chat/completions",
            Some(json!({
                "model": format!("{gateway_model}-fast"),
                "messages": [{"role": "user", "content": "real gateway job"}],
                "max_tokens": 8,
                "stream": false
            })),
            Some(&gateway_api_key),
        )
        .await
    });
    let claimed = claim_gateway_job(&app, &session_token, &node_id, &model_instance_id).await;
    let job_id = value_str(&claimed, "/job_id");
    let (_, settled) = call(
        &app,
        Method::POST,
        &format!("/v1/jobs/{job_id}/result"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": format!("gateway-result-{suffix}"),
            "result_ciphertext": standard_result_ciphertext_with_content(
                &format!("{model_name}-fast"),
                1,
                1,
                "gateway-ok"
            ),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(&session_token),
    )
    .await;
    assert_eq!(
        settled.pointer("/status").and_then(Value::as_str),
        Some("succeeded")
    );
    let (gateway_status, gateway_response) = gateway_call.await.expect("网关任务不应 panic");
    assert_eq!(gateway_status, StatusCode::OK);
    assert_eq!(
        gateway_response
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str),
        Some("gateway-ok")
    );
    let persisted_speed: String = sqlx::query_scalar("SELECT speed_class FROM jobs WHERE id=$1")
        .bind(parse_uuid(&job_id, "网关任务"))
        .fetch_one(&pool)
        .await
        .expect("应读取网关任务速度档");
    assert_eq!(persisted_speed, "fast");

    let (_, revoked) = call(
        &app,
        Method::DELETE,
        &format!("/v1/api-keys/{api_key_id}"),
        None,
        Some(&session_token),
    )
    .await;
    assert_eq!(
        revoked.pointer("/revoked").and_then(Value::as_bool),
        Some(true)
    );
    let (revoked_status, _) =
        call_unchecked(&app, Method::GET, "/v1/models", None, Some(&api_key)).await;
    assert_eq!(revoked_status, StatusCode::UNAUTHORIZED);
    let event_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM inference_api_key_events WHERE api_key_id=$1",
    )
    .bind(parse_uuid(&api_key_id, "API Key"))
    .fetch_one(&pool)
    .await
    .expect("应读取 API Key 追加式审计事件");
    assert_eq!(event_count, 2);
}

async fn prepare_create_claim_regulated_job(
    app: &axum::Router,
    consumer_token: &str,
    node_token: &str,
    node_id: &str,
    model_name: &str,
    idempotency_prefix: &str,
    seed: u8,
) -> (String, Uuid, Uuid, Uuid) {
    let (_, prepared) = call(
        app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(json!({
            "virtual_model": model_name,
            "tags": ["regulated", "lease-revalidation"],
            "estimated_input_tokens": 4,
            "max_output_tokens": 4,
            "idempotency_key": format!("{idempotency_prefix}-prepare"),
            "priority": 0
        })),
        Some(consumer_token),
    )
    .await;
    let route_id = parse_uuid(&value_str(&prepared, "/route_id"), "Regulated route");
    let report_id = parse_uuid(
        &value_str(&prepared, "/attestation/report_id"),
        "Regulated report",
    );
    let model_instance_id = parse_uuid(
        &value_str(&prepared, "/model_instance_id"),
        "Regulated model instance",
    );
    let (_, created) = call(
        app,
        Method::POST,
        "/v1/jobs/regulated",
        Some(json!({
            "route_id": route_id,
            "envelope": regulated_envelope(
                route_id,
                report_id,
                model_instance_id,
                "request",
                &"11".repeat(32),
                seed,
            ),
            "idempotency_key": format!("{idempotency_prefix}-create")
        })),
        Some(consumer_token),
    )
    .await;
    let job_id = value_str(&created, "/job_id");
    let (_, claimed) = call(
        app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({"node_id": node_id, "model_instance_id": model_instance_id})),
        Some(node_token),
    )
    .await;
    assert_eq!(value_str(&claimed, "/job_id"), job_id);
    (job_id, route_id, report_id, model_instance_id)
}

async fn assert_regulated_attestation_failure_is_atomic(
    pool: &sqlx::PgPool,
    consumer_user_id: Uuid,
    job_id: Uuid,
    expected_spendable_micro: i64,
) {
    let job_status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = $1")
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("应能读取硬件信任失效后的任务状态");
    assert_eq!(job_status, "failed");
    let attempt = sqlx::query(
        "SELECT status,error_class,retryable_requested FROM job_attempts WHERE job_id = $1 ORDER BY attempt_number DESC LIMIT 1",
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .expect("应能读取硬件信任失效后的 attempt");
    assert_eq!(
        attempt
            .try_get::<String, _>("status")
            .expect("attempt 应包含 status"),
        "failed"
    );
    assert_eq!(
        attempt
            .try_get::<Option<String>, _>("error_class")
            .expect("attempt 应包含 error_class"),
        Some("attestation".to_owned())
    );
    assert!(!attempt
        .try_get::<bool, _>("retryable_requested")
        .expect("attempt 应包含 retryable_requested"));
    let account =
        sqlx::query("SELECT spendable_micro,reserved_micro FROM quota_accounts WHERE user_id = $1")
            .bind(consumer_user_id)
            .fetch_one(pool)
            .await
            .expect("应能读取硬件信任失效后的额度账户");
    assert_eq!(
        account
            .try_get::<i64, _>("spendable_micro")
            .expect("额度账户应包含 spendable_micro"),
        expected_spendable_micro,
        "硬件信任失效不得扣款"
    );
    assert_eq!(
        account
            .try_get::<i64, _>("reserved_micro")
            .expect("额度账户应包含 reserved_micro"),
        0,
        "硬件信任失效必须释放 reservation"
    );
    let receipt_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM receipts WHERE job_id = $1")
            .bind(job_id)
            .fetch_one(pool)
            .await
            .expect("应能确认硬件信任失效没有 receipt");
    assert_eq!(receipt_count, 0, "硬件信任失效不得生成 receipt");
}

async fn install_verified_tee_report(
    pool: &sqlx::PgPool,
    node_id: Uuid,
    model_instance_id: Uuid,
    tee_public_key: String,
) -> Uuid {
    let challenge_id = Uuid::now_v7();
    let report_id = Uuid::now_v7();
    let nonce_seed = Uuid::now_v7();
    let mut nonce = Vec::with_capacity(32);
    nonce.extend_from_slice(nonce_seed.as_bytes());
    nonce.extend_from_slice(nonce_seed.as_bytes());
    let nonce_hash = format!("{}{}", Uuid::now_v7().simple(), Uuid::now_v7().simple());
    let user_id: Uuid = sqlx::query_scalar("SELECT user_id FROM nodes WHERE id = $1")
        .bind(node_id)
        .fetch_one(pool)
        .await
        .expect("应能读取节点所有者");
    sqlx::query(
        r#"
        INSERT INTO attestation_challenges
            (id,user_id,node_id,model_instance_id,provider,nonce,nonce_hash,
             sandbox_policy_hash,runtime_binary_hash,model_weights_hash,
             ephemeral_public_key,report_data,key_origin,status,expires_at,consumed_at)
        VALUES
            ($1,$2,$3,$4,'intel_tdx',$5,$6,$7,$8,$9,$10,$11,
             'tee_runtime','verified',now() + interval '1 hour',now())
        "#,
    )
    .bind(challenge_id)
    .bind(user_id)
    .bind(node_id)
    .bind(model_instance_id)
    .bind(nonce)
    .bind(nonce_hash.clone())
    .bind("44".repeat(32))
    .bind("55".repeat(32))
    .bind("0".repeat(64))
    .bind(&tee_public_key)
    .bind("66".repeat(64))
    .execute(pool)
    .await
    .expect("应能插入受控 TEE challenge");
    sqlx::query(
        r#"
        INSERT INTO attestation_reports
            (id,node_id,provider,nonce_hash,policy_hash,runtime_hash,model_hash,
             issued_at,verified_at,expires_at,status,challenge_id,model_instance_id,
             evidence_kind,evidence_sha256,evidence_base64,report_data,tee_measurement,
             ephemeral_public_key,verifier_name,signature_verified,
             certificate_chain_verified,tcb_current,collateral_current,
             collateral_expires_at,key_origin)
        VALUES
            ($1,$2,'intel_tdx',$3,$4,$5,$6,now(),now(),now() + interval '1 hour',
             'verified',$7,$8,'tdx_quote',$9,'YWJj',$10,$11,$12,
             'postgres-integration-fixture',TRUE,TRUE,TRUE,TRUE,
             now() + interval '1 hour','tee_runtime')
        "#,
    )
    .bind(report_id)
    .bind(node_id)
    .bind(nonce_hash)
    .bind("44".repeat(32))
    .bind("55".repeat(32))
    .bind("0".repeat(64))
    .bind(challenge_id)
    .bind(model_instance_id)
    .bind("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    .bind("66".repeat(64))
    .bind("77".repeat(48))
    .bind(tee_public_key)
    .execute(pool)
    .await
    .expect("应能插入受控已验证 TEE report");
    sqlx::query(
        r#"
        UPDATE nodes
        SET trust_level = 'enhanced',attestation_report_id = $2,
            trust_expires_at = now() + interval '1 hour'
        WHERE id = $1
        "#,
    )
    .bind(node_id)
    .bind(report_id)
    .execute(pool)
    .await
    .expect("应能将节点绑定到已验证 TEE report");
    report_id
}

#[allow(clippy::too_many_arguments)]
async fn insert_test_settled_node_contribution(
    pool: &sqlx::PgPool,
    standard_data_key: &[u8; 32],
    consumer_user_id: Uuid,
    model_id: Uuid,
    node_id: Uuid,
    node_user_id: Uuid,
    model_name: &str,
    contribution_micro: i64,
    suffix: &str,
) {
    let target_base_cost_micro = if contribution_micro == 0 {
        1_000
    } else {
        contribution_micro * 5 / 6
    };
    let authorized_max_output_tokens = target_base_cost_micro.max(1);
    let billing = load_test_billing_snapshot(pool, model_id, 0, authorized_max_output_tokens).await;
    let contribution_weight_ppm = if contribution_micro == 0 {
        0
    } else {
        1_000_000
    };
    let job_id = Uuid::now_v7();
    let payload = encrypt_for_storage(
        standard_data_key,
        job_id,
        StorageDirection::Payload,
        b"dGVzdA==",
    )
    .expect("应能构造贡献路由 receipt 的受保护 payload");
    let job_insert = sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,status,encrypted_payload,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             leased_to_node_id,actual_input_tokens,actual_output_tokens,completed_at,
             standard_request_fingerprint,standard_payload_storage_version,
             billing_contract_version,billing_profile_id,billing_profile_version,
             billing_profile_fingerprint,billing_model_weights_hash,
             billing_reference_hardware_class,billing_profile_evidence_hash,
             billing_profile_valid_from,billing_profile_valid_until,
             billing_profile_max_input_tokens,billing_profile_max_output_tokens,
             billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
             billing_reference_vram_mib,billing_token_rate_micro_per_1k,
             billing_gpu_rate_micro_per_second,
             billing_vram_rate_micro_per_gib_second,
             billing_authorized_input_tokens,billing_authorized_max_output_tokens,
             billing_billable_tokens,billing_reference_gpu_time_us,
             billing_reference_vram_mib_microseconds,billing_token_cost_micro,
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        VALUES ($1,$2,$3,$4,'succeeded',$5,0,$8,$9,$6,0,$8,now(),$7,1,
                $10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
                $24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35)
        "#,
    )
    .bind(job_id)
    .bind(consumer_user_id)
    .bind(model_id)
    .bind(format!("contribution-routing-receipt-job-{suffix}"))
    .bind(payload)
    .bind(node_id)
    .bind(format!("mindone-standard-hmac-v1:{}", "0".repeat(64)))
    .bind(authorized_max_output_tokens)
    .bind(billing.reservation_micro);
    bind_test_billing_snapshot!(job_insert, billing)
        .execute(pool)
        .await
        .expect("应能插入贡献路由的已结算任务夹具");
    sqlx::query(
        r#"
        INSERT INTO receipts
            (id,job_id,consumer_user_id,node_user_id,model_name,tier,trust_level,
             base_cost_micro,user_deduction_micro,node_quota_micro,
             contribution_micro,reserve_micro,settlement_hash,
             contribution_weight_ppm,
             billing_contract_version,billing_profile_id,billing_profile_version,
             billing_profile_fingerprint,billing_model_weights_hash,
             billing_reference_hardware_class,billing_profile_evidence_hash,
             billing_profile_valid_from,billing_profile_valid_until,
             billing_profile_max_input_tokens,billing_profile_max_output_tokens,
             billing_fixed_gpu_time_us,billing_gpu_time_us_per_1k_tokens,
             billing_reference_vram_mib,billing_token_rate_micro_per_1k,
             billing_gpu_rate_micro_per_second,
             billing_vram_rate_micro_per_gib_second,
             billing_authorized_input_tokens,billing_authorized_max_output_tokens,
             billing_billable_tokens,billing_reference_gpu_time_us,
             billing_reference_vram_mib_microseconds,billing_token_cost_micro,
             billing_gpu_cost_micro,billing_vram_cost_micro,billing_base_cost_micro)
        SELECT $1,j.id,$3,$4,$5,'medium','standard-limited',
               j.billing_base_cost_micro,j.billing_base_cost_micro,
               j.billing_base_cost_micro * 4 / 5,$6,
               j.billing_base_cost_micro - j.billing_base_cost_micro * 4 / 5,
               $7,$8,
               j.billing_contract_version,j.billing_profile_id,
               j.billing_profile_version,j.billing_profile_fingerprint,
               j.billing_model_weights_hash,j.billing_reference_hardware_class,
               j.billing_profile_evidence_hash,j.billing_profile_valid_from,
               j.billing_profile_valid_until,j.billing_profile_max_input_tokens,
               j.billing_profile_max_output_tokens,j.billing_fixed_gpu_time_us,
               j.billing_gpu_time_us_per_1k_tokens,j.billing_reference_vram_mib,
               j.billing_token_rate_micro_per_1k,
               j.billing_gpu_rate_micro_per_second,
               j.billing_vram_rate_micro_per_gib_second,
               j.billing_authorized_input_tokens,
               j.billing_authorized_max_output_tokens,j.billing_billable_tokens,
               j.billing_reference_gpu_time_us,
               j.billing_reference_vram_mib_microseconds,
               j.billing_token_cost_micro,j.billing_gpu_cost_micro,
               j.billing_vram_cost_micro,j.billing_base_cost_micro
        FROM jobs j WHERE j.id=$2
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(job_id)
    .bind(consumer_user_id)
    .bind(node_user_id)
    .bind(model_name)
    .bind(contribution_micro)
    .bind(hex::encode(Sha256::digest(
        format!("contribution-routing-receipt-{suffix}").as_bytes(),
    )))
    .bind(contribution_weight_ppm)
    .execute(pool)
    .await
    .expect("应能插入最终反作弊加权贡献 receipt 夹具");
}

fn regulated_envelope(
    route_id: Uuid,
    report_id: Uuid,
    model_instance_id: Uuid,
    direction: &str,
    sender_public_key: &str,
    seed: u8,
) -> Value {
    json!({
        "version": 1,
        "algorithm": "x25519-hkdf-sha256-chacha20poly1305",
        "direction": direction,
        "route_id": route_id,
        "report_id": report_id,
        "model_instance_id": model_instance_id,
        "sender_public_key": sender_public_key,
        "nonce": URL_SAFE_NO_PAD.encode([seed; 12]),
        "ciphertext": URL_SAFE_NO_PAD.encode([seed; 17])
    })
}

fn prepare_body_for_fingerprint_test(model_name: &str, idempotency_key: &str) -> Value {
    json!({
        "virtual_model": model_name,
        "tags": ["regulated"],
        "estimated_input_tokens": 8,
        "max_output_tokens": 8,
        "idempotency_key": idempotency_key,
        "priority": 0
    })
}

fn parse_uuid(value: &str, label: &str) -> Uuid {
    Uuid::parse_str(value).unwrap_or_else(|error| panic!("{label} ID 必须是 UUID：{error}"))
}

async fn register_test_node(app: &axum::Router, access_token: &str, alias: &str) -> String {
    let (_, node) = call(
        app,
        Method::POST,
        "/v1/nodes/register",
        Some(json!({
            "alias": alias,
            "hardware_profile": {
                "operating_system":"linux",
                "operating_system_version":"test",
                "architecture":"x86_64",
                "cpu_model":"Integration CPU",
                "cpu_logical_cores":16,
                "ram_total_mib":65536,
                "gpus":[],
                "cuda_available":true,
                "metal_available":false,
                "sandbox_mechanisms":["namespaces","seccomp_bpf"]
            },
            "reject_tags": [],
            "max_concurrent": 2,
            "gpu_temp_limit_c": null,
            "vram_reserve_mib": 512
        })),
        Some(access_token),
    )
    .await;
    assert_eq!(
        node.pointer("/status").and_then(Value::as_str),
        Some("offline")
    );
    value_str(&node, "/node_id")
}

async fn heartbeat_test_node(
    app: &axum::Router,
    access_token: &str,
    node_id: &str,
    tps_milli: i64,
    ttft_ms: i64,
    reject_tags: &[&str],
) {
    heartbeat_test_node_with_rtt(
        app,
        access_token,
        node_id,
        tps_milli,
        ttft_ms,
        None,
        reject_tags,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn heartbeat_test_node_with_rtt(
    app: &axum::Router,
    access_token: &str,
    node_id: &str,
    tps_milli: i64,
    ttft_ms: i64,
    coordinator_rtt_ms: Option<i64>,
    reject_tags: &[&str],
) {
    let mut request = json!({
        "tps_milli": tps_milli,
        "ttft_ms": ttft_ms,
        "current_concurrent": 0,
        "vram_used_mib": 1024,
        "vram_total_mib": 16384,
        "error_rate_ppm": 0,
        "policy": {
            "reject_tags": reject_tags,
            "max_concurrent": 2,
            "gpu_temp_limit_c": null,
            "vram_reserve_mib": 512
        }
    });
    if let Some(coordinator_rtt_ms) = coordinator_rtt_ms {
        request["coordinator_rtt_ms"] = json!(coordinator_rtt_ms);
    }
    let (_, heartbeat) = call(
        app,
        Method::POST,
        &format!("/v1/nodes/{node_id}/heartbeat"),
        Some(request),
        Some(access_token),
    )
    .await;
    assert_eq!(
        heartbeat.pointer("/status").and_then(Value::as_str),
        Some("online")
    );
}

async fn assert_latest_routing_metrics(
    pool: &sqlx::PgPool,
    node_id: &str,
    expected_ttft_ms: i64,
    expected_coordinator_rtt_ms: Option<i64>,
) {
    let metrics = sqlx::query(
        r#"
        SELECT ttft_ms,coordinator_rtt_ms
        FROM node_metrics
        WHERE node_id = $1
        ORDER BY measured_at DESC,id DESC
        LIMIT 1
        "#,
    )
    .bind(parse_uuid(node_id, "路由指标节点"))
    .fetch_one(pool)
    .await
    .expect("应能读取节点最新路由指标");
    assert_eq!(
        metrics
            .try_get::<i64, _>("ttft_ms")
            .expect("最新指标应包含 TTFT"),
        expected_ttft_ms
    );
    assert_eq!(
        metrics
            .try_get::<Option<i64>, _>("coordinator_rtt_ms")
            .expect("最新指标应包含可空 coordinator RTT"),
        expected_coordinator_rtt_ms
    );
}

async fn expire_prepared_route(pool: &sqlx::PgPool, route_id: &str) {
    let affected = sqlx::query(
        r#"
        UPDATE regulated_routes
        SET prepared_at = now() - interval '5 minutes',
            expires_at = now() - interval '1 second'
        WHERE id = $1
        "#,
    )
    .bind(parse_uuid(route_id, "待过期 Regulated route"))
    .execute(pool)
    .await
    .expect("应能过期已断言的 Regulated route")
    .rows_affected();
    assert_eq!(affected, 1, "必须且只能过期一条已断言的 route");
}

fn standard_job_body(
    model: &str,
    tags: &[&str],
    idempotency_key: &str,
    max_output_tokens: u32,
) -> Value {
    standard_job_body_with_encoding(model, tags, idempotency_key, max_output_tokens, "base64")
}

fn standard_job_body_with_encoding(
    model: &str,
    tags: &[&str],
    idempotency_key: &str,
    max_output_tokens: u32,
    payload_encoding: &str,
) -> Value {
    let request = json!({
        "model": model,
        "messages": [{"role": "user", "content": "MindOne PostgreSQL integration"}],
        "max_tokens": max_output_tokens
    });
    let estimated_input_tokens = mindone_protocol::conservative_input_token_authorization(&request)
        .expect("测试推理请求应可计算保守 Token 授权");
    let payload = serde_json::to_vec(&json!({
        "endpoint": mindone_protocol::OPENAI_CHAT_COMPLETIONS,
        "request": request
    }))
    .expect("测试 Standard 载荷应可序列化");
    let encrypted_payload = match payload_encoding {
        "base64" => BASE64_STANDARD.encode(payload),
        "base64url" => URL_SAFE_NO_PAD.encode(payload),
        other => panic!("测试载荷编码不受支持：{other}"),
    };
    json!({
        "virtual_model": model,
        "encrypted_payload": encrypted_payload,
        "payload_encoding": payload_encoding,
        "tags": tags,
        "estimated_input_tokens": estimated_input_tokens,
        "max_output_tokens": max_output_tokens,
        "idempotency_key": idempotency_key
    })
}

fn standard_result_ciphertext(model: &str, prompt_tokens: u32, completion_tokens: u32) -> String {
    standard_result_ciphertext_with_content(model, prompt_tokens, completion_tokens, "ok")
}

fn standard_result_ciphertext_with_content(
    model: &str,
    prompt_tokens: u32,
    completion_tokens: u32,
    content: &str,
) -> String {
    let response = json!({
        "id": "mindone-integration-result",
        "object": "chat.completion",
        "created": 1,
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    });
    BASE64_STANDARD.encode(serde_json::to_vec(&response).expect("测试 Standard 结果应可序列化"))
}

struct ClaimedPrivateChallenge {
    job_id: String,
    entry_commitment: String,
    prompt: String,
}

type PrivateChallengeBindingRow = (
    String,
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

async fn claim_private_challenge(
    app: &axum::Router,
    pool: &sqlx::PgPool,
    access_token: &str,
    node_id: &str,
    model_instance_id: &str,
) -> ClaimedPrivateChallenge {
    let (_, claim) = call(
        app,
        Method::POST,
        "/v1/jobs/claim",
        Some(json!({
            "node_id": node_id,
            "model_instance_id": model_instance_id
        })),
        Some(access_token),
    )
    .await;
    let job_id = value_str(&claim, "/job_id");
    let payload = BASE64_STANDARD
        .decode(value_str(&claim, "/encrypted_payload"))
        .expect("私有挑战应使用 Standard Base64 payload");
    let payload: Value = serde_json::from_slice(&payload).expect("私有挑战 payload 应为 JSON");
    let prompt = payload
        .pointer("/request/messages/0/content")
        .and_then(Value::as_str)
        .expect("私有挑战应含 evaluator Prompt")
        .to_owned();
    let binding: PrivateChallengeBindingRow = sqlx::query_as(
        r#"
        SELECT challenge_kind,private_commitment_version,
               private_catalog_entry_commitment,challenge_binding_hash,
               challenge_nonce_hash,private_catalog_valid_until,model_weights_hash,
               private_catalog_entry_id,prompt_hash,expected_hash
        FROM model_evaluation_challenges WHERE id=$1
        "#,
    )
    .bind(parse_uuid(&job_id, "私有挑战"))
    .fetch_one(pool)
    .await
    .expect("私有挑战必须持久化 commitment 与精确绑定");
    assert_eq!(binding.0, "hidden_benchmark");
    assert_eq!(binding.1, Some(2));
    assert_eq!(binding.2.as_deref().map(str::len), Some(64));
    assert_eq!(binding.3.as_deref().map(str::len), Some(64));
    assert_eq!(binding.4.as_deref().map(str::len), Some(64));
    assert!(binding.5.is_some());
    assert_eq!(binding.6, Some("0".repeat(64)));
    assert_eq!((&binding.7, &binding.8, &binding.9), (&None, &None, &None));
    ClaimedPrivateChallenge {
        job_id,
        entry_commitment: binding
            .2
            .expect("私有 challenge 必须绑定一次性 entry commitment"),
        prompt,
    }
}

async fn submit_private_challenge_result(
    app: &axum::Router,
    access_token: &str,
    node_id: &str,
    job_id: &str,
    content: &str,
    idempotency_key: String,
) -> (StatusCode, Value) {
    call_unchecked(
        app,
        Method::POST,
        &format!("/v1/jobs/{job_id}/result"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": idempotency_key,
            "result_ciphertext": standard_result_ciphertext_with_content("auto", 1, 1, content),
            "actual_input_tokens": 1,
            "actual_output_tokens": 1,
            "execution_telemetry": test_execution_telemetry()
        })),
        Some(access_token),
    )
    .await
}

async fn private_challenge_status(pool: &sqlx::PgPool, job_id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM model_evaluation_challenges WHERE id=$1")
        .bind(parse_uuid(job_id, "私有挑战状态"))
        .fetch_one(pool)
        .await
        .expect("应能读取私有挑战状态")
}

async fn wait_private_challenge_cooldown() {
    // 预算以 append-only issued event 的 PostgreSQL created_at 为权威时钟，测试不能再
    // 回写 challenge 时间戳绕过冷却。created_at 与下一次 claim 事务的 now() 分属
    // PostgreSQL 不同时间点，给 1 秒测试窗口留出明确余量，避免把调度抖动当成预算拒绝。
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
}

fn hidden_expected_from_seed(kind: &str, seed: &[u8]) -> String {
    let seed: [u8; 32] = seed.try_into().expect("隐藏评价 seed 必须是 32 字节");
    match kind {
        "hidden_benchmark" => {
            let left = u32::from(u16::from_be_bytes([seed[0], seed[1]])) % 9_000 + 1_000;
            let right = u32::from(u16::from_be_bytes([seed[2], seed[3]])) % 9_000 + 1_000;
            let small_left = left % 97 + 3;
            let small_right = right % 29 + 2;
            match seed[5] % 8 {
                0 | 1 | 7 => (left + right).to_string(),
                2 => left.to_string(),
                3 => (small_left * small_right).to_string(),
                4 => left.max(right).to_string(),
                5 => (left % 10).to_string(),
                6 => (right + small_right).to_string(),
                _ => unreachable!("模 8 必须落在已覆盖分支"),
            }
        }
        "canary" => {
            let letters = seed[..8]
                .iter()
                .map(|byte| char::from(b'A' + (byte % 26)))
                .collect::<String>();
            match seed[8] % 8 {
                0..=3 => letters,
                4 => letters.chars().rev().collect(),
                5 => letters.to_ascii_lowercase(),
                6 => letters.chars().count().to_string(),
                7 => letters.chars().take(3).collect(),
                _ => unreachable!("模 8 必须落在已覆盖分支"),
            }
        }
        other => panic!("未知隐藏评价类型：{other}"),
    }
}

fn test_execution_telemetry() -> Value {
    json!({
        "ttft_ms": 100,
        "tps_milli": 10_000,
        // 测试模型仍有服务端 8 MiB 严重偏差保守下限，1 MiB 应生成 critical 审计。
        "peak_vram_mib": 1,
        "vram_sample_count": 4
    })
}

#[derive(Debug)]
struct TestBillingSnapshot {
    contract_version: String,
    profile_id: Uuid,
    profile_version: i64,
    profile_fingerprint: String,
    model_weights_hash: String,
    reference_hardware_class: String,
    profile_evidence_hash: String,
    profile_valid_from: OffsetDateTime,
    profile_valid_until: OffsetDateTime,
    profile_max_input_tokens: i64,
    profile_max_output_tokens: i64,
    fixed_gpu_time_us: i64,
    gpu_time_us_per_1k_tokens: i64,
    reference_vram_mib: i64,
    token_rate_micro_per_1k: i64,
    gpu_rate_micro_per_second: i64,
    vram_rate_micro_per_gib_second: i64,
    authorized_input_tokens: i64,
    authorized_max_output_tokens: i64,
    billable_tokens: i64,
    reference_gpu_time_us: i64,
    reference_vram_mib_microseconds: i64,
    token_cost_micro: i64,
    gpu_cost_micro: i64,
    vram_cost_micro: i64,
    base_cost_micro: i64,
    reservation_micro: i64,
}

async fn load_test_billing_snapshot(
    pool: &sqlx::PgPool,
    model_id: Uuid,
    authorized_input_tokens: i64,
    authorized_max_output_tokens: i64,
) -> TestBillingSnapshot {
    let row = sqlx::query(
        r#"
        SELECT id,contract_version,profile_version,model_weights_hash,
               reference_hardware_class,maximum_input_tokens,maximum_output_tokens,
               fixed_gpu_time_us,gpu_time_us_per_1k_tokens,reference_vram_mib,
               token_rate_micro_per_1k,gpu_rate_micro_per_second,
               vram_rate_micro_per_gib_second,evidence_hash,profile_fingerprint,
               valid_from,valid_until
        FROM billing_profiles
        WHERE model_id=$1 AND valid_from <= now() AND valid_until > now()
        ORDER BY profile_version DESC,id
        LIMIT 1
        "#,
    )
    .bind(model_id)
    .fetch_one(pool)
    .await
    .expect("直接写入测试夹具前必须存在当前有效的物理计费 profile");
    let contract_version: String = row.get("contract_version");
    assert_eq!(
        contract_version, SERVER_REFERENCE_UPPER_BOUND_V1,
        "测试夹具只允许使用当前物理参考上界合同"
    );
    let profile = ServerReferenceBillingProfile {
        maximum_input_tokens: row.get("maximum_input_tokens"),
        maximum_output_tokens: row.get("maximum_output_tokens"),
        fixed_gpu_time_us: row.get("fixed_gpu_time_us"),
        gpu_time_us_per_1k_tokens: row.get("gpu_time_us_per_1k_tokens"),
        reference_vram_mib: row.get("reference_vram_mib"),
        token_rate_micro_per_1k: row.get("token_rate_micro_per_1k"),
        gpu_rate_micro_per_second: row.get("gpu_rate_micro_per_second"),
        vram_rate_micro_per_gib_second: row.get("vram_rate_micro_per_gib_second"),
    };
    let quote = maximum_reservation_quote(
        profile,
        authorized_input_tokens,
        authorized_max_output_tokens,
    )
    .expect("测试夹具授权 token 必须落在当前 profile 上界内");
    let reservation_micro = maximum_reservation_micro(
        profile,
        authorized_input_tokens,
        authorized_max_output_tokens,
    )
    .expect("测试夹具必须能计算最大准备金")
    .as_i64();

    TestBillingSnapshot {
        contract_version,
        profile_id: row.get("id"),
        profile_version: row.get("profile_version"),
        profile_fingerprint: row.get("profile_fingerprint"),
        model_weights_hash: row.get("model_weights_hash"),
        reference_hardware_class: row.get("reference_hardware_class"),
        profile_evidence_hash: row.get("evidence_hash"),
        profile_valid_from: row.get("valid_from"),
        profile_valid_until: row.get("valid_until"),
        profile_max_input_tokens: profile.maximum_input_tokens,
        profile_max_output_tokens: profile.maximum_output_tokens,
        fixed_gpu_time_us: profile.fixed_gpu_time_us,
        gpu_time_us_per_1k_tokens: profile.gpu_time_us_per_1k_tokens,
        reference_vram_mib: profile.reference_vram_mib,
        token_rate_micro_per_1k: profile.token_rate_micro_per_1k,
        gpu_rate_micro_per_second: profile.gpu_rate_micro_per_second,
        vram_rate_micro_per_gib_second: profile.vram_rate_micro_per_gib_second,
        authorized_input_tokens,
        authorized_max_output_tokens,
        billable_tokens: quote.billable_tokens,
        reference_gpu_time_us: quote.reference_gpu_time_us,
        reference_vram_mib_microseconds: quote.reference_vram_mib_microseconds,
        token_cost_micro: quote.token_cost.as_i64(),
        gpu_cost_micro: quote.gpu_cost.as_i64(),
        vram_cost_micro: quote.vram_cost.as_i64(),
        base_cost_micro: quote.base_cost.as_i64(),
        reservation_micro,
    }
}

#[allow(clippy::too_many_arguments)]
async fn try_insert_test_billing_profile(
    pool: &sqlx::PgPool,
    model_id: Uuid,
    model_weights_hash: &str,
    profile_version: i64,
    maximum_input_tokens: i64,
    maximum_output_tokens: i64,
    rate_scale: i64,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
) -> Result<Uuid, sqlx::Error> {
    let profile_id = Uuid::now_v7();
    let evidence_hash = hex::encode(Sha256::digest(
        format!("billing-profile-evidence-{profile_id}").as_bytes(),
    ));
    sqlx::query_scalar(
        r#"
        INSERT INTO billing_profiles
            (id,contract_version,profile_version,model_id,model_weights_hash,
             reference_hardware_class,maximum_input_tokens,maximum_output_tokens,
             fixed_gpu_time_us,gpu_time_us_per_1k_tokens,reference_vram_mib,
             token_rate_micro_per_1k,gpu_rate_micro_per_second,
             vram_rate_micro_per_gib_second,evidence_hash,profile_fingerprint,
             valid_from,valid_until)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULL,$16,$17)
        RETURNING id
        "#,
    )
    .bind(profile_id)
    .bind(SERVER_REFERENCE_UPPER_BOUND_V1)
    .bind(profile_version)
    .bind(model_id)
    .bind(model_weights_hash)
    .bind(format!("postgres-integration-reference-v{profile_version}"))
    .bind(maximum_input_tokens)
    .bind(maximum_output_tokens)
    .bind(rate_scale * 1_000)
    .bind(rate_scale * 2_000)
    .bind(rate_scale * 256)
    .bind(rate_scale * 3_000)
    .bind(rate_scale * 4_000)
    .bind(rate_scale * 5_000)
    .bind(evidence_hash)
    .bind(valid_from)
    .bind(valid_until)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn insert_test_billing_profile(
    pool: &sqlx::PgPool,
    model_id: Uuid,
    model_weights_hash: &str,
    profile_version: i64,
    maximum_input_tokens: i64,
    maximum_output_tokens: i64,
    rate_scale: i64,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
) -> Uuid {
    try_insert_test_billing_profile(
        pool,
        model_id,
        model_weights_hash,
        profile_version,
        maximum_input_tokens,
        maximum_output_tokens,
        rate_scale,
        valid_from,
        valid_until,
    )
    .await
    .unwrap_or_else(|error| panic!("应能插入受控物理计费 profile：{error}"))
}

async fn frozen_job_billing_snapshot(pool: &sqlx::PgPool, job_id: Uuid) -> Value {
    sqlx::query_scalar(
        r#"
        SELECT jsonb_object_agg(field.key,field.value)
        FROM jobs entity
        CROSS JOIN LATERAL jsonb_each(to_jsonb(entity)) field
        WHERE entity.id=$1 AND field.key LIKE 'billing_%'
        GROUP BY entity.id
        "#,
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .expect("应能读取 job 的全部冻结 billing_* 字段")
}

async fn frozen_route_billing_snapshot(pool: &sqlx::PgPool, route_id: Uuid) -> Value {
    sqlx::query_scalar(
        r#"
        SELECT jsonb_object_agg(field.key,field.value)
        FROM regulated_routes entity
        CROSS JOIN LATERAL jsonb_each(to_jsonb(entity)) field
        WHERE entity.id=$1 AND field.key LIKE 'billing_%'
        GROUP BY entity.id
        "#,
    )
    .bind(route_id)
    .fetch_one(pool)
    .await
    .expect("应能读取 Regulated route 的全部冻结 billing_* 字段")
}

#[allow(clippy::too_many_arguments)]
async fn assert_billing_route_rejected_without_writes(
    app: &axum::Router,
    pool: &sqlx::PgPool,
    consumer_token: &str,
    consumer_user_id: Uuid,
    model_id: Uuid,
    model_name: &str,
    case_id: &str,
) {
    let reserved_before: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(consumer_user_id)
            .fetch_one(pool)
            .await
            .expect("应能读取计费拒绝前 reservation");
    let jobs_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM jobs WHERE user_id=$1 AND model_id=$2")
            .bind(consumer_user_id)
            .bind(model_id)
            .fetch_one(pool)
            .await
            .expect("应能统计计费拒绝前任务数");
    let routes_before: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM regulated_routes WHERE user_id=$1 AND model_id=$2",
    )
    .bind(consumer_user_id)
    .bind(model_id)
    .fetch_one(pool)
    .await
    .expect("应能统计计费拒绝前 Regulated route 数");

    let (standard_status, standard_error) = call_unchecked(
        app,
        Method::POST,
        "/v1/jobs",
        Some(standard_job_body(
            model_name,
            &["test"],
            &format!("billing-standard-reject-{case_id}"),
            8,
        )),
        Some(consumer_token),
    )
    .await;
    assert_eq!(standard_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        standard_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("no_routable_model")
    );

    let (regulated_status, regulated_error) = call_unchecked(
        app,
        Method::POST,
        "/v1/jobs/regulated/prepare",
        Some(prepare_body_for_fingerprint_test(
            model_name,
            &format!("billing-regulated-reject-{case_id}"),
        )),
        Some(consumer_token),
    )
    .await;
    assert_eq!(regulated_status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        regulated_error
            .pointer("/error/type")
            .and_then(Value::as_str),
        Some("attestation_failed")
    );

    let reserved_after: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(consumer_user_id)
            .fetch_one(pool)
            .await
            .expect("应能读取计费拒绝后 reservation");
    let jobs_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM jobs WHERE user_id=$1 AND model_id=$2")
            .bind(consumer_user_id)
            .bind(model_id)
            .fetch_one(pool)
            .await
            .expect("应能统计计费拒绝后任务数");
    let routes_after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM regulated_routes WHERE user_id=$1 AND model_id=$2",
    )
    .bind(consumer_user_id)
    .bind(model_id)
    .fetch_one(pool)
    .await
    .expect("应能统计计费拒绝后 Regulated route 数");
    assert_eq!(
        reserved_after, reserved_before,
        "计费拒绝不得增加 reservation"
    );
    assert_eq!(jobs_after, jobs_before, "计费拒绝不得创建 job");
    assert_eq!(
        routes_after, routes_before,
        "计费拒绝不得创建 Regulated route"
    );
}

async fn create_test_job(
    app: &axum::Router,
    access_token: &str,
    model: &str,
    tags: &[&str],
    idempotency_key: &str,
) -> String {
    let (_, job) = call(
        app,
        Method::POST,
        "/v1/jobs",
        Some(standard_job_body_with_encoding(
            model,
            tags,
            idempotency_key,
            10,
            "base64url",
        )),
        Some(access_token),
    )
    .await;
    value_str(&job, "/job_id")
}

async fn fail_test_job(
    app: &axum::Router,
    node_access_token: &str,
    node_id: &str,
    job_id: &str,
    idempotency_key: &str,
) {
    let (_, failed) = call(
        app,
        Method::POST,
        &format!("/v1/jobs/{job_id}/fail"),
        Some(json!({
            "node_id": node_id,
            "idempotency_key": idempotency_key,
            "error_class": "internal",
            "error_message": "路由测试使用零扣费终态完成",
            "retryable": false
        })),
        Some(node_access_token),
    )
    .await;
    assert_eq!(
        sorted_object_keys(&failed),
        vec!["accepted", "idempotent_replay", "job_id"]
    );
    assert_eq!(
        failed.pointer("/accepted").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        failed
            .pointer("/idempotent_replay")
            .and_then(Value::as_bool),
        Some(false)
    );
}

async fn publish_test_model(
    app: &axum::Router,
    node_access_token: &str,
    node_id: &str,
    suffix: &str,
    base_cost_per_1k_micro: i64,
) -> Value {
    let (_, model) = call(
        app,
        Method::POST,
        "/v1/models/publish",
        Some(json!({
            "node_id": node_id,
            "name": format!("model-{suffix}"),
            "alias": format!("instance-{suffix}"),
            "format": "gguf",
            "weights_hash": "0".repeat(64),
            "size_bytes": 1024,
            "context_length": 4096,
            "benchmark_normalized": 0,
            "glicko_normalized": 0,
            "evaluation_samples": 0,
            "base_cost_per_1k_micro": base_cost_per_1k_micro,
            "tags": ["test"]
        })),
        Some(node_access_token),
    )
    .await;
    model
}

fn sign_refresh_proof(device_key_seed: &str, challenge: &str, refresh_token: &str) -> String {
    let secret_digest = Sha256::digest(device_key_seed.as_bytes());
    let mut secret = [0_u8; mindone_protocol::DEVICE_PUBLIC_KEY_BYTES];
    secret.copy_from_slice(&secret_digest);
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key = signing_key.verifying_key().to_bytes();
    let mut challenge_bytes = [0_u8; mindone_protocol::REFRESH_KEY_CHALLENGE_BYTES];
    if hex::decode_to_slice(challenge, &mut challenge_bytes).is_err() {
        panic!("refresh challenge 必须是规范十六进制：{challenge}");
    }
    let message = mindone_protocol::refresh_key_possession_message(
        &challenge_bytes,
        refresh_token,
        &public_key,
        mindone_protocol::DeviceKeyAlgorithm::Ed25519,
    );
    hex::encode(signing_key.sign(&message).to_bytes())
}

async fn login(app: &axum::Router, device_key_seed: &str) -> (String, String, String) {
    let secret_digest = Sha256::digest(device_key_seed.as_bytes());
    let mut secret = [0_u8; mindone_protocol::DEVICE_PUBLIC_KEY_BYTES];
    secret.copy_from_slice(&secret_digest);
    let signing_key = SigningKey::from_bytes(&secret);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let device_public_key = hex::encode(public_key_bytes);
    let expected_fingerprint = mindone_protocol::device_key_fingerprint(&public_key_bytes);
    let (_, start) = call(
        app,
        Method::POST,
        "/v1/auth/device/start",
        Some(json!({
            "device_public_key": device_public_key,
            "device_key_algorithm": "ed25519"
        })),
        None,
    )
    .await;
    let flow_id_text = value_str(&start, "/flow_id");
    let flow_id = parse_uuid(&flow_id_text, "device flow");
    let challenge_text = value_str(&start, "/device_challenge");
    let mut challenge = [0_u8; mindone_protocol::DEVICE_KEY_CHALLENGE_BYTES];
    if hex::decode_to_slice(&challenge_text, &mut challenge).is_err() {
        panic!("设备 challenge 必须是规范十六进制：{challenge_text}");
    }
    let message = mindone_protocol::device_key_possession_message(
        flow_id,
        &challenge,
        &public_key_bytes,
        mindone_protocol::DeviceKeyAlgorithm::Ed25519,
    );
    let signature = hex::encode(signing_key.sign(&message).to_bytes());
    let (_, poll) = call(
        app,
        Method::POST,
        "/v1/auth/device/poll",
        Some(json!({
            "flow_id": flow_id,
            "device_key_signature": signature
        })),
        None,
    )
    .await;
    assert_eq!(
        value_str(&poll, "/device_key_fingerprint"),
        expected_fingerprint
    );
    assert_eq!(value_str(&poll, "/refresh_challenge").len(), 64);
    (
        value_str(&poll, "/access_token"),
        value_str(&poll, "/refresh_token"),
        value_str(&poll, "/user/id"),
    )
}

async fn call(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let (status, body) = call_unchecked(app, method, uri, body, token).await;
    if !status.is_success() {
        panic!("请求 {uri} 失败：{status} {body}");
    }
    (status, body)
}

async fn call_unchecked(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let bytes = body.map_or_else(Vec::new, |value| value.to_string().into_bytes());
    let mut builder = Request::builder().method(method).uri(uri);
    if !bytes.is_empty() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = token {
        builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let request = match builder.body(Body::from(bytes)) {
        Ok(request) => request,
        Err(error) => panic!("无法构造请求：{error}"),
    };
    let response = match app.clone().oneshot(request).await {
        Ok(response) => response,
        Err(error) => match error {},
    };
    let status = response.status();
    let collected = match response.into_body().collect().await {
        Ok(collected) => collected,
        Err(error) => panic!("无法读取响应：{error}"),
    };
    let response_bytes = collected.to_bytes();
    let body = if response_bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&response_bytes) {
            Ok(value) => value,
            Err(error) => panic!("响应不是 JSON：{error}"),
        }
    };
    (status, body)
}

async fn call_sse_unchecked(
    app: &axum::Router,
    uri: &str,
    body: Value,
    token: &str,
) -> (StatusCode, HeaderMap, String) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|error| panic!("无法构造 SSE 请求：{error}"));
    let response = app
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|error| match error {});
    let status = response.status();
    let headers = response.headers().clone();
    let collected = response
        .into_body()
        .collect()
        .await
        .unwrap_or_else(|error| panic!("无法读取 SSE 响应：{error}"));
    let body = String::from_utf8(collected.to_bytes().to_vec())
        .unwrap_or_else(|error| panic!("SSE 响应不是 UTF-8：{error}"));
    (status, headers, body)
}

async fn claim_gateway_job(
    app: &axum::Router,
    session_token: &str,
    node_id: &str,
    model_instance_id: &str,
) -> Value {
    for _ in 0..100 {
        let (status, body) = call_unchecked(
            app,
            Method::POST,
            "/v1/jobs/claim",
            Some(json!({
                "node_id": node_id,
                "model_instance_id": model_instance_id
            })),
            Some(session_token),
        )
        .await;
        if status == StatusCode::OK {
            return body;
        }
        assert_eq!(status, StatusCode::NO_CONTENT);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("OpenAI 网关应创建可由真实 worker 路由领取的任务");
}

fn value_str(value: &Value, pointer: &str) -> String {
    match value.pointer(pointer).and_then(Value::as_str) {
        Some(value) => value.to_owned(),
        None => panic!("响应缺少字符串字段 {pointer}: {value}"),
    }
}

fn sorted_object_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .expect("响应必须是 JSON 对象")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

fn value_i64(value: &Value, pointer: &str) -> i64 {
    match value.pointer(pointer).and_then(Value::as_i64) {
        Some(value) => value,
        None => panic!("响应缺少整数字段 {pointer}: {value}"),
    }
}

fn count_entry_type(value: &Value, expected: &str) -> usize {
    value
        .pointer("/entries")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    entry.pointer("/entry_type").and_then(Value::as_str) == Some(expected)
                })
                .count()
        })
        .unwrap_or(0)
}

fn assert_history_entry_locally_recomputes(value: &Value) {
    let entry: LedgerEntryResponse =
        serde_json::from_value(value.clone()).expect("history 应公开全部 canonical 输入字段");
    assert_eq!(entry.hash_version, LEDGER_HASH_VERSION);
    assert_eq!(
        entry.recomputation_status,
        LedgerRecomputationStatus::CanonicalV2Recomputable
    );
    let kind = match (entry.ledger, entry.entry_type.as_str()) {
        (LedgerNamespace::Quota, "consumer_deduction") => LedgerKind::ConsumerDeduction,
        (LedgerNamespace::Quota, "node_reward") => LedgerKind::NodeQuotaCredit,
        (LedgerNamespace::Quota, "bootstrap_grant") => LedgerKind::BootstrapGrant,
        (LedgerNamespace::Quota, "operator_grant") => LedgerKind::OperatorGrant,
        (LedgerNamespace::Contribution, "node_contribution") => LedgerKind::ContributionCredit,
        _ => panic!(
            "history 返回不受 canonical v2 支持的 scope/type：{:?}/{}",
            entry.ledger, entry.entry_type
        ),
    };
    LedgerEntry {
        hash_version: entry.hash_version,
        id: entry.id,
        account_id: entry.account_id,
        request_id: entry.request_id,
        idempotency_key: entry.idempotency_key,
        kind,
        amount_micro: entry.delta_micro,
        balance_before_micro: entry.balance_before_micro,
        balance_after_micro: entry.balance_after_micro,
        created_at: entry.created_at,
        previous_hash: entry.prev_hash,
        metadata: entry.metadata,
        hash: entry.entry_hash,
    }
    .validate()
    .expect("history canonical v2 行应能完全由公开字段本地重算");
}
