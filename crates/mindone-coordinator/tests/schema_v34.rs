use std::{borrow::Cow, env, path::PathBuf, str::FromStr, time::Duration as StdDuration};

use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const CLUSTER_ROLE_MIGRATION_VERSION: i64 = 26;
const FINAL_BILLING_MIGRATION_VERSION: i64 = 34;

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy)]
struct BillingFixture {
    user_id: Uuid,
    node_id: Uuid,
    model_id: Uuid,
    model_instance_id: Uuid,
    report_id: Uuid,
    profile_id: Uuid,
}

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v34 物理计费最终门禁测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v34 物理计费最终门禁测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn migrator_through_without_cluster_role(source: &Migrator, maximum_version: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            source
                .iter()
                .filter(|migration| {
                    migration.migration_type.is_up_migration()
                        && migration.version <= maximum_version
                        && migration.version != CLUSTER_ROLE_MIGRATION_VERSION
                })
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

async fn connect_admin(database_url: &str) -> TestResult<(PgPool, PgConnectOptions)> {
    let base_options = PgConnectOptions::from_str(database_url)
        .map_err(|error| format!("DATABASE_URL 无效：{error}"))?;
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(StdDuration::from_secs(10))
        .connect_with(base_options.clone().database("postgres"))
        .await
        .map_err(|error| format!("无法连接 PostgreSQL maintenance database：{error}"))?;
    Ok((admin_pool, base_options))
}

fn database_identifier(label: &str) -> TestResult<String> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("临时数据库标签包含不安全字符".to_owned());
    }
    let name = format!("mindone_v34_{label}_{}", Uuid::now_v7().simple());
    if name.len() > 63 {
        return Err("临时数据库名超过 PostgreSQL 标识符长度".to_owned());
    }
    Ok(name)
}

async fn create_test_database(
    admin_pool: &PgPool,
    base_options: &PgConnectOptions,
) -> TestResult<(String, PgPool)> {
    let database_name = database_identifier("billing")?;
    sqlx::query(&format!(
        r#"CREATE DATABASE "{database_name}" TEMPLATE template0"#
    ))
    .execute(admin_pool)
    .await
    .map_err(|error| format!("无法创建 v34 隔离数据库：{error}"))?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(StdDuration::from_secs(10))
        .connect_with(
            base_options
                .clone()
                .database(&database_name)
                .options([("search_path", "public,pg_catalog")]),
        )
        .await
        .map_err(|error| format!("无法连接 v34 隔离数据库：{error}"))?;
    Ok((database_name, pool))
}

async fn drop_test_database(admin_pool: &PgPool, database_name: &str) -> TestResult {
    sqlx::query(&format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v34 隔离数据库：{error}"))
}

fn expect_database_message<T>(
    result: Result<T, sqlx::Error>,
    expected_code: &str,
    expected_message: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation} 应被数据库拒绝")),
        Err(sqlx::Error::Database(database))
            if database.code().as_deref() == Some(expected_code)
                && database.message() == expected_message =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "{operation} 错误分类不正确：期望 {expected_code}/{expected_message}，实际 {error}"
        )),
    }
}

async fn seed_fixture(pool: &PgPool) -> TestResult<BillingFixture> {
    let user_id = Uuid::now_v7();
    let device_key_id = Uuid::now_v7();
    let node_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    let model_instance_id = Uuid::now_v7();
    let report_id = Uuid::now_v7();
    let profile_id = Uuid::now_v7();
    let audit_id = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'schema-v34',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("schema-v34-{user_id}"))
    .bind(format!("最终计费-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v34 用户：{error}"))?;
    sqlx::query("INSERT INTO device_keys (id,user_id,fingerprint,public_key) VALUES ($1,$2,$3,$4)")
        .bind(device_key_id)
        .bind(user_id)
        .bind(format!("schema-v34-device-{device_key_id}"))
        .bind("schema-v34-public-key")
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 v34 device key：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO nodes (id,user_id,alias,hardware_profile,device_key_id)
        VALUES ($1,$2,$3,'{}'::jsonb,$4)
        "#,
    )
    .bind(node_id)
    .bind(user_id)
    .bind(format!("schema-v34-node-{node_id}"))
    .bind(device_key_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v34 node：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO models
            (id,owner_user_id,name,format,weights_hash,size_bytes,context_length,
             base_cost_per_1k_micro)
        VALUES ($1,$2,$3,'gguf',$4,1048576,4096,1000000)
        "#,
    )
    .bind(model_id)
    .bind(user_id)
    .bind(format!("schema-v34-{model_id}"))
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v34 model：{error}"))?;
    sqlx::query("INSERT INTO model_instances (id,model_id,node_id,alias) VALUES ($1,$2,$3,$4)")
        .bind(model_instance_id)
        .bind(model_id)
        .bind(node_id)
        .bind(format!("schema-v34-instance-{model_instance_id}"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 v34 model instance：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO attestation_reports
            (id,node_id,provider,nonce_hash,policy_hash,runtime_hash,
             issued_at,expires_at,status,model_instance_id)
        VALUES ($1,$2,'amd_sev_snp',$3,$4,$5,now(),now()+interval '1 hour',
                'pending',$6)
        "#,
    )
    .bind(report_id)
    .bind(node_id)
    .bind("01".repeat(32))
    .bind("02".repeat(32))
    .bind("03".repeat(32))
    .bind(model_instance_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v34 attestation report：{error}"))?;

    let valid_from = OffsetDateTime::now_utc() - Duration::hours(1);
    let valid_until = OffsetDateTime::now_utc() + Duration::hours(1);
    sqlx::query(
        r#"
        SELECT out_profile_id
        FROM mindone_record_billing_profile_v1(
            $1,$2,$3,1,'reference-a100-80g',4096,1024,0,1000000,1024,
            1000,1000,1000,$4,$5,$6,'ops/schema-v34',
            '为最终计费门禁测试发布参考费率','schema-v34-profile',$7
        )
        "#,
    )
    .bind(profile_id)
    .bind(audit_id)
    .bind(model_id)
    .bind("de".repeat(32))
    .bind(valid_from)
    .bind(valid_until)
    .bind("ac".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法供应 v34 billing profile：{error}"))?;

    Ok(BillingFixture {
        user_id,
        node_id,
        model_id,
        model_instance_id,
        report_id,
        profile_id,
    })
}

async fn insert_job_without_billing(
    pool: &PgPool,
    fixture: BillingFixture,
    job_id: Uuid,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             standard_request_fingerprint,standard_payload_storage_version)
        VALUES ($1,$2,$3,$4,'mindone-standard-aead-v1:djM0','base64',
                800,200,4500,$5,1)
        "#,
    )
    .bind(job_id)
    .bind(fixture.user_id)
    .bind(fixture.model_id)
    .bind(format!("schema-v34-job-{job_id}"))
    .bind(format!("mindone-standard-hmac-v1:{}", "c".repeat(64)))
    .execute(pool)
    .await
}

async fn insert_v1_job(
    pool: &PgPool,
    fixture: BillingFixture,
    job_id: Uuid,
    protocol_input_tokens: i32,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro,
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
        SELECT $1,$2,$3,$4,'mindone-standard-aead-v1:djM0','base64',
               $5,200,4500,$6,1,
               profile.contract_version,profile.id,profile.profile_version,
               profile.profile_fingerprint,profile.model_weights_hash,
               profile.reference_hardware_class,profile.evidence_hash,
               profile.valid_from,profile.valid_until,
               profile.maximum_input_tokens,profile.maximum_output_tokens,
               profile.fixed_gpu_time_us,profile.gpu_time_us_per_1k_tokens,
               profile.reference_vram_mib,profile.token_rate_micro_per_1k,
               profile.gpu_rate_micro_per_second,
               profile.vram_rate_micro_per_gib_second,
               800,200,1000,1000000,1024000000,1000,1000,1000,3000
        FROM billing_profiles AS profile
        WHERE profile.id=$7
        "#,
    )
    .bind(job_id)
    .bind(fixture.user_id)
    .bind(fixture.model_id)
    .bind(format!("schema-v34-v1-job-{job_id}"))
    .bind(protocol_input_tokens)
    .bind(format!("mindone-standard-hmac-v1:{}", "d".repeat(64)))
    .bind(fixture.profile_id)
    .execute(pool)
    .await
}

async fn insert_route_without_billing(
    pool: &PgPool,
    fixture: BillingFixture,
    route_id: Uuid,
    expired: bool,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let (prepared_at, expires_at) = if expired {
        (
            OffsetDateTime::now_utc() - Duration::minutes(20),
            OffsetDateTime::now_utc() - Duration::minutes(10),
        )
    } else {
        (
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc() + Duration::minutes(10),
        )
    };
    sqlx::query(
        r#"
        INSERT INTO regulated_routes
            (id,user_id,idempotency_key,model_id,model_instance_id,node_id,
             attestation_report_id,estimated_input_tokens,max_output_tokens,
             prepared_at,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,800,200,$8,$9)
        "#,
    )
    .bind(route_id)
    .bind(fixture.user_id)
    .bind(format!("schema-v34-route-{route_id}"))
    .bind(fixture.model_id)
    .bind(fixture.model_instance_id)
    .bind(fixture.node_id)
    .bind(fixture.report_id)
    .bind(prepared_at)
    .bind(expires_at)
    .execute(pool)
    .await
}

async fn insert_v1_route(
    pool: &PgPool,
    fixture: BillingFixture,
    route_id: Uuid,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO regulated_routes
            (id,user_id,idempotency_key,model_id,model_instance_id,node_id,
             attestation_report_id,estimated_input_tokens,max_output_tokens,expires_at,
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
        SELECT $1,$2,$3,$4,$5,$6,$7,800,200,now()+interval '10 minutes',
               profile.contract_version,profile.id,profile.profile_version,
               profile.profile_fingerprint,profile.model_weights_hash,
               profile.reference_hardware_class,profile.evidence_hash,
               profile.valid_from,profile.valid_until,
               profile.maximum_input_tokens,profile.maximum_output_tokens,
               profile.fixed_gpu_time_us,profile.gpu_time_us_per_1k_tokens,
               profile.reference_vram_mib,profile.token_rate_micro_per_1k,
               profile.gpu_rate_micro_per_second,
               profile.vram_rate_micro_per_gib_second,
               800,200,1000,1000000,1024000000,1000,1000,1000,3000
        FROM billing_profiles AS profile WHERE profile.id=$8
        "#,
    )
    .bind(route_id)
    .bind(fixture.user_id)
    .bind(format!("schema-v34-v1-route-{route_id}"))
    .bind(fixture.model_id)
    .bind(fixture.model_instance_id)
    .bind(fixture.node_id)
    .bind(fixture.report_id)
    .bind(fixture.profile_id)
    .execute(pool)
    .await
}

async fn insert_receipt_without_billing(
    pool: &PgPool,
    fixture: BillingFixture,
    receipt_id: Uuid,
    job_id: Uuid,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO receipts
            (id,job_id,consumer_user_id,node_user_id,model_name,tier,trust_level,
             base_cost_micro,user_deduction_micro,node_quota_micro,
             contribution_micro,reserve_micro,settlement_hash)
        VALUES ($1,$2,$3,$3,'schema-v34','medium','standard',
                3000,3000,2400,3600,600,$4)
        "#,
    )
    .bind(receipt_id)
    .bind(job_id)
    .bind(fixture.user_id)
    .bind(format!("{:0<64}", receipt_id.simple()))
    .execute(pool)
    .await
}

async fn insert_v1_receipt(
    pool: &PgPool,
    fixture: BillingFixture,
    receipt_id: Uuid,
    job_id: Uuid,
    top_level_base_micro: i64,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
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
        SELECT $1,job.id,$2,$2,'schema-v34','medium','standard',
               $3,3000,2400,3600,600,$4,
               job.billing_contract_version,job.billing_profile_id,
               job.billing_profile_version,job.billing_profile_fingerprint,
               job.billing_model_weights_hash,job.billing_reference_hardware_class,
               job.billing_profile_evidence_hash,job.billing_profile_valid_from,
               job.billing_profile_valid_until,job.billing_profile_max_input_tokens,
               job.billing_profile_max_output_tokens,job.billing_fixed_gpu_time_us,
               job.billing_gpu_time_us_per_1k_tokens,job.billing_reference_vram_mib,
               job.billing_token_rate_micro_per_1k,
               job.billing_gpu_rate_micro_per_second,
               job.billing_vram_rate_micro_per_gib_second,
               job.billing_authorized_input_tokens,
               job.billing_authorized_max_output_tokens,job.billing_billable_tokens,
               job.billing_reference_gpu_time_us,
               job.billing_reference_vram_mib_microseconds,
               job.billing_token_cost_micro,job.billing_gpu_cost_micro,
               job.billing_vram_cost_micro,job.billing_base_cost_micro
        FROM jobs AS job WHERE job.id=$5
        "#,
    )
    .bind(receipt_id)
    .bind(fixture.user_id)
    .bind(top_level_base_micro)
    .bind(format!("{:f<64}", receipt_id.simple()))
    .bind(job_id)
    .execute(pool)
    .await
}

async fn exercise_v34(pool: &PgPool, through_33: &Migrator, through_34: &Migrator) -> TestResult {
    through_33
        .run(pool)
        .await
        .map_err(|error| format!("无法迁移 v34 fixture 到 0033：{error}"))?;
    let fixture = seed_fixture(pool).await?;

    let historical_job_id = Uuid::now_v7();
    insert_job_without_billing(pool, fixture, historical_job_id)
        .await
        .map_err(|error| format!("无法创建 transitional 非终态 job：{error}"))?;
    let expired_route_id = Uuid::now_v7();
    insert_route_without_billing(pool, fixture, expired_route_id, true)
        .await
        .map_err(|error| format!("无法创建已过期 prepared route：{error}"))?;

    let blocked = through_34
        .run(pool)
        .await
        .expect_err("0034 必须拒绝非终态 NULL billing job");
    let blocked_message = blocked.to_string();
    if !blocked_message.contains("请先停止协调服务器")
        || !blocked_message.contains("排空或取消任务")
        || !blocked_message.contains("释放准备金")
    {
        return Err(format!("0034 升级错误缺少运维处置指引：{blocked_message}"));
    }
    let version_after_rejection: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version),0) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取拒绝后的 migration 版本：{error}"))?;
    if version_after_rejection != 33 {
        return Err(format!(
            "0034 preflight 失败没有原子回滚：{version_after_rejection}"
        ));
    }

    sqlx::query("UPDATE jobs SET status='failed',completed_at=now(),updated_at=now() WHERE id=$1")
        .bind(historical_job_id)
        .execute(pool)
        .await
        .map_err(|error| format!("无法把 transitional job 排空为历史终态：{error}"))?;
    through_34
        .run(pool)
        .await
        .map_err(|error| format!("排空后无法迁移到 0034：{error}"))?;

    let history: (String, Option<String>, String, Option<String>) = sqlx::query_as(
        r#"
        SELECT job.status,job.billing_contract_version,
               route.status,route.billing_contract_version
        FROM jobs AS job
        CROSS JOIN regulated_routes AS route
        WHERE job.id=$1 AND route.id=$2
        "#,
    )
    .bind(historical_job_id)
    .bind(expired_route_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 0034 保留的历史 NULL 行：{error}"))?;
    if history != ("failed".to_owned(), None, "prepared".to_owned(), None) {
        return Err(format!("0034 改写或拒绝了不可消费的历史行：{history:?}"));
    }

    expect_database_message(
        insert_job_without_billing(pool, fixture, Uuid::now_v7()).await,
        "23514",
        "new rows require a complete server_reference_upper_bound_v1 billing snapshot",
        "0034 后插入 NULL billing job",
    )?;
    expect_database_message(
        insert_v1_job(pool, fixture, Uuid::now_v7(), 801).await,
        "23514",
        "protocol token authorization does not match billing authorization",
        "新 job 的 protocol/billing token 授权不一致",
    )?;
    let valid_job_id = Uuid::now_v7();
    insert_v1_job(pool, fixture, valid_job_id, 800)
        .await
        .map_err(|error| format!("完整 v1 job 被 0034 错误拒绝：{error}"))?;

    expect_database_message(
        insert_route_without_billing(pool, fixture, Uuid::now_v7(), false).await,
        "23514",
        "new rows require a complete server_reference_upper_bound_v1 billing snapshot",
        "0034 后插入 NULL billing regulated route",
    )?;
    insert_v1_route(pool, fixture, Uuid::now_v7())
        .await
        .map_err(|error| format!("完整 v1 regulated route 被 0034 错误拒绝：{error}"))?;

    expect_database_message(
        insert_receipt_without_billing(pool, fixture, Uuid::now_v7(), valid_job_id).await,
        "23514",
        "new rows require a complete server_reference_upper_bound_v1 billing snapshot",
        "0034 后插入 NULL billing receipt",
    )?;
    expect_database_message(
        insert_v1_receipt(pool, fixture, Uuid::now_v7(), valid_job_id, 3001).await,
        "23514",
        "receipt base_cost_micro does not match billing_base_cost_micro",
        "receipt 顶层 base 与 billing base 不一致",
    )?;
    insert_v1_receipt(pool, fixture, Uuid::now_v7(), valid_job_id, 3000)
        .await
        .map_err(|error| format!("完整 v1 receipt 被 0034 错误拒绝：{error}"))?;
    Ok(())
}

#[tokio::test]
async fn schema_34_gates_upgrade_and_requires_complete_new_billing_rows() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let source = Migrator::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
        .await
        .expect("应能加载 migrations");
    let through_33 = migrator_through_without_cluster_role(&source, 33);
    let through_34 =
        migrator_through_without_cluster_role(&source, FINAL_BILLING_MIGRATION_VERSION);
    let (admin_pool, base_options) = connect_admin(&database_url)
        .await
        .expect("应能连接 v34 maintenance database");
    let (database_name, pool) = create_test_database(&admin_pool, &base_options)
        .await
        .expect("应能创建 v34 隔离数据库");

    let exercise = exercise_v34(&pool, &through_33, &through_34).await;
    pool.close().await;
    let cleanup = drop_test_database(&admin_pool, &database_name).await;
    admin_pool.close().await;

    match (exercise, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => panic!("{error}"),
        (Ok(()), Err(error)) => panic!("{error}"),
        (Err(error), Err(cleanup_error)) => panic!("{error}；清理同时失败：{cleanup_error}"),
    }
}
