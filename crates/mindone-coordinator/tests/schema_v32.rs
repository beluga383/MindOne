use std::{borrow::Cow, env, path::PathBuf, str::FromStr};

use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Row,
};
use uuid::Uuid;

const CLUSTER_ROLE_MIGRATION_VERSION: i64 = 26;
const PHYSICAL_BILLING_MIGRATION_VERSION: i64 = 32;

type TestResult<T = ()> = Result<T, String>;

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v32 物理计费 schema 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v32 物理计费 schema 测试：未设置 DATABASE_URL");
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

async fn create_isolated_pool(database_url: &str, schema: &str) -> TestResult<PgPool> {
    let options = PgConnectOptions::from_str(database_url)
        .map_err(|error| format!("DATABASE_URL 无效：{error}"))?
        .options([("search_path", schema)]);
    PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|error| format!("无法连接隔离 schema {schema}：{error}"))
}

fn expect_sqlstate<T>(
    result: Result<T, sqlx::Error>,
    expected: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation} 应被数据库拒绝")),
        Err(sqlx::Error::Database(database)) if database.code().as_deref() == Some(expected) => {
            Ok(())
        }
        Err(error) => Err(format!(
            "{operation} 错误分类不正确：期望 SQLSTATE {expected}，实际 {error}"
        )),
    }
}

async fn seed_model(pool: &PgPool) -> TestResult<(Uuid, Uuid)> {
    let user_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'schema-v32',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("schema-v32-{user_id}"))
    .bind(format!("物理计费-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v32 用户：{error}"))?;
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
    .bind(format!("schema-v32-{model_id}"))
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v32 模型：{error}"))?;
    Ok((user_id, model_id))
}

async fn insert_v1_job(
    pool: &PgPool,
    job_id: Uuid,
    user_id: Uuid,
    model_id: Uuid,
    profile_id: Uuid,
    billing_base_cost_micro: i64,
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
        SELECT $1,$2,$3,$4,'mindone-standard-aead-v1:djMy','base64',
               800,200,4500,$5,1,
               profile.contract_version,profile.id,profile.profile_version,
               profile.profile_fingerprint,profile.model_weights_hash,
               profile.reference_hardware_class,profile.evidence_hash,
               profile.valid_from,profile.valid_until,
               profile.maximum_input_tokens,profile.maximum_output_tokens,
               profile.fixed_gpu_time_us,profile.gpu_time_us_per_1k_tokens,
               profile.reference_vram_mib,profile.token_rate_micro_per_1k,
               profile.gpu_rate_micro_per_second,
               profile.vram_rate_micro_per_gib_second,
               800,200,1000,1000000,1024000000,1000,1000,1000,$7
        FROM billing_profiles AS profile
        WHERE profile.id=$6
        "#,
    )
    .bind(job_id)
    .bind(user_id)
    .bind(model_id)
    .bind(format!("schema-v32-job-{job_id}"))
    .bind(format!("mindone-standard-hmac-v1:{}", "c".repeat(64)))
    .bind(profile_id)
    .bind(billing_base_cost_micro)
    .execute(pool)
    .await
}

async fn exercise_fresh_v32(pool: &PgPool) -> TestResult {
    let (user_id, model_id) = seed_model(pool).await?;
    let profile_id = Uuid::now_v7();
    let profile = sqlx::query(
        r#"
        INSERT INTO billing_profiles
            (id,contract_version,profile_version,model_id,model_weights_hash,
             reference_hardware_class,maximum_input_tokens,maximum_output_tokens,
             fixed_gpu_time_us,gpu_time_us_per_1k_tokens,reference_vram_mib,
             token_rate_micro_per_1k,gpu_rate_micro_per_second,
             vram_rate_micro_per_gib_second,evidence_hash,valid_from,valid_until)
        VALUES
            ($1,'server_reference_upper_bound_v1',1,$2,$3,'reference-a100-80g',
             4096,1024,0,1000000,1024,1000,1000,1000,$4,
             now()-interval '1 hour',now()+interval '1 hour')
        RETURNING profile_fingerprint
        "#,
    )
    .bind(profile_id)
    .bind(model_id)
    .bind("ab".repeat(32))
    .bind("de".repeat(32))
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法创建不可变 billing profile：{error}"))?;
    let fingerprint: String = profile
        .try_get("profile_fingerprint")
        .map_err(|error| format!("profile_fingerprint 类型错误：{error}"))?;
    if fingerprint.len() != 64 || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "数据库未生成有效 profile fingerprint：{fingerprint}"
        ));
    }

    let job_id = Uuid::now_v7();
    insert_v1_job(pool, job_id, user_id, model_id, profile_id, 3_000)
        .await
        .map_err(|error| format!("无法写入完整 v1 计费快照：{error}"))?;
    let quote: (i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT billing_token_cost_micro,billing_gpu_cost_micro,
               billing_vram_cost_micro,billing_base_cost_micro,reserved_cost_micro
        FROM jobs WHERE id=$1
        "#,
    )
    .bind(job_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 v1 三分项：{error}"))?;
    if quote != (1_000, 1_000, 1_000, 3_000, 4_500) {
        return Err(format!("v1 三分项或分项和错误：{quote:?}"));
    }

    expect_sqlstate(
        insert_v1_job(pool, Uuid::now_v7(), user_id, model_id, profile_id, 2_999).await,
        "23514",
        "写入错误分项和",
    )?;

    expect_sqlstate(
        sqlx::query("UPDATE jobs SET billing_base_cost_micro=3001 WHERE id=$1")
            .bind(job_id)
            .execute(pool)
            .await,
        "23514",
        "修改冻结的 job 计费快照",
    )?;
    expect_sqlstate(
        sqlx::query("UPDATE billing_profiles SET token_rate_micro_per_1k=1001 WHERE id=$1")
            .bind(profile_id)
            .execute(pool)
            .await,
        "23514",
        "修改 billing profile",
    )?;

    let transitional_job_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             standard_request_fingerprint,standard_payload_storage_version)
        VALUES ($1,$2,$3,$4,'mindone-standard-aead-v1:djMy','base64',
                1,1,1,$5,1)
        "#,
    )
    .bind(transitional_job_id)
    .bind(user_id)
    .bind(model_id)
    .bind(format!("schema-v32-transitional-{transitional_job_id}"))
    .bind(format!("mindone-standard-hmac-v1:{}", "d".repeat(64)))
    .execute(pool)
    .await
    .map_err(|error| format!("旧 writer transitional NULL 应保持兼容：{error}"))?;
    let transitional_version: Option<String> =
        sqlx::query_scalar("SELECT billing_contract_version FROM jobs WHERE id=$1")
            .bind(transitional_job_id)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取 transitional job：{error}"))?;
    if transitional_version.is_some() {
        return Err("新行不得通过默认值伪装成 legacy".to_owned());
    }
    expect_sqlstate(
        sqlx::query("UPDATE jobs SET billing_contract_version='legacy_token_v1' WHERE id=$1")
            .bind(transitional_job_id)
            .execute(pool)
            .await,
        "23514",
        "把 transitional job 事后改成 legacy",
    )?;

    let forged_legacy_job_id = Uuid::now_v7();
    expect_sqlstate(
        sqlx::query(
            r#"
            INSERT INTO jobs
                (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
                 estimated_input_tokens,max_output_tokens,reserved_cost_micro,
                 standard_request_fingerprint,standard_payload_storage_version,
                 billing_contract_version)
            VALUES ($1,$2,$3,$4,'mindone-standard-aead-v1:djMy','base64',
                    1,1,1,$5,1,'legacy_token_v1')
            "#,
        )
        .bind(forged_legacy_job_id)
        .bind(user_id)
        .bind(model_id)
        .bind(format!("schema-v32-forged-{forged_legacy_job_id}"))
        .bind(format!("mindone-standard-hmac-v1:{}", "e".repeat(64)))
        .execute(pool)
        .await,
        "23514",
        "新 job 伪造 legacy 标记",
    )?;
    expect_sqlstate(
        sqlx::query(
            "INSERT INTO physical_billing_legacy_allowlist (entity_kind,entity_id) \
             VALUES ('jobs',$1)",
        )
        .bind(forged_legacy_job_id)
        .execute(pool)
        .await,
        "23514",
        "迁移后扩充 legacy allowlist",
    )?;

    let receipt_id = Uuid::now_v7();
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
        SELECT $1,job.id,$2,$2,'schema-v32','medium','standard',
               3000,3000,2400,3600,600,$3,
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
        FROM jobs AS job WHERE job.id=$4
        "#,
    )
    .bind(receipt_id)
    .bind(user_id)
    .bind("f".repeat(64))
    .bind(job_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法写入与 job 一致的 v1 receipt：{error}"))?;
    expect_sqlstate(
        sqlx::query("UPDATE receipts SET reserve_micro=reserve_micro WHERE id=$1")
            .bind(receipt_id)
            .execute(pool)
            .await,
        "23514",
        "修改 append-only receipt",
    )?;
    Ok(())
}

#[tokio::test]
async fn fresh_schema_32_enforces_physical_billing_contract() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("应能连接 v32 schema 测试数据库");
    let source = Migrator::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
        .await
        .expect("应能加载 migrations");
    let through_32 =
        migrator_through_without_cluster_role(&source, PHYSICAL_BILLING_MIGRATION_VERSION);
    let schema = format!("mindone_schema_v32_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(&admin_pool)
        .await
        .expect("应能创建 v32 隔离 schema");

    let body_result = match create_isolated_pool(&database_url, &schema).await {
        Ok(pool) => {
            let result = match through_32.run(&pool).await {
                Ok(()) => exercise_fresh_v32(&pool).await,
                Err(error) => Err(format!("无法迁移 fresh schema 到 0032：{error}")),
            };
            pool.close().await;
            result
        }
        Err(error) => Err(error),
    };
    let cleanup_result = sqlx::query(&format!(r#"DROP SCHEMA "{schema}" CASCADE"#))
        .execute(&admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v32 隔离 schema：{error}"));
    admin_pool.close().await;

    match (body_result, cleanup_result) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => panic!("{error}"),
        (Ok(()), Err(error)) => panic!("{error}"),
        (Err(error), Err(cleanup)) => panic!("{error}；清理同时失败：{cleanup}"),
    }
}
