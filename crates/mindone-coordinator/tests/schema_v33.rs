use std::{borrow::Cow, env, path::PathBuf, str::FromStr};

use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

const CLUSTER_ROLE_MIGRATION_VERSION: i64 = 26;
const BILLING_PROVISION_MIGRATION_VERSION: i64 = 33;

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone)]
struct ProvisionRequest {
    profile_id: Uuid,
    audit_id: Uuid,
    model_id: Uuid,
    profile_version: i64,
    reference_hardware_class: String,
    maximum_input_tokens: i64,
    maximum_output_tokens: i64,
    fixed_gpu_time_us: i64,
    gpu_time_us_per_1k_tokens: i64,
    reference_vram_mib: i64,
    token_rate_micro_per_1k: i64,
    gpu_rate_micro_per_second: i64,
    vram_rate_micro_per_gib_second: i64,
    evidence_sha256: String,
    valid_from: OffsetDateTime,
    valid_until: OffsetDateTime,
    operator_id: String,
    reason: String,
    idempotency_key: String,
    request_fingerprint: String,
}

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v33 计费 profile provisioning 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v33 计费 profile provisioning 测试：未设置 DATABASE_URL");
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

fn timestamp(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).expect("固定测试时间应有效")
}

fn test_idempotency_key(suffix: &str) -> String {
    ["billing", "h100", suffix].join("-")
}

fn request(model_id: Uuid) -> ProvisionRequest {
    ProvisionRequest {
        profile_id: Uuid::now_v7(),
        audit_id: Uuid::now_v7(),
        model_id,
        profile_version: 1,
        reference_hardware_class: "nvidia-h100-sxm-80gb".to_owned(),
        maximum_input_tokens: 4_096,
        maximum_output_tokens: 1_024,
        fixed_gpu_time_us: 100_000,
        gpu_time_us_per_1k_tokens: 2_000_000,
        reference_vram_mib: 81_920,
        token_rate_micro_per_1k: 1_000,
        gpu_rate_micro_per_second: 2_000,
        vram_rate_micro_per_gib_second: 3_000,
        evidence_sha256: "de".repeat(32),
        valid_from: timestamp("2026-07-20T00:00:00Z"),
        valid_until: timestamp("2026-08-20T00:00:00Z"),
        operator_id: "ops/billing".to_owned(),
        reason: "根据独立硬件基准证据发布生产费率".to_owned(),
        idempotency_key: test_idempotency_key("2026-0001"),
        request_fingerprint: "ac".repeat(32),
    }
}

async fn seed_model(pool: &PgPool) -> TestResult<Uuid> {
    let user_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'schema-v33',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("schema-v33-{user_id}"))
    .bind(format!("计费供应-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v33 用户：{error}"))?;
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
    .bind(format!("schema-v33-{model_id}"))
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v33 模型：{error}"))?;
    Ok(model_id)
}

async fn provision(
    pool: &PgPool,
    request: &ProvisionRequest,
) -> Result<(Uuid, Uuid, String, String, OffsetDateTime, bool), sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT out_audit_id,out_profile_id,out_model_weights_hash,
               out_profile_fingerprint,out_created_at,out_idempotent_replay
        FROM mindone_record_billing_profile_v1(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            $11,$12,$13,$14,$15,$16,$17,$18,$19,$20
        )
        "#,
    )
    .bind(request.profile_id)
    .bind(request.audit_id)
    .bind(request.model_id)
    .bind(request.profile_version)
    .bind(&request.reference_hardware_class)
    .bind(request.maximum_input_tokens)
    .bind(request.maximum_output_tokens)
    .bind(request.fixed_gpu_time_us)
    .bind(request.gpu_time_us_per_1k_tokens)
    .bind(request.reference_vram_mib)
    .bind(request.token_rate_micro_per_1k)
    .bind(request.gpu_rate_micro_per_second)
    .bind(request.vram_rate_micro_per_gib_second)
    .bind(&request.evidence_sha256)
    .bind(request.valid_from)
    .bind(request.valid_until)
    .bind(&request.operator_id)
    .bind(&request.reason)
    .bind(&request.idempotency_key)
    .bind(&request.request_fingerprint)
    .fetch_one(pool)
    .await
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

async fn exercise_fresh_v33(pool: &PgPool) -> TestResult {
    let initial_profiles: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM billing_profiles")
        .fetch_one(pool)
        .await
        .map_err(|error| format!("无法读取 fresh billing profile 数量：{error}"))?;
    if initial_profiles != 0 {
        return Err("Development/Production fresh schema 不得预置默认计费 profile".to_owned());
    }

    let missing_model_request = request(Uuid::now_v7());
    expect_database_message(
        provision(pool, &missing_model_request).await,
        "23503",
        "billing profile model does not exist",
        "为不存在的模型供应 profile",
    )?;

    let model_id = seed_model(pool).await?;
    let original = request(model_id);
    let created = provision(pool, &original)
        .await
        .map_err(|error| format!("无法通过原子入口创建计费 profile：{error}"))?;
    if created.0 != original.audit_id
        || created.1 != original.profile_id
        || created.2 != "ab".repeat(32)
        || created.3.len() != 64
        || created.5
    {
        return Err(format!("首次 provisioning 返回值无效：{created:?}"));
    }

    let database_fingerprint: String = sqlx::query_scalar(
        r#"
        SELECT mindone_billing_profile_fingerprint_v1(
            id,contract_version,profile_version,model_id,model_weights_hash,
            reference_hardware_class,maximum_input_tokens,maximum_output_tokens,
            fixed_gpu_time_us,gpu_time_us_per_1k_tokens,reference_vram_mib,
            token_rate_micro_per_1k,gpu_rate_micro_per_second,
            vram_rate_micro_per_gib_second,evidence_hash,valid_from,valid_until
        )
        FROM billing_profiles WHERE id=$1
        "#,
    )
    .bind(original.profile_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法复算数据库 profile fingerprint：{error}"))?;
    if database_fingerprint != created.3 {
        return Err("provisioning 没有使用数据库 v1 指纹函数的精确结果".to_owned());
    }

    let mut invalid_audit = original.clone();
    invalid_audit.profile_id = Uuid::now_v7();
    invalid_audit.audit_id = Uuid::now_v7();
    invalid_audit.profile_version = 2;
    invalid_audit.idempotency_key = test_idempotency_key("invalid-audit");
    invalid_audit.request_fingerprint = "bd".repeat(32);
    invalid_audit.reason = "太短".to_owned();
    match provision(pool, &invalid_audit).await {
        Err(sqlx::Error::Database(database)) if database.code().as_deref() == Some("23514") => {}
        Ok(_) => return Err("audit 校验失败时 profile INSERT 不应成功".to_owned()),
        Err(error) => return Err(format!("audit 校验失败分类不正确：{error}")),
    }
    let leaked_profile: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM billing_profiles \
         WHERE model_id=$1 AND profile_version=2)",
    )
    .bind(model_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法检查失败 provisioning 的原子回滚：{error}"))?;
    if leaked_profile {
        return Err("audit INSERT 失败后遗留了未审计 billing profile".to_owned());
    }

    let mut replay = original.clone();
    replay.profile_id = Uuid::now_v7();
    replay.audit_id = Uuid::now_v7();
    let replayed = provision(pool, &replay)
        .await
        .map_err(|error| format!("完全相同请求重放失败：{error}"))?;
    if replayed.0 != original.audit_id
        || replayed.1 != original.profile_id
        || replayed.3 != created.3
        || !replayed.5
    {
        return Err(format!("幂等重放没有返回原记录：{replayed:?}"));
    }

    let mut conflicting_replay = replay.clone();
    conflicting_replay.reason.push('。');
    expect_database_message(
        provision(pool, &conflicting_replay).await,
        "23505",
        "billing profile idempotency conflict",
        "同幂等键变更 reason",
    )?;

    let mut conflicting_version = original.clone();
    conflicting_version.profile_id = Uuid::now_v7();
    conflicting_version.audit_id = Uuid::now_v7();
    conflicting_version.idempotency_key = test_idempotency_key("2026-other");
    conflicting_version.request_fingerprint = "bc".repeat(32);
    expect_database_message(
        provision(pool, &conflicting_version).await,
        "23505",
        "billing profile version conflict",
        "不同幂等键复用 model/profile version",
    )?;

    expect_database_message(
        sqlx::query("UPDATE billing_profile_provision_audits SET reason=reason WHERE id=$1")
            .bind(original.audit_id)
            .execute(pool)
            .await,
        "23514",
        "MindOne physical billing records are append-only",
        "修改 provisioning audit",
    )?;
    expect_database_message(
        sqlx::query("DELETE FROM billing_profiles WHERE id=$1")
            .bind(original.profile_id)
            .execute(pool)
            .await,
        "23514",
        "MindOne physical billing records are append-only",
        "删除 billing profile",
    )?;

    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*)::bigint FROM billing_profiles), \
                (SELECT COUNT(*)::bigint FROM billing_profile_provision_audits)",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取最终 provisioning 数量：{error}"))?;
    if counts != (1, 1) {
        return Err(format!("冲突或重放产生了重复 profile/audit：{counts:?}"));
    }
    Ok(())
}

#[tokio::test]
async fn fresh_schema_33_enforces_atomic_billing_profile_provisioning() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("应能连接 v33 schema 测试数据库");
    let source = Migrator::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
        .await
        .expect("应能加载 migrations");
    let through_33 =
        migrator_through_without_cluster_role(&source, BILLING_PROVISION_MIGRATION_VERSION);
    let schema = format!("mindone_schema_v33_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(&admin_pool)
        .await
        .expect("应能创建 v33 隔离 schema");

    let body_result = match create_isolated_pool(&database_url, &schema).await {
        Ok(pool) => {
            let result = match through_33.run(&pool).await {
                Ok(()) => exercise_fresh_v33(&pool).await,
                Err(error) => Err(format!("无法迁移 fresh schema 到 0033：{error}")),
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
        .map_err(|error| format!("无法清理 v33 隔离 schema：{error}"));
    admin_pool.close().await;

    match (body_result, cleanup_result) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => panic!("{error}"),
        (Ok(()), Err(error)) => panic!("{error}"),
        (Err(error), Err(cleanup)) => panic!("{error}；清理同时失败：{cleanup}"),
    }
}
