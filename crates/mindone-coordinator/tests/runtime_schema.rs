use std::{borrow::Cow, env, future::Future, path::PathBuf, str::FromStr, time::Duration};

use mindone_coordinator::db::{prepare_runtime, RuntimePrepareError};
use serial_test::serial;
use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use uuid::Uuid;

const CLUSTER_ROLE_MIGRATION_VERSION: i64 = 26;
const COORDINATOR_RTT_MIGRATION_VERSION: i64 = 29;
const LATEST_SCHEMA_VERSION: i64 = 39;
const STANDARD_DATA_KEY: [u8; 32] = [37_u8; 32];
const LEGACY_PAYLOAD: &str = "bGVnYWN5LXBheWxvYWQ=";

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy, Debug)]
enum DriftCase {
    MissingPublicTable,
    ExtraVersion,
    WrongDescription,
    FailedMigration,
    ChecksumDrift,
}

impl DriftCase {
    const ALL: [Self; 5] = [
        Self::MissingPublicTable,
        Self::ExtraVersion,
        Self::WrongDescription,
        Self::FailedMigration,
        Self::ChecksumDrift,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::MissingPublicTable => "missing",
            Self::ExtraVersion => "extra",
            Self::WrongDescription => "description",
            Self::FailedMigration => "failed",
            Self::ChecksumDrift => "checksum",
        }
    }
}

struct LegacyFixture {
    job_id: Uuid,
    user_id: Uuid,
    username: String,
    fingerprint: Option<String>,
}

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("运行时 schema PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过运行时 schema PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

async fn load_migrator() -> TestResult<Migrator> {
    let migrations = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    Migrator::new(migrations)
        .await
        .map_err(|error| format!("无法加载测试 migration：{error}"))
}

fn schema_migrator_without_cluster_role(source: &Migrator) -> TestResult<Migrator> {
    let role_migration_count = source
        .iter()
        .filter(|migration| {
            migration.migration_type.is_up_migration()
                && migration.version == CLUSTER_ROLE_MIGRATION_VERSION
        })
        .count();
    if role_migration_count != 1 {
        return Err(format!(
            "预期恰好一个 {CLUSTER_ROLE_MIGRATION_VERSION} runtime role migration，实际为 {role_migration_count}"
        ));
    }

    Ok(Migrator {
        migrations: Cow::Owned(
            source
                .iter()
                .filter(|migration| {
                    migration.migration_type.is_up_migration()
                        && migration.version != CLUSTER_ROLE_MIGRATION_VERSION
                })
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    })
}

async fn connect_admin(database_url: &str) -> TestResult<(PgPool, PgConnectOptions)> {
    let base_options = PgConnectOptions::from_str(database_url)
        .map_err(|error| format!("DATABASE_URL 无效：{error}"))?;
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options.clone().database("postgres"))
        .await
        .map_err(|error| format!("无法连接 PostgreSQL maintenance database：{error}"))?;
    Ok((admin_pool, base_options))
}

fn temporary_database_name(label: &str) -> TestResult<String> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
    {
        return Err("临时数据库标签包含不安全字符".to_owned());
    }
    let name = format!("mindone_rt_{label}_{}", Uuid::now_v7().simple());
    if name.len() > 63 {
        return Err("临时数据库名超过 PostgreSQL 标识符长度".to_owned());
    }
    Ok(name)
}

fn quoted_identifier(identifier: &str) -> TestResult<String> {
    if identifier.is_empty()
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("拒绝不安全的 PostgreSQL 标识符".to_owned());
    }
    Ok(format!("\"{identifier}\""))
}

async fn initialize_isolated_schema(pool: &PgPool, source: &Migrator) -> TestResult {
    schema_migrator_without_cluster_role(source)?
        .run(pool)
        .await
        .map_err(|error| format!("无法在隔离数据库执行 schema migrations：{error}"))?;

    let role_migration = source
        .iter()
        .find(|migration| {
            migration.migration_type.is_up_migration()
                && migration.version == CLUSTER_ROLE_MIGRATION_VERSION
        })
        .ok_or_else(|| "缺少 runtime role migration 元数据".to_owned())?;
    sqlx::query(
        r#"
        INSERT INTO public._sqlx_migrations
            (version,description,success,checksum,execution_time)
        VALUES ($1,$2,TRUE,$3,0)
        "#,
    )
    .bind(role_migration.version)
    .bind(role_migration.description.as_ref())
    .bind(role_migration.checksum.as_ref())
    .execute(pool)
    .await
    .map_err(|error| format!("无法登记被安全跳过的 runtime role migration：{error}"))?;
    Ok(())
}

async fn with_temporary_database<F, Fut>(
    admin_pool: &PgPool,
    base_options: &PgConnectOptions,
    migrator: &Migrator,
    label: &str,
    operation: F,
) -> TestResult
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = TestResult>,
{
    let database_name = temporary_database_name(label)?;
    let database_identifier = quoted_identifier(&database_name)?;
    sqlx::query(&format!(
        "CREATE DATABASE {database_identifier} TEMPLATE template0"
    ))
    .execute(admin_pool)
    .await
    .map_err(|error| format!("无法创建隔离测试数据库 {database_name}：{error}"))?;

    let work_result = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(
            base_options
                .clone()
                .database(&database_name)
                .options([("search_path", "public,pg_catalog")]),
        )
        .await
    {
        Ok(pool) => {
            let result = match initialize_isolated_schema(&pool, migrator).await {
                Ok(()) => operation(pool.clone()).await,
                Err(error) => Err(error),
            };
            pool.close().await;
            result
        }
        Err(error) => Err(format!("无法连接隔离测试数据库 {database_name}：{error}")),
    };

    let cleanup_result = sqlx::query(&format!("DROP DATABASE {database_identifier} WITH (FORCE)"))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理隔离测试数据库 {database_name}：{error}"));
    match (work_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(work_error), Ok(())) => Err(work_error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Err(work_error), Err(cleanup_error)) => Err(format!("{work_error}；并且 {cleanup_error}")),
    }
}

async fn with_standard_trigger_disabled<F, Fut>(pool: &PgPool, operation: F) -> TestResult
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = TestResult>,
{
    sqlx::query("ALTER TABLE public.jobs DISABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(pool)
        .await
        .map_err(|error| format!("无法禁用隔离数据库 Standard 写入守卫：{error}"))?;
    let operation_result = operation().await;
    let enable_result =
        sqlx::query("ALTER TABLE public.jobs ENABLE TRIGGER jobs_enforce_standard_data_at_rest")
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("无法恢复隔离数据库 Standard 写入守卫：{error}"));
    match (operation_result, enable_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(operation_error), Ok(())) => Err(operation_error),
        (Ok(()), Err(enable_error)) => Err(enable_error),
        (Err(operation_error), Err(enable_error)) => {
            Err(format!("{operation_error}；并且 {enable_error}"))
        }
    }
}

async fn with_legacy_standard_insert_triggers_disabled<F, Fut>(
    pool: &PgPool,
    operation: F,
) -> TestResult
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = TestResult>,
{
    sqlx::query("ALTER TABLE public.jobs DISABLE TRIGGER jobs_enforce_standard_data_at_rest")
        .execute(pool)
        .await
        .map_err(|error| format!("无法禁用隔离数据库 Standard 写入守卫：{error}"))?;
    if let Err(error) = sqlx::query(
        "ALTER TABLE public.jobs DISABLE TRIGGER jobs_00_require_current_physical_billing_v1",
    )
    .execute(pool)
    .await
    {
        let restore = sqlx::query(
            "ALTER TABLE public.jobs ENABLE TRIGGER jobs_enforce_standard_data_at_rest",
        )
        .execute(pool)
        .await;
        return match restore {
            Ok(_) => Err(format!("无法禁用隔离数据库 v34 计费写入守卫：{error}")),
            Err(restore_error) => Err(format!(
                "无法禁用隔离数据库 v34 计费写入守卫：{error}；并且无法恢复 Standard 写入守卫：{restore_error}"
            )),
        };
    }

    let operation_result = operation().await;
    let billing_restore = sqlx::query(
        "ALTER TABLE public.jobs ENABLE TRIGGER jobs_00_require_current_physical_billing_v1",
    )
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(|error| format!("无法恢复隔离数据库 v34 计费写入守卫：{error}"));
    let standard_restore =
        sqlx::query("ALTER TABLE public.jobs ENABLE TRIGGER jobs_enforce_standard_data_at_rest")
            .execute(pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("无法恢复隔离数据库 Standard 写入守卫：{error}"));

    let mut errors = Vec::new();
    if let Err(error) = operation_result {
        errors.push(error);
    }
    if let Err(error) = billing_restore {
        errors.push(error);
    }
    if let Err(error) = standard_restore {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("；"))
    }
}

async fn insert_legacy_standard_job(
    pool: &PgPool,
    fingerprint: Option<String>,
) -> TestResult<LegacyFixture> {
    let user_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    let username = format!("runtime-schema-{user_id}");
    sqlx::query(
        "INSERT INTO public.users (id,provider,provider_subject,username) \
         VALUES ($1,'runtime-schema-test',$2,$3)",
    )
    .bind(user_id)
    .bind(user_id.to_string())
    .bind(&username)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 Standard 升级哨兵用户：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO public.models
            (id,owner_user_id,name,format,weights_hash,size_bytes,context_length,
             base_cost_per_1k_micro)
        VALUES ($1,$2,$3,'gguf',$4,1,1,1000000)
        "#,
    )
    .bind(model_id)
    .bind(user_id)
    .bind(format!("runtime-schema-{model_id}"))
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 Standard 升级哨兵模型：{error}"))?;

    // fresh v34 没有真实 migration 前历史行。测试只在 owner 控制的隔离数据库中
    // 临时关闭两个 INSERT guard，构造一个终态 transitional NULL billing 历史行，
    // 用于证明 schema 漂移会在 Standard 数据升级前失败；活动任务仍由 0034 拒绝。
    with_legacy_standard_insert_triggers_disabled(pool, || async {
        sqlx::query(
            r#"
            INSERT INTO public.jobs
                (id,user_id,model_id,idempotency_key,status,encrypted_payload,
                 estimated_input_tokens,max_output_tokens,reserved_cost_micro,
                 confidentiality_mode,standard_request_fingerprint,
                 standard_payload_storage_version,standard_result_storage_version,
                 completed_at)
            VALUES ($1,$2,$3,$4,'failed',$5,1,1,1,'standard',$6,0,NULL,now())
            "#,
        )
        .bind(job_id)
        .bind(user_id)
        .bind(model_id)
        .bind(format!("runtime-schema-{job_id}"))
        .bind(LEGACY_PAYLOAD)
        .bind(fingerprint.as_deref())
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 Standard 旧数据哨兵：{error}"))?;
        Ok(())
    })
    .await?;

    Ok(LegacyFixture {
        job_id,
        user_id,
        username,
        fingerprint,
    })
}

async fn apply_drift(pool: &PgPool, case: DriftCase, migrator: &Migrator) -> TestResult {
    match case {
        DriftCase::MissingPublicTable => {
            sqlx::query("CREATE SCHEMA runtime_metadata_shadow")
                .execute(pool)
                .await
                .map_err(|error| format!("无法创建 migration metadata 遮蔽 schema：{error}"))?;
            sqlx::query("ALTER TABLE public._sqlx_migrations SET SCHEMA runtime_metadata_shadow")
                .execute(pool)
                .await
                .map_err(|error| format!("无法移动 public migration metadata 表：{error}"))?;
            sqlx::query("SET search_path=runtime_metadata_shadow,public,pg_catalog")
                .execute(pool)
                .await
                .map_err(|error| format!("无法设置 migration metadata 遮蔽路径：{error}"))?;
        }
        DriftCase::ExtraVersion => {
            let extra_version = migrator
                .iter()
                .filter(|migration| migration.migration_type.is_up_migration())
                .map(|migration| migration.version)
                .max()
                .ok_or_else(|| "内嵌 migrations 为空".to_owned())?
                .checked_add(1)
                .ok_or_else(|| "额外 migration 版本溢出".to_owned())?;
            sqlx::query(
                r#"
                INSERT INTO public._sqlx_migrations
                    (version,description,success,checksum,execution_time)
                VALUES ($1,'unexpected migration',TRUE,$2,0)
                "#,
            )
            .bind(extra_version)
            .bind(vec![0_u8; 48])
            .execute(pool)
            .await
            .map_err(|error| format!("无法注入额外 migration 版本：{error}"))?;
        }
        DriftCase::WrongDescription => {
            sqlx::query(
                "UPDATE public._sqlx_migrations \
                 SET description=description || ' drift' WHERE version=$1",
            )
            .bind(CLUSTER_ROLE_MIGRATION_VERSION)
            .execute(pool)
            .await
            .map_err(|error| format!("无法注入 migration description 漂移：{error}"))?;
        }
        DriftCase::FailedMigration => {
            sqlx::query("UPDATE public._sqlx_migrations SET success=FALSE WHERE version=$1")
                .bind(CLUSTER_ROLE_MIGRATION_VERSION)
                .execute(pool)
                .await
                .map_err(|error| format!("无法注入失败 migration 记录：{error}"))?;
        }
        DriftCase::ChecksumDrift => {
            let checksum_length = migrator
                .iter()
                .find(|migration| migration.version == CLUSTER_ROLE_MIGRATION_VERSION)
                .map(|migration| migration.checksum.len())
                .ok_or_else(|| "缺少 runtime role migration checksum".to_owned())?;
            sqlx::query("UPDATE public._sqlx_migrations SET checksum=$2 WHERE version=$1")
                .bind(CLUSTER_ROLE_MIGRATION_VERSION)
                .bind(vec![0_u8; checksum_length])
                .execute(pool)
                .await
                .map_err(|error| format!("无法注入 migration checksum 漂移：{error}"))?;
        }
    }
    Ok(())
}

async fn assert_legacy_fixture_unchanged(pool: &PgPool, fixture: &LegacyFixture) -> TestResult {
    let actual: (String, i16, Option<String>) = sqlx::query_as(
        "SELECT encrypted_payload,standard_payload_storage_version,\
         standard_request_fingerprint FROM public.jobs WHERE id=$1",
    )
    .bind(fixture.job_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 Standard 旧数据哨兵：{error}"))?;
    let expected = (
        LEGACY_PAYLOAD.to_owned(),
        0_i16,
        fixture.fingerprint.clone(),
    );
    if actual != expected {
        return Err(format!(
            "schema 校验失败后 Standard 旧数据被意外修改：{actual:?}"
        ));
    }
    let key_state_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM public.standard_data_key_state")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取 Standard key state：{error}"))?;
    if key_state_count != 0 {
        return Err(format!(
            "schema 校验失败后 Standard 数据升级被意外启动，key state 数量为 {key_state_count}"
        ));
    }
    Ok(())
}

async fn assert_verification_transaction_closed(
    pool: &PgPool,
    fixture: &LegacyFixture,
) -> TestResult {
    let mut probe = pool
        .begin()
        .await
        .map_err(|error| format!("schema 校验失败后无法开启探针事务：{error}"))?;
    sqlx::query("UPDATE public.users SET username=$2 WHERE id=$1")
        .bind(fixture.user_id)
        .bind(format!("{}-rollback-probe", fixture.username))
        .execute(&mut *probe)
        .await
        .map_err(|error| format!("schema 校验事务残留为只读或未释放连接：{error}"))?;
    probe
        .rollback()
        .await
        .map_err(|error| format!("无法回滚 schema 校验后的探针事务：{error}"))?;
    let username: String = sqlx::query_scalar("SELECT username FROM public.users WHERE id=$1")
        .bind(fixture.user_id)
        .fetch_one(pool)
        .await
        .map_err(|error| format!("无法验证探针事务回滚：{error}"))?;
    if username != fixture.username {
        return Err("schema 校验后的事务回滚探针留下了写入".to_owned());
    }
    Ok(())
}

async fn exercise_drift_case(pool: &PgPool, case: DriftCase, migrator: &Migrator) -> TestResult {
    let fixture = insert_legacy_standard_job(pool, Some("a".repeat(64))).await?;
    apply_drift(pool, case, migrator).await?;
    let result = prepare_runtime(pool, &STANDARD_DATA_KEY).await;
    match (case, result) {
        (DriftCase::MissingPublicTable, Err(RuntimePrepareError::SchemaUnavailable(_))) => {}
        (
            DriftCase::ExtraVersion
            | DriftCase::WrongDescription
            | DriftCase::FailedMigration
            | DriftCase::ChecksumDrift,
            Err(RuntimePrepareError::SchemaDrift),
        ) => {}
        (_, Ok(())) => {
            return Err(format!(
                "{} schema 漂移应失败关闭，但 prepare_runtime 意外成功",
                case.label()
            ));
        }
        (_, Err(error)) => {
            return Err(format!(
                "{} schema 漂移返回了错误分类：{error}",
                case.label()
            ));
        }
    }
    assert_legacy_fixture_unchanged(pool, &fixture).await?;
    assert_verification_transaction_closed(pool, &fixture).await
}

async fn exercise_standard_rollback(pool: &PgPool) -> TestResult {
    let fixture = insert_legacy_standard_job(pool, None).await?;
    match prepare_runtime(pool, &STANDARD_DATA_KEY).await {
        Err(RuntimePrepareError::StandardData(_)) => {}
        Ok(()) => return Err("损坏的 Standard 旧数据应令数据升级失败".to_owned()),
        Err(error) => return Err(format!("Standard 数据升级返回了错误分类：{error}")),
    }
    assert_legacy_fixture_unchanged(pool, &fixture).await?;

    let repaired_fingerprint = "b".repeat(64);
    with_standard_trigger_disabled(pool, || async {
        sqlx::query("UPDATE public.jobs SET standard_request_fingerprint=$2 WHERE id=$1")
            .bind(fixture.job_id)
            .bind(&repaired_fingerprint)
            .execute(pool)
            .await
            .map_err(|error| format!("无法修复 Standard 旧指纹测试夹具：{error}"))?;
        Ok(())
    })
    .await?;
    prepare_runtime(pool, &STANDARD_DATA_KEY)
        .await
        .map_err(|error| format!("修复测试夹具后 Standard 数据升级仍失败：{error}"))?;

    let upgraded: (bool, i16, bool) = sqlx::query_as(
        r#"
        SELECT encrypted_payload LIKE 'mindone-standard-aead-v1:%',
               standard_payload_storage_version,
               standard_request_fingerprint LIKE 'mindone-standard-hmac-v1:%'
        FROM public.jobs
        WHERE id=$1
        "#,
    )
    .bind(fixture.job_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取升级后的 Standard 测试夹具：{error}"))?;
    if upgraded != (true, 1, true) {
        return Err(format!("修复后的 Standard 数据未完整升级：{upgraded:?}"));
    }
    let key_state_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM public.standard_data_key_state")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取升级后的 Standard key state：{error}"))?;
    if key_state_count != 1 {
        return Err(format!(
            "修复后 Standard 数据升级应只提交一个 key state，实际为 {key_state_count}"
        ));
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn runtime_schema_drift_fails_closed_before_standard_upgrade() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    let (admin_pool, base_options) = connect_admin(&database_url).await?;
    let mut result = Ok(());
    for case in DriftCase::ALL {
        let migrator_ref = &migrator;
        let case_result = with_temporary_database(
            &admin_pool,
            &base_options,
            &migrator,
            case.label(),
            |pool| async move { exercise_drift_case(&pool, case, migrator_ref).await },
        )
        .await;
        if let Err(error) = case_result {
            result = Err(error);
            break;
        }
    }
    if result.is_ok() {
        result = with_temporary_database(
            &admin_pool,
            &base_options,
            &migrator,
            "rollback",
            |pool| async move { exercise_standard_rollback(&pool).await },
        )
        .await;
    }
    admin_pool.close().await;
    result
}

#[tokio::test]
#[serial]
async fn schema_39_is_contiguous_and_preserves_billing_cutover() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    let migration_versions = migrator
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .map(|migration| migration.version)
        .collect::<Vec<_>>();
    let expected_versions = (1..=LATEST_SCHEMA_VERSION).collect::<Vec<_>>();
    if migration_versions != expected_versions {
        return Err(format!(
            "schema migration 必须从 1 到 {LATEST_SCHEMA_VERSION} 连续且各出现一次，实际为 {migration_versions:?}"
        ));
    }
    let latest_version = migrator
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .map(|migration| migration.version)
        .max()
        .ok_or_else(|| "内嵌 migrations 为空".to_owned())?;
    if latest_version != LATEST_SCHEMA_VERSION {
        return Err(format!(
            "预期最新 schema 为 {LATEST_SCHEMA_VERSION}，实际为 {latest_version}"
        ));
    }
    if migrator
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .filter(|migration| migration.version == COORDINATOR_RTT_MIGRATION_VERSION)
        .count()
        != 1
    {
        return Err(format!(
            "schema {COORDINATOR_RTT_MIGRATION_VERSION} migration 必须恰好存在一次"
        ));
    }

    let (admin_pool, base_options) = connect_admin(&database_url).await?;
    let result = with_temporary_database(
        &admin_pool,
        &base_options,
        &migrator,
        "coordinator_rtt",
        |pool| async move {
            let (is_nullable, column_default): (String, Option<String>) = sqlx::query_as(
                r#"
                SELECT is_nullable,column_default
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name='node_metrics'
                  AND column_name='coordinator_rtt_ms'
                "#,
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("无法读取 coordinator RTT 列定义：{error}"))?;
            if is_nullable != "YES" || column_default.is_some() {
                return Err(format!(
                    "coordinator RTT 必须可空且无默认值，实际 nullable={is_nullable} default={column_default:?}"
                ));
            }
            let constraint: String = sqlx::query_scalar(
                r#"
                SELECT pg_get_constraintdef(oid)
                FROM pg_constraint
                WHERE conrelid='public.node_metrics'::regclass
                  AND conname='node_metrics_coordinator_rtt_ms_range_v1'
                "#,
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("无法读取 coordinator RTT 范围约束：{error}"))?;
            if !constraint.contains("coordinator_rtt_ms IS NULL")
                || !constraint.contains("coordinator_rtt_ms >= 1")
                || !constraint.contains("coordinator_rtt_ms <= 60000")
            {
                return Err(format!("coordinator RTT 范围约束不完整：{constraint}"));
            }

            let transitional_columns_are_explicit: bool = sqlx::query_scalar(
                r#"
                SELECT COUNT(*) = 3
                   AND bool_and(column_row.is_nullable = 'YES')
                   AND bool_and(column_row.column_default IS NULL)
                FROM information_schema.columns AS column_row
                WHERE column_row.table_schema = 'public'
                  AND column_row.table_name IN ('jobs','regulated_routes','receipts')
                  AND column_row.column_name = 'billing_contract_version'
                "#,
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("无法读取 0032 transitional 计费列定义：{error}"))?;
            if !transitional_columns_are_explicit {
                return Err(
                    "0032 transitional 计费版本列必须可空且没有 legacy 默认值".to_owned(),
                );
            }

            let fresh_billing_state: (bool, bool, bool, bool, bool, i64, i64) = sqlx::query_as(
                r#"
                SELECT to_regclass('public.billing_profiles') IS NOT NULL,
                       to_regclass('public.physical_billing_legacy_allowlist') IS NOT NULL,
                       to_regclass('public.billing_profile_provision_audits') IS NOT NULL,
                       to_regprocedure(
                           'public.mindone_record_billing_profile_v1(uuid,uuid,uuid,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,text,timestamptz,timestamptz,text,text,text,text)'
                       ) IS NOT NULL,
                       to_regprocedure(
                           'public.mindone_require_current_physical_billing_insert_v1()'
                       ) IS NOT NULL,
                       (SELECT COUNT(*)::bigint
                        FROM pg_trigger
                        WHERE NOT tgisinternal
                          AND tgname IN (
                              'jobs_00_require_current_physical_billing_v1',
                              'regulated_routes_00_require_current_physical_billing_v1',
                              'receipts_00_require_current_physical_billing_v1'
                          )),
                       (SELECT COUNT(*)::bigint
                        FROM public.physical_billing_legacy_allowlist)
                "#,
            )
            .fetch_one(&pool)
            .await
            .map_err(|error| format!("无法读取 fresh 0034 计费 schema：{error}"))?;
            if fresh_billing_state != (true, true, true, true, true, 3, 0) {
                return Err(format!(
                    "fresh 0034 必须包含审计入口、三个 INSERT guard 且不应伪造 legacy 行，实际为 {fresh_billing_state:?}"
                ));
            }
            Ok(())
        },
    )
    .await;
    admin_pool.close().await;
    result
}
