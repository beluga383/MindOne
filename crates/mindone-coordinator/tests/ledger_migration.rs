use std::{borrow::Cow, env, path::PathBuf, str::FromStr};

use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool, Row,
};
use uuid::Uuid;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

type TestResult<T = ()> = Result<T, String>;

#[derive(Clone, Copy, Debug)]
enum FixtureKind {
    Valid,
    Fork,
    Disconnect,
    Orphan,
    NonZeroEmpty,
}

impl FixtureKind {
    const ALL: [Self; 5] = [
        Self::Valid,
        Self::Fork,
        Self::Disconnect,
        Self::Orphan,
        Self::NonZeroEmpty,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Fork => "fork",
            Self::Disconnect => "disconnect",
            Self::Orphan => "orphan",
            Self::NonZeroEmpty => "non_zero_empty",
        }
    }

    fn expects_success(self) -> bool {
        matches!(self, Self::Valid)
    }
}

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("账本升级 PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过账本升级 PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn migrator_through(source: &Migrator, maximum_version: i64) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            source
                .iter()
                .filter(|migration| migration.version <= maximum_version)
                .cloned()
                .collect(),
        ),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

fn migrator_through_without(
    source: &Migrator,
    maximum_version: i64,
    excluded_version: i64,
) -> Migrator {
    Migrator {
        migrations: Cow::Owned(
            source
                .iter()
                .filter(|migration| {
                    migration.version <= maximum_version && migration.version != excluded_version
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

async fn create_user(pool: &PgPool, user_id: Uuid, label: &str) -> TestResult {
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'ledger-migration',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("{label}-{user_id}"))
    .bind(format!("账本升级-{label}-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 {label} 用户：{error}"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_quota_entry(
    pool: &PgPool,
    user_id: Uuid,
    label: &str,
    delta: i64,
    before: i64,
    after: i64,
    previous_hash: &str,
    entry_hash: &str,
) -> TestResult {
    sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'migration_fixture',$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(delta)
    .bind(before)
    .bind(after)
    .bind(format!("ledger-migration-{label}-{user_id}"))
    .bind(previous_hash)
    .bind(entry_hash)
    .execute(pool)
    .await
    .map_err(|error| format!("无法写入 {label} quota 旧账本：{error}"))?;
    Ok(())
}

async fn seed_valid_fixture(pool: &PgPool) -> TestResult {
    let user_id = Uuid::now_v7();
    let quota_hash_1 = "1111111111111111111111111111111111111111111111111111111111111111";
    let quota_hash_2 = "2222222222222222222222222222222222222222222222222222222222222222";
    let contribution_hash = "3333333333333333333333333333333333333333333333333333333333333333";
    let reserve_hash = "4444444444444444444444444444444444444444444444444444444444444444";

    create_user(pool, user_id, "valid").await?;
    sqlx::query(
        "INSERT INTO quota_accounts (user_id,spendable_micro,contribution_micro) VALUES ($1,30,11)",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 valid 旧额度账户：{error}"))?;
    insert_quota_entry(
        pool,
        user_id,
        "valid-quota-1",
        10,
        0,
        10,
        GENESIS_HASH,
        quota_hash_1,
    )
    .await?;
    insert_quota_entry(
        pool,
        user_id,
        "valid-quota-2",
        20,
        10,
        30,
        quota_hash_1,
        quota_hash_2,
    )
    .await?;
    sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'migration_fixture',11,0,11,$3,$4,$5)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-migration-valid-contribution-{user_id}"))
    .bind(GENESIS_HASH)
    .bind(contribution_hash)
    .execute(pool)
    .await
    .map_err(|error| format!("无法写入 valid contribution 旧账本：{error}"))?;
    sqlx::query("UPDATE reserve_accounts SET balance_micro=7 WHERE id=1")
        .execute(pool)
        .await
        .map_err(|error| format!("无法设置 valid 旧准备金余额：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',7,0,7,$2,$3,$4)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(format!("ledger-migration-valid-reserve-{user_id}"))
    .bind(GENESIS_HASH)
    .bind(reserve_hash)
    .execute(pool)
    .await
    .map_err(|error| format!("无法写入 valid reserve 旧账本：{error}"))?;

    sqlx::query(
        "INSERT INTO ledger_migration_expected (user_id,quota_head,contribution_head,reserve_head) VALUES ($1,$2,$3,$4)",
    )
    .bind(user_id)
    .bind(quota_hash_2)
    .bind(contribution_hash)
    .bind(reserve_hash)
    .execute(pool)
    .await
    .map_err(|error| format!("无法保存 valid 夹具期望值：{error}"))?;
    Ok(())
}

async fn seed_invalid_fixture(pool: &PgPool, kind: FixtureKind) -> TestResult {
    let user_id = Uuid::now_v7();
    create_user(pool, user_id, kind.label()).await?;

    if matches!(kind, FixtureKind::Orphan) {
        return insert_quota_entry(
            pool,
            user_id,
            "orphan",
            1,
            0,
            1,
            GENESIS_HASH,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await;
    }

    let spendable = match kind {
        FixtureKind::Fork => 10,
        FixtureKind::Disconnect => 15,
        FixtureKind::NonZeroEmpty => 9,
        FixtureKind::Valid | FixtureKind::Orphan => 0,
    };
    sqlx::query("INSERT INTO quota_accounts (user_id,spendable_micro) VALUES ($1,$2)")
        .bind(user_id)
        .bind(spendable)
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 {} 旧额度账户：{error}", kind.label()))?;

    match kind {
        FixtureKind::Fork => {
            insert_quota_entry(
                pool,
                user_id,
                "fork-1",
                10,
                0,
                10,
                GENESIS_HASH,
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .await?;
            insert_quota_entry(
                pool,
                user_id,
                "fork-2",
                10,
                0,
                10,
                GENESIS_HASH,
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .await?;
        }
        FixtureKind::Disconnect => {
            insert_quota_entry(
                pool,
                user_id,
                "disconnect-root",
                10,
                0,
                10,
                GENESIS_HASH,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .await?;
            insert_quota_entry(
                pool,
                user_id,
                "disconnect-island",
                5,
                10,
                15,
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )
            .await?;
        }
        FixtureKind::NonZeroEmpty => {}
        FixtureKind::Valid | FixtureKind::Orphan => {
            return Err(format!("{} 不是此函数支持的损坏夹具", kind.label()));
        }
    }
    Ok(())
}

async fn assert_valid_upgrade(pool: &PgPool) -> TestResult {
    let expected = sqlx::query(
        "SELECT user_id,quota_head,contribution_head,reserve_head FROM ledger_migration_expected",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 valid 夹具期望值：{error}"))?;
    let user_id: Uuid = expected
        .try_get("user_id")
        .map_err(|error| format!("valid 夹具 user_id 类型错误：{error}"))?;
    let expected_quota_head: String = expected
        .try_get("quota_head")
        .map_err(|error| format!("valid 夹具 quota_head 类型错误：{error}"))?;
    let expected_contribution_head: String = expected
        .try_get("contribution_head")
        .map_err(|error| format!("valid 夹具 contribution_head 类型错误：{error}"))?;
    let expected_reserve_head: String = expected
        .try_get("reserve_head")
        .map_err(|error| format!("valid 夹具 reserve_head 类型错误：{error}"))?;
    let account = sqlx::query(
        r#"
        SELECT spendable_micro,contribution_micro,
               quota_ledger_head_hash,quota_ledger_entry_count,
               contribution_ledger_head_hash,contribution_ledger_entry_count
        FROM quota_accounts WHERE user_id=$1
        "#,
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取升级后的额度账户：{error}"))?;
    let spendable: i64 = account
        .try_get("spendable_micro")
        .map_err(|error| format!("升级后 spendable_micro 类型错误：{error}"))?;
    let contribution: i64 = account
        .try_get("contribution_micro")
        .map_err(|error| format!("升级后 contribution_micro 类型错误：{error}"))?;
    let quota_head: String = account
        .try_get("quota_ledger_head_hash")
        .map_err(|error| format!("升级后 quota_ledger_head_hash 类型错误：{error}"))?;
    let quota_count: i64 = account
        .try_get("quota_ledger_entry_count")
        .map_err(|error| format!("升级后 quota_ledger_entry_count 类型错误：{error}"))?;
    let contribution_head: String = account
        .try_get("contribution_ledger_head_hash")
        .map_err(|error| format!("升级后 contribution_ledger_head_hash 类型错误：{error}"))?;
    let contribution_count: i64 = account
        .try_get("contribution_ledger_entry_count")
        .map_err(|error| format!("升级后 contribution_ledger_entry_count 类型错误：{error}"))?;
    if spendable != 30
        || contribution != 11
        || quota_head != expected_quota_head
        || quota_count != 2
        || contribution_head != expected_contribution_head
        || contribution_count != 1
    {
        return Err("valid 夹具升级后的额度余额、链头或计数不正确".to_owned());
    }

    let reserve = sqlx::query(
        "SELECT balance_micro,ledger_head_hash,ledger_entry_count FROM reserve_accounts WHERE id=1",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取升级后的准备金账户：{error}"))?;
    let reserve_balance: i64 = reserve
        .try_get("balance_micro")
        .map_err(|error| format!("升级后 reserve balance_micro 类型错误：{error}"))?;
    let reserve_head: String = reserve
        .try_get("ledger_head_hash")
        .map_err(|error| format!("升级后 reserve ledger_head_hash 类型错误：{error}"))?;
    let reserve_count: i64 = reserve
        .try_get("ledger_entry_count")
        .map_err(|error| format!("升级后 reserve ledger_entry_count 类型错误：{error}"))?;
    if reserve_balance != 7 || reserve_head != expected_reserve_head || reserve_count != 1 {
        return Err("valid 夹具升级后的准备金余额、链头或计数不正确".to_owned());
    }
    let latest_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version),0) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取 valid 迁移版本：{error}"))?;
    if latest_version != 24 {
        return Err(format!(
            "valid 夹具迁移版本应为 24，实际为 {latest_version}"
        ));
    }
    Ok(())
}

async fn assert_canonical_upgrade(pool: &PgPool) -> TestResult {
    let legacy_state: (i64, i64, bool) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint,
               COUNT(*) FILTER (WHERE hash_version=1)::bigint,
               COALESCE(BOOL_AND(metadata='{}'::jsonb),TRUE)
        FROM (
            SELECT hash_version,metadata FROM quota_ledger
            UNION ALL
            SELECT hash_version,metadata FROM contribution_ledger
            UNION ALL
            SELECT hash_version,metadata FROM reserve_ledger
        ) legacy
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 canonical 升级后的 legacy 标记：{error}"))?;
    if legacy_state != (4, 4, true) {
        return Err(format!(
            "0027 必须原样保留四条 legacy v1 记录，实际为 {legacy_state:?}"
        ));
    }

    let expected = sqlx::query("SELECT user_id,quota_head FROM ledger_migration_expected LIMIT 1")
        .fetch_one(pool)
        .await
        .map_err(|error| format!("无法读取 canonical 升级期望链头：{error}"))?;
    let user_id: Uuid = expected
        .try_get("user_id")
        .map_err(|error| format!("canonical user_id 类型错误：{error}"))?;
    let legacy_head: String = expected
        .try_get("quota_head")
        .map_err(|error| format!("canonical quota_head 类型错误：{error}"))?;
    let new_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',1,30,31,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-migration-v2-{user_id}"))
    .bind(&legacy_head)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("0027 后无法追加数据库生成的 canonical v2 记录：{error}"))?;
    let account: (i64, String, i64) = sqlx::query_as(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count \
         FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 canonical 升级后的账户：{error}"))?;
    if account != (31, new_hash.clone(), 3) {
        return Err(format!(
            "legacy v1 → canonical v2 续链未保持余额/head/count：{account:?}"
        ));
    }
    let v2_state: (i16, String, bool) = sqlx::query_as(
        "SELECT hash_version,entry_hash,metadata='{}'::jsonb \
         FROM quota_ledger WHERE entry_hash=$1",
    )
    .bind(&new_hash)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取升级后新增 v2 行：{error}"))?;
    if v2_state != (2, new_hash, true) {
        return Err(format!("升级后新增行不是完整 canonical v2：{v2_state:?}"));
    }
    Ok(())
}

async fn assert_0024_rolled_back(pool: &PgPool, kind: FixtureKind) -> TestResult {
    let latest_version: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version),0) FROM _sqlx_migrations")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取 {} 迁移版本：{error}", kind.label()))?;
    let head_column_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema=current_schema()
              AND table_name='quota_accounts'
              AND column_name='quota_ledger_head_hash'
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法检查 {} 回滚状态：{error}", kind.label()))?;
    if latest_version != 23 || head_column_exists {
        return Err(format!(
            "{} 的 0024 失败未原子回滚：version={latest_version}, head_column_exists={head_column_exists}",
            kind.label()
        ));
    }
    Ok(())
}

async fn run_fixture(
    admin_pool: &PgPool,
    database_url: &str,
    through_23: &Migrator,
    through_24: &Migrator,
    through_27_without_26: &Migrator,
    kind: FixtureKind,
) -> TestResult {
    let schema = format!("mindone_ledger_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(admin_pool)
        .await
        .map_err(|error| format!("无法创建隔离 schema {schema}：{error}"))?;

    let body_result = match create_isolated_pool(database_url, &schema).await {
        Ok(pool) => {
            let result = async {
                through_23
                    .run(&pool)
                    .await
                    .map_err(|error| format!("{} 无法迁移到 0023：{error}", kind.label()))?;
                sqlx::query(
                    r#"
                    CREATE TABLE ledger_migration_expected (
                        user_id UUID NOT NULL,
                        quota_head TEXT NOT NULL,
                        contribution_head TEXT NOT NULL,
                        reserve_head TEXT NOT NULL
                    )
                    "#,
                )
                .execute(&pool)
                .await
                .map_err(|error| format!("无法创建夹具期望值表：{error}"))?;

                if kind.expects_success() {
                    seed_valid_fixture(&pool).await?;
                    through_24
                        .run(&pool)
                        .await
                        .map_err(|error| format!("valid 夹具执行 0024 失败：{error}"))?;
                    assert_valid_upgrade(&pool).await?;
                    through_27_without_26
                        .run(&pool)
                        .await
                        .map_err(|error| format!("valid 夹具执行 0025/0027 失败：{error}"))?;
                    assert_canonical_upgrade(&pool).await?;
                } else {
                    seed_invalid_fixture(&pool, kind).await?;
                    let migration_result = through_24.run(&pool).await;
                    if migration_result.is_ok() {
                        return Err(format!("{} 损坏夹具错误地通过了 0024", kind.label()));
                    }
                    assert_0024_rolled_back(&pool, kind).await?;
                }
                Ok(())
            }
            .await;
            pool.close().await;
            result
        }
        Err(error) => Err(error),
    };

    let cleanup_result = sqlx::query(&format!(r#"DROP SCHEMA "{schema}" CASCADE"#))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理隔离 schema {schema}：{error}"));
    match (body_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(body), Ok(())) => Err(body),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(body), Err(cleanup)) => Err(format!("{body}；此外 {cleanup}")),
    }
}

#[tokio::test]
async fn migrations_upgrade_valid_legacy_ledgers_and_reject_corruption_atomically() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let admin_pool = match PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => pool,
        Err(error) => panic!("无法连接账本升级测试数据库：{error}"),
    };
    let migrations_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let source = Migrator::new(migrations_path)
        .await
        .expect("应能加载仓库迁移");
    let through_23 = migrator_through(&source, 23);
    let through_24 = migrator_through(&source, 24);
    // 0026 修改 cluster role/ACL，隔离 schema 测试不能重复执行；0027 本身必须
    // 证明能把 0024 的真实 legacy 链原样升级并继续追加 canonical v2。
    let through_27_without_26 = migrator_through_without(&source, 27, 26);

    let mut failures = Vec::new();
    for kind in FixtureKind::ALL {
        if let Err(error) = run_fixture(
            &admin_pool,
            &database_url,
            &through_23,
            &through_24,
            &through_27_without_26,
            kind,
        )
        .await
        {
            failures.push(error);
        }
    }
    admin_pool.close().await;
    assert!(
        failures.is_empty(),
        "账本 0023→0024→0027 升级门禁失败：\n{}",
        failures.join("\n")
    );
}

#[derive(Clone, Copy)]
struct PhysicalBillingLegacyFixture {
    job_id: Uuid,
    route_id: Uuid,
    receipt_id: Uuid,
}

async fn seed_physical_billing_legacy_fixture(
    pool: &PgPool,
) -> TestResult<PhysicalBillingLegacyFixture> {
    let user_id = Uuid::now_v7();
    let device_key_id = Uuid::now_v7();
    let node_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    let model_instance_id = Uuid::now_v7();
    let report_id = Uuid::now_v7();
    let route_id = Uuid::now_v7();
    let job_id = Uuid::now_v7();
    let receipt_id = Uuid::now_v7();

    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'billing-migration',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("billing-migration-{user_id}"))
    .bind(format!("计费升级-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建计费升级用户：{error}"))?;
    sqlx::query("INSERT INTO device_keys (id,user_id,fingerprint,public_key) VALUES ($1,$2,$3,$4)")
        .bind(device_key_id)
        .bind(user_id)
        .bind(format!("billing-device-{device_key_id}"))
        .bind("billing-migration-public-key")
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建设备密钥：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO nodes (id,user_id,alias,hardware_profile,device_key_id)
        VALUES ($1,$2,$3,'{}'::jsonb,$4)
        "#,
    )
    .bind(node_id)
    .bind(user_id)
    .bind(format!("billing-node-{node_id}"))
    .bind(device_key_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建计费升级节点：{error}"))?;
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
    .bind(format!("billing-model-{model_id}"))
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建计费升级模型：{error}"))?;
    sqlx::query("INSERT INTO model_instances (id,model_id,node_id,alias) VALUES ($1,$2,$3,$4)")
        .bind(model_instance_id)
        .bind(model_id)
        .bind(node_id)
        .bind(format!("billing-instance-{model_instance_id}"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建计费升级模型实例：{error}"))?;
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
    .map_err(|error| format!("无法创建计费升级硬件报告：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO regulated_routes
            (id,user_id,idempotency_key,model_id,model_instance_id,node_id,
             attestation_report_id,estimated_input_tokens,max_output_tokens,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,10,20,now()+interval '1 day')
        "#,
    )
    .bind(route_id)
    .bind(user_id)
    .bind(format!("billing-route-{route_id}"))
    .bind(model_id)
    .bind(model_instance_id)
    .bind(node_id)
    .bind(report_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 legacy regulated route：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,encrypted_payload,payload_encoding,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro,
             standard_request_fingerprint,standard_payload_storage_version)
        VALUES ($1,$2,$3,$4,'mindone-standard-aead-v1:bGVnYWN5','base64',
                10,20,30000,$5,1)
        "#,
    )
    .bind(job_id)
    .bind(user_id)
    .bind(model_id)
    .bind(format!("billing-job-{job_id}"))
    .bind(format!("mindone-standard-hmac-v1:{}", "c".repeat(64)))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 legacy job：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO receipts
            (id,job_id,consumer_user_id,node_user_id,model_name,tier,trust_level,
             base_cost_micro,user_deduction_micro,node_quota_micro,
             contribution_micro,reserve_micro,settlement_hash)
        VALUES ($1,$2,$3,$3,'billing-legacy','medium','standard',
                30000,30000,24000,36000,6000,$4)
        "#,
    )
    .bind(receipt_id)
    .bind(job_id)
    .bind(user_id)
    .bind("ef".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 legacy receipt：{error}"))?;

    Ok(PhysicalBillingLegacyFixture {
        job_id,
        route_id,
        receipt_id,
    })
}

async fn assert_physical_billing_legacy_upgrade(
    pool: &PgPool,
    fixture: PhysicalBillingLegacyFixture,
) -> TestResult {
    let state: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT COUNT(*)::bigint FROM jobs
             WHERE id=$1 AND billing_contract_version='legacy_token_v1'
               AND billing_profile_id IS NULL AND billing_base_cost_micro IS NULL),
            (SELECT COUNT(*)::bigint FROM regulated_routes
             WHERE id=$2 AND billing_contract_version='legacy_token_v1'
               AND billing_profile_id IS NULL AND billing_base_cost_micro IS NULL),
            (SELECT COUNT(*)::bigint FROM receipts
             WHERE id=$3 AND billing_contract_version='legacy_token_v1'
               AND billing_profile_id IS NULL AND billing_base_cost_micro IS NULL)
        "#,
    )
    .bind(fixture.job_id)
    .bind(fixture.route_id)
    .bind(fixture.receipt_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 physical billing legacy 状态：{error}"))?;
    if state != (1, 1, 1) {
        return Err(format!("0032 没有诚实保留三类 legacy 行：{state:?}"));
    }
    let allowlist_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM physical_billing_legacy_allowlist")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法读取 physical billing allowlist：{error}"))?;
    if allowlist_count != 3 {
        return Err(format!(
            "0032 legacy allowlist 应恰有三条，实际 {allowlist_count}"
        ));
    }
    let receipt_amounts: (i64, i64, i64) = sqlx::query_as(
        "SELECT base_cost_micro,user_deduction_micro,reserve_micro FROM receipts WHERE id=$1",
    )
    .bind(fixture.receipt_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取升级后 legacy receipt 金额：{error}"))?;
    if receipt_amounts != (30_000, 30_000, 6_000) {
        return Err(format!(
            "0032 改写了既有 legacy receipt 金额：{receipt_amounts:?}"
        ));
    }
    if sqlx::query("UPDATE jobs SET billing_contract_version=NULL WHERE id=$1")
        .bind(fixture.job_id)
        .execute(pool)
        .await
        .is_ok()
    {
        return Err("0032 允许改写 legacy job 计费身份".to_owned());
    }
    if sqlx::query("UPDATE receipts SET reserve_micro=reserve_micro WHERE id=$1")
        .bind(fixture.receipt_id)
        .execute(pool)
        .await
        .is_ok()
    {
        return Err("0032 允许修改 append-only receipt".to_owned());
    }
    Ok(())
}

async fn run_physical_billing_legacy_upgrade(
    admin_pool: &PgPool,
    database_url: &str,
    through_31: &Migrator,
    through_32: &Migrator,
    through_33: &Migrator,
    through_34: &Migrator,
) -> TestResult {
    let schema = format!("mindone_billing_legacy_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(admin_pool)
        .await
        .map_err(|error| format!("无法创建 physical billing legacy schema：{error}"))?;
    let body_result = match create_isolated_pool(database_url, &schema).await {
        Ok(pool) => {
            let result = async {
                through_31
                    .run(&pool)
                    .await
                    .map_err(|error| format!("无法迁移 legacy fixture 到 0031：{error}"))?;
                let fixture = seed_physical_billing_legacy_fixture(&pool).await?;
                through_32
                    .run(&pool)
                    .await
                    .map_err(|error| format!("无法把 legacy fixture 升级到 0032：{error}"))?;
                assert_physical_billing_legacy_upgrade(&pool, fixture).await?;
                through_33
                    .run(&pool)
                    .await
                    .map_err(|error| format!("无法把 legacy fixture 升级到 0033：{error}"))?;
                let v33_state: (i64, i64, i64) = sqlx::query_as(
                    r#"
                    SELECT COALESCE(MAX(version),0),
                           (SELECT COUNT(*)::bigint FROM billing_profiles),
                           (SELECT COUNT(*)::bigint
                            FROM billing_profile_provision_audits)
                    FROM _sqlx_migrations
                    "#,
                )
                .fetch_one(&pool)
                .await
                .map_err(|error| format!("无法读取 0033 legacy 升级状态：{error}"))?;
                if v33_state != (33, 0, 0) {
                    return Err(format!(
                        "0033 不得为 legacy 数据伪造默认 profile 或 audit：{v33_state:?}"
                    ));
                }
                let blocked = through_34
                    .run(&pool)
                    .await
                    .expect_err("0034 必须拒绝仍非终态的 legacy job/route");
                let blocked_message = blocked.to_string();
                if !blocked_message.contains("请先停止协调服务器")
                    || !blocked_message.contains("排空或取消任务")
                    || !blocked_message.contains("释放准备金")
                {
                    return Err(format!(
                        "0034 升级门禁没有给出停服务、排空/取消和释放指引：{blocked_message}"
                    ));
                }
                let version_after_rejection: i64 =
                    sqlx::query_scalar("SELECT COALESCE(MAX(version),0) FROM _sqlx_migrations")
                        .fetch_one(&pool)
                        .await
                        .map_err(|error| format!("无法读取 0034 拒绝后的版本：{error}"))?;
                if version_after_rejection != 33 {
                    return Err(format!(
                        "0034 门禁失败后 migration 版本未原子回滚：{version_after_rejection}"
                    ));
                }

                sqlx::query(
                    "UPDATE jobs SET status='failed',completed_at=now(),updated_at=now() \
                     WHERE id=$1 AND status IN ('queued','leased','retry')",
                )
                .bind(fixture.job_id)
                .execute(&pool)
                .await
                .map_err(|error| format!("无法排空 legacy job：{error}"))?;
                sqlx::query(
                    "UPDATE regulated_routes SET status='expired',consumed_at=now() \
                     WHERE id=$1 AND status='prepared'",
                )
                .bind(fixture.route_id)
                .execute(&pool)
                .await
                .map_err(|error| format!("无法作废 legacy prepared route：{error}"))?;

                through_34
                    .run(&pool)
                    .await
                    .map_err(|error| format!("排空后无法升级到 0034：{error}"))?;
                let v34_state: (i64, String, String, i64, i64) = sqlx::query_as(
                    r#"
                    SELECT COALESCE(MAX(version),0),
                           (SELECT status FROM jobs WHERE id=$1),
                           (SELECT status FROM regulated_routes WHERE id=$2),
                           (SELECT COUNT(*)::bigint FROM billing_profiles),
                           (SELECT COUNT(*)::bigint
                            FROM billing_profile_provision_audits)
                    FROM _sqlx_migrations
                    "#,
                )
                .bind(fixture.job_id)
                .bind(fixture.route_id)
                .fetch_one(&pool)
                .await
                .map_err(|error| format!("无法读取 0034 legacy 升级状态：{error}"))?;
                if v34_state != (34, "failed".to_owned(), "expired".to_owned(), 0, 0) {
                    return Err(format!(
                        "0034 没有保留已排空 legacy 历史或伪造了默认 profile：{v34_state:?}"
                    ));
                }
                assert_physical_billing_legacy_upgrade(&pool, fixture).await
            }
            .await;
            pool.close().await;
            result
        }
        Err(error) => Err(error),
    };
    let cleanup_result = sqlx::query(&format!(r#"DROP SCHEMA "{schema}" CASCADE"#))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 physical billing legacy schema：{error}"));
    match (body_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}；清理同时失败：{cleanup}")),
    }
}

async fn run_physical_billing_atomic_rollback(
    admin_pool: &PgPool,
    database_url: &str,
    through_31: &Migrator,
    through_32: &Migrator,
) -> TestResult {
    let schema = format!("mindone_billing_atomic_{}", Uuid::new_v4().simple());
    sqlx::query(&format!(r#"CREATE SCHEMA "{schema}""#))
        .execute(admin_pool)
        .await
        .map_err(|error| format!("无法创建 physical billing atomic schema：{error}"))?;
    let body_result = match create_isolated_pool(database_url, &schema).await {
        Ok(pool) => {
            let result = async {
                through_31
                    .run(&pool)
                    .await
                    .map_err(|error| format!("atomic fixture 无法迁移到 0031：{error}"))?;
                let fixture = seed_physical_billing_legacy_fixture(&pool).await?;
                sqlx::query(
                    r#"
                    CREATE FUNCTION mindone_billing_profile_fingerprint_v1(
                        UUID,TEXT,BIGINT,UUID,TEXT,TEXT,BIGINT,BIGINT,BIGINT,
                        BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,TEXT,
                        TIMESTAMPTZ,TIMESTAMPTZ
                    ) RETURNS INTEGER LANGUAGE sql IMMUTABLE AS 'SELECT 1'
                    "#,
                )
                .execute(&pool)
                .await
                .map_err(|error| format!("无法创建 0032 原子回滚冲突探针：{error}"))?;
                if through_32.run(&pool).await.is_ok() {
                    return Err("冲突函数应使 0032 失败关闭".to_owned());
                }

                let rollback_state: (i64, bool, bool, i64) = sqlx::query_as(
                    r#"
                    SELECT COALESCE(MAX(version),0),
                           to_regclass('billing_profiles') IS NOT NULL,
                           to_regclass('physical_billing_legacy_allowlist') IS NOT NULL,
                           (SELECT COUNT(*)::bigint
                            FROM information_schema.columns
                            WHERE table_schema=current_schema()
                              AND table_name='jobs'
                              AND column_name='billing_contract_version')
                    FROM _sqlx_migrations
                    "#,
                )
                .fetch_one(&pool)
                .await
                .map_err(|error| format!("无法读取 0032 原子回滚状态：{error}"))?;
                if rollback_state != (31, false, false, 0) {
                    return Err(format!(
                        "0032 失败没有原子回滚全部 schema 写入：{rollback_state:?}"
                    ));
                }
                let fixture_still_present: bool =
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM jobs WHERE id=$1)")
                        .bind(fixture.job_id)
                        .fetch_one(&pool)
                        .await
                        .map_err(|error| format!("无法确认原子回滚后 legacy fixture：{error}"))?;
                if !fixture_still_present {
                    return Err("0032 回滚误删了 migration 前 legacy 行".to_owned());
                }
                Ok(())
            }
            .await;
            pool.close().await;
            result
        }
        Err(error) => Err(error),
    };
    let cleanup_result = sqlx::query(&format!(r#"DROP SCHEMA "{schema}" CASCADE"#))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 physical billing atomic schema：{error}"));
    match (body_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}；清理同时失败：{cleanup}")),
    }
}

#[tokio::test]
async fn migration_34_requires_legacy_drain_and_32_rolls_back_atomically() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("应能连接 physical billing migration 测试数据库");
    let source = Migrator::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
        .await
        .expect("应能加载 physical billing migrations");
    let through_31 = migrator_through_without(&source, 31, 26);
    let through_32 = migrator_through_without(&source, 32, 26);
    let through_33 = migrator_through_without(&source, 33, 26);
    let through_34 = migrator_through_without(&source, 34, 26);

    let legacy_result = run_physical_billing_legacy_upgrade(
        &admin_pool,
        &database_url,
        &through_31,
        &through_32,
        &through_33,
        &through_34,
    )
    .await;
    let atomic_result = if legacy_result.is_ok() {
        run_physical_billing_atomic_rollback(&admin_pool, &database_url, &through_31, &through_32)
            .await
    } else {
        Ok(())
    };
    admin_pool.close().await;
    if let Err(error) = legacy_result {
        panic!("{error}");
    }
    if let Err(error) = atomic_result {
        panic!("{error}");
    }
}
