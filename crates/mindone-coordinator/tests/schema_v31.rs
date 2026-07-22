use std::{borrow::Cow, env, path::PathBuf, str::FromStr, time::Duration};

use serial_test::serial;
use sqlx::{
    migrate::Migrator,
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult},
    PgPool,
};
use uuid::Uuid;

const CLUSTER_ROLE_MIGRATION_VERSION: i64 = 26;
const DEVICE_BINDING_MIGRATION_VERSION: i64 = 30;
const PRIVATE_HMAC_BUDGET_MIGRATION_VERSION: i64 = 31;

type TestResult<T = ()> = Result<T, String>;
type LegacyChallengeProjection = (
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
);
type PrivateV1ChallengeProjection = (
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v31 schema PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v31 schema PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

async fn load_migrator() -> TestResult<Migrator> {
    Migrator::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../migrations"))
        .await
        .map_err(|error| format!("无法加载 migrations：{error}"))
}

fn migrator_through(source: &Migrator, maximum_version: i64) -> Migrator {
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

async fn migrate_through(pool: &PgPool, source: &Migrator, maximum_version: i64) -> TestResult {
    let migration_table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法检查 migration metadata 表：{error}"))?;
    let role_already_applied = if migration_table_exists {
        sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version=$1 AND success=TRUE)",
        )
        .bind(CLUSTER_ROLE_MIGRATION_VERSION)
        .fetch_one(pool)
        .await
        .map_err(|error| format!("无法检查 migration 26 metadata：{error}"))?
    } else {
        false
    };
    let mut resolved = migrator_through(source, maximum_version);
    // migration 26 含 cluster role DDL，隔离数据库测试只登记其精确 metadata。分段继续
    // 迁移时只允许这个已知、已验证的缺项；checksum 和其余已应用 migration 仍由 SQLx 校验。
    resolved.ignore_missing = role_already_applied;
    resolved
        .run(pool)
        .await
        .map_err(|error| format!("无法迁移到 schema {maximum_version}：{error}"))?;
    if maximum_version >= CLUSTER_ROLE_MIGRATION_VERSION {
        let role_migration = source
            .iter()
            .find(|migration| {
                migration.migration_type.is_up_migration()
                    && migration.version == CLUSTER_ROLE_MIGRATION_VERSION
            })
            .ok_or_else(|| "缺少 migration 26".to_owned())?;
        sqlx::query(
            r#"
            INSERT INTO _sqlx_migrations
                (version,description,success,checksum,execution_time)
            VALUES ($1,$2,TRUE,$3,0)
            ON CONFLICT (version) DO NOTHING
            "#,
        )
        .bind(role_migration.version)
        .bind(role_migration.description.as_ref())
        .bind(role_migration.checksum.as_ref())
        .execute(pool)
        .await
        .map_err(|error| format!("无法登记隔离测试跳过的 migration 26：{error}"))?;
    }
    Ok(())
}

struct IsolatedDatabase {
    admin_pool: PgPool,
    pool: PgPool,
    name: String,
}

impl IsolatedDatabase {
    async fn create(database_url: &str, label: &str) -> TestResult<Self> {
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err("隔离数据库标签无效".to_owned());
        }
        let base = PgConnectOptions::from_str(database_url)
            .map_err(|error| format!("DATABASE_URL 无效：{error}"))?;
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(base.clone().database("postgres"))
            .await
            .map_err(|error| format!("无法连接 maintenance database：{error}"))?;
        let unique = Uuid::now_v7().simple().to_string();
        let name = format!("m31_{label}_{}", &unique[..16]);
        if name.len() > 63 {
            return Err("隔离数据库名过长".to_owned());
        }
        sqlx::query(&format!("CREATE DATABASE \"{name}\" TEMPLATE template0"))
            .execute(&admin_pool)
            .await
            .map_err(|error| format!("无法创建隔离数据库 {name}：{error}"))?;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect_with(base.database(&name))
            .await
            .map_err(|error| format!("无法连接隔离数据库 {name}：{error}"))?;
        Ok(Self {
            admin_pool,
            pool,
            name,
        })
    }

    async fn cleanup(self) -> TestResult {
        self.pool.close().await;
        let result = sqlx::query(&format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name))
            .execute(&self.admin_pool)
            .await
            .map(|_| ())
            .map_err(|error| format!("无法清理隔离数据库 {}：{error}", self.name));
        self.admin_pool.close().await;
        result
    }
}

#[derive(Clone, Copy)]
struct Resources {
    user_id: Uuid,
    node_id: Uuid,
    model_id: Uuid,
    model_instance_id: Uuid,
    device_key_id: Option<Uuid>,
}

async fn insert_resources(pool: &PgPool, with_device_binding: bool) -> TestResult<Resources> {
    let user_id = Uuid::now_v7();
    let node_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    let model_instance_id = Uuid::now_v7();
    let device_key_id = with_device_binding.then(Uuid::now_v7);
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'v31-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind(format!("用户-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建用户：{error}"))?;
    if let Some(device_key_id) = device_key_id {
        insert_device_key(pool, user_id, device_key_id, 'a').await?;
        sqlx::query(
            r#"
            INSERT INTO nodes
                (id,user_id,alias,trust_level,status,hardware_profile,device_key_id)
            VALUES ($1,$2,$3,'standard','online','{}'::jsonb,$4)
            "#,
        )
        .bind(node_id)
        .bind(user_id)
        .bind(format!("node-{node_id}"))
        .bind(device_key_id)
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建已绑定节点：{error}"))?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO nodes (id,user_id,alias,trust_level,status,hardware_profile)
            VALUES ($1,$2,$3,'standard','online','{}'::jsonb)
            "#,
        )
        .bind(node_id)
        .bind(user_id)
        .bind(format!("node-{node_id}"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 legacy 节点：{error}"))?;
    }
    sqlx::query(
        r#"
        INSERT INTO models
            (id,owner_user_id,name,format,weights_hash,size_bytes,context_length,
             base_cost_per_1k_micro)
        VALUES ($1,$2,$3,'gguf',$4,1024,4096,1000000)
        "#,
    )
    .bind(model_id)
    .bind(user_id)
    .bind(format!("model-{model_id}"))
    .bind("1".repeat(64))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建模型：{error}"))?;
    sqlx::query("INSERT INTO model_instances (id,model_id,node_id,alias) VALUES ($1,$2,$3,$4)")
        .bind(model_instance_id)
        .bind(model_id)
        .bind(node_id)
        .bind(format!("instance-{model_instance_id}"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建模型实例：{error}"))?;
    Ok(Resources {
        user_id,
        node_id,
        model_id,
        model_instance_id,
        device_key_id,
    })
}

async fn insert_device_key(
    pool: &PgPool,
    user_id: Uuid,
    device_key_id: Uuid,
    marker: char,
) -> TestResult {
    sqlx::query(
        r#"
        INSERT INTO device_keys (id,user_id,fingerprint,public_key,algorithm)
        VALUES ($1,$2,$3,$4,'ed25519')
        "#,
    )
    .bind(device_key_id)
    .bind(user_id)
    .bind(marker.to_string().repeat(64))
    .bind(marker.to_string().repeat(64))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建设备密钥：{error}"))?;
    Ok(())
}

async fn insert_terminal_legacy_attempt(pool: &PgPool, resources: Resources) -> TestResult<Uuid> {
    let job_id = Uuid::now_v7();
    let attempt_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,model_instance_id,idempotency_key,status,
             encrypted_payload,estimated_input_tokens,max_output_tokens,
             reserved_cost_micro,attempt_count,standard_request_fingerprint,
             standard_payload_storage_version,completed_at)
        VALUES ($1,$2,$3,$4,$5,'failed',$6,1,1,1,1,$7,1,now())
        "#,
    )
    .bind(job_id)
    .bind(resources.user_id)
    .bind(resources.model_id)
    .bind(resources.model_instance_id)
    .bind(format!("legacy-terminal-{job_id}"))
    .bind("mindone-standard-aead-v1:AA")
    .bind(format!("mindone-standard-hmac-v1:{}", "6".repeat(64)))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 legacy terminal job：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO job_attempts
            (id,job_id,node_id,attempt_number,status,lease_started_at,
             lease_expires_at,finished_at,error_class)
        VALUES ($1,$2,$3,1,'failed',now()-interval '2 hours',
                now()-interval '1 hour',now()-interval '1 hour','legacy_failure')
        "#,
    )
    .bind(attempt_id)
    .bind(job_id)
    .bind(resources.node_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 legacy terminal attempt：{error}"))?;
    Ok(attempt_id)
}

async fn insert_active_ordinary(
    pool: &PgPool,
    resources: Resources,
    schema_30: bool,
) -> TestResult<Uuid> {
    let job_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,model_instance_id,idempotency_key,status,
             encrypted_payload,estimated_input_tokens,max_output_tokens,
             reserved_cost_micro,leased_to_node_id,lease_expires_at,attempt_count,
             standard_request_fingerprint,standard_payload_storage_version)
        VALUES ($1,$2,$3,$4,$5,'leased',$6,1,1,1,$7,
                now()+interval '1 hour',1,$8,1)
        "#,
    )
    .bind(job_id)
    .bind(resources.user_id)
    .bind(resources.model_id)
    .bind(resources.model_instance_id)
    .bind(format!("job-{job_id}"))
    .bind("mindone-standard-aead-v1:AA")
    .bind(resources.node_id)
    .bind(format!("mindone-standard-hmac-v1:{}", "2".repeat(64)))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建活动 ordinary job：{error}"))?;
    if schema_30 {
        sqlx::query(
            r#"
            INSERT INTO job_attempts
                (id,job_id,node_id,attempt_number,status,lease_started_at,lease_expires_at,
                 claim_device_binding_version,claim_device_key_id)
            VALUES ($1,$2,$3,1,'leased',now(),now()+interval '1 hour',1,$4)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(resources.node_id)
        .bind(
            resources
                .device_key_id
                .ok_or_else(|| "schema 30 ordinary fixture 缺少设备密钥".to_owned())?,
        )
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 schema 30 attempt：{error}"))?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO job_attempts
                (id,job_id,node_id,attempt_number,status,lease_started_at,lease_expires_at)
            VALUES ($1,$2,$3,1,'leased',now(),now()+interval '1 hour')
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(job_id)
        .bind(resources.node_id)
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 legacy attempt：{error}"))?;
    }
    Ok(job_id)
}

async fn insert_active_hidden(
    pool: &PgPool,
    resources: Resources,
    schema_30: bool,
) -> TestResult<Uuid> {
    let challenge_id = Uuid::now_v7();
    if schema_30 {
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,lease_expires_at,
                 claimed_user_id,claimed_device_key_id,claim_device_binding_version)
            VALUES ($1,$2,$3,$4,'canary',$5,$6,$7,$8,'leased',
                    now()+interval '1 hour',$9,$10,1)
            "#,
        )
        .bind(challenge_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind(vec![7_u8; 32])
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .bind(resources.user_id)
        .bind(
            resources
                .device_key_id
                .ok_or_else(|| "schema 30 hidden fixture 缺少设备密钥".to_owned())?,
        )
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 schema 30 hidden lease：{error}"))?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,lease_expires_at)
            VALUES ($1,$2,$3,$4,'canary',$5,$6,$7,$8,'leased',
                    now()+interval '1 hour')
            "#,
        )
        .bind(challenge_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind(vec![7_u8; 32])
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .execute(pool)
        .await
        .map_err(|error| format!("无法创建 legacy hidden lease：{error}"))?;
    }
    Ok(challenge_id)
}

fn expect_sqlstate(
    result: Result<PgQueryResult, sqlx::Error>,
    expected: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation}应被拒绝，但意外成功")),
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some(expected) => Ok(()),
        Err(error) => Err(format!(
            "{operation}应返回 SQLSTATE {expected}，实际为 {error}"
        )),
    }
}

async fn migration_state(pool: &PgPool) -> TestResult<(i64, i64, i64, bool)> {
    sqlx::query_as(
        "SELECT COUNT(*)::bigint,MIN(version),MAX(version),COALESCE(BOOL_AND(success),FALSE) FROM _sqlx_migrations",
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 migration state：{error}"))
}

#[tokio::test]
#[serial]
async fn active_ordinary_and_hidden_leases_block_0030_before_any_write() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    for (label, lease_kind) in [
        ("block30_ordinary", "ordinary"),
        ("block30_hidden", "hidden"),
        ("block30_attempt_only", "attempt_only"),
    ] {
        let database = IsolatedDatabase::create(&database_url, label).await?;
        let result = async {
            migrate_through(&database.pool, &migrator, 29).await?;
            let resources = insert_resources(&database.pool, false).await?;
            match lease_kind {
                "hidden" => {
                    insert_active_hidden(&database.pool, resources, false).await?;
                }
                "ordinary" => {
                    insert_active_ordinary(&database.pool, resources, false).await?;
                }
                "attempt_only" => {
                    let job_id = insert_active_ordinary(&database.pool, resources, false).await?;
                    sqlx::query(
                        "UPDATE jobs SET status='queued',leased_to_node_id=NULL,\
                         lease_expires_at=NULL WHERE id=$1",
                    )
                    .bind(job_id)
                    .execute(&database.pool)
                    .await
                    .map_err(|error| format!("无法构造 attempt-only lease：{error}"))?;
                }
                _ => return Err("未知 migration 30 lease fixture".to_owned()),
            }
            let error = migrator
                .run(&database.pool)
                .await
                .expect_err("活动租约必须阻止 migration 30")
                .to_string();
            if !error.contains("migration 0030 requires zero active worker leases") {
                return Err(format!("migration 30 错误不符合预期：{error}"));
            }
            if migration_state(&database.pool).await? != (29, 1, 29, true) {
                return Err("migration 30 失败后 metadata 被改写".to_owned());
            }
            let device_column_count: i64 = sqlx::query_scalar(
                r#"
                SELECT COUNT(*)::bigint FROM information_schema.columns
                WHERE table_schema='public' AND table_name='nodes'
                  AND column_name='device_key_id'
                "#,
            )
            .fetch_one(&database.pool)
            .await
            .map_err(|error| format!("无法检查 migration 30 零写入：{error}"))?;
            if device_column_count != 0 {
                return Err("migration 30 被拒后仍创建了 device_key_id".to_owned());
            }
            let node_status: String = sqlx::query_scalar("SELECT status FROM nodes WHERE id=$1")
                .bind(resources.node_id)
                .fetch_one(&database.pool)
                .await
                .map_err(|error| format!("无法读取 legacy 节点：{error}"))?;
            if node_status != "online" {
                return Err(format!("migration 30 被拒后修改了节点状态：{node_status}"));
            }
            Ok(())
        }
        .await;
        let cleanup = database.cleanup().await;
        result?;
        cleanup?;
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn migration_0030_lock_closes_concurrent_claim_race() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    let database = IsolatedDatabase::create(&database_url, "block30_race").await?;
    let result = async {
        migrate_through(&database.pool, &migrator, 29).await?;
        let resources = insert_resources(&database.pool, false).await?;
        let mut claim_tx = database
            .pool
            .begin()
            .await
            .map_err(|error| format!("无法开始并发 claim 事务：{error}"))?;
        sqlx::query("SELECT id FROM nodes WHERE id=$1 FOR UPDATE")
            .bind(resources.node_id)
            .execute(&mut *claim_tx)
            .await
            .map_err(|error| format!("无法按真实 claim 顺序锁定节点：{error}"))?;

        let migration_pool = database.pool.clone();
        let (migration_started_tx, migration_started_rx) = tokio::sync::oneshot::channel();
        let migration_task = tokio::spawn(async move {
            let _ = migration_started_tx.send(());
            let outcome = sqlx::raw_sql(include_str!(
                "../../../migrations/0030_node_device_binding.sql"
            ))
            .execute(&migration_pool)
            .await;
            match outcome {
                Ok(_) => Err("migration 0030 在并发 lease 下意外成功".to_owned()),
                Err(error) => Ok(error.to_string()),
            }
        });
        migration_started_rx
            .await
            .map_err(|_| "migration task 未进入锁等待路径".to_owned())?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        if migration_task.is_finished() {
            return Err("migration 未先等待 node-first claim".to_owned());
        }
        let job_id = Uuid::now_v7();
        tokio::time::timeout(Duration::from_secs(2), async {
            sqlx::query(
                r#"
                INSERT INTO jobs
                    (id,user_id,model_id,model_instance_id,idempotency_key,status,
                     encrypted_payload,estimated_input_tokens,max_output_tokens,
                     reserved_cost_micro,leased_to_node_id,lease_expires_at,attempt_count,
                     standard_request_fingerprint,standard_payload_storage_version)
                VALUES ($1,$2,$3,$4,$5,'leased',$6,1,1,1,$7,
                        now()+interval '1 hour',1,$8,1)
                "#,
            )
            .bind(job_id)
            .bind(resources.user_id)
            .bind(resources.model_id)
            .bind(resources.model_instance_id)
            .bind(format!("race-{job_id}"))
            .bind("mindone-standard-aead-v1:AA")
            .bind(resources.node_id)
            .bind(format!("mindone-standard-hmac-v1:{}", "a".repeat(64)))
            .execute(&mut *claim_tx)
            .await
            .map_err(|error| format!("node-first claim 无法写入 lease：{error}"))?;
            sqlx::query(
                r#"
                INSERT INTO job_attempts
                    (id,job_id,node_id,attempt_number,status,lease_started_at,lease_expires_at)
                VALUES ($1,$2,$3,1,'leased',now(),now()+interval '1 hour')
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(resources.node_id)
            .execute(&mut *claim_tx)
            .await
            .map_err(|error| format!("node-first claim 无法写入 attempt：{error}"))?;
            claim_tx
                .commit()
                .await
                .map_err(|error| format!("无法提交 node-first 并发 lease：{error}"))?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "migration 锁顺序令 node-first claim 死锁".to_owned())??;
        let migration_error = tokio::time::timeout(Duration::from_secs(10), migration_task)
            .await
            .map_err(|_| "migration 等待并发 claim 超时".to_owned())?
            .map_err(|error| format!("migration task 异常结束：{error}"))??;
        if !migration_error.contains("migration 0030 requires zero active worker leases") {
            return Err(format!(
                "并发 claim 后 migration 错误不正确：{migration_error}"
            ));
        }
        let column_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)::bigint FROM information_schema.columns
            WHERE table_schema='public' AND table_name='nodes'
              AND column_name='device_key_id'
            "#,
        )
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法检查竞态测试零写入：{error}"))?;
        if column_count != 0 {
            return Err("竞态失败后 migration 仍产生结构写入".to_owned());
        }
        Ok(())
    }
    .await;
    let cleanup = database.cleanup().await;
    result?;
    cleanup
}

#[tokio::test]
#[serial]
async fn active_ordinary_and_hidden_leases_block_0031_before_any_write() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    for (label, lease_kind) in [
        ("block31_ordinary", "ordinary"),
        ("block31_hidden", "hidden"),
        ("block31_attempt_only", "attempt_only"),
    ] {
        let database = IsolatedDatabase::create(&database_url, label).await?;
        let result = async {
            migrate_through(&database.pool, &migrator, DEVICE_BINDING_MIGRATION_VERSION).await?;
            let resources = insert_resources(&database.pool, true).await?;
            match lease_kind {
                "hidden" => {
                    insert_active_hidden(&database.pool, resources, true).await?;
                }
                "ordinary" => {
                    insert_active_ordinary(&database.pool, resources, true).await?;
                }
                "attempt_only" => {
                    let job_id = insert_active_ordinary(&database.pool, resources, true).await?;
                    sqlx::query(
                        "UPDATE jobs SET status='queued',leased_to_node_id=NULL,\
                         lease_expires_at=NULL WHERE id=$1",
                    )
                    .bind(job_id)
                    .execute(&database.pool)
                    .await
                    .map_err(|error| format!("无法构造 schema30 attempt-only lease：{error}"))?;
                }
                _ => return Err("未知 migration 31 lease fixture".to_owned()),
            }
            let error = migrator
                .run(&database.pool)
                .await
                .expect_err("活动租约必须阻止 migration 31")
                .to_string();
            if !error.contains("migration 0031 requires zero active worker leases") {
                return Err(format!("migration 31 错误不符合预期：{error}"));
            }
            if migration_state(&database.pool).await? != (30, 1, 30, true) {
                return Err("migration 31 失败后 metadata 被改写".to_owned());
            }
            let v31_table: Option<String> = sqlx::query_scalar(
                "SELECT to_regclass('public.private_evaluation_hmac_key_state')::text",
            )
            .fetch_one(&database.pool)
            .await
            .map_err(|error| format!("无法检查 migration 31 零写入：{error}"))?;
            if v31_table.is_some() {
                return Err("migration 31 被拒后仍创建了 HMAC key state".to_owned());
            }
            Ok(())
        }
        .await;
        let cleanup = database.cleanup().await;
        result?;
        cleanup?;
    }
    Ok(())
}

#[tokio::test]
#[serial]
async fn legacy_rows_are_preserved_and_nodes_require_explicit_rebind() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    let database = IsolatedDatabase::create(&database_url, "legacy").await?;
    let result = async {
        migrate_through(&database.pool, &migrator, CLUSTER_ROLE_MIGRATION_VERSION).await?;
        let resources = insert_resources(&database.pool, false).await?;
        let legacy_attempt_id = insert_terminal_legacy_attempt(&database.pool, resources).await?;
        let public_challenge_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,result_hash,
                 score_normalized,resulting_tier,resulting_evaluation_samples,
                 lease_expires_at,completed_at)
            VALUES ($1,$2,$3,$4,'canary',NULL,$5,$6,$7,'succeeded',$8,
                    1000000,'medium',0,now()-interval '1 hour',now())
            "#,
        )
        .bind(public_challenge_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind("6".repeat(64))
        .bind("7".repeat(64))
        .bind("8".repeat(64))
        .bind("9".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建 schema26 legacy challenge：{error}"))?;

        migrate_through(&database.pool, &migrator, 28).await?;
        let private_challenge_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,result_hash,
                 score_normalized,resulting_tier,resulting_evaluation_samples,
                 lease_expires_at,completed_at,model_weights_hash,
                 challenge_nonce_hash,challenge_binding_hash,
                 challenge_issued_expires_at,authorized_input_tokens,
                 authorized_max_output_tokens,inference_seed,private_catalog_id,
                 private_catalog_entry_id,private_case_family,
                 private_catalog_commitment,private_evaluator_id,
                 private_evaluator_key_fingerprint,private_catalog_valid_until)
            VALUES ($1,$2,$3,$4,'hidden_benchmark',NULL,$5,$6,$7,'succeeded',$8,
                    1000000,'medium',1,now()-interval '1 hour',now(),$9,$10,$11,
                    now()+interval '1 hour',1,1,7,'legacy-catalog',
                    'legacy-entry','legacy-family',$12,'legacy-evaluator',$13,
                    now()+interval '2 hours')
            "#,
        )
        .bind(private_challenge_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind("a".repeat(64))
        .bind("b".repeat(64))
        .bind("8".repeat(64))
        .bind("9".repeat(64))
        .bind("1".repeat(64))
        .bind("f".repeat(64))
        .bind("e".repeat(64))
        .bind("c".repeat(64))
        .bind("d".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建 0028 private-v1 challenge：{error}"))?;
        sqlx::query(
            "INSERT INTO model_evaluation_challenge_events \
             (id,challenge_id,event_kind,prompt_hash) VALUES ($1,$2,'issued',$3)",
        )
        .bind(Uuid::now_v7())
        .bind(private_challenge_id)
        .bind("a".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建 0028 private-v1 lifecycle event：{error}"))?;
        sqlx::query(
            r#"
            INSERT INTO model_authenticity_arbitration_events
                (id,challenge_id,model_id,model_instance_id,model_weights_hash,
                 private_evaluator_key_fingerprint,private_catalog_commitment,
                 private_case_family,passed,observed_distinct_instances,
                 passed_distinct_instances,failed_distinct_instances,verdict,
                 challenge_binding_hash)
            VALUES ($1,$2,$3,$4,$5,$6,$7,'legacy-family',TRUE,1,1,0,'pending',$8)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(private_challenge_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind("1".repeat(64))
        .bind("d".repeat(64))
        .bind("c".repeat(64))
        .bind("e".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建 0028 private-v1 arbitration：{error}"))?;

        migrate_through(
            &database.pool,
            &migrator,
            PRIVATE_HMAC_BUDGET_MIGRATION_VERSION,
        )
        .await
        .map_err(|error| format!("schema26/0028 legacy 无法升级到31：{error}"))?;
        if migration_state(&database.pool).await? != (31, 1, 31, true) {
            return Err("legacy 升级后 migration metadata 不完整".to_owned());
        }
        let node: (String, Option<String>, Option<Uuid>, bool) = sqlx::query_as(
            "SELECT status,pause_reason,device_key_id,last_seen_at IS NULL \
             FROM nodes WHERE id=$1",
        )
        .bind(resources.node_id)
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法读取升级后的 legacy 节点：{error}"))?;
        if node
            != (
                "offline".to_owned(),
                Some("device_rebind_required".to_owned()),
                None,
                true,
            )
        {
            return Err(format!("legacy 节点未安全下线：{node:?}"));
        }
        let public_legacy: LegacyChallengeProjection = sqlx::query_as(
            "SELECT private_commitment_version,prompt_hash,expected_hash,\
             claimed_user_id,claimed_device_key_id \
             FROM model_evaluation_challenges WHERE id=$1",
        )
        .bind(public_challenge_id)
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法读取升级后的 legacy challenge：{error}"))?;
        if public_legacy != (None, Some("6".repeat(64)), Some("7".repeat(64)), None, None) {
            return Err(format!("legacy challenge 被改写：{public_legacy:?}"));
        }
        let legacy_attempt: (String, Option<i32>, Option<Uuid>) = sqlx::query_as(
            "SELECT status,claim_device_binding_version,claim_device_key_id \
             FROM job_attempts WHERE id=$1",
        )
        .bind(legacy_attempt_id)
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法读取升级后的 legacy attempt：{error}"))?;
        if legacy_attempt != ("failed".to_owned(), None, None) {
            return Err(format!("legacy attempt 被改写：{legacy_attempt:?}"));
        }
        let private_v1: PrivateV1ChallengeProjection = sqlx::query_as(
            "SELECT private_commitment_version,private_catalog_id,\
             private_catalog_entry_id,private_case_family,private_catalog_commitment,\
             private_evaluator_key_fingerprint \
             FROM model_evaluation_challenges WHERE id=$1",
        )
        .bind(private_challenge_id)
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法读取升级后的 private-v1 challenge：{error}"))?;
        if private_v1
            != (
                None,
                Some("legacy-catalog".to_owned()),
                Some("legacy-entry".to_owned()),
                Some("legacy-family".to_owned()),
                Some("c".repeat(64)),
                Some("d".repeat(64)),
            )
        {
            return Err(format!("0028 private-v1 identity 被改写：{private_v1:?}"));
        }
        let projection_count: i64 = sqlx::query_scalar(
            "SELECT \
             (SELECT COUNT(*) FROM model_evaluation_challenge_events WHERE challenge_id=$1) + \
             (SELECT COUNT(*) FROM model_authenticity_arbitration_events WHERE challenge_id=$1)",
        )
        .bind(private_challenge_id)
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法验证 legacy private-v1 projections：{error}"))?;
        if projection_count != 2 {
            return Err(format!(
                "legacy private-v1 projections 未保留：{projection_count}"
            ));
        }

        expect_sqlstate(
            sqlx::query("UPDATE job_attempts SET finished_at=finished_at WHERE id=$1")
                .bind(legacy_attempt_id)
                .execute(&database.pool)
                .await,
            "23514",
            "更新未绑定 legacy attempt",
        )?;
        let other_user_id = Uuid::now_v7();
        let other_device_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO users (id,provider,provider_subject,username) \
             VALUES ($1,'v31-test',$2,$3)",
        )
        .bind(other_user_id)
        .bind(format!("other-subject-{other_user_id}"))
        .bind(format!("其他用户-{other_user_id}"))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建 legacy rebind 负例用户：{error}"))?;
        insert_device_key(&database.pool, other_user_id, other_device_id, 'd').await?;
        expect_sqlstate(
            sqlx::query("UPDATE nodes SET user_id=$2,device_key_id=$3 WHERE id=$1")
                .bind(resources.node_id)
                .bind(other_user_id)
                .bind(other_device_id)
                .execute(&database.pool)
                .await,
            "23514",
            "借首次 rebind 更换 legacy 节点 owner",
        )?;
        let original_device_id = Uuid::now_v7();
        insert_device_key(&database.pool, resources.user_id, original_device_id, 'c').await?;
        sqlx::query("UPDATE nodes SET device_key_id=$2 WHERE id=$1")
            .bind(resources.node_id)
            .bind(original_device_id)
            .execute(&database.pool)
            .await
            .map_err(|error| format!("legacy 节点无法显式绑定原 owner 设备：{error}"))?;
        Ok(())
    }
    .await;
    let cleanup = database.cleanup().await;
    result?;
    cleanup
}

#[tokio::test]
#[serial]
async fn fresh_v31_enforces_shapes_immutable_identity_and_append_only_state() -> TestResult {
    let Some(database_url) = database_url_or_skip() else {
        return Ok(());
    };
    let migrator = load_migrator().await?;
    let database = IsolatedDatabase::create(&database_url, "fresh").await?;
    let result = async {
        migrate_through(
            &database.pool,
            &migrator,
            PRIVATE_HMAC_BUDGET_MIGRATION_VERSION,
        )
        .await?;
        if migration_state(&database.pool).await? != (31, 1, 31, true) {
            return Err("fresh v31 migration metadata 不完整".to_owned());
        }
        let resources = insert_resources(&database.pool, true).await?;
        let device_one = resources
            .device_key_id
            .ok_or_else(|| "fresh fixture 缺少 device one".to_owned())?;
        let device_two = Uuid::now_v7();
        insert_device_key(&database.pool, resources.user_id, device_two, 'b').await?;
        let second_node_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO nodes
                (id,user_id,alias,trust_level,status,hardware_profile,device_key_id)
            VALUES ($1,$2,$3,'standard','online','{}'::jsonb,$4)
            "#,
        )
        .bind(second_node_id)
        .bind(resources.user_id)
        .bind(format!("same-device-node-{second_node_id}"))
        .bind(device_one)
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法创建同设备第二节点：{error}"))?;

        expect_sqlstate(
            sqlx::query("UPDATE nodes SET device_key_id=$2 WHERE id=$1")
                .bind(resources.node_id)
                .bind(device_two)
                .execute(&database.pool)
                .await,
            "23514",
            "更换已绑定节点设备",
        )?;

        let job_id = insert_active_ordinary(&database.pool, resources, true).await?;
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO job_attempts
                    (id,job_id,node_id,attempt_number,status,lease_started_at,
                     lease_expires_at,claim_device_binding_version,claim_device_key_id)
                VALUES ($1,$2,$3,3,'leased',now(),now()+interval '1 hour',1,$4)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(resources.node_id)
            .bind(device_two)
            .execute(&database.pool)
            .await,
            "23503",
            "用同账号另一设备伪造 attempt 领取绑定",
        )?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE job_attempts SET claim_device_key_id=$2 WHERE job_id=$1 AND status='leased'",
            )
            .bind(job_id)
            .bind(device_two)
            .execute(&database.pool)
            .await,
            "23514",
            "更换 attempt 领取设备",
        )?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE job_attempts SET node_id=$2 WHERE job_id=$1 AND status='leased'",
            )
            .bind(job_id)
            .bind(second_node_id)
            .execute(&database.pool)
            .await,
            "23514",
            "把 attempt 改绑到同设备另一节点",
        )?;
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO job_attempts
                    (id,job_id,node_id,attempt_number,status,lease_started_at,
                     lease_expires_at,claim_device_key_id)
                VALUES ($1,$2,$3,2,'leased',now(),now()+interval '1 hour',$4)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(resources.node_id)
            .bind(device_one)
            .execute(&database.pool)
            .await,
            "23514",
            "插入缺少 binding version 的 leased attempt",
        )?;
        expect_sqlstate(
            sqlx::query(
            r#"
            INSERT INTO job_attempts
                (id,job_id,node_id,attempt_number,status,lease_started_at,
                 lease_expires_at,finished_at)
            VALUES ($1,$2,$3,2,'failed',now()-interval '2 hours',
                    now()-interval '1 hour',now()-interval '1 hour')
            "#,
            )
            .bind(Uuid::now_v7())
            .bind(job_id)
            .bind(resources.node_id)
            .execute(&database.pool)
            .await,
            "23514",
            "在 v31 新插无绑定 terminal attempt",
        )?;

        let v1_id = Uuid::now_v7();
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO model_evaluation_challenges
                    (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                     prompt_hash,expected_hash,lease_token_hash,status,lease_expires_at,
                     claimed_user_id,claimed_device_key_id,claim_device_binding_version)
                VALUES ($1,$2,$3,$4,'canary',$5,$6,$7,$8,'leased',
                        now()+interval '1 hour',$9,$10,1)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(resources.model_id)
            .bind(resources.model_instance_id)
            .bind(resources.node_id)
            .bind(vec![6_u8; 32])
            .bind("7".repeat(64))
            .bind("8".repeat(64))
            .bind("9".repeat(64))
            .bind(resources.user_id)
            .bind(device_two)
            .execute(&database.pool)
            .await,
            "23503",
            "用同账号另一设备伪造 hidden 领取绑定",
        )?;
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO model_evaluation_challenges
                    (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                     prompt_hash,expected_hash,lease_token_hash,status,lease_expires_at,
                     claimed_user_id,claimed_device_key_id)
                VALUES ($1,$2,$3,$4,'canary',$5,$6,$7,$8,'leased',
                        now()+interval '1 hour',$9,$10)
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(resources.model_id)
            .bind(resources.model_instance_id)
            .bind(resources.node_id)
            .bind(vec![6_u8; 32])
            .bind("7".repeat(64))
            .bind("8".repeat(64))
            .bind("9".repeat(64))
            .bind(resources.user_id)
            .bind(device_one)
            .execute(&database.pool)
            .await,
            "23514",
            "插入缺少 binding version 的 leased challenge",
        )?;
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO model_evaluation_challenges
                    (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                     prompt_hash,expected_hash,lease_token_hash,status,result_hash,
                     score_normalized,resulting_tier,resulting_evaluation_samples,
                     lease_expires_at,completed_at)
                VALUES ($1,$2,$3,$4,'canary',NULL,$5,$6,$7,'succeeded',$8,
                        1000000,'medium',0,now()-interval '1 hour',now())
                "#,
            )
            .bind(v1_id)
            .bind(resources.model_id)
            .bind(resources.model_instance_id)
            .bind(resources.node_id)
            .bind("c".repeat(64))
            .bind("d".repeat(64))
            .bind("e".repeat(64))
            .bind("f".repeat(64))
            .execute(&database.pool)
            .await,
            "23514",
            "在 v31 新插无绑定 terminal challenge",
        )?;
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,result_hash,
                 score_normalized,resulting_tier,resulting_evaluation_samples,
                 lease_expires_at,completed_at,claimed_user_id,
                 claimed_device_key_id,claim_device_binding_version)
            VALUES ($1,$2,$3,$4,'canary',NULL,$5,$6,$7,'succeeded',$8,
                    1000000,'medium',0,now()-interval '1 hour',now(),$9,$10,1)
            "#,
        )
        .bind(v1_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind("c".repeat(64))
        .bind("d".repeat(64))
        .bind("e".repeat(64))
        .bind("f".repeat(64))
        .bind(resources.user_id)
        .bind(device_one)
        .execute(&database.pool)
        .await
        .map_err(|error| format!("v31 拒绝合法绑定 v1 shape：{error}"))?;
        expect_sqlstate(
            sqlx::query("UPDATE model_evaluation_challenges SET node_id=$2 WHERE id=$1")
                .bind(v1_id)
                .bind(second_node_id)
                .execute(&database.pool)
                .await,
            "23514",
            "把 challenge 改绑到同设备另一节点",
        )?;
        expect_sqlstate(
            sqlx::query(
                r#"
                INSERT INTO model_evaluation_challenges
                    (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                     prompt_hash,expected_hash,lease_token_hash,status,result_hash,
                     score_normalized,resulting_tier,resulting_evaluation_samples,
                     lease_expires_at,completed_at,claimed_user_id,
                     claimed_device_key_id,claim_device_binding_version,
                     private_catalog_id)
                VALUES ($1,$2,$3,$4,'hidden_benchmark',NULL,$5,$6,$7,'succeeded',$8,
                        1000000,'medium',0,now()-interval '1 hour',now(),$9,$10,1,
                        'partial-catalog')
                "#,
            )
            .bind(Uuid::now_v7())
            .bind(resources.model_id)
            .bind(resources.model_instance_id)
            .bind(resources.node_id)
            .bind("6".repeat(64))
            .bind("7".repeat(64))
            .bind("8".repeat(64))
            .bind("9".repeat(64))
            .bind(resources.user_id)
            .bind(device_one)
            .execute(&database.pool)
            .await,
            "23514",
            "插入 partial private-v1 catalog identity",
        )?;

        let v2_id = Uuid::now_v7();
        let commitment = "a".repeat(64);
        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenges
                (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
                 prompt_hash,expected_hash,lease_token_hash,status,lease_expires_at,
                 model_weights_hash,challenge_nonce_hash,challenge_binding_hash,
                 challenge_issued_expires_at,authorized_input_tokens,
                 authorized_max_output_tokens,inference_seed,private_catalog_valid_until,
                 claimed_user_id,claimed_device_key_id,claim_device_binding_version,
                 private_commitment_version,private_catalog_statement_commitment,
                 private_catalog_id_commitment,private_catalog_entry_commitment,
                 private_case_family_commitment,private_evaluator_id_commitment,
                 private_evaluator_key_commitment,private_prompt_commitment,
                 private_expected_commitment,private_account_commitment,
                 private_device_commitment,private_node_commitment)
            VALUES ($1,$2,$3,$4,'hidden_benchmark',$5,NULL,NULL,$6,'leased',
                    now()+interval '1 hour',$7,$8,$9,now()+interval '1 hour',1,1,1,
                    now()+interval '2 hours',$10,$11,1,2,$12,$13,$14,$15,$16,$17,
                    $18,$19,$20,$21,$22)
            "#,
        )
        .bind(v2_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind(resources.node_id)
        .bind(vec![9_u8; 32])
        .bind("0".repeat(64))
        .bind("1".repeat(64))
        .bind("2".repeat(64))
        .bind("3".repeat(64))
        .bind(resources.user_id)
        .bind(device_one)
        .bind(&commitment)
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .bind("d".repeat(64))
        .bind("e".repeat(64))
        .bind("f".repeat(64))
        .bind("1".repeat(64))
        .bind("2".repeat(64))
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("v31 拒绝合法 v2 shape：{error}"))?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE model_evaluation_challenges SET claimed_device_key_id=$2 WHERE id=$1",
            )
            .bind(v2_id)
            .bind(device_two)
            .execute(&database.pool)
            .await,
            "23514",
            "更换 v2 challenge 领取设备",
        )?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE model_evaluation_challenges SET private_catalog_id='raw-leak' WHERE id=$1",
            )
            .bind(v2_id)
            .execute(&database.pool)
            .await,
            "23514",
            "给 v2 challenge 混入 raw catalog 标识符",
        )?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE model_evaluation_challenges SET private_catalog_valid_until=NULL WHERE id=$1",
            )
            .bind(v2_id)
            .execute(&database.pool)
            .await,
            "23514",
            "清除 v2 challenge 绝对有效期",
        )?;

        sqlx::query(
            r#"
            INSERT INTO model_evaluation_challenge_events
                (id,challenge_id,event_kind,prompt_hash,
                 private_commitment_version,private_catalog_statement_commitment,
                 private_catalog_id_commitment,private_catalog_entry_commitment,
                 private_case_family_commitment,private_evaluator_id_commitment,
                 private_evaluator_key_commitment,private_prompt_commitment,
                 private_expected_commitment,private_account_commitment,
                 private_device_commitment,private_node_commitment)
            VALUES ($1,$2,'issued',NULL,2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(v2_id)
        .bind(&commitment)
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .bind("d".repeat(64))
        .bind("e".repeat(64))
        .bind("f".repeat(64))
        .bind("1".repeat(64))
        .bind("2".repeat(64))
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("v31 拒绝合法 v2 lifecycle event：{error}"))?;

        sqlx::query(
            r#"
            INSERT INTO model_authenticity_arbitration_events
                (id,challenge_id,model_id,model_instance_id,model_weights_hash,
                 private_evaluator_key_fingerprint,private_catalog_commitment,
                 private_case_family,passed,observed_distinct_instances,
                 passed_distinct_instances,failed_distinct_instances,verdict,
                 challenge_binding_hash,private_commitment_version,
                 private_catalog_statement_commitment,private_catalog_id_commitment,
                 private_catalog_entry_commitment,private_case_family_commitment,
                 private_evaluator_id_commitment,private_evaluator_key_commitment,
                 private_prompt_commitment,private_expected_commitment,
                 private_account_commitment,private_device_commitment,
                 private_node_commitment)
            VALUES ($1,$2,$3,$4,$5,NULL,NULL,NULL,TRUE,1,1,0,'pending',$6,2,
                    $7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(v2_id)
        .bind(resources.model_id)
        .bind(resources.model_instance_id)
        .bind("1".repeat(64))
        .bind("3".repeat(64))
        .bind(&commitment)
        .bind("b".repeat(64))
        .bind("c".repeat(64))
        .bind("d".repeat(64))
        .bind("e".repeat(64))
        .bind("f".repeat(64))
        .bind("1".repeat(64))
        .bind("2".repeat(64))
        .bind("3".repeat(64))
        .bind("4".repeat(64))
        .bind("5".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("v31 拒绝合法 v2 arbitration event：{error}"))?;

        sqlx::query(
            "INSERT INTO private_evaluation_hmac_key_state (version,key_commitment) VALUES (1,$1)",
        )
        .bind("7".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法写入 key state：{error}"))?;
        expect_sqlstate(
            sqlx::query(
                "UPDATE private_evaluation_hmac_key_state SET key_commitment=$1 WHERE version=1",
            )
            .bind("8".repeat(64))
            .execute(&database.pool)
            .await,
            "P0001",
            "修改 append-only key state",
        )?;
        sqlx::query(
            r#"
            INSERT INTO private_evaluation_budget_scopes
                (version,scope_kind,scope_commitment)
            VALUES (2,'catalog',$1)
            "#,
        )
        .bind("9".repeat(64))
        .execute(&database.pool)
        .await
        .map_err(|error| format!("无法写入 budget scope：{error}"))?;
        expect_sqlstate(
            sqlx::query(
                "DELETE FROM private_evaluation_budget_scopes \
                 WHERE version=2 AND scope_kind='catalog' AND scope_commitment=$1",
            )
            .bind("9".repeat(64))
            .execute(&database.pool)
            .await,
            "P0001",
            "删除 append-only budget scope",
        )?;
        let key_comment: String = sqlx::query_scalar(
            r#"
            SELECT col_description('private_evaluation_hmac_key_state'::regclass,2)
            "#,
        )
        .fetch_one(&database.pool)
        .await
        .map_err(|error| format!("无法读取 key commitment 注释：{error}"))?;
        if !key_comment.contains("Domain-separated SHA-256")
            || !key_comment.contains("bare SHA-256(key)")
        {
            return Err(format!("key commitment 语义注释不完整：{key_comment}"));
        }
        Ok(())
    }
    .await;
    let cleanup = database.cleanup().await;
    result?;
    cleanup
}
