use std::{env, str::FromStr, time::Duration};

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult},
    PgPool,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;

const MIGRATION: &str = include_str!("../../../migrations/0038_job_speed_class.sql");

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v38 速度档测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v38 速度档 PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn expect_check_violation(result: Result<PgQueryResult, sqlx::Error>) -> TestResult {
    match result {
        Ok(_) => Err("非法 speed_class 应被数据库拒绝".to_owned()),
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23514") => Ok(()),
        Err(error) => Err(format!(
            "非法 speed_class 应返回 SQLSTATE 23514，实际为 {error}"
        )),
    }
}

async fn exercise_v38(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(include_str!("../../../migrations/0001_initial.sql"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 v38 测试基线：{error}"))?;
    sqlx::raw_sql(MIGRATION)
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 0038 迁移：{error}"))?;

    let shape: (String, bool, bool) = sqlx::query_as(
        r#"
        SELECT column_default,
               is_nullable = 'NO',
               to_regclass('public.jobs_ready_speed_queue_idx') IS NOT NULL
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name='jobs' AND column_name='speed_class'
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法审计 v38 schema：{error}"))?;
    if shape != ("'standard'::text".to_owned(), true, true) {
        return Err(format!("v38 speed_class schema 不符合合同：{shape:?}"));
    }

    let user_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'test',$2,'v38')",
    )
    .bind(user_id)
    .bind(user_id.to_string())
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v38 用户：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO models
            (id,owner_user_id,name,weights_hash,format,size_bytes,context_length,
             base_cost_per_1k_micro,enabled)
        VALUES ($1,$2,'model',$3,'gguf',1024,4096,1,TRUE)
        "#,
    )
    .bind(model_id)
    .bind(user_id)
    .bind("a".repeat(64))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v38 模型：{error}"))?;
    for speed_class in ["fast", "standard", "slow"] {
        sqlx::query(
            r#"
            INSERT INTO jobs
                (id,user_id,model_id,idempotency_key,encrypted_payload,
                 estimated_input_tokens,max_output_tokens,reserved_cost_micro,speed_class)
            VALUES ($1,$2,$3,$4,'eA==',1,1,1,$5)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(model_id)
        .bind(format!("v38-{speed_class}"))
        .bind(speed_class)
        .execute(pool)
        .await
        .map_err(|error| format!("合法速度档 {speed_class} 应可写入：{error}"))?;
    }
    expect_check_violation(
        sqlx::query(
            r#"
            INSERT INTO jobs
                (id,user_id,model_id,idempotency_key,encrypted_payload,
                 estimated_input_tokens,max_output_tokens,reserved_cost_micro,speed_class)
            VALUES ($1,$2,$3,'v38-invalid','eA==',1,1,1,'turbo')
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(user_id)
        .bind(model_id)
        .execute(pool)
        .await,
    )?;
    Ok(())
}

#[test]
fn migration_source_has_bounded_speed_classes_and_ready_index() {
    assert!(MIGRATION.contains("speed_class IN ('fast', 'standard', 'slow')"));
    assert!(MIGRATION.contains("jobs_ready_speed_queue_idx"));
    assert!(!MIGRATION.to_ascii_lowercase().contains("drop table"));
}

#[tokio::test]
async fn schema_v38_persists_only_three_speed_classes() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let base_options =
        PgConnectOptions::from_str(&database_url).expect("DATABASE_URL 应是合法 PostgreSQL URL");
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options.clone().database("postgres"))
        .await
        .expect("应能连接 PostgreSQL maintenance database");
    let database_name = format!("mindone_v38_speed_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        r#"CREATE DATABASE "{database_name}" TEMPLATE template0"#
    ))
    .execute(&admin_pool)
    .await
    .expect("应能创建 v38 隔离数据库");
    let result = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options.database(&database_name))
        .await
    {
        Ok(pool) => {
            let result = exercise_v38(&pool).await;
            pool.close().await;
            result
        }
        Err(error) => Err(format!("无法连接 v38 隔离数据库：{error}")),
    };
    let cleanup = sqlx::query(&format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#))
        .execute(&admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v38 隔离数据库：{error}"));
    admin_pool.close().await;
    result
        .and(cleanup)
        .unwrap_or_else(|error| panic!("{error}"));
}
