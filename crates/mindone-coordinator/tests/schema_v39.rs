use std::{env, str::FromStr, time::Duration};

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult},
    PgPool,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;
const MIGRATION: &str = include_str!("../../../migrations/0039_inference_api_keys.sql");

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v39 API Key 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v39 API Key PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn expect_database_code(
    result: Result<PgQueryResult, sqlx::Error>,
    expected: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation} 应被数据库拒绝")),
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some(expected) => Ok(()),
        Err(error) => Err(format!(
            "{operation} 应返回 SQLSTATE {expected}，实际为 {error}"
        )),
    }
}

async fn exercise_v39(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(include_str!("../../../migrations/0001_initial.sql"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 v39 测试基线：{error}"))?;
    sqlx::raw_sql(MIGRATION)
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 0039 迁移：{error}"))?;

    let secret_columns_absent: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema='public' AND table_name='inference_api_keys'
              AND column_name IN ('api_key','secret','token','plaintext')
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法审计 v39 Secret 列：{error}"))?;
    if !secret_columns_absent {
        return Err("inference_api_keys 不得保存明文 Secret".to_owned());
    }

    let user_id = Uuid::now_v7();
    let device_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let key_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'test',$2,'v39')",
    )
    .bind(user_id)
    .bind(user_id.to_string())
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v39 用户：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO device_keys (id,user_id,fingerprint,public_key)
        VALUES ($1,$2,$3,$4)
        "#,
    )
    .bind(device_id)
    .bind(user_id)
    .bind("a".repeat(64))
    .bind("b".repeat(64))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v39 设备：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO sessions
            (id,user_id,access_token_hash,refresh_token_hash,access_expires_at,refresh_expires_at)
        VALUES ($1,$2,$3,$4,now()+interval '1 hour',now()+interval '1 day')
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .bind("c".repeat(43))
    .bind("d".repeat(43))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v39 会话：{error}"))?;
    sqlx::query(
        r#"
        INSERT INTO inference_api_keys
            (id,user_id,created_by_session_id,device_key_id,name,key_prefix,key_hash)
        VALUES ($1,$2,$3,$4,'production','mok_ABCDEFGH',$5)
        "#,
    )
    .bind(key_id)
    .bind(user_id)
    .bind(session_id)
    .bind(device_id)
    .bind("e".repeat(43))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建合法 v39 API Key：{error}"))?;
    let event_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO inference_api_key_events (id,api_key_id,user_id,event_type) VALUES ($1,$2,$3,'created')",
    )
    .bind(event_id)
    .bind(key_id)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v39 API Key 事件：{error}"))?;
    expect_database_code(
        sqlx::query("UPDATE inference_api_key_events SET event_type='revoked' WHERE id=$1")
            .bind(event_id)
            .execute(pool)
            .await,
        "55000",
        "修改 API Key 审计事件",
    )?;
    expect_database_code(
        sqlx::query(
            r#"
            INSERT INTO inference_api_keys
                (id,user_id,created_by_session_id,device_key_id,name,key_prefix,key_hash)
            VALUES ($1,$2,$3,$4,'invalid','raw-secret',$5)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(session_id)
        .bind(device_id)
        .bind("f".repeat(43))
        .execute(pool)
        .await,
        "23514",
        "写入非法 Key 前缀",
    )?;
    Ok(())
}

#[test]
fn migration_source_is_hash_only_and_audit_is_append_only() {
    assert!(MIGRATION.contains("key_hash TEXT NOT NULL UNIQUE"));
    assert!(MIGRATION.contains("reject_inference_api_key_event_mutation"));
    assert!(MIGRATION.contains("GRANT SELECT, INSERT, UPDATE ON TABLE inference_api_keys"));
    assert!(MIGRATION.contains("GRANT SELECT, INSERT ON TABLE inference_api_key_events"));
    assert!(!MIGRATION.contains("api_key TEXT"));
    assert!(!MIGRATION.contains("secret TEXT"));
}

#[tokio::test]
async fn schema_v39_never_stores_plaintext_key_and_events_are_append_only() {
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
    let database_name = format!("mindone_v39_keys_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        r#"CREATE DATABASE "{database_name}" TEMPLATE template0"#
    ))
    .execute(&admin_pool)
    .await
    .expect("应能创建 v39 隔离数据库");
    let result = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options.database(&database_name))
        .await
    {
        Ok(pool) => {
            let result = exercise_v39(&pool).await;
            pool.close().await;
            result
        }
        Err(error) => Err(format!("无法连接 v39 隔离数据库：{error}")),
    };
    let cleanup = sqlx::query(&format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#))
        .execute(&admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v39 隔离数据库：{error}"));
    admin_pool.close().await;
    result
        .and(cleanup)
        .unwrap_or_else(|error| panic!("{error}"));
}
