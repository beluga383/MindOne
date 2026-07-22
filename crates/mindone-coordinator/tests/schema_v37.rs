use std::{env, str::FromStr, time::Duration};

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult},
    PgPool,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;

const MIGRATION: &str = include_str!("../../../migrations/0037_email_password_auth.sql");

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v37 邮箱 Device Flow 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v37 邮箱 Device Flow PostgreSQL 测试：未设置 DATABASE_URL");
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

async fn exercise_v37(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(include_str!("../../../migrations/0001_initial.sql"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 v37 测试基线：{error}"))?;
    sqlx::raw_sql(MIGRATION)
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 0037 迁移：{error}"))?;

    let sensitive_shape: (bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema='public'
                  AND table_name='email_verification_tokens'
                  AND column_name='token_hash'
            ),
            NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema='public'
                  AND table_name='email_verification_tokens'
                  AND column_name IN ('token','email','access_token','refresh_token')
            ),
            to_regclass('public.password_reset_tokens') IS NULL,
            to_regclass('public.web_device_bindings') IS NULL,
            EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema='public' AND table_name='auth_device_flows'
                  AND column_name='email_authorized_user_id'
            ) AND EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema='public' AND table_name='auth_device_flows'
                  AND column_name='email_authorized_at'
            )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法审计 v37 敏感 schema：{error}"))?;
    if sensitive_shape != (true, true, true, true, true) {
        return Err(format!(
            "v37 仍可能持久化原始 token 或缺少 Device Flow 绑定列：{sensitive_shape:?}"
        ));
    }

    let public_acl_safe: bool = sqlx::query_scalar(
        r#"
        SELECT NOT EXISTS (
            SELECT 1
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace_row
              ON namespace_row.oid=relation.relnamespace
            CROSS JOIN LATERAL aclexplode(
                COALESCE(relation.relacl,acldefault('r',relation.relowner))
            ) AS privilege
            WHERE namespace_row.nspname='public'
              AND relation.relname='email_verification_tokens'
              AND privilege.grantee=0
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法审计 v37 PUBLIC ACL：{error}"))?;
    if !public_acl_safe {
        return Err("一次性令牌表不得向 PUBLIC 暴露".to_owned());
    }

    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users
            (id,provider,provider_subject,username,email,password_hash)
        VALUES ($1,'email','alice@example.com','Alice','alice@example.com','argon2-hash')
        "#,
    )
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法插入合法 email 用户：{error}"))?;

    expect_database_code(
        sqlx::query(
            r#"
            INSERT INTO users
                (id,provider,provider_subject,username,email,password_hash)
            VALUES ($1,'email','case@example.com','Case','Case@Example.com','argon2-hash')
            "#,
        )
        .bind(Uuid::now_v7())
        .execute(pool)
        .await,
        "23514",
        "写入未规范化邮箱",
    )?;

    sqlx::query(
        r#"
        INSERT INTO email_verification_tokens
            (id,user_id,token_hash,expires_at)
        VALUES ($1,$2,$3,now()+interval '1 hour')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind("A".repeat(43))
    .execute(pool)
    .await
    .map_err(|error| format!("无法插入 hash-only 验证 token：{error}"))?;
    expect_database_code(
        sqlx::query(
            r#"
            INSERT INTO email_verification_tokens
                (id,user_id,token_hash,expires_at)
            VALUES ($1,$2,'raw-token',now()+interval '1 hour')
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .execute(pool)
        .await,
        "23514",
        "写入非 HMAC 验证 token",
    )?;

    let flow_id = Uuid::now_v7();
    let device_code_hash = "B".repeat(43);
    sqlx::query(
        r#"
        INSERT INTO auth_device_flows
            (id,provider,provider_device_code,user_code,verification_uri,
             interval_seconds,expires_at)
        VALUES ($1,'email',$2,'ABCDEF123456','https://example.com/auth/login',2,
                now()+interval '5 minutes')
        "#,
    )
    .bind(flow_id)
    .bind(&device_code_hash)
    .execute(pool)
    .await
    .map_err(|error| format!("无法插入 email Device Flow：{error}"))?;
    expect_database_code(
        sqlx::query("UPDATE auth_device_flows SET email_authorized_user_id=$2 WHERE id=$1")
            .bind(flow_id)
            .bind(user_id)
            .execute(pool)
            .await,
        "23514",
        "只写授权用户不写授权时间",
    )?;
    sqlx::query(
        r#"
        UPDATE auth_device_flows
        SET email_authorized_user_id=$2,email_authorized_at=now()
        WHERE id=$1
        "#,
    )
    .bind(flow_id)
    .bind(user_id)
    .execute(pool)
    .await
    .map_err(|error| format!("合法 email Device Flow 授权应成功：{error}"))?;
    expect_database_code(
        sqlx::query(
            r#"
            INSERT INTO auth_device_flows
                (id,provider,provider_device_code,user_code,verification_uri,
                 interval_seconds,expires_at)
            VALUES ($1,'email',$2,'123456ABCDEF','https://example.com/auth/login',2,
                    now()+interval '5 minutes')
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(device_code_hash)
        .execute(pool)
        .await,
        "23505",
        "重复 email Device Flow code hash",
    )?;

    Ok(())
}

#[test]
fn migration_source_has_no_raw_token_or_bearer_storage() {
    assert!(MIGRATION.contains("token_hash TEXT NOT NULL UNIQUE"));
    assert!(!MIGRATION.contains("token TEXT"));
    assert!(!MIGRATION.contains("access_token TEXT"));
    assert!(!MIGRATION.contains("refresh_token TEXT"));
    assert!(!MIGRATION.contains("web_device_bindings"));
}

#[tokio::test]
async fn schema_v37_is_hash_only_normalized_and_device_bound() {
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
    let database_name = format!("mindone_v37_email_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        r#"CREATE DATABASE "{database_name}" TEMPLATE template0"#
    ))
    .execute(&admin_pool)
    .await
    .expect("应能创建 v37 隔离数据库");

    let result = match PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options.database(&database_name))
        .await
    {
        Ok(pool) => {
            let result = exercise_v37(&pool).await;
            pool.close().await;
            result
        }
        Err(error) => Err(format!("无法连接 v37 隔离数据库：{error}")),
    };
    let cleanup = sqlx::query(&format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#))
        .execute(&admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v37 隔离数据库：{error}"));
    admin_pool.close().await;

    match (result, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => panic!("{error}"),
        (Ok(()), Err(error)) => panic!("{error}"),
        (Err(error), Err(cleanup_error)) => panic!("{error}；清理同时失败：{cleanup_error}"),
    }
}
