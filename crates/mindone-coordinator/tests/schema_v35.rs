use std::env;

use sqlx::{postgres::PgPoolOptions, PgConnection};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v35 Standard SSE schema 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v35 Standard SSE schema 测试：未设置 DATABASE_URL");
            None
        }
    }
}

async fn expect_rejected(
    connection: &mut PgConnection,
    sql: &str,
    expected_sqlstate: &str,
    operation: &str,
) -> TestResult {
    sqlx::query("SAVEPOINT rejected_case")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("{operation} 无法创建 savepoint：{error}"))?;
    let result = sqlx::query(sql).execute(&mut *connection).await;
    sqlx::query("ROLLBACK TO SAVEPOINT rejected_case")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("{operation} 无法回滚 savepoint：{error}"))?;
    match result {
        Ok(_) => Err(format!("{operation} 应被数据库拒绝")),
        Err(sqlx::Error::Database(database))
            if database.code().as_deref() == Some(expected_sqlstate) =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "{operation} SQLSTATE 错误：期望 {expected_sqlstate}，实际 {error}"
        )),
    }
}

async fn exercise_schema(connection: &mut PgConnection, schema: &str) -> TestResult {
    let job_a = Uuid::now_v7();
    let job_b = Uuid::now_v7();
    sqlx::query("BEGIN")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法开始 v35 schema 事务：{error}"))?;
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法创建 v35 隔离 schema：{error}"))?;
    sqlx::query(&format!("SET LOCAL search_path = {schema}, pg_catalog"))
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法设置 v35 隔离 search_path：{error}"))?;
    sqlx::query("CREATE TABLE jobs (id UUID PRIMARY KEY)")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法创建 v35 最小 jobs 父表：{error}"))?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0035_standard_job_sse_events.sql"
    ))
    .execute(&mut *connection)
    .await
    .map_err(|error| format!("无法应用 0035 Standard SSE migration：{error}"))?;
    sqlx::query("INSERT INTO jobs(id) VALUES ($1),($2)")
        .bind(job_a)
        .bind(job_b)
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法写入 v35 测试 job：{error}"))?;

    sqlx::query(
        r#"
        INSERT INTO job_stream_events
          (job_id,attempt_number,sequence_number,idempotency_key,event_kind,
           event_ciphertext,standard_event_storage_version,plaintext_bytes)
        VALUES ($1,1,0,'stream-a-0','data','mindone-standard-aead-v1:AAAA',1,32),
               ($1,1,1,'stream-a-done','upstream_done',NULL,NULL,0),
               ($1,2,0,'stream-a-attempt-2','data','mindone-standard-aead-v1:BBBB',1,16),
               ($2,1,0,'stream-a-0','data','mindone-standard-aead-v1:CCCC',1,8)
        "#,
    )
    .bind(job_a)
    .bind(job_b)
    .execute(&mut *connection)
    .await
    .map_err(|error| format!("合法 v35 事件形状被错误拒绝：{error}"))?;

    expect_rejected(
        connection,
        &format!(
            "INSERT INTO job_stream_events VALUES \
             ('{job_a}',1,0,'different-sequence-key','data',\
              'mindone-standard-aead-v1:DDDD',1,4,now())"
        ),
        "23505",
        "同一 job/attempt/sequence 重放",
    )
    .await?;
    expect_rejected(
        connection,
        &format!(
            "INSERT INTO job_stream_events VALUES \
             ('{job_a}',3,0,'stream-a-0','data',\
              'mindone-standard-aead-v1:EEEE',1,4,now())"
        ),
        "23505",
        "同一 job 跨 attempt 复用幂等键",
    )
    .await?;
    expect_rejected(
        connection,
        &format!(
            "INSERT INTO job_stream_events VALUES \
             ('{job_a}',3,1,'plaintext-leak','data','真实输出明文',1,18,now())"
        ),
        "23514",
        "Response 明文持久化",
    )
    .await?;
    expect_rejected(
        connection,
        "UPDATE job_stream_events SET plaintext_bytes=1 WHERE idempotency_key='stream-a-0'",
        "23514",
        "流式事件 UPDATE",
    )
    .await?;
    expect_rejected(
        connection,
        "DELETE FROM job_stream_events WHERE idempotency_key='stream-a-0'",
        "23514",
        "流式事件 DELETE",
    )
    .await?;

    let plaintext_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM job_stream_events \
         WHERE event_kind='data' AND event_ciphertext NOT LIKE 'mindone-standard-aead-v1:%'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| format!("无法审计 v35 ciphertext-only 状态：{error}"))?;
    if plaintext_rows != 0 {
        return Err("v35 表中出现非 AEAD data 事件".to_owned());
    }
    let runtime_acl: (bool, bool, bool, bool) = sqlx::query_as(&format!(
        "SELECT has_table_privilege('mindone_app','{schema}.job_stream_events','SELECT'),\
                has_table_privilege('mindone_app','{schema}.job_stream_events','INSERT'),\
                has_table_privilege('mindone_app','{schema}.job_stream_events','UPDATE'),\
                has_table_privilege('mindone_app','{schema}.job_stream_events','DELETE')"
    ))
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| format!("无法读取 v35 runtime ACL：{error}"))?;
    if runtime_acl != (true, true, false, false) {
        return Err(format!("v35 runtime ACL 不是只读追加合同：{runtime_acl:?}"));
    }
    sqlx::query("ROLLBACK")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法回滚 v35 隔离 schema：{error}"))?;
    Ok(())
}

#[tokio::test]
async fn schema_v35_is_ciphertext_only_append_only_and_runtime_minimal() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("应连接 v35 PostgreSQL 测试库");
    let mut connection = pool.acquire().await.expect("应获取 v35 PostgreSQL 连接");
    let schema = format!("mindone_v35_{}", Uuid::now_v7().simple());
    if let Err(error) = exercise_schema(&mut connection, &schema).await {
        let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
        panic!("{error}");
    }
}
