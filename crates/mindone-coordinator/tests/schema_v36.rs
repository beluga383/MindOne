use std::{env, str::FromStr, time::Duration as StdDuration};

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, String>;

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("v36 SLA 审计排除测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过 v36 SLA 审计排除测试：未设置 DATABASE_URL");
            None
        }
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

async fn create_test_database(
    admin_pool: &PgPool,
    base_options: &PgConnectOptions,
) -> TestResult<(String, PgPool)> {
    let database_name = format!("mindone_v36_sla_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        r#"CREATE DATABASE "{database_name}" TEMPLATE template0"#
    ))
    .execute(admin_pool)
    .await
    .map_err(|error| format!("无法创建 v36 隔离数据库：{error}"))?;
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(StdDuration::from_secs(10))
        .connect_with(
            base_options
                .clone()
                .database(&database_name)
                .options([("search_path", "public,pg_catalog")]),
        )
        .await
        .map_err(|error| format!("无法连接 v36 隔离数据库：{error}"))?;
    Ok((database_name, pool))
}

async fn drop_test_database(admin_pool: &PgPool, database_name: &str) -> TestResult {
    sqlx::query(&format!(r#"DROP DATABASE "{database_name}" WITH (FORCE)"#))
        .execute(admin_pool)
        .await
        .map(|_| ())
        .map_err(|error| format!("无法清理 v36 隔离数据库：{error}"))
}

fn expect_database_code<T>(
    result: Result<T, sqlx::Error>,
    expected_code: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation} 应被数据库拒绝")),
        Err(sqlx::Error::Database(database))
            if database.code().as_deref() == Some(expected_code) =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "{operation} SQLSTATE 错误：期望 {expected_code}，实际 {error}"
        )),
    }
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

#[derive(Clone, Copy)]
struct Fixture {
    user_id: Uuid,
    node_id: Uuid,
    model_id: Uuid,
}

async fn seed_fixture(pool: &PgPool) -> TestResult<Fixture> {
    let user_id = Uuid::now_v7();
    let node_id = Uuid::now_v7();
    let model_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'schema-v36',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("schema-v36-{user_id}"))
    .bind(format!("SLA 审计-{user_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v36 用户：{error}"))?;
    sqlx::query(
        "INSERT INTO nodes (id,user_id,alias,hardware_profile) VALUES ($1,$2,$3,'{}'::jsonb)",
    )
    .bind(node_id)
    .bind(user_id)
    .bind(format!("schema-v36-node-{node_id}"))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v36 node：{error}"))?;
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
    .bind(format!("schema-v36-{model_id}"))
    .bind("ab".repeat(32))
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 v36 model：{error}"))?;
    Ok(Fixture {
        user_id,
        node_id,
        model_id,
    })
}

async fn seed_job(pool: &PgPool, fixture: Fixture, status: &str) -> TestResult<Uuid> {
    let job_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO jobs
            (id,user_id,model_id,idempotency_key,status,encrypted_payload,
             estimated_input_tokens,max_output_tokens,reserved_cost_micro)
        VALUES ($1,$2,$3,$4,$5,'e30=',1,1,1)
        "#,
    )
    .bind(job_id)
    .bind(fixture.user_id)
    .bind(fixture.model_id)
    .bind(format!("schema-v36-job-{job_id}"))
    .bind(status)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 {status} v36 job：{error}"))?;
    Ok(job_id)
}

struct RecordInput<'a> {
    event_id: Uuid,
    job_id: Uuid,
    category: &'a str,
    idempotency_key: &'a str,
    reason: &'a str,
    evidence_sha256: &'a str,
    request_fingerprint: &'a str,
}

async fn record(pool: &PgPool, input: RecordInput<'_>) -> Result<(Uuid, bool), sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT out_event_id,out_idempotent_replay
        FROM mindone_record_sla_exclusion_v1($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(input.event_id)
    .bind(input.job_id)
    .bind(input.category)
    .bind("ops/governance")
    .bind(input.reason)
    .bind(input.idempotency_key)
    .bind(input.evidence_sha256)
    .bind(input.request_fingerprint)
    .fetch_one(pool)
    .await
}

async fn assert_runtime_acl_and_direct_dml_rejected(
    pool: &PgPool,
    failed_job_id: Uuid,
    function_job_id: Uuid,
) -> TestResult {
    let table_acl: (bool, bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_table_privilege('mindone_app','public.sla_exclusion_events','SELECT'),
               has_table_privilege('mindone_app','public.sla_exclusion_events','INSERT'),
               has_table_privilege('mindone_app','public.sla_exclusion_events','UPDATE'),
               has_table_privilege('mindone_app','public.sla_exclusion_events','DELETE'),
               has_table_privilege('mindone_app','public.sla_exclusion_events','TRUNCATE')
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 v36 runtime table ACL：{error}"))?;
    if table_acl != (true, false, false, false, false) {
        return Err(format!(
            "v36 runtime table ACL 不符合只读合同：{table_acl:?}"
        ));
    }
    let function_acl: (bool, bool, bool, bool) = sqlx::query_as(
        r#"
        SELECT has_function_privilege(
                   'mindone_app',
                   'public.mindone_record_sla_exclusion_v1(uuid,uuid,text,text,text,text,text,text)',
                   'EXECUTE'
               ),
               has_function_privilege(
                   'mindone_app','public.mindone_validate_sla_exclusion_insert_v1()','EXECUTE'
               ),
               has_function_privilege(
                   'mindone_app','public.mindone_prevent_sla_exclusion_mutation_v1()','EXECUTE'
               ),
               NOT EXISTS (
                   SELECT 1
                   FROM pg_proc AS procedure
                   CROSS JOIN LATERAL aclexplode(
                       COALESCE(procedure.proacl,acldefault('f',procedure.proowner))
                   ) AS privilege
                   WHERE procedure.oid =
                       'public.mindone_record_sla_exclusion_v1(uuid,uuid,text,text,text,text,text,text)'::regprocedure
                     AND privilege.grantee=0
                     AND privilege.privilege_type='EXECUTE'
               )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法读取 v36 runtime function ACL：{error}"))?;
    if function_acl != (true, false, false, true) {
        return Err(format!(
            "v36 runtime function allowlist 不符合合同：{function_acl:?}"
        ));
    }

    let mut connection = pool
        .acquire()
        .await
        .map_err(|error| format!("无法获取 runtime ACL 探针连接：{error}"))?;
    sqlx::query("SET ROLE mindone_app")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法切换 runtime role：{error}"))?;
    let visible: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sla_exclusion_events")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| format!("runtime role 无法读取 SLA 排除事件：{error}"))?;
    if visible < 0 {
        return Err("runtime SLA 事件计数不可能为负".to_owned());
    }
    let runtime_event_id = Uuid::now_v7();
    let recorded_by_function: Uuid = sqlx::query_scalar(
        r#"
        SELECT out_event_id
        FROM mindone_record_sla_exclusion_v1(
            $1,$2,'force_majeure','ops/runtime-function',
            'runtime 只能通过审计函数记录事件','schema-v36-runtime-function',$3,$4
        )
        "#,
    )
    .bind(runtime_event_id)
    .bind(function_job_id)
    .bind("ca".repeat(32))
    .bind("cb".repeat(32))
    .fetch_one(&mut *connection)
    .await
    .map_err(|error| format!("runtime role 无法执行唯一 SLA 记录函数：{error}"))?;
    if recorded_by_function != runtime_event_id {
        return Err("runtime SLA 函数没有返回新建审计事件".to_owned());
    }
    let insert = sqlx::query(
        r#"
        INSERT INTO sla_exclusion_events
            (id,job_id,category,operator_id,reason,idempotency_key,
             evidence_sha256,request_fingerprint)
        VALUES ($1,$2,'force_majeure','ops/runtime','runtime 不得直接写入事件',
                'runtime-direct-insert',$3,$4)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(failed_job_id)
    .bind("aa".repeat(32))
    .bind("bb".repeat(32))
    .execute(&mut *connection)
    .await;
    expect_database_code(insert, "42501", "runtime direct INSERT")?;
    expect_database_code(
        sqlx::query("UPDATE sla_exclusion_events SET reason=reason")
            .execute(&mut *connection)
            .await,
        "42501",
        "runtime direct UPDATE",
    )?;
    expect_database_code(
        sqlx::query("DELETE FROM sla_exclusion_events")
            .execute(&mut *connection)
            .await,
        "42501",
        "runtime direct DELETE",
    )?;
    expect_database_code(
        sqlx::query("TRUNCATE sla_exclusion_events")
            .execute(&mut *connection)
            .await,
        "42501",
        "runtime direct TRUNCATE",
    )?;
    sqlx::query("RESET ROLE")
        .execute(&mut *connection)
        .await
        .map_err(|error| format!("无法恢复数据库 owner role：{error}"))?;
    Ok(())
}

async fn exercise_v36(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(include_str!("../../../migrations/0001_initial.sql"))
        .execute(pool)
        .await
        .map_err(|error| format!("无法应用 v36 测试基线：{error}"))?;
    sqlx::raw_sql(include_str!(
        "../../../migrations/0036_audited_sla_exclusions.sql"
    ))
    .execute(pool)
    .await
    .map_err(|error| format!("无法应用 0036 SLA migration：{error}"))?;

    let path_columns: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name='sla_exclusion_events'
          AND (column_name LIKE '%path%' OR column_name LIKE '%prompt%'
               OR column_name LIKE '%response%')
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法审计 v36 隐私列：{error}"))?;
    if path_columns != 0 {
        return Err("SLA 排除表不得保存 evidence path、Prompt 或 Response".to_owned());
    }

    let fixture = seed_fixture(pool).await?;
    let excluded_failed = seed_job(pool, fixture, "failed").await?;
    let excluded_cancelled = seed_job(pool, fixture, "cancelled").await?;
    let queued = seed_job(pool, fixture, "queued").await?;
    let worker_failed = seed_job(pool, fixture, "failed").await?;
    let _succeeded = seed_job(pool, fixture, "succeeded").await?;

    // A node-reported error_class remains an attempt fact and never creates an
    // operator exclusion event.
    sqlx::query(
        r#"
        INSERT INTO job_attempts
            (id,job_id,node_id,attempt_number,status,lease_started_at,
             lease_expires_at,finished_at,error_class,error_message)
        VALUES ($1,$2,$3,1,'failed',now()-interval '2 minutes',
                now()-interval '1 minute',now()-interval '1 minute',
                'force_majeure','节点自报不得影响 SLA')
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(worker_failed)
    .bind(fixture.node_id)
    .execute(pool)
    .await
    .map_err(|error| format!("无法创建 node error_class 回归夹具：{error}"))?;
    let auto_exclusions: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sla_exclusion_events WHERE job_id=$1")
            .bind(worker_failed)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("无法检查 node error_class 隔离：{error}"))?;
    if auto_exclusions != 0 {
        return Err("节点 error_class 不得自动创建 SLA 排除".to_owned());
    }

    let failed_event_id = Uuid::now_v7();
    let failed_created = record(
        pool,
        RecordInput {
            event_id: failed_event_id,
            job_id: excluded_failed,
            category: "content_policy_refusal",
            idempotency_key: "schema-v36-failed",
            reason: "经独立证据确认属于内容政策拒绝",
            evidence_sha256: &"11".repeat(32),
            request_fingerprint: &"21".repeat(32),
        },
    )
    .await
    .map_err(|error| format!("无法记录 failed SLA 排除：{error}"))?;
    if failed_created != (failed_event_id, false) {
        return Err(format!("首次 failed 排除返回无效：{failed_created:?}"));
    }
    let replay = record(
        pool,
        RecordInput {
            event_id: Uuid::now_v7(),
            job_id: excluded_failed,
            category: "content_policy_refusal",
            idempotency_key: "schema-v36-failed",
            reason: "经独立证据确认属于内容政策拒绝",
            evidence_sha256: &"11".repeat(32),
            request_fingerprint: &"21".repeat(32),
        },
    )
    .await
    .map_err(|error| format!("完全相同 SLA 请求重放失败：{error}"))?;
    if replay != (failed_event_id, true) {
        return Err(format!("SLA exact replay 没有返回原事件：{replay:?}"));
    }
    expect_database_message(
        record(
            pool,
            RecordInput {
                event_id: Uuid::now_v7(),
                job_id: excluded_failed,
                category: "content_policy_refusal",
                idempotency_key: "schema-v36-failed",
                reason: "变更理由后不得复用同一幂等键",
                evidence_sha256: &"11".repeat(32),
                request_fingerprint: &"22".repeat(32),
            },
        )
        .await,
        "23505",
        "sla exclusion idempotency conflict",
        "同幂等键变更请求",
    )?;
    expect_database_message(
        record(
            pool,
            RecordInput {
                event_id: Uuid::now_v7(),
                job_id: excluded_failed,
                category: "force_majeure",
                idempotency_key: "schema-v36-same-job",
                reason: "同一任务不得记录第二个排除决定",
                evidence_sha256: &"12".repeat(32),
                request_fingerprint: &"23".repeat(32),
            },
        )
        .await,
        "23505",
        "sla exclusion job conflict",
        "不同幂等键复用同一 job",
    )?;
    expect_database_message(
        record(
            pool,
            RecordInput {
                event_id: Uuid::now_v7(),
                job_id: queued,
                category: "force_majeure",
                idempotency_key: "schema-v36-queued",
                reason: "非终态任务不得记录审计排除决定",
                evidence_sha256: &"13".repeat(32),
                request_fingerprint: &"24".repeat(32),
            },
        )
        .await,
        "23514",
        "sla exclusion requires a failed or cancelled job",
        "queued job 排除",
    )?;

    let invalid_category_job = seed_job(pool, fixture, "failed").await?;
    expect_database_code(
        record(
            pool,
            RecordInput {
                event_id: Uuid::now_v7(),
                job_id: invalid_category_job,
                category: "worker_error_class",
                idempotency_key: "schema-v36-invalid-category",
                reason: "节点分类不得作为合法排除类别",
                evidence_sha256: &"14".repeat(32),
                request_fingerprint: &"25".repeat(32),
            },
        )
        .await,
        "23514",
        "非法 SLA 排除类别",
    )?;

    record(
        pool,
        RecordInput {
            event_id: Uuid::now_v7(),
            job_id: excluded_cancelled,
            category: "force_majeure",
            idempotency_key: "schema-v36-cancelled",
            reason: "经独立证据确认属于不可抗力事件",
            evidence_sha256: &"15".repeat(32),
            request_fingerprint: &"26".repeat(32),
        },
    )
    .await
    .map_err(|error| format!("无法记录 cancelled SLA 事件：{error}"))?;

    let concurrent_job = seed_job(pool, fixture, "failed").await?;
    let first_evidence = "31".repeat(32);
    let first_fingerprint = "41".repeat(32);
    let second_evidence = "32".repeat(32);
    let second_fingerprint = "42".repeat(32);
    let first = record(
        pool,
        RecordInput {
            event_id: Uuid::now_v7(),
            job_id: concurrent_job,
            category: "force_majeure",
            idempotency_key: "schema-v36-concurrent-a",
            reason: "并发事件由第一份独立证据裁决",
            evidence_sha256: &first_evidence,
            request_fingerprint: &first_fingerprint,
        },
    );
    let second = record(
        pool,
        RecordInput {
            event_id: Uuid::now_v7(),
            job_id: concurrent_job,
            category: "content_policy_refusal",
            idempotency_key: "schema-v36-concurrent-b",
            reason: "并发事件由第二份独立证据裁决",
            evidence_sha256: &second_evidence,
            request_fingerprint: &second_fingerprint,
        },
    );
    let (first, second) = tokio::join!(first, second);
    let concurrent_successes = usize::from(first.is_ok()) + usize::from(second.is_ok());
    if concurrent_successes != 1 {
        return Err(format!(
            "同 job 并发决定必须恰好一个成功：first={first:?}, second={second:?}"
        ));
    }
    let rejected = if first.is_err() { first } else { second };
    expect_database_message(
        rejected,
        "23505",
        "sla exclusion job conflict",
        "同 job 并发第二决定",
    )?;

    // Cancelled jobs were already outside the denominator. Both category totals
    // include their audit, but only failed exclusions shrink the denominator.
    let governance_counts: (i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FILTER (WHERE job.status IN ('succeeded','failed','cancelled'))::bigint,
               COUNT(*) FILTER (WHERE job.status='succeeded')::bigint,
               (
                   COUNT(*) FILTER (WHERE job.status='succeeded')
                   + COUNT(*) FILTER (
                       WHERE job.status='failed' AND exclusion.id IS NULL
                   )
               )::bigint,
               COUNT(exclusion.id)::bigint,
               COUNT(exclusion.id) FILTER (WHERE job.status='failed')::bigint,
               COUNT(exclusion.id) FILTER (
                   WHERE exclusion.category='content_policy_refusal'
               )::bigint,
               COUNT(exclusion.id) FILTER (
                   WHERE exclusion.category='force_majeure'
               )::bigint
        FROM jobs AS job
        LEFT JOIN sla_exclusion_events AS exclusion ON exclusion.job_id=job.id
        WHERE job.id <> $1 AND job.id <> $2
        "#,
    )
    .bind(invalid_category_job)
    .bind(concurrent_job)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("无法复算 v36 SLA 治理计数：{error}"))?;
    if governance_counts != (4, 1, 2, 2, 1, 1, 1) {
        return Err(format!(
            "v36 SLA 计数未遵守 failed-only 分母：{governance_counts:?}"
        ));
    }

    let runtime_function_job = seed_job(pool, fixture, "failed").await?;
    assert_runtime_acl_and_direct_dml_rejected(pool, worker_failed, runtime_function_job).await?;

    expect_database_message(
        sqlx::query("UPDATE sla_exclusion_events SET reason=reason")
            .execute(pool)
            .await,
        "23514",
        "MindOne SLA exclusion events are append-only",
        "owner UPDATE append-only 事件",
    )?;
    expect_database_message(
        sqlx::query("DELETE FROM sla_exclusion_events")
            .execute(pool)
            .await,
        "23514",
        "MindOne SLA exclusion events are append-only",
        "owner DELETE append-only 事件",
    )?;
    expect_database_message(
        sqlx::query("TRUNCATE sla_exclusion_events")
            .execute(pool)
            .await,
        "23514",
        "MindOne SLA exclusion events are append-only",
        "owner TRUNCATE append-only 事件",
    )?;
    Ok(())
}

#[tokio::test]
async fn schema_v36_is_audited_idempotent_append_only_and_failed_only() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let (admin_pool, base_options) = connect_admin(&database_url)
        .await
        .expect("应能连接 v36 maintenance database");
    let (database_name, pool) = create_test_database(&admin_pool, &base_options)
        .await
        .expect("应能创建 v36 隔离数据库");

    let exercise = exercise_v36(&pool).await;
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
