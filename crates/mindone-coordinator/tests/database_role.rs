use std::{env, str::FromStr};

use mindone_coordinator::{
    config::Config,
    db::{connect, migrate, prepare_runtime},
};
use serial_test::serial;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions, PgQueryResult},
    PgPool, Row,
};
use uuid::Uuid;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

type TestResult<T = ()> = Result<T, String>;

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("运行时数据库角色 PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过运行时数据库角色 PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn expect_database_error(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_code: &str,
    operation: &str,
) -> TestResult {
    match result {
        Ok(_) => Err(format!("{operation}应被数据库拒绝，但意外成功")),
        Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some(expected_code) => {
            Ok(())
        }
        Err(error) => Err(format!(
            "{operation}应返回 SQLSTATE {expected_code}，实际为：{error}"
        )),
    }
}

async fn assert_role_flags(owner_pool: &PgPool) -> TestResult {
    let row = sqlx::query(
        r#"
        SELECT rolsuper,rolcreatedb,rolcreaterole,rolinherit,
               rolreplication,rolbypassrls,rolconnlimit,
               (rolvaliduntil IS NULL OR rolvaliduntil='infinity'::timestamptz)
                   AS valid_until_safe,
               NOT EXISTS (
                   SELECT 1 FROM pg_auth_members membership
                   WHERE membership.roleid=role_row.oid
                      OR membership.member=role_row.oid
               ) AS no_memberships,
               NOT EXISTS (
                   SELECT 1 FROM pg_shdepend dependency
                   WHERE dependency.refclassid='pg_authid'::regclass
                     AND dependency.refobjid=role_row.oid
                     AND dependency.deptype='o'
               ) AS no_ownership,
               (
                   SELECT count(*)=1
                      AND bool_and(setting.setdatabase=0)
                      AND bool_and(setting.setconfig=ARRAY['search_path=pg_catalog, public']::text[])
                   FROM pg_db_role_setting setting
                   WHERE setting.setrole=role_row.oid
               ) AS settings_safe,
               NOT has_database_privilege('mindone_app',current_database(),'CREATE')
                   AS no_database_create,
               NOT has_database_privilege('mindone_app',current_database(),'TEMPORARY')
                   AS no_database_temp,
               NOT EXISTS (
                   SELECT 1 FROM pg_database database_row
                   WHERE database_row.datname<>current_database()
                     AND has_database_privilege('mindone_app',database_row.datname,'CONNECT')
               ) AS no_other_database_connect,
               COALESCE((
                   SELECT bool_and(
                       NOT has_function_privilege(
                           'mindone_app',procedure_row.oid,'EXECUTE'
                       )
                       OR (
                           procedure_row.oid =
                               'public.mindone_physical_billing_snapshot_is_valid_v1(text,uuid,bigint,text,text,text,text,timestamptz,timestamptz,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)'::regprocedure
                           AND procedure_row.provolatile='i'
                           AND procedure_row.proparallel='s'
                           AND procedure_row.prokind='f'
                           AND NOT procedure_row.prosecdef
                           AND procedure_row.prorettype='boolean'::regtype
                           AND procedure_row.proconfig=
                               ARRAY['search_path=pg_catalog']::text[]
                           AND language_row.lanname='sql'
                       )
                       OR (
                           procedure_row.oid =
                               'public.mindone_record_billing_profile_v1(uuid,uuid,uuid,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,text,timestamptz,timestamptz,text,text,text,text)'::regprocedure
                           AND procedure_row.provolatile='v'
                           AND procedure_row.proparallel='u'
                           AND procedure_row.prokind='f'
                           AND procedure_row.prosecdef
                           AND procedure_row.prorettype='record'::regtype
                           AND procedure_row.proconfig=
                               ARRAY['search_path="$user", public']::text[]
                           AND language_row.lanname='plpgsql'
                       )
                       OR (
                           procedure_row.oid =
                               'public.mindone_record_sla_exclusion_v1(uuid,uuid,text,text,text,text,text,text)'::regprocedure
                           AND procedure_row.provolatile='v'
                           AND procedure_row.proparallel='u'
                           AND procedure_row.prokind='f'
                           AND procedure_row.prosecdef
                           AND procedure_row.prorettype='record'::regtype
                           AND procedure_row.proconfig=
                               ARRAY['search_path=pg_catalog, public']::text[]
                           AND language_row.lanname='plpgsql'
                       )
                   )
                   FROM pg_proc procedure_row
                   JOIN pg_namespace namespace_row
                     ON namespace_row.oid=procedure_row.pronamespace
                   JOIN pg_language language_row
                     ON language_row.oid=procedure_row.prolang
                   WHERE namespace_row.nspname='public'
               ),TRUE) AS runtime_function_allowlist_safe,
               NOT EXISTS (
                   SELECT 1
                   FROM pg_proc procedure_row
                   JOIN pg_namespace namespace_row
                     ON namespace_row.oid=procedure_row.pronamespace
                   CROSS JOIN LATERAL aclexplode(
                       COALESCE(
                           procedure_row.proacl,
                           acldefault('f',procedure_row.proowner)
                       )
                   ) acl
                   WHERE namespace_row.nspname='public'
                     AND acl.grantee=0
                     AND acl.privilege_type='EXECUTE'
               ) AS no_public_role_function_execute
        FROM pg_roles role_row
        WHERE role_row.rolname='mindone_app'
        "#,
    )
    .fetch_optional(owner_pool)
    .await
    .map_err(|error| format!("无法读取 mindone_app 角色标志：{error}"))?
    .ok_or_else(|| "迁移未创建 mindone_app 角色".to_owned())?;

    let superuser: bool = row
        .try_get("rolsuper")
        .map_err(|error| format!("rolsuper 类型错误：{error}"))?;
    let create_db: bool = row
        .try_get("rolcreatedb")
        .map_err(|error| format!("rolcreatedb 类型错误：{error}"))?;
    let create_role: bool = row
        .try_get("rolcreaterole")
        .map_err(|error| format!("rolcreaterole 类型错误：{error}"))?;
    let inherit: bool = row
        .try_get("rolinherit")
        .map_err(|error| format!("rolinherit 类型错误：{error}"))?;
    let replication: bool = row
        .try_get("rolreplication")
        .map_err(|error| format!("rolreplication 类型错误：{error}"))?;
    let bypass_rls: bool = row
        .try_get("rolbypassrls")
        .map_err(|error| format!("rolbypassrls 类型错误：{error}"))?;
    let connection_limit: i32 = row
        .try_get("rolconnlimit")
        .map_err(|error| format!("rolconnlimit 类型错误：{error}"))?;
    let valid_until_safe: bool = row
        .try_get("valid_until_safe")
        .map_err(|error| format!("valid_until_safe 类型错误：{error}"))?;
    let no_memberships: bool = row
        .try_get("no_memberships")
        .map_err(|error| format!("no_memberships 类型错误：{error}"))?;
    let no_ownership: bool = row
        .try_get("no_ownership")
        .map_err(|error| format!("no_ownership 类型错误：{error}"))?;
    let settings_safe: bool = row
        .try_get("settings_safe")
        .map_err(|error| format!("settings_safe 类型错误：{error}"))?;
    let no_database_create: bool = row
        .try_get("no_database_create")
        .map_err(|error| format!("no_database_create 类型错误：{error}"))?;
    let no_database_temp: bool = row
        .try_get("no_database_temp")
        .map_err(|error| format!("no_database_temp 类型错误：{error}"))?;
    let no_other_database_connect: bool = row
        .try_get("no_other_database_connect")
        .map_err(|error| format!("no_other_database_connect 类型错误：{error}"))?;
    let runtime_function_allowlist_safe: bool = row
        .try_get("runtime_function_allowlist_safe")
        .map_err(|error| format!("runtime_function_allowlist_safe 类型错误：{error}"))?;
    let no_public_role_function_execute: bool = row
        .try_get("no_public_role_function_execute")
        .map_err(|error| format!("no_public_role_function_execute 类型错误：{error}"))?;

    if superuser
        || create_db
        || create_role
        || inherit
        || replication
        || bypass_rls
        || connection_limit != 32
        || !valid_until_safe
        || !no_memberships
        || !no_ownership
        || !settings_safe
        || !no_database_create
        || !no_database_temp
        || !no_other_database_connect
        || !runtime_function_allowlist_safe
        || !no_public_role_function_execute
    {
        return Err(format!(
            "mindone_app 包含危险角色标志：superuser={superuser}, createdb={create_db}, \
             createrole={create_role}, inherit={inherit}, replication={replication}, \
             bypassrls={bypass_rls}, connlimit={connection_limit}, \
             valid_until_safe={valid_until_safe}, no_memberships={no_memberships}, \
             no_ownership={no_ownership}, settings_safe={settings_safe}, \
             no_database_create={no_database_create}, no_database_temp={no_database_temp}, \
             no_other_database_connect={no_other_database_connect}, \
             runtime_function_allowlist_safe={runtime_function_allowlist_safe}, \
             no_public_role_function_execute={no_public_role_function_execute}"
        ));
    }
    Ok(())
}

async fn exercise_runtime_pool(
    runtime_pool: &PgPool,
    owner_pool: &PgPool,
    config: &Config,
    probe_table: &str,
) -> TestResult {
    prepare_runtime(runtime_pool, &config.standard_data_key)
        .await
        .map_err(|error| format!("运行时数据准备失败：{error}"))?;

    let current_user: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(runtime_pool)
        .await
        .map_err(|error| format!("无法读取运行时 current_user：{error}"))?;
    if current_user != "mindone_app" {
        return Err(format!(
            "运行时连接必须使用 mindone_app，实际为 {current_user}"
        ));
    }
    assert_role_flags(owner_pool).await?;

    let v31_table_acl: bool = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) = 2
           AND bool_and(
               has_table_privilege('mindone_app',format('public.%I',table_name),'SELECT')
               AND has_table_privilege('mindone_app',format('public.%I',table_name),'INSERT')
               AND has_table_privilege('mindone_app',format('public.%I',table_name),'UPDATE')
               AND has_table_privilege('mindone_app',format('public.%I',table_name),'DELETE')
           )
           AND bool_and(
               NOT has_table_privilege('mindone_app',format('public.%I',table_name),'TRUNCATE')
               AND NOT has_table_privilege('mindone_app',format('public.%I',table_name),'REFERENCES')
               AND NOT has_table_privilege('mindone_app',format('public.%I',table_name),'TRIGGER')
           )
        FROM unnest(ARRAY[
            'private_evaluation_hmac_key_state',
            'private_evaluation_budget_scopes'
        ]) AS requested(table_name)
        WHERE to_regclass(format('public.%I',table_name)) IS NOT NULL
        "#,
    )
    .fetch_one(owner_pool)
    .await
    .map_err(|error| format!("无法读取 v31 私有评价表 ACL：{error}"))?;
    if !v31_table_acl {
        return Err("v31 私有评价新表没有继承 runtime 最小权限合同".to_owned());
    }

    let protected_runtime_acl: bool = sqlx::query_scalar(
        r#"
        SELECT
            has_table_privilege('mindone_app','public.billing_profiles','SELECT')
            AND NOT has_table_privilege('mindone_app','public.billing_profiles','INSERT')
            AND NOT has_table_privilege('mindone_app','public.billing_profiles','UPDATE')
            AND NOT has_table_privilege('mindone_app','public.billing_profiles','DELETE')
            AND has_table_privilege(
                'mindone_app','public.physical_billing_legacy_allowlist','SELECT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.physical_billing_legacy_allowlist','INSERT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.physical_billing_legacy_allowlist','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.physical_billing_legacy_allowlist','DELETE'
            )
            AND has_table_privilege('mindone_app','public.receipts','SELECT')
            AND has_table_privilege('mindone_app','public.receipts','INSERT')
            AND NOT has_table_privilege('mindone_app','public.receipts','UPDATE')
            AND NOT has_table_privilege('mindone_app','public.receipts','DELETE')
            AND has_table_privilege(
                'mindone_app','public.billing_profile_provision_audits','SELECT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.billing_profile_provision_audits','INSERT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.billing_profile_provision_audits','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.billing_profile_provision_audits','DELETE'
            )
            AND has_table_privilege(
                'mindone_app','public.job_stream_events','SELECT'
            )
            AND has_table_privilege(
                'mindone_app','public.job_stream_events','INSERT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.job_stream_events','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.job_stream_events','DELETE'
            )
            AND has_table_privilege(
                'mindone_app','public.sla_exclusion_events','SELECT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.sla_exclusion_events','INSERT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.sla_exclusion_events','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.sla_exclusion_events','DELETE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.sla_exclusion_events','TRUNCATE'
            )
            AND has_table_privilege(
                'mindone_app','public.email_verification_tokens','SELECT'
            )
            AND has_table_privilege(
                'mindone_app','public.email_verification_tokens','INSERT'
            )
            AND has_table_privilege(
                'mindone_app','public.email_verification_tokens','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.email_verification_tokens','DELETE'
            )
            AND has_table_privilege(
                'mindone_app','public.inference_api_keys','SELECT'
            )
            AND has_table_privilege(
                'mindone_app','public.inference_api_keys','INSERT'
            )
            AND has_table_privilege(
                'mindone_app','public.inference_api_keys','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.inference_api_keys','DELETE'
            )
            AND has_table_privilege(
                'mindone_app','public.inference_api_key_events','SELECT'
            )
            AND has_table_privilege(
                'mindone_app','public.inference_api_key_events','INSERT'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.inference_api_key_events','UPDATE'
            )
            AND NOT has_table_privilege(
                'mindone_app','public.inference_api_key_events','DELETE'
            )
            AND has_function_privilege(
                'mindone_app',
                'public.mindone_physical_billing_snapshot_is_valid_v1(text,uuid,bigint,text,text,text,text,timestamptz,timestamptz,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint)',
                'EXECUTE'
            )
            AND has_function_privilege(
                'mindone_app',
                'public.mindone_record_billing_profile_v1(uuid,uuid,uuid,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,text,timestamptz,timestamptz,text,text,text,text)',
                'EXECUTE'
            )
            AND has_function_privilege(
                'mindone_app',
                'public.mindone_record_sla_exclusion_v1(uuid,uuid,text,text,text,text,text,text)',
                'EXECUTE'
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_proc AS procedure_row,
                     LATERAL aclexplode(
                         COALESCE(
                             procedure_row.proacl,
                             acldefault('f',procedure_row.proowner)
                         )
                     ) AS acl
                WHERE procedure_row.oid =
                    'public.mindone_record_billing_profile_v1(uuid,uuid,uuid,bigint,text,bigint,bigint,bigint,bigint,bigint,bigint,bigint,bigint,text,timestamptz,timestamptz,text,text,text,text)'::regprocedure
                  AND acl.grantee=0
                  AND acl.privilege_type='EXECUTE'
            )
            AND NOT EXISTS (
                SELECT 1
                FROM pg_proc AS procedure_row,
                     LATERAL aclexplode(
                         COALESCE(
                             procedure_row.proacl,
                             acldefault('f',procedure_row.proowner)
                         )
                     ) AS acl
                WHERE procedure_row.oid =
                    'public.mindone_record_sla_exclusion_v1(uuid,uuid,text,text,text,text,text,text)'::regprocedure
                  AND acl.grantee=0
                  AND acl.privilege_type='EXECUTE'
            )
            AND NOT has_function_privilege(
                'mindone_app',
                'public.mindone_require_current_physical_billing_insert_v1()',
                'EXECUTE'
            )
        "#,
    )
    .fetch_one(owner_pool)
    .await
    .map_err(|error| format!("无法读取 protected runtime ACL：{error}"))?;
    if !protected_runtime_acl {
        return Err(
            "physical billing、provisioning、SSE、SLA 审计、令牌表与函数没有执行最小权限合同"
                .to_owned(),
        );
    }
    expect_database_error(
        sqlx::query("INSERT INTO billing_profiles (id) VALUES ($1)")
            .bind(Uuid::now_v7())
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 绕过 provisioning 函数直接插入 billing profile",
    )?;
    expect_database_error(
        sqlx::query("INSERT INTO billing_profile_provision_audits (id) VALUES ($1)")
            .bind(Uuid::now_v7())
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 直接伪造 billing profile provisioning audit",
    )?;
    expect_database_error(
        sqlx::query("INSERT INTO sla_exclusion_events (id) VALUES ($1)")
            .bind(Uuid::now_v7())
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 直接伪造 SLA exclusion event",
    )?;

    sqlx::query(
        r#"
        INSERT INTO private_evaluation_hmac_key_state (version,key_commitment)
        VALUES (1,$1)
        ON CONFLICT (version) DO NOTHING
        "#,
    )
    .bind("a".repeat(64))
    .execute(runtime_pool)
    .await
    .map_err(|error| format!("mindone_app 无法初始化 v31 HMAC key state：{error}"))?;
    expect_database_error(
        sqlx::query(
            "UPDATE private_evaluation_hmac_key_state \
             SET key_commitment=key_commitment WHERE version=1",
        )
        .execute(runtime_pool)
        .await,
        "P0001",
        "mindone_app 修改 append-only HMAC key state",
    )?;

    let budget_commitment = hex::encode(Uuid::now_v7().as_bytes());
    let budget_commitment = format!("{budget_commitment}{}", "0".repeat(32));
    sqlx::query(
        r#"
        INSERT INTO private_evaluation_budget_scopes
            (version,scope_kind,scope_commitment)
        VALUES (2,'catalog',$1)
        "#,
    )
    .bind(&budget_commitment)
    .execute(runtime_pool)
    .await
    .map_err(|error| format!("mindone_app 无法创建 v31 budget lock row：{error}"))?;
    expect_database_error(
        sqlx::query(
            "DELETE FROM private_evaluation_budget_scopes \
             WHERE version=2 AND scope_kind='catalog' AND scope_commitment=$1",
        )
        .bind(&budget_commitment)
        .execute(runtime_pool)
        .await,
        "P0001",
        "mindone_app 删除 append-only budget lock row",
    )?;

    let forbidden_table = format!("mindone_forbidden_{}", Uuid::now_v7().simple());
    expect_database_error(
        sqlx::query(&format!(
            "CREATE TABLE public.{forbidden_table} (id BIGINT PRIMARY KEY)"
        ))
        .execute(runtime_pool)
        .await,
        "42501",
        "mindone_app 在 public schema 中 CREATE TABLE",
    )?;

    expect_database_error(
        sqlx::query("CREATE TEMP TABLE mindone_forbidden_temp (id BIGINT PRIMARY KEY)")
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 创建 TEMP 遮蔽表",
    )?;

    let forbidden_schema = format!("mindone_forbidden_{}", Uuid::now_v7().simple());
    expect_database_error(
        sqlx::query(&format!("CREATE SCHEMA {forbidden_schema}"))
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 创建优先 schema",
    )?;

    expect_database_error(
        sqlx::query("UPDATE public._sqlx_migrations SET description=description WHERE version=27")
            .execute(runtime_pool)
            .await,
        "42501",
        "mindone_app 修改 _sqlx_migrations",
    )?;

    expect_database_error(
        sqlx::query(
            "ALTER TABLE public.quota_accounts DISABLE TRIGGER quota_accounts_guard_ledger_state",
        )
        .execute(runtime_pool)
        .await,
        "42501",
        "mindone_app 禁用账本守卫 trigger",
    )?;

    let probe_id: i64 = sqlx::query_scalar(&format!(
        "INSERT INTO public.{probe_table} (note) VALUES ($1) RETURNING id"
    ))
    .bind("运行角色 future table/sequence 权限探针")
    .fetch_one(runtime_pool)
    .await
    .map_err(|error| format!("未能使用未来表和 sequence 默认权限：{error}"))?;
    if probe_id <= 0 {
        return Err(format!("future sequence 返回了无效 ID：{probe_id}"));
    }

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'database-role-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("runtime-role-{user_id}"))
    .bind(format!("运行角色-{user_id}"))
    .execute(runtime_pool)
    .await
    .map_err(|error| format!("mindone_app 无法创建唯一测试用户：{error}"))?;

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(runtime_pool)
        .await
        .map_err(|error| format!("mindone_app 无法创建零余额账户：{error}"))?;

    expect_database_error(
        sqlx::query("UPDATE quota_accounts SET spendable_micro=1 WHERE user_id=$1")
            .bind(user_id)
            .execute(runtime_pool)
            .await,
        "23514",
        "mindone_app 直接修改 ledger tracked 余额",
    )?;

    let entry_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',1000,0,1000,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("runtime-role:{user_id}"))
    .bind(GENESIS_HASH)
    .fetch_one(runtime_pool)
    .await
    .map_err(|error| format!("mindone_app 无法插入合法 quota ledger：{error}"))?;

    let account: (i64, i64, String, i64) = sqlx::query_as(
        "SELECT spendable_micro,reserved_micro,quota_ledger_head_hash,\
         quota_ledger_entry_count FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(runtime_pool)
    .await
    .map_err(|error| format!("无法读取账本触发器更新后的账户：{error}"))?;
    if account != (1000, 0, entry_hash, 1) {
        return Err(format!(
            "合法 ledger insert 未原子推进余额/链头/计数：{account:?}"
        ));
    }

    sqlx::query("UPDATE quota_accounts SET reserved_micro=400 WHERE user_id=$1")
        .bind(user_id)
        .execute(runtime_pool)
        .await
        .map_err(|error| format!("mindone_app 的合法 reserved_micro 更新失败：{error}"))?;
    let reserved: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(runtime_pool)
            .await
            .map_err(|error| format!("无法读取 reserved_micro：{error}"))?;
    if reserved != 400 {
        return Err(format!(
            "合法 reserved_micro 更新未持久化：期望 400，实际 {reserved}"
        ));
    }

    Ok(())
}

async fn connect_and_exercise_runtime(
    database_url: &str,
    owner_pool: &PgPool,
    config: &Config,
    probe_table: &str,
) -> TestResult {
    let options = PgConnectOptions::from_str(database_url)
        .map_err(|error| format!("DATABASE_URL 无效：{error}"))?;
    let runtime_pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET ROLE mindone_app")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .map_err(|error| format!("无法建立并切换至 mindone_app 的 PostgreSQL 连接：{error}"))?;

    let result = exercise_runtime_pool(&runtime_pool, owner_pool, config, probe_table).await;
    runtime_pool.close().await;
    result
}

async fn cleanup_owner_state(owner_pool: &PgPool, probe_table: &str) -> TestResult {
    sqlx::query(&format!("DROP TABLE IF EXISTS public.{probe_table}"))
        .execute(owner_pool)
        .await
        .map_err(|error| format!("无法删除 future table/sequence 测试探针：{error}"))?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn runtime_role_is_least_privileged_and_keeps_ledger_paths_working() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url.clone());
    let owner_pool = connect(&config).await.expect("所有者应能连接测试数据库");
    migrate(&owner_pool, &config.standard_data_key)
        .await
        .expect("所有者应能完成全部迁移");

    let probe_table = format!("mindone_runtime_probe_{}", Uuid::now_v7().simple());
    sqlx::query(&format!(
        "CREATE TABLE public.{probe_table} (\
         id BIGSERIAL PRIMARY KEY,note TEXT NOT NULL)"
    ))
    .execute(&owner_pool)
    .await
    .expect("所有者应能创建未来表与 sequence 权限探针");

    let exercise =
        connect_and_exercise_runtime(&database_url, &owner_pool, &config, &probe_table).await;
    let cleanup = cleanup_owner_state(&owner_pool, &probe_table).await;

    match (exercise, cleanup) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => panic!("{error}"),
        (Ok(()), Err(cleanup_error)) => panic!("{cleanup_error}"),
        (Err(error), Err(cleanup_error)) => {
            panic!("{error}；清理同时失败：{cleanup_error}")
        }
    }
}
