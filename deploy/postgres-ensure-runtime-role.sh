#!/bin/sh
set -eu

: "${PGHOST:?缺少 PGHOST}"
: "${PGPORT:?缺少 PGPORT}"
: "${PGDATABASE:?缺少 PGDATABASE}"
: "${PGUSER:?缺少 PGUSER}"
: "${PGPASSWORD:?缺少数据库 owner 密码}"
: "${PGSSLMODE:?缺少 PGSSLMODE}"
: "${PGSSLROOTCERT:?缺少 PGSSLROOTCERT}"
: "${MINDONE_POSTGRES_APP_PASSWORD:?缺少 runtime 数据库密码}"

# 必须在连接和任何数据库变更之前拒绝复用；错误只说明原因，不回显任一值。
if [ "${PGPASSWORD}" = "${MINDONE_POSTGRES_APP_PASSWORD}" ]; then
    echo "数据库 owner 与 runtime 密码不得相同，拒绝初始化 runtime role" >&2
    exit 1
fi

if [ "${PGSSLMODE}" != "verify-full" ]; then
    echo "runtime role 初始化只允许 PostgreSQL TLS verify-full" >&2
    exit 1
fi

if [ ! -f "${PGSSLROOTCERT}" ] || [ -L "${PGSSLROOTCERT}" ] || [ ! -r "${PGSSLROOTCERT}" ]; then
    echo "PostgreSQL CA 文件不可读，拒绝初始化 runtime role" >&2
    exit 1
fi

# \getenv 从环境读取密码，再由 :'app_password' 作为 SQL literal 安全引用。
# 密码不出现在 shell/psql argv，也不启用 echo。所有 DDL、密码轮换、属性与
# ACL/default ACL 刷新都处于一个事务；任一步失败会随连接退出整体回滚。
psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 <<'SQL'
\getenv app_password MINDONE_POSTGRES_APP_PASSWORD
BEGIN;
SELECT pg_advisory_xact_lock(1296649806, 1919907180);
SET LOCAL password_encryption = 'scram-sha-256';

DO $$
DECLARE
    database_owner NAME;
BEGIN
    SELECT pg_get_userbyid(datdba)
      INTO database_owner
      FROM pg_database
     WHERE datname = current_database();

    IF database_owner IS DISTINCT FROM current_user THEN
        RAISE EXCEPTION
            'runtime role initialization must be executed by the current database owner';
    END IF;

    IF current_user = 'mindone_app' THEN
        RAISE EXCEPTION 'runtime role cannot initialize itself';
    END IF;
END;
$$;

SELECT format(
    'CREATE ROLE mindone_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32 VALID UNTIL ''infinity'' PASSWORD %L',
    :'app_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app')
\gexec

SELECT format(
    'ALTER ROLE mindone_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 32 VALID UNTIL ''infinity'' PASSWORD %L',
    :'app_password'
)
\gexec
\unset app_password

ALTER ROLE mindone_app RESET ALL;

DO $$
DECLARE
    app_oid OID := (SELECT oid FROM pg_roles WHERE rolname = 'mindone_app');
    setting_database RECORD;
    membership RECORD;
BEGIN
    FOR setting_database IN
        SELECT database_role_setting.datname
          FROM pg_db_role_setting
          JOIN pg_database AS database_role_setting
            ON database_role_setting.oid = pg_db_role_setting.setdatabase
         WHERE pg_db_role_setting.setrole = app_oid
           AND pg_db_role_setting.setdatabase <> 0
    LOOP
        EXECUTE format(
            'ALTER ROLE mindone_app IN DATABASE %I RESET ALL',
            setting_database.datname
        );
    END LOOP;

    -- NOINHERIT 不能阻止 SET ROLE；清除 runtime 位于任一侧的所有成员边。
    FOR membership IN
        SELECT granted_role.rolname AS granted_role
          FROM pg_auth_members
          JOIN pg_roles AS granted_role
            ON granted_role.oid = pg_auth_members.roleid
         WHERE pg_auth_members.member = app_oid
    LOOP
        EXECUTE format('REVOKE %I FROM mindone_app', membership.granted_role);
    END LOOP;

    FOR membership IN
        SELECT member_role.rolname AS member_role
          FROM pg_auth_members
          JOIN pg_roles AS member_role
            ON member_role.oid = pg_auth_members.member
         WHERE pg_auth_members.roleid = app_oid
    LOOP
        EXECUTE format('REVOKE mindone_app FROM %I', membership.member_role);
    END LOOP;

    -- 自动 REASSIGN 可能把攻击者准备的对象交给 owner，因此 ownership 异常
    -- 必须失败关闭；外层事务会连同新密码和此前属性修改一起回滚。
    IF EXISTS (
        SELECT 1
          FROM pg_shdepend
         WHERE refclassid = 'pg_authid'::regclass
           AND refobjid = app_oid
           AND deptype = 'o'
    ) THEN
        RAISE EXCEPTION 'mindone_app owns database objects; refusing automatic reassignment';
    END IF;
END;
$$;

ALTER ROLE mindone_app SET search_path = pg_catalog, public;

-- 删除其他数据库上的 runtime direct grants；当前专用数据库只恢复 CONNECT。
DO $$
DECLARE
    target_database RECORD;
BEGIN
    FOR target_database IN SELECT datname FROM pg_database
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON DATABASE %I FROM mindone_app',
            target_database.datname
        );
        -- PUBLIC 权限会累加到 runtime；专用 cluster 必须先全部撤销，
        -- 再只为目标数据库恢复 mindone_app 的 direct CONNECT。
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON DATABASE %I FROM PUBLIC',
            target_database.datname
        );
    END LOOP;

    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO mindone_app',
        current_database()
    );
END;
$$;

-- 清除所有非系统 schema 中遗留的 runtime 直接 ACL 和当前 owner 的默认 ACL。
DO $$
DECLARE
    application_schema RECORD;
BEGIN
    FOR application_schema IN
        SELECT nspname
          FROM pg_namespace
         WHERE nspname <> 'information_schema'
           AND nspname !~ '^pg_'
    LOOP
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA %I FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA %I FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA %I FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL PRIVILEGES ON TABLES FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL PRIVILEGES ON SEQUENCES FROM mindone_app',
            application_schema.nspname
        );
        EXECUTE format(
            'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL PRIVILEGES ON FUNCTIONS FROM mindone_app',
            application_schema.nspname
        );
    END LOOP;
END;
$$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM mindone_app;
GRANT USAGE ON SCHEMA public TO mindone_app;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, mindone_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mindone_app;

-- 0032/0033/0035/0036/0037/0039 把不可变记录、SSE、SLA 审计、一次性令牌
-- 与推理 API Key 表
-- 收窄为精确
-- allowlist。上面的 blanket GRANT 用于普通业务表；每次 role-init
-- 都必须随后恢复 migration 已建立的更小权限，不能把它们放宽。
REVOKE ALL PRIVILEGES ON TABLE
    public.billing_profiles,
    public.physical_billing_legacy_allowlist,
    public.receipts,
    public.billing_profile_provision_audits,
    public.job_stream_events,
    public.sla_exclusion_events,
    public.email_verification_tokens,
    public.inference_api_keys,
    public.inference_api_key_events
FROM mindone_app;
GRANT SELECT ON TABLE
    public.billing_profiles,
    public.physical_billing_legacy_allowlist,
    public.billing_profile_provision_audits,
    public.sla_exclusion_events
TO mindone_app;
GRANT SELECT, INSERT ON TABLE
    public.receipts,
    public.job_stream_events,
    public.inference_api_key_events
TO mindone_app;
GRANT SELECT, INSERT, UPDATE ON TABLE
    public.email_verification_tokens,
    public.inference_api_keys
TO mindone_app;

REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, mindone_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mindone_app;

-- trigger 不要求 DML 调用者拥有 trigger function 的 EXECUTE。
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, mindone_app;
GRANT EXECUTE ON FUNCTION public.mindone_physical_billing_snapshot_is_valid_v1(
    TEXT,UUID,BIGINT,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,
    BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
    BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT
) TO mindone_app;
GRANT EXECUTE ON FUNCTION public.mindone_record_billing_profile_v1(
    UUID,UUID,UUID,BIGINT,TEXT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,BIGINT,
    BIGINT,BIGINT,TEXT,TIMESTAMPTZ,TIMESTAMPTZ,TEXT,TEXT,TEXT,TEXT
) TO mindone_app;
GRANT EXECUTE ON FUNCTION public.mindone_record_sla_exclusion_v1(
    UUID,UUID,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT
) TO mindone_app;

ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON TABLES FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON SEQUENCES FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON FUNCTIONS FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mindone_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO mindone_app;

-- Runtime 启动只读取迁移状态，不得写 SQLx migration 元数据。
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations FROM PUBLIC, mindone_app;
GRANT SELECT ON TABLE public._sqlx_migrations TO mindone_app;

DO $$
DECLARE
    app_oid OID := (SELECT oid FROM pg_roles WHERE rolname = 'mindone_app');
    role_is_safe BOOLEAN;
BEGIN
    SELECT rolcanlogin
       AND NOT rolsuper
       AND NOT rolcreatedb
       AND NOT rolcreaterole
       AND NOT rolinherit
       AND NOT rolreplication
       AND NOT rolbypassrls
       AND rolconnlimit = 32
       AND (rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'::timestamptz)
      INTO role_is_safe
      FROM pg_roles
     WHERE oid = app_oid;

    IF role_is_safe IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'mindone_app role attributes do not match the safe baseline';
    END IF;

    IF EXISTS (
        SELECT 1 FROM pg_auth_members
         WHERE roleid = app_oid OR member = app_oid
    ) THEN
        RAISE EXCEPTION 'mindone_app still has role membership edges';
    END IF;

    IF (
        SELECT count(*)
          FROM pg_db_role_setting
          CROSS JOIN LATERAL unnest(setconfig) AS configured(setting)
         WHERE setrole = app_oid
    ) <> 1 OR NOT EXISTS (
        SELECT 1
          FROM pg_db_role_setting
          CROSS JOIN LATERAL unnest(setconfig) AS configured(setting)
         WHERE setrole = app_oid
           AND setdatabase = 0
           AND configured.setting = 'search_path=pg_catalog, public'
    ) THEN
        RAISE EXCEPTION 'mindone_app has unexpected role settings';
    END IF;

    IF has_database_privilege('mindone_app', current_database(), 'CREATE')
       OR has_database_privilege('mindone_app', current_database(), 'TEMPORARY')
       OR has_schema_privilege('mindone_app', 'public', 'CREATE') THEN
        RAISE EXCEPTION 'mindone_app retains database or schema object-creation privileges';
    END IF;
END;
$$;

COMMIT;
SQL
