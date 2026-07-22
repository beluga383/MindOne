-- 协调器运行时不应使用 migration owner。本迁移提供固定的最小权限
-- fallback 角色；部署可事先为同名角色配置 LOGIN 和密码，迁移不得覆盖它们。
-- SQLx 默认在事务中执行 migration；事务级锁也与 role-init 共用，避免并发刷新
-- 角色和 ACL 时观察到半套策略。
SELECT pg_advisory_xact_lock(1296649806, 1919907180);

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
            'runtime role migration must be executed by the current database owner';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mindone_app') THEN
        CREATE ROLE mindone_app
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            NOBYPASSRLS
            CONNECTION LIMIT 32
            VALID UNTIL 'infinity';
    ELSE
        -- 故意不指定 LOGIN/NOLOGIN 或 PASSWORD，保留部署方的连接凭据。
        ALTER ROLE mindone_app
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOINHERIT
            NOREPLICATION
            NOBYPASSRLS
            CONNECTION LIMIT 32
            VALID UNTIL 'infinity';
    END IF;
END;
$$;

-- 先清除所有 cluster/database scope 的角色设置，再只保留固定安全搜索路径。
-- pg_catalog 必须位于 public 前；TEMP 会在下文从 PUBLIC 和 runtime 撤销。
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

    -- NOINHERIT 不能阻止 SET ROLE；runtime 不得位于成员关系任一侧。
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

    -- 自动改 owner 可能把攻击者准备的对象交给 migration owner，因此异常 ownership
    -- 必须令整个 migration 回滚，由运维者先审计和处置。
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

-- runtime 只能连接当前专用数据库；显式 direct grant 会先被清空。
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
        -- 数据库权限会经 PUBLIC 累加，只有撤销 PUBLIC 才能保证 runtime
        -- 不能连接其他数据库或在那里创建临时对象。此 migration 仅支持
        -- MindOne 专用 cluster；其他合法角色必须使用自己的 direct grant。
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

-- 清除当前数据库所有非系统 schema 中遗留的 runtime 直接授权。只有 public
-- 会在后面重新获得应用数据面权限。
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

        -- 清除 migration owner 在其他 application schema 留下的默认授权。
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

-- PUBLIC 不能创建 schema/临时表或借默认函数 EXECUTE 绕过表级合同。
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM mindone_app;
GRANT USAGE ON SCHEMA public TO mindone_app;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM PUBLIC, mindone_app;
GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public
    TO mindone_app;

REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, mindone_app;
GRANT USAGE, SELECT
    ON ALL SEQUENCES IN SCHEMA public
    TO mindone_app;

REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, mindone_app;

-- 先清除全局 default ACL，再只为 migration owner 的 public 新对象建立合同。
ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON TABLES FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON SEQUENCES FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE ALL PRIVILEGES ON FUNCTIONS FROM mindone_app;
ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mindone_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO mindone_app;

-- SQLx 迁移历史只允许运行时读取。
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations FROM PUBLIC, mindone_app;
GRANT SELECT ON TABLE public._sqlx_migrations TO mindone_app;

-- 最后在同一事务内验证角色基线；任一异常都会回滚上述全部变更。
DO $$
DECLARE
    app_oid OID := (SELECT oid FROM pg_roles WHERE rolname = 'mindone_app');
    role_is_safe BOOLEAN;
BEGIN
    SELECT NOT rolsuper
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
