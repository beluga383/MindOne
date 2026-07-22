use std::{collections::BTreeMap, env};

use mindone_accounting::{LedgerEntry, LedgerKind};
use mindone_coordinator::{
    config::Config,
    db::{connect, migrate},
    operator_grant::{grant_operator_quota, OperatorQuotaGrantRequest},
};
use serial_test::serial;
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn metadata_json(metadata: &BTreeMap<String, String>) -> serde_json::Value {
    serde_json::Value::Object(
        metadata
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect(),
    )
}

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("账本完整性 PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过账本完整性 PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

#[tokio::test]
#[serial]
async fn trigger_rejects_wrong_prev_hash() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 尝试插入 prev_hash 不匹配的 ledger
    let wrong_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let result = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',100,0,100,'test-wrong-prev',$3,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(wrong_hash)
    .execute(&pool)
    .await;

    assert!(result.is_err(), "错误的 prev_hash 必须被 trigger 拒绝");

    // 验证账户余额未被修改
    let balance: i64 =
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("应能读取余额");
    assert_eq!(balance, 0, "失败的 ledger insert 不应修改余额");
}

#[tokio::test]
#[serial]
async fn trigger_rejects_wrong_balance_before() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 尝试插入 balance_before 不等于当前余额的 ledger
    let result = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',100,999,1099,'test-wrong-before',$3,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;

    assert!(result.is_err(), "错误的 balance_before 必须被 trigger 拒绝");

    // 验证账户余额未被修改
    let balance: i64 =
        sqlx::query_scalar("SELECT spendable_micro FROM quota_accounts WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("应能读取余额");
    assert_eq!(balance, 0, "失败的 ledger insert 不应修改余额");
}

#[tokio::test]
#[serial]
async fn trigger_rejects_genesis_hash_reuse() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 尝试插入 entry_hash 等于 genesis 的 ledger
    let result = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',100,0,100,'test-genesis-reuse',$3,$3)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "复用 genesis hash 作为 entry_hash 必须被拒绝"
    );
}

#[tokio::test]
#[serial]
async fn trigger_rejects_negative_balance() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 尝试插入会导致负余额的 ledger
    let result = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'consumer_deduction',-100,0,-100,'test-negative',$3,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;

    assert!(result.is_err(), "导致负余额的 ledger 必须被拒绝");
}

#[tokio::test]
#[serial]
async fn guard_trigger_blocks_direct_balance_update() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 尝试直接更新 spendable_micro
    let result = sqlx::query("UPDATE quota_accounts SET spendable_micro = 1000 WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "直接更新 spendable_micro 必须被 guard trigger 拒绝"
    );

    // 尝试直接更新 contribution_micro
    let result =
        sqlx::query("UPDATE quota_accounts SET contribution_micro = 500 WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;

    assert!(
        result.is_err(),
        "直接更新 contribution_micro 必须被 guard trigger 拒绝"
    );

    // 尝试直接更新 quota_ledger_head_hash
    let result = sqlx::query("UPDATE quota_accounts SET quota_ledger_head_hash = 'aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab' WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "直接更新 quota_ledger_head_hash 必须被 guard trigger 拒绝"
    );

    // 尝试直接更新 quota_ledger_entry_count
    let result =
        sqlx::query("UPDATE quota_accounts SET quota_ledger_entry_count = 10 WHERE user_id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;

    assert!(
        result.is_err(),
        "直接更新 quota_ledger_entry_count 必须被 guard trigger 拒绝"
    );
}

#[tokio::test]
#[serial]
async fn guard_trigger_blocks_direct_reserve_balance_update() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    // 尝试直接更新 reserve balance_micro
    let result = sqlx::query("UPDATE reserve_accounts SET balance_micro = 999999 WHERE id = 1")
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "直接更新 reserve balance_micro 必须被 guard trigger 拒绝"
    );

    // 尝试直接更新 reserve ledger_head_hash
    let result = sqlx::query("UPDATE reserve_accounts SET ledger_head_hash = 'bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab' WHERE id = 1")
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "直接更新 reserve ledger_head_hash 必须被 guard trigger 拒绝"
    );

    // 尝试直接更新 reserve ledger_entry_count
    let result = sqlx::query("UPDATE reserve_accounts SET ledger_entry_count = 50 WHERE id = 1")
        .execute(&pool)
        .await;

    assert!(
        result.is_err(),
        "直接更新 reserve ledger_entry_count 必须被 guard trigger 拒绝"
    );
}

#[tokio::test]
#[serial]
async fn guard_trigger_allows_reserved_micro_update() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    let _funding_hash: String = sqlx::query_scalar(
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
    .bind(format!("test-reserved-funding-{user_id}"))
    .bind(GENESIS_HASH)
    .fetch_one(&pool)
    .await
    .expect("应先通过账本增加可用额度");

    // reserved_micro 不是 ledger tracked balance，且不超过 spendable 时应可直接更新
    let result = sqlx::query("UPDATE quota_accounts SET reserved_micro = 500 WHERE user_id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;

    assert!(
        result.is_ok(),
        "reserved_micro 应允许直接更新（不是 ledger tracked balance）"
    );

    let reserved: i64 =
        sqlx::query_scalar("SELECT reserved_micro FROM quota_accounts WHERE user_id=$1")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("应能读取 reserved_micro");
    assert_eq!(reserved, 500);
}

#[tokio::test]
#[serial]
async fn trigger_updates_balance_head_count_atomically() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'integrity-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{user_id}"))
    .bind("测试用户")
    .execute(&pool)
    .await
    .expect("应创建用户");

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建账户");

    // 插入第一笔 ledger
    let entry_hash_1: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',100,0,100,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("test-atomic-1-{user_id}"))
    .bind(GENESIS_HASH)
    .fetch_one(&pool)
    .await
    .expect("应能插入第一笔 ledger");

    // 验证 trigger 自动更新了余额、head 和 count
    let account = sqlx::query(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count FROM quota_accounts WHERE user_id=$1"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应能读取账户");

    assert_eq!(account.get::<i64, _>("spendable_micro"), 100);
    assert_eq!(
        account.get::<String, _>("quota_ledger_head_hash"),
        entry_hash_1
    );
    assert_eq!(account.get::<i64, _>("quota_ledger_entry_count"), 1);

    // 插入第二笔 ledger
    let entry_hash_2: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',50,100,150,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("test-atomic-2-{user_id}"))
    .bind(&entry_hash_1)
    .fetch_one(&pool)
    .await
    .expect("应能插入第二笔 ledger");

    // 验证 trigger 原子更新
    let account = sqlx::query(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count FROM quota_accounts WHERE user_id=$1"
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应能读取账户");

    assert_eq!(account.get::<i64, _>("spendable_micro"), 150);
    assert_eq!(
        account.get::<String, _>("quota_ledger_head_hash"),
        entry_hash_2
    );
    assert_eq!(account.get::<i64, _>("quota_ledger_entry_count"), 2);
}

#[tokio::test]
#[serial]
async fn foreign_key_prevents_orphan_ledger() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("迁移应成功");

    let nonexistent_user = Uuid::now_v7();

    // 尝试插入指向不存在账户的 quota_ledger
    let result = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',100,0,100,'test-orphan',$3,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(nonexistent_user)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "指向不存在账户的 quota_ledger 必须被外键约束拒绝"
    );

    // 尝试插入指向不存在账户的 contribution_ledger
    let result = sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',50,0,50,'test-orphan-contrib',$3,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(nonexistent_user)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "指向不存在账户的 contribution_ledger 必须被外键约束拒绝"
    );
}

#[tokio::test]
#[serial]
async fn canonical_v2_covers_all_persisted_fields_and_rejects_forgery() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config)
        .await
        .expect("应能连接 canonical 账本测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("canonical 账本迁移应成功");

    let suffix = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) \
         VALUES ($1,'canonical-ledger-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("canonical-{suffix}"))
    .bind(format!("Canonical 账本-{suffix}"))
    .execute(&pool)
    .await
    .expect("应创建 canonical 测试用户");
    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建 canonical 测试账户");

    let quota_metadata = BTreeMap::from([
        ("operator_id".to_owned(), "ops/账本@example.com".to_owned()),
        ("reason".to_owned(), "包含冒号:和多字节文本".to_owned()),
    ]);
    let quota = LedgerEntry::new(
        Uuid::now_v7(),
        user_id,
        None,
        format!("canonical-quota-{suffix}"),
        LedgerKind::OperatorGrant,
        100,
        0,
        100,
        OffsetDateTime::now_utc(),
        GENESIS_HASH,
        quota_metadata.clone(),
    )
    .expect("Rust 应生成 quota canonical 记录");
    sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(quota.id)
    .bind(user_id)
    .bind(quota.amount_micro)
    .bind(quota.balance_before_micro)
    .bind(quota.balance_after_micro)
    .bind(&quota.idempotency_key)
    .bind(&quota.previous_hash)
    .bind(&quota.hash)
    .bind(quota.hash_version)
    .bind(metadata_json(&quota.metadata))
    .bind(quota.created_at)
    .execute(&pool)
    .await
    .expect("Rust 与 PostgreSQL 的 quota canonical hash 必须一致");

    let contribution = LedgerEntry::new(
        Uuid::now_v7(),
        user_id,
        None,
        format!("canonical-contribution-{suffix}"),
        LedgerKind::ContributionCredit,
        7,
        0,
        7,
        OffsetDateTime::now_utc(),
        GENESIS_HASH,
        BTreeMap::from([("source".to_owned(), "settlement:test".to_owned())]),
    )
    .expect("Rust 应生成 contribution canonical 记录");
    sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'node_contribution',$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(contribution.id)
    .bind(user_id)
    .bind(contribution.amount_micro)
    .bind(contribution.balance_before_micro)
    .bind(contribution.balance_after_micro)
    .bind(&contribution.idempotency_key)
    .bind(&contribution.previous_hash)
    .bind(&contribution.hash)
    .bind(contribution.hash_version)
    .bind(metadata_json(&contribution.metadata))
    .bind(contribution.created_at)
    .execute(&pool)
    .await
    .expect("Rust 与 PostgreSQL 的 contribution canonical hash 必须一致");

    let reserve_state = sqlx::query(
        "SELECT balance_micro,ledger_head_hash FROM reserve_accounts WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&pool)
    .await
    .expect("应读取准备金链头");
    let reserve_before: i64 = reserve_state.get("balance_micro");
    let reserve_prev: String = reserve_state.get("ledger_head_hash");
    let reserve = LedgerEntry::new(
        Uuid::now_v7(),
        Uuid::from_u128(1),
        None,
        format!("canonical-reserve-{suffix}"),
        LedgerKind::ReserveInflow,
        9,
        reserve_before,
        reserve_before + 9,
        OffsetDateTime::now_utc(),
        reserve_prev,
        BTreeMap::new(),
    )
    .expect("Rust 应生成 reserve canonical 记录");
    sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,NULL,'settlement_inflow',$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(reserve.id)
    .bind(reserve.amount_micro)
    .bind(reserve.balance_before_micro)
    .bind(reserve.balance_after_micro)
    .bind(&reserve.idempotency_key)
    .bind(&reserve.previous_hash)
    .bind(&reserve.hash)
    .bind(reserve.hash_version)
    .bind(metadata_json(&reserve.metadata))
    .bind(reserve.created_at)
    .execute(&pool)
    .await
    .expect("Rust 与 PostgreSQL 的 reserve canonical hash 必须一致");

    let persisted: (i16, bool, bool) = sqlx::query_as(
        "SELECT hash_version,metadata=$2,entry_hash=$3 FROM quota_ledger WHERE id=$1",
    )
    .bind(quota.id)
    .bind(metadata_json(&quota_metadata))
    .bind(&quota.hash)
    .fetch_one(&pool)
    .await
    .expect("应读取持久化 canonical 字段");
    assert_eq!(persisted, (2, true, true));

    let next_quota = LedgerEntry::new(
        Uuid::now_v7(),
        user_id,
        None,
        format!("canonical-next-{suffix}"),
        LedgerKind::OperatorGrant,
        1,
        100,
        101,
        OffsetDateTime::now_utc(),
        &quota.hash,
        BTreeMap::from([("proof".to_owned(), "original".to_owned())]),
    )
    .expect("应生成待篡改的 canonical 记录");
    let arbitrary_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let arbitrary_quota = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',1,100,101,$3,$4,$5,2,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(&next_quota.previous_hash)
    .bind(arbitrary_hash)
    .bind(metadata_json(&next_quota.metadata))
    .bind(next_quota.created_at)
    .execute(&pool)
    .await;
    assert!(arbitrary_quota.is_err(), "quota 任意 64hex 必须拒绝");

    let arbitrary_contribution = sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',1,7,8,$3,$4,$5)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("canonical-forged-contribution-{suffix}"))
    .bind(&contribution.hash)
    .bind("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .execute(&pool)
    .await;
    assert!(
        arbitrary_contribution.is_err(),
        "contribution 任意 64hex 必须拒绝"
    );

    let arbitrary_reserve = sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve.balance_after_micro)
    .bind(reserve.balance_after_micro + 1)
    .bind(format!("canonical-forged-reserve-{suffix}"))
    .bind(&reserve.hash)
    .bind("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    .execute(&pool)
    .await;
    assert!(arbitrary_reserve.is_err(), "reserve 任意 64hex 必须拒绝");

    let changed_fields = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',2,100,102,$3,$4,$5,2,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(&next_quota.previous_hash)
    .bind(&next_quota.hash)
    .bind(metadata_json(&next_quota.metadata))
    .bind(next_quota.created_at)
    .execute(&pool)
    .await;
    assert!(changed_fields.is_err(), "改写金额/余额字段必须拒绝");

    let changed_metadata = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',1,100,101,$3,$4,$5,2,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(&next_quota.previous_hash)
    .bind(&next_quota.hash)
    .bind(serde_json::json!({"proof":"tampered"}))
    .bind(next_quota.created_at)
    .execute(&pool)
    .await;
    assert!(changed_metadata.is_err(), "改写 metadata 必须拒绝");

    let changed_time = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',1,100,101,$3,$4,$5,2,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(&next_quota.previous_hash)
    .bind(&next_quota.hash)
    .bind(metadata_json(&next_quota.metadata))
    .bind(next_quota.created_at + time::Duration::seconds(1))
    .execute(&pool)
    .await;
    assert!(changed_time.is_err(), "改写 created_at 必须拒绝");

    let changed_prev = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',1,100,101,$3,$4,$5,2,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(GENESIS_HASH)
    .bind(&next_quota.hash)
    .bind(metadata_json(&next_quota.metadata))
    .bind(next_quota.created_at)
    .execute(&pool)
    .await;
    assert!(changed_prev.is_err(), "改写 prev_hash 必须拒绝");

    let legacy_insert = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash,hash_version,
             metadata,created_at)
        VALUES ($1,$2,NULL,'operator_grant',1,100,101,$3,$4,$5,1,$6,$7)
        "#,
    )
    .bind(next_quota.id)
    .bind(user_id)
    .bind(&next_quota.idempotency_key)
    .bind(&next_quota.previous_hash)
    .bind(&next_quota.hash)
    .bind(metadata_json(&next_quota.metadata))
    .bind(next_quota.created_at)
    .execute(&pool)
    .await;
    assert!(legacy_insert.is_err(), "新增 legacy v1 行必须拒绝");

    let unchanged: (i64, String, i64) = sqlx::query_as(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count \
         FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应读取伪造失败后的 quota 状态");
    assert_eq!(unchanged, (100, quota.hash.clone(), 1));

    let grant_request = OperatorQuotaGrantRequest {
        user_id,
        amount_micro: 5,
        idempotency_key: format!("canonical-idempotent-{suffix}"),
        operator_id: "ops/canonical@example.com".to_owned(),
        reason: "验证 canonical 赠额的幂等重放不会追加第二行".to_owned(),
    };
    let first = grant_operator_quota(&pool, &grant_request)
        .await
        .expect("第一次 canonical 赠额应成功");
    let replay = grant_operator_quota(&pool, &grant_request)
        .await
        .expect("相同 canonical 赠额应幂等重放");
    assert!(!first.idempotent_replay);
    assert!(replay.idempotent_replay);
    assert_eq!(first.quota_ledger_id, replay.quota_ledger_id);
    assert_eq!(
        first.quota_ledger_entry_hash,
        replay.quota_ledger_entry_hash
    );
    let final_account: (i64, String, i64) = sqlx::query_as(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count \
         FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应读取幂等赠额后的 quota 状态");
    assert_eq!(
        final_account,
        (105, first.quota_ledger_entry_hash.clone(), 2)
    );
}
