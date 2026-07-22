use std::env;

use mindone_accounting::ReservePurpose;
use mindone_coordinator::{
    config::Config,
    db::{connect, migrate},
    operator_grant::{grant_operator_quota, OperatorQuotaGrantRequest},
    settlement::{release_reserve, ReserveReleaseCommand},
};
use serial_test::serial;
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::OffsetDateTime;
use uuid::Uuid;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn database_url_or_skip() -> Option<String> {
    match env::var("DATABASE_URL") {
        Ok(value) => Some(value),
        Err(_) if env::var("MINDONE_REQUIRE_POSTGRES_TESTS").as_deref() == Ok("1") => {
            panic!("账本链头 PostgreSQL 测试被强制启用但 DATABASE_URL 缺失")
        }
        Err(_) => {
            eprintln!("跳过账本链头 PostgreSQL 测试：未设置 DATABASE_URL");
            None
        }
    }
}

fn test_hash(label: &str, suffix: Uuid) -> String {
    let mut digest = Sha256::new();
    digest.update(label.as_bytes());
    digest.update(suffix.as_bytes());
    hex::encode(digest.finalize())
}

#[tokio::test]
#[serial]
async fn authoritative_heads_survive_backdated_commit_order_and_reject_forks() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接账本链头测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("账本链头迁移应成功");

    let suffix = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'ledger-head-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("subject-{suffix}"))
    .bind(format!("账本链头-{suffix}"))
    .execute(&pool)
    .await
    .expect("应创建测试用户");
    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("应创建测试额度账户");

    // T1 的 transaction timestamp 更早，但故意在 T2 提交后才取得账户锁并插入。
    let mut quota_t1 = pool.begin().await.expect("应开始 quota T1");
    let quota_t1_time: OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *quota_t1)
        .await
        .expect("应固定 quota T1 时间");
    let mut quota_t2 = pool.begin().await.expect("应开始 quota T2");
    let quota_t2_time: OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *quota_t2)
        .await
        .expect("应固定 quota T2 时间");
    assert!(quota_t1_time < quota_t2_time);

    sqlx::query("SELECT user_id FROM quota_accounts WHERE user_id=$1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *quota_t2)
        .await
        .expect("quota T2 应先取得账户锁");
    // ledger insert trigger 会自动更新 spendable_micro, head 和 count
    let quota_hash_t2: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',10,0,10,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-head-quota-t2-{suffix}"))
    .bind(GENESIS_HASH)
    .fetch_one(&mut *quota_t2)
    .await
    .expect("quota T2 应从 genesis 推进链头");
    quota_t2.commit().await.expect("quota T2 应先提交");

    let observed_head: String = sqlx::query_scalar(
        "SELECT quota_ledger_head_hash FROM quota_accounts WHERE user_id=$1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_one(&mut *quota_t1)
    .await
    .expect("quota T1 应看到 T2 已提交链头");
    assert_eq!(observed_head, quota_hash_t2);
    // ledger insert trigger 会自动更新 spendable_micro
    let quota_hash_t1: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',10,10,20,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-head-quota-t1-{suffix}"))
    .bind(&quota_hash_t2)
    .fetch_one(&mut *quota_t1)
    .await
    .expect("较早 timestamp 的 quota T1 仍应扩展真实链头");
    quota_t1.commit().await.expect("quota T1 应后提交");

    let grant = grant_operator_quota(
        &pool,
        &OperatorQuotaGrantRequest {
            user_id,
            amount_micro: 5,
            idempotency_key: format!("ledger-head-grant-{suffix}"),
            operator_id: "ops/ledger-head@example.com".to_owned(),
            reason: "验证权威账户链头不依赖事务时间排序".to_owned(),
        },
    )
    .await
    .expect("后续赠额应扩展 T1 链头");
    let grant_prev_hash: String =
        sqlx::query_scalar("SELECT prev_hash FROM quota_ledger WHERE id=$1")
            .bind(grant.quota_ledger_id)
            .fetch_one(&pool)
            .await
            .expect("应读取赠额前驱哈希");
    assert_eq!(grant_prev_hash, quota_hash_t1);
    let quota_account = sqlx::query(
        "SELECT spendable_micro,quota_ledger_head_hash,quota_ledger_entry_count FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应读取权威 quota 链头");
    assert_eq!(quota_account.get::<i64, _>("spendable_micro"), 25);
    assert_eq!(
        quota_account.get::<String, _>("quota_ledger_head_hash"),
        grant.quota_ledger_entry_hash
    );
    assert_eq!(quota_account.get::<i64, _>("quota_ledger_entry_count"), 3);

    // Reserve 使用同一逆序提交场景；最后的受控释放必须以前一笔真实后继为 prev。
    let mut reserve_t1 = pool.begin().await.expect("应开始 reserve T1");
    let reserve_t1_time: OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *reserve_t1)
        .await
        .expect("应固定 reserve T1 时间");
    let mut reserve_t2 = pool.begin().await.expect("应开始 reserve T2");
    let reserve_t2_time: OffsetDateTime = sqlx::query_scalar("SELECT transaction_timestamp()")
        .fetch_one(&mut *reserve_t2)
        .await
        .expect("应固定 reserve T2 时间");
    assert!(reserve_t1_time < reserve_t2_time);

    let reserve_before_t2 = sqlx::query(
        "SELECT balance_micro,ledger_head_hash,ledger_entry_count FROM reserve_accounts WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&mut *reserve_t2)
    .await
    .expect("reserve T2 应先取得账户锁");
    let reserve_balance_t2: i64 = reserve_before_t2.get("balance_micro");
    let reserve_prev_t2: String = reserve_before_t2.get("ledger_head_hash");
    let reserve_count_before_t2: i64 = reserve_before_t2.get("ledger_entry_count");
    // ledger insert trigger 会自动更新 balance_micro
    let reserve_hash_t2: String = sqlx::query_scalar(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',10,$2,$3,$4,$5,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve_balance_t2)
    .bind(reserve_balance_t2 + 10)
    .bind(format!("ledger-head-reserve-t2-{suffix}"))
    .bind(&reserve_prev_t2)
    .fetch_one(&mut *reserve_t2)
    .await
    .expect("reserve T2 应推进链头");
    reserve_t2.commit().await.expect("reserve T2 应先提交");

    let reserve_before_t1 = sqlx::query(
        "SELECT balance_micro,ledger_head_hash FROM reserve_accounts WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&mut *reserve_t1)
    .await
    .expect("reserve T1 应看到 T2 链头");
    let reserve_balance_t1: i64 = reserve_before_t1.get("balance_micro");
    assert_eq!(
        reserve_before_t1.get::<String, _>("ledger_head_hash"),
        reserve_hash_t2
    );
    // ledger insert trigger 会自动更新 balance_micro
    let reserve_hash_t1: String = sqlx::query_scalar(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',10,$2,$3,$4,$5,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve_balance_t1)
    .bind(reserve_balance_t1 + 10)
    .bind(format!("ledger-head-reserve-t1-{suffix}"))
    .bind(&reserve_hash_t2)
    .fetch_one(&mut *reserve_t1)
    .await
    .expect("较早 timestamp 的 reserve T1 仍应扩展真实链头");
    reserve_t1.commit().await.expect("reserve T1 应后提交");

    let released = release_reserve(
        &pool,
        ReserveReleaseCommand {
            purpose: ReservePurpose::ResultValidation,
            amount_micro: 1,
            reference_id: format!("ledger-head-verification:{suffix}"),
            idempotency_key: format!("ledger-head-release-{suffix}"),
            operator_id: "ops/ledger-head@example.com".to_owned(),
            reason: "验证准备金释放扩展权威链头而非时间排序结果".to_owned(),
        },
    )
    .await
    .expect("后续准备金释放应扩展 T1 链头");
    let release_prev_hash: String =
        sqlx::query_scalar("SELECT prev_hash FROM reserve_ledger WHERE id=$1")
            .bind(released.release_id)
            .fetch_one(&pool)
            .await
            .expect("应读取准备金释放前驱哈希");
    assert_eq!(release_prev_hash, reserve_hash_t1);
    // 验证 reserve 最终 head 和 count
    let reserve_account = sqlx::query(
        "SELECT balance_micro,ledger_head_hash,ledger_entry_count FROM reserve_accounts WHERE id=1",
    )
    .fetch_one(&pool)
    .await
    .expect("应读取权威 reserve 链头");
    assert_eq!(
        reserve_account.get::<String, _>("ledger_head_hash"),
        released.entry_hash
    );
    assert_eq!(
        reserve_account.get::<i64, _>("ledger_entry_count"),
        reserve_count_before_t2 + 3
    );

    // Contribution 的单一 successor 约束与 head trigger 必须拒绝 stale genesis 分叉，
    // 且失败事务不能留下余额或链头更新。
    let mut contribution = pool.begin().await.expect("应开始 contribution 事务");
    sqlx::query("SELECT user_id FROM quota_accounts WHERE user_id=$1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *contribution)
        .await
        .expect("应锁定 contribution 账户");
    // ledger insert trigger 会自动更新 contribution_micro
    let contribution_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',1,0,1,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-head-contribution-first-{suffix}"))
    .bind(GENESIS_HASH)
    .fetch_one(&mut *contribution)
    .await
    .expect("第一笔 contribution 应推进链头");
    contribution
        .commit()
        .await
        .expect("第一笔 contribution 应提交");

    let mut fork = pool.begin().await.expect("应开始 stale fork 事务");
    // 尝试插入 stale prev_hash，trigger 应拒绝
    let fork_result = sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',1,1,2,$3,$4,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("ledger-head-contribution-fork-{suffix}"))
    .bind(GENESIS_HASH)
    .execute(&mut *fork)
    .await;
    assert!(fork_result.is_err(), "stale prev_hash 必须被数据库拒绝");
    fork.rollback().await.expect("失败分叉事务应回滚");
    let contribution_account = sqlx::query(
        "SELECT contribution_micro,contribution_ledger_head_hash,contribution_ledger_entry_count FROM quota_accounts WHERE user_id=$1",
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应读取 contribution 权威链头");
    assert_eq!(contribution_account.get::<i64, _>("contribution_micro"), 1);
    assert_eq!(
        contribution_account.get::<String, _>("contribution_ledger_head_hash"),
        contribution_hash
    );
    assert_eq!(
        contribution_account.get::<i64, _>("contribution_ledger_entry_count"),
        1
    );
}

#[tokio::test]
#[serial]
async fn ledger_triggers_reject_wrong_before_genesis_and_direct_tracked_updates() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接账本负面测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("账本负面测试迁移应成功");

    let suffix = Uuid::now_v7();
    let user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'ledger-guard-test',$2,$3)",
    )
    .bind(user_id)
    .bind(format!("guard-subject-{suffix}"))
    .bind(format!("账本守卫-{suffix}"))
    .execute(&pool)
    .await
    .expect("应创建账本守卫用户");
    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("零余额账户应允许创建");

    let quota_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',10,0,10,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-quota-seed-{suffix}"))
    .bind(GENESIS_HASH)
    .fetch_one(&pool)
    .await
    .expect("quota seed 应由 trigger 推进余额与 head");

    let contribution_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',2,0,2,$3,$4,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-contribution-seed-{suffix}"))
    .bind(GENESIS_HASH)
    .fetch_one(&pool)
    .await
    .expect("contribution seed 应由 trigger 推进余额与 head");

    let mut reserve_seed = pool.begin().await.expect("应开始 reserve seed 事务");
    let reserve_before = sqlx::query(
        "SELECT balance_micro,ledger_head_hash,ledger_entry_count FROM reserve_accounts WHERE id=1 FOR UPDATE",
    )
    .fetch_one(&mut *reserve_seed)
    .await
    .expect("应锁定 reserve 账户");
    let reserve_balance_before: i64 = reserve_before.get("balance_micro");
    let reserve_head_before: String = reserve_before.get("ledger_head_hash");
    let reserve_count_before: i64 = reserve_before.get("ledger_entry_count");
    let reserve_hash: String = sqlx::query_scalar(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',10,$2,$3,$4,$5,NULL)
        RETURNING entry_hash
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve_balance_before)
    .bind(reserve_balance_before + 10)
    .bind(format!("guard-reserve-seed-{suffix}"))
    .bind(&reserve_head_before)
    .fetch_one(&mut *reserve_seed)
    .await
    .expect("reserve seed 应由 trigger 推进余额与 head");
    reserve_seed.commit().await.expect("reserve seed 应提交");
    let reserve_balance = reserve_balance_before + 10;

    // 三类错误记录都保持算术与 after=当前余额成立，只让 before 与真实前驱断开；
    // 旧 trigger 会接受，新的权威 writer 必须逐类拒绝。
    let wrong_quota_before = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',1,9,10,$3,$4,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-quota-wrong-before-{suffix}"))
    .bind(&quota_hash)
    .execute(&pool)
    .await;
    assert!(
        wrong_quota_before.is_err(),
        "quota balance_before 数值断链必须拒绝"
    );

    let wrong_contribution_before = sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',1,1,2,$3,$4,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-contribution-wrong-before-{suffix}"))
    .bind(&contribution_hash)
    .execute(&pool)
    .await;
    assert!(
        wrong_contribution_before.is_err(),
        "contribution balance_before 数值断链必须拒绝"
    );

    let wrong_reserve_before = sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',1,$2,$3,$4,$5,NULL)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve_balance - 1)
    .bind(reserve_balance)
    .bind(format!("guard-reserve-wrong-before-{suffix}"))
    .bind(&reserve_hash)
    .execute(&pool)
    .await;
    assert!(
        wrong_reserve_before.is_err(),
        "reserve balance_before 数值断链必须拒绝"
    );

    let quota_genesis = sqlx::query(
        r#"
        INSERT INTO quota_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'operator_grant',1,10,11,$3,$4,$5)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-quota-genesis-{suffix}"))
    .bind(&quota_hash)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;
    assert!(quota_genesis.is_err(), "quota entry_hash 不得复用 genesis");

    let contribution_genesis = sqlx::query(
        r#"
        INSERT INTO contribution_ledger
            (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,$2,NULL,'node_contribution',1,2,3,$3,$4,$5)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind(format!("guard-contribution-genesis-{suffix}"))
    .bind(&contribution_hash)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;
    assert!(
        contribution_genesis.is_err(),
        "contribution entry_hash 不得复用 genesis"
    );

    let reserve_genesis = sqlx::query(
        r#"
        INSERT INTO reserve_ledger
            (id,request_id,entry_type,delta_micro,balance_before_micro,
             balance_after_micro,idempotency_key,prev_hash,entry_hash)
        VALUES ($1,NULL,'settlement_inflow',1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(reserve_balance)
    .bind(reserve_balance + 1)
    .bind(format!("guard-reserve-genesis-{suffix}"))
    .bind(&reserve_hash)
    .bind(GENESIS_HASH)
    .execute(&pool)
    .await;
    assert!(
        reserve_genesis.is_err(),
        "reserve entry_hash 不得复用 genesis"
    );

    assert!(
        sqlx::query("UPDATE quota_accounts SET spendable_micro=spendable_micro+1 WHERE user_id=$1")
            .bind(user_id)
            .execute(&pool)
            .await
            .is_err(),
        "直接修改 spendable 必须拒绝"
    );
    assert!(
        sqlx::query(
            "UPDATE quota_accounts SET contribution_micro=contribution_micro+1 WHERE user_id=$1"
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .is_err(),
        "直接修改 contribution 必须拒绝"
    );
    assert!(
        sqlx::query(
            "UPDATE quota_accounts SET quota_ledger_head_hash=$2,quota_ledger_entry_count=quota_ledger_entry_count+1 WHERE user_id=$1",
        )
        .bind(user_id)
        .bind(test_hash("guard-direct-quota-head", suffix))
        .execute(&pool)
        .await
        .is_err(),
        "直接修改 quota head/count 必须拒绝"
    );
    assert!(
        sqlx::query(
            "UPDATE quota_accounts SET contribution_ledger_head_hash=$2,contribution_ledger_entry_count=contribution_ledger_entry_count+1 WHERE user_id=$1",
        )
        .bind(user_id)
        .bind(test_hash("guard-direct-contribution-head", suffix))
        .execute(&pool)
        .await
        .is_err(),
        "直接修改 contribution head/count 必须拒绝"
    );
    assert!(
        sqlx::query("UPDATE reserve_accounts SET balance_micro=balance_micro+1 WHERE id=1")
            .execute(&pool)
            .await
            .is_err(),
        "直接修改 reserve balance 必须拒绝"
    );
    assert!(
        sqlx::query(
            "UPDATE reserve_accounts SET ledger_head_hash=$1,ledger_entry_count=ledger_entry_count+1 WHERE id=1",
        )
        .bind(test_hash("guard-direct-reserve-head", suffix))
        .execute(&pool)
        .await
        .is_err(),
        "直接修改 reserve head/count 必须拒绝"
    );

    let account = sqlx::query(
        r#"
        SELECT spendable_micro,contribution_micro,quota_ledger_head_hash,
               quota_ledger_entry_count,contribution_ledger_head_hash,
               contribution_ledger_entry_count
        FROM quota_accounts WHERE user_id=$1
        "#,
    )
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("应读取未被负面 SQL 改动的 quota 账户");
    assert_eq!(account.get::<i64, _>("spendable_micro"), 10);
    assert_eq!(account.get::<i64, _>("contribution_micro"), 2);
    assert_eq!(
        account.get::<String, _>("quota_ledger_head_hash"),
        quota_hash
    );
    assert_eq!(account.get::<i64, _>("quota_ledger_entry_count"), 1);
    assert_eq!(
        account.get::<String, _>("contribution_ledger_head_hash"),
        contribution_hash
    );
    assert_eq!(account.get::<i64, _>("contribution_ledger_entry_count"), 1);
    let reserve = sqlx::query(
        "SELECT balance_micro,ledger_head_hash,ledger_entry_count FROM reserve_accounts WHERE id=1",
    )
    .fetch_one(&pool)
    .await
    .expect("应读取未被负面 SQL 改动的 reserve 账户");
    assert_eq!(reserve.get::<i64, _>("balance_micro"), reserve_balance);
    assert_eq!(reserve.get::<String, _>("ledger_head_hash"), reserve_hash);
    assert_eq!(
        reserve.get::<i64, _>("ledger_entry_count"),
        reserve_count_before + 1
    );
}

#[tokio::test]
#[serial]
async fn account_guards_reject_nonzero_insert_delete_and_orphan_ledgers() {
    let Some(database_url) = database_url_or_skip() else {
        return;
    };
    let config = Config::development_for_tests(database_url);
    let pool = connect(&config).await.expect("应能连接账户守卫测试数据库");
    migrate(&pool, &config.standard_data_key)
        .await
        .expect("账户守卫测试迁移应成功");

    let suffix = Uuid::now_v7();
    let orphan_user = Uuid::now_v7();
    let spendable_user = Uuid::now_v7();
    let contribution_user = Uuid::now_v7();
    let forged_head_user = Uuid::now_v7();
    let deletable_user = Uuid::now_v7();
    for (user_id, label) in [
        (orphan_user, "orphan"),
        (spendable_user, "spendable"),
        (contribution_user, "contribution"),
        (forged_head_user, "forged-head"),
        (deletable_user, "delete"),
    ] {
        sqlx::query(
            "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,'ledger-account-guard',$2,$3)",
        )
        .bind(user_id)
        .bind(format!("account-guard-{label}-{suffix}"))
        .bind(format!("账户守卫-{label}-{suffix}"))
        .execute(&pool)
        .await
        .expect("应创建账户守卫用户");
    }

    assert!(
        sqlx::query("INSERT INTO quota_accounts (user_id,spendable_micro) VALUES ($1,1)")
            .bind(spendable_user)
            .execute(&pool)
            .await
            .is_err(),
        "新 quota account 不得绕过 ledger 携带 spendable"
    );
    assert!(
        sqlx::query("INSERT INTO quota_accounts (user_id,contribution_micro) VALUES ($1,1)")
            .bind(contribution_user)
            .execute(&pool)
            .await
            .is_err(),
        "新 quota account 不得绕过 ledger 携带 contribution"
    );
    assert!(
        sqlx::query(
            r#"
            INSERT INTO quota_accounts
                (user_id,quota_ledger_head_hash,quota_ledger_entry_count)
            VALUES ($1,$2,1)
            "#,
        )
        .bind(forged_head_user)
        .bind(test_hash("forged-account-head", suffix))
        .execute(&pool)
        .await
        .is_err(),
        "新 quota account 不得伪造非 genesis head"
    );

    let forged_reserve = sqlx::query(
        r#"
        INSERT INTO reserve_accounts (id,balance_micro,ledger_head_hash,ledger_entry_count)
        VALUES (1,1,$1,1)
        "#,
    )
    .bind(test_hash("forged-reserve-account", suffix))
    .execute(&pool)
    .await;
    let reserve_guard_message = match forged_reserve {
        Err(sqlx::Error::Database(error)) => error.message().to_owned(),
        Err(error) => panic!("reserve 非零 INSERT 应返回数据库守卫错误：{error}"),
        Ok(_) => panic!("reserve singleton 不得绕过 ledger 携带余额"),
    };
    assert!(
        reserve_guard_message.contains("reserve account must start from zero ledger genesis"),
        "必须由 reserve INSERT guard 拒绝，而不是只依赖主键冲突：{reserve_guard_message}"
    );

    let orphan_hash = test_hash("orphan-quota", suffix);
    assert!(
        sqlx::query(
            r#"
            INSERT INTO quota_ledger
                (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
                 balance_after_micro,idempotency_key,prev_hash,entry_hash)
            VALUES ($1,$2,NULL,'operator_grant',1,0,1,$3,$4,$5)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(orphan_user)
        .bind(format!("orphan-quota-{suffix}"))
        .bind(GENESIS_HASH)
        .bind(&orphan_hash)
        .execute(&pool)
        .await
        .is_err(),
        "没有 quota account 的 quota ledger 必须拒绝"
    );
    assert!(
        sqlx::query(
            r#"
            INSERT INTO contribution_ledger
                (id,user_id,request_id,entry_type,delta_micro,balance_before_micro,
                 balance_after_micro,idempotency_key,prev_hash,entry_hash)
            VALUES ($1,$2,NULL,'node_contribution',1,0,1,$3,$4,$5)
            "#,
        )
        .bind(Uuid::now_v7())
        .bind(orphan_user)
        .bind(format!("orphan-contribution-{suffix}"))
        .bind(GENESIS_HASH)
        .bind(test_hash("orphan-contribution", suffix))
        .execute(&pool)
        .await
        .is_err(),
        "没有 quota account 的 contribution ledger 必须拒绝"
    );
    let account_fk_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM pg_constraint
        WHERE conname IN ('quota_ledger_account_fk','contribution_ledger_account_fk')
          AND contype='f'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("应能查询 ledger account FK");
    assert_eq!(
        account_fk_count, 2,
        "两类用户 ledger 都必须绑定 quota account"
    );

    sqlx::query("INSERT INTO quota_accounts (user_id) VALUES ($1)")
        .bind(deletable_user)
        .execute(&pool)
        .await
        .expect("应创建零余额删除守卫账户");
    assert!(
        sqlx::query("UPDATE quota_accounts SET user_id=$2 WHERE user_id=$1")
            .bind(deletable_user)
            .bind(orphan_user)
            .execute(&pool)
            .await
            .is_err(),
        "即使没有 ledger，quota account 身份也不得直接改写"
    );
    assert!(
        sqlx::query("DELETE FROM quota_accounts WHERE user_id=$1")
            .bind(deletable_user)
            .execute(&pool)
            .await
            .is_err(),
        "即使没有 ledger，quota account 也不得直接删除"
    );
    assert!(
        sqlx::query("DELETE FROM reserve_accounts WHERE id=1")
            .execute(&pool)
            .await
            .is_err(),
        "reserve singleton 不得直接删除"
    );
}
