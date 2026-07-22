use axum::http::{header::AUTHORIZATION, HeaderMap};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use subtle::ConstantTimeEq;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    auth::{Principal, TokenService},
    config::{Config, PrivateEvaluationHmacKey},
    error::ApiError,
    private_evaluation_catalog::load_private_evaluation_catalog,
    PrivateEvaluationRuntimeSecurity,
};

include!(concat!(env!("OUT_DIR"), "/embedded_migrations.rs"));

const PRIVATE_HMAC_STATE_LOCK_NAMESPACE: i32 = 0x4d4f_5048;
const PRIVATE_HMAC_STATE_LOCK_KEY: i32 = 0x4b45_5931;
const PRIVATE_HMAC_KEY_COMMITMENT_DOMAIN: &[u8] = b"mindone:private-hidden:hmac-key-state:v1\0";

pub async fn connect(config: &Config) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_database_connections)
        .acquire_timeout(config.database_acquire_timeout)
        .connect(&config.database_url)
        .await
}

pub async fn migrate(
    pool: &PgPool,
    standard_data_key: &[u8; 32],
) -> Result<(), crate::standard_data::StandardDataMigrationError> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(crate::standard_data::StandardDataMigrationError::Schema)?;
    crate::standard_data::migrate_legacy_rows(pool, standard_data_key).await
}

#[derive(Error)]
pub enum RuntimePrepareError {
    #[error("数据库结构校验失败：迁移记录表缺失、不可读或连接无权读取")]
    SchemaUnavailable(#[source] sqlx::Error),
    #[error("数据库结构校验失败：迁移记录与当前程序内嵌结构不一致")]
    SchemaDrift,
    #[error("Standard 数据静态保护迁移失败")]
    StandardData(#[from] crate::standard_data::StandardDataMigrationError),
}

impl std::fmt::Debug for RuntimePrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

/// 校验 owner 已经完整应用当前程序内嵌的结构，然后执行允许 runtime 账号运行的数据升级。
///
/// 此路径不会创建或修改数据库结构；缺表、缺版本、额外版本、失败记录、描述或 checksum
/// 不一致都会在运行任何 Standard 数据升级前失败关闭。
pub async fn prepare_runtime(
    pool: &PgPool,
    standard_data_key: &[u8; 32],
) -> Result<(), RuntimePrepareError> {
    verify_runtime_schema(pool).await?;
    crate::standard_data::migrate_legacy_rows(pool, standard_data_key).await?;
    Ok(())
}

#[derive(Error)]
pub enum PrivateEvaluationRuntimePrepareError {
    #[error("private-hidden 启动校验无法读取或写入数据库")]
    Database(#[source] sqlx::Error),
    #[error("private-hidden 已启用或数据库已有 v2 状态，但未配置独立 HMAC 密钥文件")]
    MissingHmacKey,
    #[error("真实 private-hidden catalog 已启用，但六项显式抗耗尽预算未完整配置")]
    MissingBudget,
    #[error("private-hidden HMAC key-state 或 v2 数据结构发生漂移")]
    KeyStateDrift,
    #[error("配置的 private-hidden HMAC 密钥与数据库 key-state 不匹配")]
    HmacKeyMismatch,
}

impl std::fmt::Debug for PrivateEvaluationRuntimePrepareError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateHmacKeyStateAction {
    Disabled,
    Initialize,
    Verified,
}

/// 在监听端口前验证 private-hidden catalog、HMAC key lifecycle 与显式预算。
///
/// 首次启用会在事务级 advisory lock 下只追加 v1 key commitment。之后每次启动都以
/// 常量时间比较同一 commitment；缺 key、错 key、缺预算、多行或历史 v2 数据缺失
/// key-state 都会失败关闭。此函数从不记录 key、commitment、catalog 路径或 Prompt。
pub async fn prepare_private_evaluation_runtime(
    pool: &PgPool,
    config: &Config,
) -> Result<Option<PrivateEvaluationRuntimeSecurity>, PrivateEvaluationRuntimePrepareError> {
    let catalog_enabled = match load_private_evaluation_catalog(
        config.quality_evaluator_keys_dir.as_deref(),
        OffsetDateTime::now_utc(),
    ) {
        Ok(catalog) => catalog.is_some(),
        Err(error) => {
            // 与 claim 路径一致：无效或过期 catalog 只允许 public canary。只记录稳定
            // code，不记录路径、签名 envelope、Prompt 或 Secret。
            tracing::warn!(
                catalog_error = error.code(),
                "private-hidden catalog 启动校验未通过，仅启用 public canary"
            );
            false
        }
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(PRIVATE_HMAC_STATE_LOCK_NAMESPACE)
        .bind(PRIVATE_HMAC_STATE_LOCK_KEY)
        .execute(&mut *tx)
        .await
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;

    let rows = sqlx::query(
        r#"
        SELECT version,key_commitment
        FROM private_evaluation_hmac_key_state
        ORDER BY version
        FOR UPDATE
        LIMIT 3
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
    let key_state_rows = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<i32, _>("version")?,
                row.try_get::<String, _>("key_commitment")?,
            ))
        })
        .collect::<Result<Vec<_>, sqlx::Error>>()
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
    let has_v2_rows: bool = sqlx::query_scalar(
        r#"
        SELECT
            EXISTS (
                SELECT 1 FROM model_evaluation_challenges
                WHERE private_commitment_version = 2
            )
            OR EXISTS (
                SELECT 1 FROM model_evaluation_challenge_events
                WHERE private_commitment_version = 2
            )
            OR EXISTS (
                SELECT 1 FROM model_authenticity_arbitration_events
                WHERE private_commitment_version = 2
            )
            OR EXISTS (
                SELECT 1 FROM private_evaluation_budget_scopes
                WHERE version = 2
            )
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(PrivateEvaluationRuntimePrepareError::Database)?;

    let action = decide_private_hmac_key_state(
        catalog_enabled,
        config.private_evaluation_hmac_key.as_ref(),
        config.private_evaluation_budget.is_some(),
        &key_state_rows,
        has_v2_rows,
    )?;
    if action == PrivateHmacKeyStateAction::Initialize {
        let key = config
            .private_evaluation_hmac_key
            .as_ref()
            .ok_or(PrivateEvaluationRuntimePrepareError::MissingHmacKey)?;
        let commitment = hex::encode(private_hmac_key_commitment(key));
        let inserted = sqlx::query(
            r#"
            INSERT INTO private_evaluation_hmac_key_state (version,key_commitment)
            VALUES (1,$1)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(commitment)
        .execute(&mut *tx)
        .await
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
        if inserted.rows_affected() != 1 {
            return Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift);
        }
    }
    let security = match (action, config.private_evaluation_hmac_key.as_ref()) {
        (
            PrivateHmacKeyStateAction::Initialize | PrivateHmacKeyStateAction::Verified,
            Some(key),
        ) => Some(PrivateEvaluationRuntimeSecurity::new(
            key.clone(),
            config.private_evaluation_budget.clone(),
        )),
        _ => None,
    };
    tx.commit()
        .await
        .map_err(PrivateEvaluationRuntimePrepareError::Database)?;
    Ok(security)
}

fn decide_private_hmac_key_state(
    catalog_enabled: bool,
    configured_key: Option<&PrivateEvaluationHmacKey>,
    budget_configured: bool,
    key_state_rows: &[(i32, String)],
    has_v2_rows: bool,
) -> Result<PrivateHmacKeyStateAction, PrivateEvaluationRuntimePrepareError> {
    if key_state_rows.len() > 1
        || key_state_rows
            .first()
            .is_some_and(|(version, commitment)| *version != 1 || !canonical_sha256(commitment))
    {
        return Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift);
    }
    let key_required = catalog_enabled || has_v2_rows || !key_state_rows.is_empty();
    let Some(configured_key) = configured_key else {
        return if key_required {
            Err(PrivateEvaluationRuntimePrepareError::MissingHmacKey)
        } else {
            Ok(PrivateHmacKeyStateAction::Disabled)
        };
    };
    if catalog_enabled && !budget_configured {
        return Err(PrivateEvaluationRuntimePrepareError::MissingBudget);
    }

    match key_state_rows.first() {
        Some((_, stored_commitment)) => {
            if private_hmac_key_commitment_matches(configured_key, stored_commitment) {
                Ok(PrivateHmacKeyStateAction::Verified)
            } else {
                Err(PrivateEvaluationRuntimePrepareError::HmacKeyMismatch)
            }
        }
        None if has_v2_rows => Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift),
        // 成组预配置也必须提前绑定 key-state，防止启动后热加入有效 catalog 绕过
        // lifecycle 门禁。key-only 则保持未启用，不污染数据库状态。
        None if catalog_enabled || budget_configured => Ok(PrivateHmacKeyStateAction::Initialize),
        None => Ok(PrivateHmacKeyStateAction::Disabled),
    }
}

fn private_hmac_key_commitment(key: &PrivateEvaluationHmacKey) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(PRIVATE_HMAC_KEY_COMMITMENT_DOMAIN);
    digest.update(32_u64.to_be_bytes());
    digest.update(key.material());
    digest.finalize().into()
}

fn private_hmac_key_commitment_matches(
    key: &PrivateEvaluationHmacKey,
    stored_commitment: &str,
) -> bool {
    if !canonical_sha256(stored_commitment) {
        return false;
    }
    let mut stored = Zeroizing::new([0_u8; 32]);
    if hex::decode_to_slice(stored_commitment.as_bytes(), &mut *stored).is_err() {
        return false;
    }
    private_hmac_key_commitment(key)
        .ct_eq(stored.as_ref())
        .unwrap_u8()
        == 1
}

fn canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// 以只读事务逐项比对当前二进制内嵌迁移与数据库迁移记录。
///
/// 不创建或修改数据库对象，也不执行 Standard 旧数据升级；供启动门禁和显式
/// 配置连通性检查复用同一份 exact schema 合同。
pub async fn verify_runtime_schema(pool: &PgPool) -> Result<(), RuntimePrepareError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(RuntimePrepareError::SchemaUnavailable)?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(RuntimePrepareError::SchemaUnavailable)?;
    let applied = sqlx::query(
        r#"
        SELECT version, description, success, checksum
        FROM public._sqlx_migrations
        ORDER BY version
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(RuntimePrepareError::SchemaUnavailable)?;

    let expected = MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .collect::<Vec<_>>();
    if applied.len() != expected.len() {
        return Err(RuntimePrepareError::SchemaDrift);
    }

    for (row, migration) in applied.iter().zip(expected) {
        let version: i64 = row
            .try_get("version")
            .map_err(RuntimePrepareError::SchemaUnavailable)?;
        let description: String = row
            .try_get("description")
            .map_err(RuntimePrepareError::SchemaUnavailable)?;
        let success: bool = row
            .try_get("success")
            .map_err(RuntimePrepareError::SchemaUnavailable)?;
        let checksum: Vec<u8> = row
            .try_get("checksum")
            .map_err(RuntimePrepareError::SchemaUnavailable)?;
        if version != migration.version
            || description.as_str() != migration.description.as_ref()
            || !success
            || checksum.as_slice() != migration.checksum.as_ref()
        {
            return Err(RuntimePrepareError::SchemaDrift);
        }
    }
    tx.commit()
        .await
        .map_err(RuntimePrepareError::SchemaUnavailable)?;
    Ok(())
}

pub async fn authenticate(
    pool: &PgPool,
    tokens: &TokenService,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::authentication("缺少 Bearer 访问令牌"))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::authentication("Authorization 格式无效"))?;
    let token_hash = tokens
        .hash(token)
        .map_err(|_| ApiError::authentication("访问令牌无效"))?;
    let row = sqlx::query(
        r#"
        SELECT s.id AS session_id, u.id AS user_id, u.username,
               dk.id AS device_key_id
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        JOIN device_keys dk
          ON dk.id = s.device_key_id
         AND dk.user_id = s.user_id
         AND dk.revoked_at IS NULL
        WHERE s.access_token_hash = $1
          AND s.revoked_at IS NULL
          AND s.access_expires_at > now()
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    let row = row.ok_or_else(|| ApiError::authentication("访问令牌已失效或已撤销"))?;
    let session_id = row.try_get("session_id")?;
    let principal = Principal {
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        session_id,
        device_key_id: row.try_get("device_key_id")?,
    };
    sqlx::query("UPDATE sessions SET last_used_at = now() WHERE id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(principal)
}

/// 仅供推理数据面与模型发现使用。管理、节点、额度和运维路由必须继续调用
/// [`authenticate`]，从而保证 `mok_` Key 不能扩大为通用账户令牌。
pub async fn authenticate_inference(
    pool: &PgPool,
    tokens: &TokenService,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| ApiError::authentication("缺少 Bearer API Key"))?;
    let token = authorization
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::authentication("Authorization 格式无效"))?;
    if !token.starts_with("mok_") {
        return authenticate(pool, tokens, headers).await;
    }
    let token_hash = tokens
        .hash(token)
        .map_err(|_| ApiError::authentication("API Key 无效"))?;
    let row = sqlx::query(
        r#"
        SELECT key.id AS api_key_id,key.created_by_session_id AS session_id,
               key.device_key_id,u.id AS user_id,u.username
        FROM inference_api_keys key
        JOIN users u ON u.id=key.user_id
        JOIN sessions session
          ON session.id=key.created_by_session_id
         AND session.user_id=key.user_id
         AND session.device_key_id=key.device_key_id
         AND session.revoked_at IS NULL
        JOIN device_keys device
          ON device.id=key.device_key_id
         AND device.user_id=key.user_id
         AND device.revoked_at IS NULL
        WHERE key.key_hash=$1 AND key.revoked_at IS NULL
        "#,
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ApiError::authentication("API Key 已失效、已撤销或设备会话已注销"))?;
    let api_key_id: Uuid = row.try_get("api_key_id")?;
    sqlx::query(
        "UPDATE inference_api_keys SET last_used_at=now() WHERE id=$1 AND revoked_at IS NULL",
    )
    .bind(api_key_id)
    .execute(pool)
    .await?;
    Ok(Principal {
        user_id: row.try_get("user_id")?,
        username: row.try_get("username")?,
        session_id: row.try_get("session_id")?,
        device_key_id: row.try_get("device_key_id")?,
    })
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn test_config() -> Config {
        Config::development_for_tests("postgres://invalid".to_owned())
    }

    #[test]
    fn deployed_migration_14_checksum_remains_immutable() {
        let migration = MIGRATOR
            .iter()
            .find(|migration| migration.version == 14)
            .expect("应内嵌已部署的 migration 14");
        assert_eq!(
            hex::encode(migration.checksum.as_ref()),
            "3f7610c0380e8cc394a4aa1b96a7af0664713a2e58b53281d67c959126b88ace0b6586cb41a7ea42d809ba403d4a6563",
            "已部署 migration 的空行、注释和 SQL 均属于不可变校验和；后续变化必须新增 migration"
        );
    }

    #[test]
    fn private_hmac_key_commitment_is_domain_separated_and_deterministic() {
        let config = test_config();
        let key = config
            .private_evaluation_hmac_key
            .as_ref()
            .expect("测试 key 应存在");
        let first = private_hmac_key_commitment(key);
        let second = private_hmac_key_commitment(key);
        assert_eq!(first, second);
        assert_eq!(
            hex::encode(first),
            "8660e72aad649e7df07f97e26e46aefca437b618c1593da0c8b34b3b5ee8d1a0"
        );
        let bare = Sha256::digest(key.material());
        assert_ne!(&first[..], &bare[..]);

        let mut manual = Sha256::new();
        manual.update(PRIVATE_HMAC_KEY_COMMITMENT_DOMAIN);
        manual.update(32_u64.to_be_bytes());
        manual.update(key.material());
        let manual = manual.finalize();
        assert_eq!(&first[..], &manual[..]);
    }

    #[test]
    fn pristine_public_runtime_does_not_require_or_persist_a_key() {
        assert_eq!(
            decide_private_hmac_key_state(false, None, false, &[], false)
                .expect("纯 public canary 应保持可启动"),
            PrivateHmacKeyStateAction::Disabled
        );

        let config = test_config();
        let key = config.private_evaluation_hmac_key.as_ref();
        assert_eq!(
            decide_private_hmac_key_state(false, key, false, &[], false)
                .expect("仅预置 key 不应初始化状态"),
            PrivateHmacKeyStateAction::Disabled
        );
    }

    #[test]
    fn key_and_budget_preconfiguration_initializes_before_catalog_hot_add() {
        let config = test_config();
        let key = config.private_evaluation_hmac_key.as_ref();
        assert_eq!(
            decide_private_hmac_key_state(false, key, true, &[], false)
                .expect("成组预配置必须提前绑定 key-state"),
            PrivateHmacKeyStateAction::Initialize
        );
    }

    #[test]
    fn valid_catalog_requires_both_key_and_explicit_budget() {
        let config = test_config();
        let key = config.private_evaluation_hmac_key.as_ref();
        assert!(matches!(
            decide_private_hmac_key_state(true, None, true, &[], false),
            Err(PrivateEvaluationRuntimePrepareError::MissingHmacKey)
        ));
        assert!(matches!(
            decide_private_hmac_key_state(true, key, false, &[], false),
            Err(PrivateEvaluationRuntimePrepareError::MissingBudget)
        ));
        assert_eq!(
            decide_private_hmac_key_state(true, key, true, &[], false)
                .expect("首次真实启用应初始化 key-state"),
            PrivateHmacKeyStateAction::Initialize
        );
    }

    #[test]
    fn historical_state_requires_the_same_key_and_detects_drift() {
        let config = test_config();
        let key = config
            .private_evaluation_hmac_key
            .as_ref()
            .expect("测试 key 应存在");
        let stored = hex::encode(private_hmac_key_commitment(key));
        assert_eq!(
            decide_private_hmac_key_state(false, Some(key), false, &[(1, stored.clone())], true,)
                .expect("历史 v2 state 与相同 key 应通过"),
            PrivateHmacKeyStateAction::Verified
        );
        assert!(matches!(
            decide_private_hmac_key_state(false, None, false, &[(1, stored.clone())], true),
            Err(PrivateEvaluationRuntimePrepareError::MissingHmacKey)
        ));
        assert!(matches!(
            decide_private_hmac_key_state(false, Some(key), false, &[(1, "00".repeat(32))], true,),
            Err(PrivateEvaluationRuntimePrepareError::HmacKeyMismatch)
        ));
        assert!(matches!(
            decide_private_hmac_key_state(false, Some(key), true, &[], true),
            Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift)
        ));
        assert!(matches!(
            decide_private_hmac_key_state(
                false,
                Some(key),
                true,
                &[(1, stored.clone()), (2, stored)],
                true,
            ),
            Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift)
        ));
        assert!(matches!(
            decide_private_hmac_key_state(false, Some(key), true, &[(1, "A0".repeat(32))], true,),
            Err(PrivateEvaluationRuntimePrepareError::KeyStateDrift)
        ));
    }
}
