//! 服务端私有质量挑战。
//!
//! 这里刻意不暴露独立 HTTP 路由。挑战复用普通 claim、renew、result、fail endpoint，
//! 并只序列化公开的任务协议字段，不携带专用评价标签；评价种类、seed、期望答案和判分
//! 始终留在协调器事务内。真正的 hidden benchmark 来自仓库外、受信 evaluator 签名的
//! 一次性 catalog；仓库内生成器只用于公开 canary 风险信号。

use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use mindone_protocol::{
    ChatCompletionsResponse, ClaimJobResponse, ConfidentialityMode, ContentPart, JobFailRequest,
    JobFailResponse, JobResultRequest, JobResultResponse, JobStatus, MessageContent,
    PayloadEncoding, RenewJobResponse, StandardJobPayload,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::private_evaluation_catalog::{
    load_private_evaluation_catalog, private_evaluation_commitment_hex,
    private_evaluation_commitment_matches_hex, private_evaluation_expected_behavior_commitment_hex,
    private_evaluation_sha256_commitment_hex, PrivateEvaluationCatalogEntry,
    PrivateEvaluationCommitmentDomain, VerifiedPrivateEvaluationCatalog,
};
use crate::{
    auth::Principal,
    config::{PrivateEvaluationBudgetConfig, PrivateEvaluationHmacKey},
    device_binding::{exact_claim_device_binding, DEVICE_BINDING_VERSION},
    error::ApiError,
    settlement::finalize_draining_instance,
    AppState, PrivateEvaluationTerminalCapability,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateEvaluationKind {
    HiddenBenchmark,
    Canary,
}

struct SensitiveEvaluationPayload(StandardJobPayload);

impl std::ops::Deref for SensitiveEvaluationPayload {
    type Target = StandardJobPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SensitiveEvaluationPayload {
    fn zeroize_owned(&mut self) {
        self.0.endpoint.zeroize();
        zeroize_json_value(&mut self.0.request);
    }
}

impl Drop for SensitiveEvaluationPayload {
    fn drop(&mut self) {
        self.zeroize_owned();
    }
}

struct SensitiveChatCompletionsResponse(ChatCompletionsResponse);

impl std::ops::Deref for SensitiveChatCompletionsResponse {
    type Target = ChatCompletionsResponse;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveChatCompletionsResponse {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveChatCompletionsResponse {
    fn drop(&mut self) {
        self.0.id.zeroize();
        self.0.object.zeroize();
        self.0.model.zeroize();
        if let Some(fingerprint) = self.0.system_fingerprint.as_mut() {
            fingerprint.zeroize();
        }
        for choice in &mut self.0.choices {
            zeroize_message_content(&mut choice.message.content);
            if let Some(name) = choice.message.name.as_mut() {
                name.zeroize();
            }
            if let Some(tool_call_id) = choice.message.tool_call_id.as_mut() {
                tool_call_id.zeroize();
            }
        }
    }
}

fn zeroize_message_content(content: &mut MessageContent) {
    match content {
        MessageContent::Text(value) => value.zeroize(),
        MessageContent::Parts(parts) => {
            for part in parts {
                match part {
                    ContentPart::Text { text } => text.zeroize(),
                    ContentPart::ImageUrl { image_url } => {
                        image_url.url.zeroize();
                        if let Some(detail) = image_url.detail.as_mut() {
                            detail.zeroize();
                        }
                    }
                }
            }
        }
    }
}

fn zeroize_json_value(value: &mut serde_json::Value) {
    match std::mem::take(value) {
        serde_json::Value::String(mut text) => text.zeroize(),
        serde_json::Value::Array(mut values) => {
            for nested in &mut values {
                zeroize_json_value(nested);
            }
        }
        serde_json::Value::Object(values) => {
            for (mut key, mut nested) in values {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

// Public-template canaries and private evaluator challenges both feed bounded,
// exact-instance risk handling. Only the latter also writes cross-instance
// authenticity arbitration events.
const QUARANTINE_FAILURE_THRESHOLD: i32 = 3;
const RECOVERY_PASS_THRESHOLD: i32 = 2;
const EXPIRY_SWEEP_BATCH_SIZE: i64 = 128;
const PRIVATE_COMMITMENT_VERSION: i32 = 2;
const PRIVATE_BUDGET_WINDOW_SECONDS: i64 = 60 * 60;
// 所有 private catalog 共用同一把事务锁。与 HMAC key-state 使用不同 namespace/key，
// 避免无关启动事务互相阻塞；固定双整数也不会把 catalog 或 Prompt 派生值暴露给锁表。
const PRIVATE_RESERVE_LOCK_NAMESPACE: i32 = 0x4d4f_5052;
const PRIVATE_RESERVE_LOCK_KEY: i32 = 0x5253_5632;

#[derive(Clone, Copy)]
enum TerminalMutationAuthorization<'a> {
    Legacy,
    V2(PrivateEvaluationTerminalCapability<'a>),
}

fn authorize_terminal_mutation<'a>(
    private_commitment_version: Option<i32>,
    capability: Option<PrivateEvaluationTerminalCapability<'a>>,
) -> Result<TerminalMutationAuthorization<'a>, ApiError> {
    match private_commitment_version {
        None => Ok(TerminalMutationAuthorization::Legacy),
        Some(PRIVATE_COMMITMENT_VERSION) => capability
            .map(TerminalMutationAuthorization::V2)
            .ok_or_else(ApiError::internal),
        Some(_) => Err(ApiError::internal()),
    }
}

fn authorize_terminal_row<'a>(
    row: &sqlx::postgres::PgRow,
    capability: Option<PrivateEvaluationTerminalCapability<'a>>,
) -> Result<TerminalMutationAuthorization<'a>, ApiError> {
    authorize_terminal_mutation(row.try_get("private_commitment_version")?, capability)
}

fn verify_terminal_authorization(
    row: &sqlx::postgres::PgRow,
    authorization: TerminalMutationAuthorization<'_>,
) -> Result<(), ApiError> {
    match (
        row.try_get::<Option<i32>, _>("private_commitment_version")?,
        authorization,
    ) {
        (None, TerminalMutationAuthorization::Legacy)
        | (Some(PRIVATE_COMMITMENT_VERSION), TerminalMutationAuthorization::V2(_)) => Ok(()),
        _ => Err(ApiError::internal()),
    }
}

/// 在普通 claim 事务中以 CSPRNG 决定是否混入一个挑战。
///
/// 即便当前只有评价候选，未命中的 draw 也返回普通 204；节点无法通过队列时序得到
/// 一个确定性挑战信号。每个模型实例还有服务端冷却窗口。
pub(super) async fn maybe_claim_hidden_job(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
    node_id: Uuid,
    requested_model_instance_id: Uuid,
) -> Result<Option<ClaimJobResponse>, ApiError> {
    expire_stale_challenges(state, tx, node_id).await?;
    if state.config.evaluation_draw_denominator == 0 {
        return Ok(None);
    }
    if OsRng.next_u32() % state.config.evaluation_draw_denominator != 0 {
        return Ok(None);
    }
    let evaluation_cooldown_seconds =
        i64::try_from(state.config.evaluation_instance_cooldown.as_secs()).map_err(|_| {
            tracing::error!("评价实例冷却时间超出 PostgreSQL bigint 范围");
            ApiError::internal()
        })?;
    let candidate = sqlx::query(
        r#"
        SELECT mi.id AS model_instance_id,m.id AS model_id,m.name AS model_name,m.weights_hash
        FROM model_instances mi
        JOIN models m ON m.id=mi.model_id
        JOIN nodes n ON n.id=mi.node_id
        WHERE mi.node_id=$1 AND mi.id=$2
          AND mi.status='published' AND m.enabled=TRUE AND n.status='online'
          AND n.last_seen_at > now() - interval '90 seconds'
          AND NOT EXISTS (
              SELECT 1 FROM model_evaluation_challenges active
              WHERE active.model_instance_id=mi.id AND active.status='leased'
          )
          AND NOT EXISTS (
              SELECT 1 FROM model_evaluation_challenges recent
              WHERE recent.model_instance_id=mi.id
                AND recent.issued_at > now() - ($3::bigint * interval '1 second')
          )
        ORDER BY mi.id
        FOR UPDATE OF mi SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(node_id)
    .bind(requested_model_instance_id)
    .bind(evaluation_cooldown_seconds)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };

    let model_instance_id: Uuid = candidate.try_get("model_instance_id")?;
    let model_id: Uuid = candidate.try_get("model_id")?;
    let model_name: String = candidate.try_get("model_name")?;
    let model_weights_hash: String = candidate.try_get("weights_hash")?;
    let lease_duration = time::Duration::try_from(state.config.lease_duration).map_err(|_| {
        tracing::error!("评价租约时长超出 time 支持范围");
        ApiError::internal()
    })?;
    let private_runtime = state.private_evaluation_issuance_security();
    let catalog = if private_runtime.is_some() {
        match load_private_evaluation_catalog(
            state.config.quality_evaluator_keys_dir.as_deref(),
            OffsetDateTime::now_utc(),
        ) {
            Ok(catalog) => catalog,
            Err(error) => {
                // 只记录稳定错误码，不把路径、Prompt、签名 envelope 或响应写入日志。
                tracing::warn!(
                    catalog_error = error.code(),
                    "私有评价 catalog 不可用，本次仅允许公开 canary"
                );
                None
            }
        }
    } else {
        None
    };
    let private_availability = match (catalog.as_ref(), private_runtime) {
        (Some(catalog), Some((key, _))) => {
            // 必须先于任何 availability/冲突快照取得。事务级 advisory lock 会一直
            // 持有到 challenge 与 issued event 一并提交或回滚，使不同 catalog 的
            // 全局 Prompt/behavior 唯一约束和 reserve 判断使用同一个串行顺序。
            lock_private_global_reserve(tx).await?;
            available_private_entries(
                tx,
                catalog,
                key,
                principal,
                node_id,
                &model_weights_hash,
                lease_duration,
            )
            .await?
        }
        _ => PrivateCatalogAvailability::default(),
    };

    // 全局事务锁使所有合规 coordinator 的 availability 快照保持稳定；数据库唯一索引
    // 仍是最终防线。若防御性 INSERT 发现冲突，本事务继续尝试下一条；全部用尽后只能
    // 发公开 canary，不能伪造 hidden benchmark。
    for candidate in private_availability.candidates {
        let Some((_, budget)) = private_runtime else {
            return Err(ApiError::internal());
        };
        if !private_budget_allows_claim(
            tx,
            budget,
            &candidate.commitments,
            private_availability.remaining_catalog_entries,
        )
        .await?
        {
            // 所有预算拒绝都与“没有 private candidate”使用相同的 canary fallback。
            break;
        }
        let generated = GeneratedChallenge::from_private_entry(candidate.entry);
        if let Some(claim) = insert_challenge_claim(
            state,
            tx,
            principal,
            node_id,
            model_id,
            model_instance_id,
            &model_name,
            &model_weights_hash,
            PrivateEvaluationKind::HiddenBenchmark,
            generated,
            None,
            Some(candidate.metadata),
            Some(candidate.commitments),
            lease_duration,
        )
        .await?
        {
            return Ok(Some(claim));
        }
    }

    let mut canary_seed = [0_u8; 32];
    OsRng.fill_bytes(&mut canary_seed);
    let generated = generate_public_canary(&canary_seed);
    debug_assert!(prompt_has_no_private_marker(&generated.prompt));
    insert_challenge_claim(
        state,
        tx,
        principal,
        node_id,
        model_id,
        model_instance_id,
        &model_name,
        &model_weights_hash,
        PrivateEvaluationKind::Canary,
        generated,
        Some(canary_seed),
        None,
        None,
        lease_duration,
    )
    .await
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PrivateChallengeMetadata {
    catalog_id: String,
    catalog_entry_id: String,
    case_family: String,
    catalog_commitment: String,
    evaluator_id: String,
    evaluator_key_fingerprint: String,
    #[zeroize(skip)]
    catalog_valid_until: OffsetDateTime,
}

impl PrivateChallengeMetadata {
    fn from_catalog(
        catalog: &VerifiedPrivateEvaluationCatalog,
        entry: &PrivateEvaluationCatalogEntry,
    ) -> Self {
        Self {
            catalog_id: catalog.catalog_id.clone(),
            catalog_entry_id: entry.entry_id.clone(),
            case_family: entry.case_family.clone(),
            catalog_commitment: catalog.catalog_commitment.clone(),
            evaluator_id: catalog.evaluator_id.clone(),
            evaluator_key_fingerprint: catalog.evaluator_key_fingerprint.clone(),
            catalog_valid_until: catalog.valid_until,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct PrivateV2Commitments {
    catalog_statement: String,
    catalog_id: String,
    catalog_entry: String,
    case_family: String,
    evaluator_id: String,
    evaluator_key: String,
    prompt: String,
    expected: String,
    account: String,
    device: String,
    node: String,
}

impl PrivateV2Commitments {
    fn from_catalog(
        key: &PrivateEvaluationHmacKey,
        catalog: &VerifiedPrivateEvaluationCatalog,
        entry: &PrivateEvaluationCatalogEntry,
        principal: &Principal,
        node_id: Uuid,
    ) -> Result<Self, ApiError> {
        let account_id = Zeroizing::new(principal.user_id.to_string());
        let device_id = Zeroizing::new(principal.device_key_id.to_string());
        let node_id = Zeroizing::new(node_id.to_string());
        Ok(Self {
            catalog_statement: private_evaluation_sha256_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::CatalogStatement,
                &catalog.catalog_commitment,
            )
            .map_err(|_| ApiError::internal())?,
            catalog_id: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::CatalogId,
                catalog.catalog_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            catalog_entry: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::EntryId,
                entry.entry_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            case_family: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::CaseFamily,
                entry.case_family.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            evaluator_id: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::EvaluatorId,
                catalog.evaluator_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            evaluator_key: private_evaluation_sha256_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::EvaluatorKey,
                &catalog.evaluator_key_fingerprint,
            )
            .map_err(|_| ApiError::internal())?,
            prompt: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::Prompt,
                entry.prompt.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            expected: private_evaluation_expected_behavior_commitment_hex(
                key,
                &entry.expected_behavior_sha256,
            )
            .map_err(|_| ApiError::internal())?,
            account: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::AccountId,
                account_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            device: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::DeviceId,
                device_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            node: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::NodeId,
                node_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
        })
    }
}

struct PrivateClaimCandidate {
    entry: PrivateEvaluationCatalogEntry,
    metadata: PrivateChallengeMetadata,
    commitments: PrivateV2Commitments,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PrivateCatalogEntryCommitments {
    catalog_entry: String,
    prompt: String,
    expected: String,
}

impl PrivateCatalogEntryCommitments {
    fn from_entry(
        key: &PrivateEvaluationHmacKey,
        entry: &PrivateEvaluationCatalogEntry,
    ) -> Result<Self, ApiError> {
        Ok(Self {
            catalog_entry: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::EntryId,
                entry.entry_id.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            prompt: private_evaluation_commitment_hex(
                key,
                PrivateEvaluationCommitmentDomain::Prompt,
                entry.prompt.as_bytes(),
            )
            .map_err(|_| ApiError::internal())?,
            expected: private_evaluation_expected_behavior_commitment_hex(
                key,
                &entry.expected_behavior_sha256,
            )
            .map_err(|_| ApiError::internal())?,
        })
    }
}

#[derive(Default)]
struct PrivateCatalogAvailability {
    candidates: Vec<PrivateClaimCandidate>,
    remaining_catalog_entries: u64,
}

async fn lock_private_global_reserve(tx: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(PRIVATE_RESERVE_LOCK_NAMESPACE)
        .bind(PRIVATE_RESERVE_LOCK_KEY)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn available_private_entries(
    tx: &mut Transaction<'_, Postgres>,
    catalog: &VerifiedPrivateEvaluationCatalog,
    key: &PrivateEvaluationHmacKey,
    principal: &Principal,
    node_id: Uuid,
    model_weights_hash: &str,
    lease_duration: time::Duration,
) -> Result<PrivateCatalogAvailability, ApiError> {
    let now = OffsetDateTime::now_utc();
    if now
        .checked_add(lease_duration)
        .is_none_or(|lease_end| lease_end >= catalog.valid_until)
    {
        return Ok(PrivateCatalogAvailability::default());
    }

    let entry_ids = catalog
        .entries
        .iter()
        .map(|entry| entry.entry_id.clone())
        .collect::<Vec<_>>();
    let prompt_hashes = catalog
        .entries
        .iter()
        .map(|entry| sha256_hex(entry.prompt.as_bytes()))
        .collect::<Vec<_>>();
    let expected_hashes = catalog
        .entries
        .iter()
        .map(|entry| entry.expected_behavior_sha256.clone())
        .collect::<Vec<_>>();
    let entry_commitments = catalog
        .entries
        .iter()
        .map(|entry| PrivateCatalogEntryCommitments::from_entry(key, entry))
        .collect::<Result<Vec<_>, ApiError>>()?;
    let catalog_entry_commitments = entry_commitments
        .iter()
        .map(|commitments| commitments.catalog_entry.clone())
        .collect::<Vec<_>>();
    let prompt_commitments = entry_commitments
        .iter()
        .map(|commitments| commitments.prompt.clone())
        .collect::<Vec<_>>();
    let expected_commitments = entry_commitments
        .iter()
        .map(|commitments| commitments.expected.clone())
        .collect::<Vec<_>>();
    let catalog_id_commitment = private_evaluation_commitment_hex(
        key,
        PrivateEvaluationCommitmentDomain::CatalogId,
        catalog.catalog_id.as_bytes(),
    )
    .map_err(|_| ApiError::internal())?;

    // UNIQUE 索引最终决定一项能否发行，因此 remaining 必须与 challenge 表中的同一组
    // 冲突键一致。按当前 catalog entry 的 ordinal 做 EXISTS 并集，既不会把一项的
    // entry/prompt/expected 多重命中重复扣减，也不会把跨 catalog 行的 entry id 错配
    // 给另一项。查询覆盖 catalog 全部 entry，而不只覆盖本次模型权重的候选。
    let unavailable_rows = sqlx::query(
        r#"
        WITH current_entries AS (
            SELECT entry_id,prompt_hash,expected_hash,
                   entry_commitment,prompt_commitment,expected_commitment,entry_ordinal
            FROM unnest(
                $3::text[],$4::text[],$5::text[],
                $6::text[],$7::text[],$8::text[]
            ) WITH ORDINALITY AS entry(
                entry_id,prompt_hash,expected_hash,
                entry_commitment,prompt_commitment,expected_commitment,entry_ordinal
            )
        )
        SELECT entry.entry_ordinal::bigint AS entry_ordinal
        FROM current_entries entry
        WHERE EXISTS (
            SELECT 1
            FROM model_evaluation_challenges challenge
            WHERE (
                challenge.private_commitment_version IS NULL
                AND challenge.private_catalog_commitment IS NOT NULL
                AND (
                    (challenge.private_catalog_commitment=$1
                        AND challenge.private_catalog_entry_id=entry.entry_id)
                    OR challenge.prompt_hash=entry.prompt_hash
                    OR challenge.expected_hash=entry.expected_hash
                )
            ) OR (
                challenge.private_commitment_version=2
                AND (
                    (challenge.private_catalog_id_commitment=$2
                        AND challenge.private_catalog_entry_commitment=entry.entry_commitment)
                    OR challenge.private_prompt_commitment=entry.prompt_commitment
                    OR challenge.private_expected_commitment=entry.expected_commitment
                )
            )
        )
        ORDER BY entry.entry_ordinal
        "#,
    )
    .bind(&catalog.catalog_commitment)
    .bind(&catalog_id_commitment)
    .bind(&entry_ids)
    .bind(&prompt_hashes)
    .bind(&expected_hashes)
    .bind(&catalog_entry_commitments)
    .bind(&prompt_commitments)
    .bind(&expected_commitments)
    .fetch_all(&mut **tx)
    .await?;
    let mut unavailable_entry_indices = BTreeSet::new();
    for row in unavailable_rows {
        let ordinal: i64 = row.try_get("entry_ordinal")?;
        let index = ordinal
            .checked_sub(1)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|index| *index < catalog.entries.len())
            .ok_or_else(ApiError::internal)?;
        unavailable_entry_indices.insert(index);
    }
    let remaining_catalog_entries = catalog
        .entries
        .len()
        .checked_sub(unavailable_entry_indices.len())
        .and_then(|remaining| u64::try_from(remaining).ok())
        .ok_or_else(ApiError::internal)?;
    let mut available = catalog
        .entries
        .iter()
        .enumerate()
        .filter(|(index, entry)| {
            entry.model_weights_sha256 == model_weights_hash
                && !unavailable_entry_indices.contains(index)
        })
        .map(|(_, entry)| {
            Ok(PrivateClaimCandidate {
                entry: entry.clone(),
                metadata: PrivateChallengeMetadata::from_catalog(catalog, entry),
                commitments: PrivateV2Commitments::from_catalog(
                    key, catalog, entry, principal, node_id,
                )?,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    if !available.is_empty() {
        let offset = usize::try_from(OsRng.next_u32()).unwrap_or(0) % available.len();
        available.rotate_left(offset);
    }
    Ok(PrivateCatalogAvailability {
        candidates: available,
        remaining_catalog_entries,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PrivateBudgetSnapshot {
    catalog_hourly: u64,
    account_hourly: u64,
    device_hourly: u64,
    node_hourly: u64,
    identity_in_cooldown: bool,
    remaining_catalog_entries: u64,
    account_seen_in_catalog: bool,
    device_seen_in_catalog: bool,
    node_seen_in_catalog: bool,
}

fn private_budget_snapshot_allows(
    budget: &PrivateEvaluationBudgetConfig,
    snapshot: PrivateBudgetSnapshot,
) -> bool {
    if snapshot.catalog_hourly >= u64::from(budget.catalog_hourly_limit)
        || snapshot.account_hourly >= u64::from(budget.account_hourly_limit)
        || snapshot.device_hourly >= u64::from(budget.device_hourly_limit)
        || snapshot.node_hourly >= u64::from(budget.node_hourly_limit)
        || snapshot.identity_in_cooldown
    {
        return false;
    }
    let reserve = u64::from(budget.global_reserve_entries);
    reserve == 0
        || snapshot.remaining_catalog_entries > reserve
        || (!snapshot.account_seen_in_catalog
            && !snapshot.device_seen_in_catalog
            && !snapshot.node_seen_in_catalog)
}

async fn private_budget_allows_claim(
    tx: &mut Transaction<'_, Postgres>,
    budget: &PrivateEvaluationBudgetConfig,
    commitments: &PrivateV2Commitments,
    remaining_catalog_entries: u64,
) -> Result<bool, ApiError> {
    // 全局 reserve advisory lock 已在 availability 前取得；所有 coordinator 副本随后
    // 必须继续使用固定 catalog/account/device/node 行锁序，避免跨 scope 事务死锁。
    for (scope_kind, scope_commitment) in [
        ("catalog", commitments.catalog_id.as_str()),
        ("account", commitments.account.as_str()),
        ("device", commitments.device.as_str()),
        ("node", commitments.node.as_str()),
    ] {
        lock_private_budget_scope(tx, scope_kind, scope_commitment).await?;
    }

    let catalog_hourly = count_private_issued_scope(
        tx,
        "catalog",
        &commitments.catalog_id,
        PRIVATE_BUDGET_WINDOW_SECONDS,
    )
    .await?;
    let account_hourly = count_private_issued_scope(
        tx,
        "account",
        &commitments.account,
        PRIVATE_BUDGET_WINDOW_SECONDS,
    )
    .await?;
    let device_hourly = count_private_issued_scope(
        tx,
        "device",
        &commitments.device,
        PRIVATE_BUDGET_WINDOW_SECONDS,
    )
    .await?;
    let node_hourly =
        count_private_issued_scope(tx, "node", &commitments.node, PRIVATE_BUDGET_WINDOW_SECONDS)
            .await?;
    let cooldown_milliseconds =
        i64::try_from(budget.cooldown.as_millis()).map_err(|_| ApiError::internal())?;
    let identity_in_cooldown: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM model_evaluation_challenge_events
            WHERE private_commitment_version=2 AND event_kind='issued'
              AND (
                  private_account_commitment=$1
                  OR private_device_commitment=$2
                  OR private_node_commitment=$3
              )
              AND created_at > now() - ($4::bigint * interval '1 millisecond')
        )
        "#,
    )
    .bind(&commitments.account)
    .bind(&commitments.device)
    .bind(&commitments.node)
    .bind(cooldown_milliseconds)
    .fetch_one(&mut **tx)
    .await?;
    let catalog_history = sqlx::query(
        r#"
        SELECT COALESCE(BOOL_OR(private_account_commitment=$2),FALSE) AS account_seen,
               COALESCE(BOOL_OR(private_device_commitment=$3),FALSE) AS device_seen,
               COALESCE(BOOL_OR(private_node_commitment=$4),FALSE) AS node_seen
        FROM model_evaluation_challenge_events
        WHERE private_commitment_version=2 AND event_kind='issued'
          AND private_catalog_id_commitment=$1
        "#,
    )
    .bind(&commitments.catalog_id)
    .bind(&commitments.account)
    .bind(&commitments.device)
    .bind(&commitments.node)
    .fetch_one(&mut **tx)
    .await?;
    let snapshot = PrivateBudgetSnapshot {
        catalog_hourly,
        account_hourly,
        device_hourly,
        node_hourly,
        identity_in_cooldown,
        remaining_catalog_entries,
        account_seen_in_catalog: catalog_history.try_get("account_seen")?,
        device_seen_in_catalog: catalog_history.try_get("device_seen")?,
        node_seen_in_catalog: catalog_history.try_get("node_seen")?,
    };
    Ok(private_budget_snapshot_allows(budget, snapshot))
}

async fn lock_private_budget_scope(
    tx: &mut Transaction<'_, Postgres>,
    scope_kind: &str,
    scope_commitment: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO private_evaluation_budget_scopes
            (version,scope_kind,scope_commitment)
        VALUES (2,$1,$2)
        ON CONFLICT (version,scope_kind,scope_commitment) DO NOTHING
        "#,
    )
    .bind(scope_kind)
    .bind(scope_commitment)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        r#"
        SELECT scope_commitment
        FROM private_evaluation_budget_scopes
        WHERE version=2 AND scope_kind=$1 AND scope_commitment=$2
        FOR UPDATE
        "#,
    )
    .bind(scope_kind)
    .bind(scope_commitment)
    .fetch_one(&mut **tx)
    .await?;
    Ok(())
}

async fn count_private_issued_scope(
    tx: &mut Transaction<'_, Postgres>,
    scope_kind: &str,
    scope_commitment: &str,
    window_seconds: i64,
) -> Result<u64, ApiError> {
    let statement = match scope_kind {
        "catalog" => {
            r#"
            SELECT COUNT(*)::bigint
            FROM model_evaluation_challenge_events
            WHERE private_commitment_version=2 AND event_kind='issued'
              AND private_catalog_id_commitment=$1
              AND created_at > now() - ($2::bigint * interval '1 second')
            "#
        }
        "account" => {
            r#"
            SELECT COUNT(*)::bigint
            FROM model_evaluation_challenge_events
            WHERE private_commitment_version=2 AND event_kind='issued'
              AND private_account_commitment=$1
              AND created_at > now() - ($2::bigint * interval '1 second')
            "#
        }
        "device" => {
            r#"
            SELECT COUNT(*)::bigint
            FROM model_evaluation_challenge_events
            WHERE private_commitment_version=2 AND event_kind='issued'
              AND private_device_commitment=$1
              AND created_at > now() - ($2::bigint * interval '1 second')
            "#
        }
        "node" => {
            r#"
            SELECT COUNT(*)::bigint
            FROM model_evaluation_challenge_events
            WHERE private_commitment_version=2 AND event_kind='issued'
              AND private_node_commitment=$1
              AND created_at > now() - ($2::bigint * interval '1 second')
            "#
        }
        _ => return Err(ApiError::internal()),
    };
    let count: i64 = sqlx::query_scalar(statement)
        .bind(scope_commitment)
        .bind(window_seconds)
        .fetch_one(&mut **tx)
        .await?;
    nonnegative_count(count)
}

fn nonnegative_count(count: i64) -> Result<u64, ApiError> {
    u64::try_from(count).map_err(|_| ApiError::internal())
}

#[allow(clippy::too_many_arguments)]
async fn insert_challenge_claim(
    _state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
    node_id: Uuid,
    model_id: Uuid,
    model_instance_id: Uuid,
    model_name: &str,
    model_weights_hash: &str,
    kind: PrivateEvaluationKind,
    generated: GeneratedChallenge,
    fixed_seed: Option<[u8; 32]>,
    private_metadata: Option<PrivateChallengeMetadata>,
    private_commitments: Option<PrivateV2Commitments>,
    lease_duration: time::Duration,
) -> Result<Option<ClaimJobResponse>, ApiError> {
    if !matches!(
        (
            kind,
            private_metadata.is_some(),
            private_commitments.is_some()
        ),
        (PrivateEvaluationKind::HiddenBenchmark, true, true)
            | (PrivateEvaluationKind::Canary, false, false)
    ) {
        return Err(ApiError::internal());
    }
    let mut seed = fixed_seed.unwrap_or([0_u8; 32]);
    if fixed_seed.is_none() {
        OsRng.fill_bytes(&mut seed);
    }
    let mut internal_lease_secret = [0_u8; 32];
    OsRng.fill_bytes(&mut internal_lease_secret);
    let payload = SensitiveEvaluationPayload(generated.standard_payload(model_name));
    let limits = payload.validated_limits().map_err(|error| {
        tracing::error!(error = %error, "服务端评价载荷生成失败");
        ApiError::internal()
    })?;
    let payload_json =
        Zeroizing::new(serde_json::to_vec(&*payload).map_err(|_| ApiError::internal())?);
    let encrypted_payload = BASE64_STANDARD.encode(&*payload_json);
    let challenge_id = Uuid::new_v4();
    let bare_prompt_hash = sha256_hex(generated.prompt.as_bytes());
    let bare_expected_hash = generated.expected_behavior_sha256.clone();
    let prompt_binding = private_commitments
        .as_ref()
        .map_or(bare_prompt_hash.as_str(), |value| value.prompt.as_str());
    let expected_binding = private_commitments
        .as_ref()
        .map_or(bare_expected_hash.as_str(), |value| value.expected.as_str());
    let stored_prompt_hash = private_commitments
        .is_none()
        .then_some(bare_prompt_hash.as_str());
    let stored_expected_hash = private_commitments
        .is_none()
        .then_some(bare_expected_hash.as_str());
    let lease_token_hash = sha256_hex(&internal_lease_secret);
    internal_lease_secret.fill(0);
    let challenge_nonce_hash = sha256_hex(&seed);
    let issued_at = postgres_timestamp_now()?;
    let initial_lease_expires_at = issued_at
        .checked_add(lease_duration)
        .ok_or_else(ApiError::internal)?;
    let lease_expires_at = private_metadata
        .as_ref()
        .map_or(initial_lease_expires_at, |value| {
            initial_lease_expires_at.min(value.catalog_valid_until)
        });
    let challenge_issued_expires_at = lease_expires_at;
    let private_binding = match (private_metadata.as_ref(), private_commitments.as_ref()) {
        (Some(metadata), Some(commitments)) => Some(PrivateChallengeBinding::V2 {
            commitments,
            catalog_valid_until: metadata.catalog_valid_until,
        }),
        (None, None) => None,
        _ => return Err(ApiError::internal()),
    };
    let challenge_binding_hash = challenge_binding_hash(&ChallengeBindingInput {
        challenge_id,
        model_id,
        model_instance_id,
        node_id,
        model_weights_hash,
        challenge_nonce_hash: &challenge_nonce_hash,
        prompt_binding,
        expected_binding,
        issued_at,
        challenge_issued_expires_at,
        authorized_input_tokens: limits.minimum_input_tokens,
        authorized_max_output_tokens: limits.maximum_output_tokens,
        inference_seed: generated.inference_seed,
        private_binding,
    });
    let inserted = sqlx::query(
        r#"
        INSERT INTO model_evaluation_challenges
            (id,model_id,model_instance_id,node_id,challenge_kind,challenge_seed,
             prompt_hash,expected_hash,lease_token_hash,status,issued_at,lease_expires_at,
             model_weights_hash,challenge_nonce_hash,challenge_binding_hash,
             challenge_issued_expires_at,authorized_input_tokens,
             authorized_max_output_tokens,inference_seed,
             private_catalog_id,private_catalog_entry_id,private_case_family,
             private_catalog_commitment,private_evaluator_id,
             private_evaluator_key_fingerprint,private_catalog_valid_until,
             claimed_user_id,claimed_device_key_id,claim_device_binding_version,
             private_commitment_version,private_catalog_statement_commitment,
             private_catalog_id_commitment,private_catalog_entry_commitment,
             private_case_family_commitment,private_evaluator_id_commitment,
             private_evaluator_key_commitment,private_prompt_commitment,
             private_expected_commitment,private_account_commitment,
             private_device_commitment,private_node_commitment)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'leased',$10,$11,$12,$13,$14,
                $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,
                $29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(challenge_id)
    .bind(model_id)
    .bind(model_instance_id)
    .bind(node_id)
    .bind(kind_name(kind))
    .bind(seed.as_slice())
    .bind(stored_prompt_hash)
    .bind(stored_expected_hash)
    .bind(&lease_token_hash)
    .bind(issued_at)
    .bind(lease_expires_at)
    .bind(model_weights_hash)
    .bind(&challenge_nonce_hash)
    .bind(&challenge_binding_hash)
    .bind(challenge_issued_expires_at)
    .bind(limits.minimum_input_tokens)
    .bind(limits.maximum_output_tokens)
    .bind(i64::from(generated.inference_seed))
    .bind(None::<&str>)
    .bind(None::<&str>)
    .bind(None::<&str>)
    .bind(None::<&str>)
    .bind(None::<&str>)
    .bind(None::<&str>)
    .bind(
        private_metadata
            .as_ref()
            .map(|value| value.catalog_valid_until),
    )
    .bind(principal.user_id)
    .bind(principal.device_key_id)
    .bind(DEVICE_BINDING_VERSION)
    .bind(
        private_commitments
            .as_ref()
            .map(|_| PRIVATE_COMMITMENT_VERSION),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|value| &value.catalog_statement),
    )
    .bind(private_commitments.as_ref().map(|value| &value.catalog_id))
    .bind(
        private_commitments
            .as_ref()
            .map(|value| &value.catalog_entry),
    )
    .bind(private_commitments.as_ref().map(|value| &value.case_family))
    .bind(
        private_commitments
            .as_ref()
            .map(|value| &value.evaluator_id),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|value| &value.evaluator_key),
    )
    .bind(private_commitments.as_ref().map(|value| &value.prompt))
    .bind(private_commitments.as_ref().map(|value| &value.expected))
    .bind(private_commitments.as_ref().map(|value| &value.account))
    .bind(private_commitments.as_ref().map(|value| &value.device))
    .bind(private_commitments.as_ref().map(|value| &value.node))
    .execute(&mut **tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return if private_commitments.is_some() {
            Ok(None)
        } else {
            Err(ApiError::internal())
        };
    }
    insert_lifecycle_event(
        tx,
        challenge_id,
        "issued",
        stored_prompt_hash,
        private_commitments.as_ref(),
        None,
        None,
    )
    .await?;

    Ok(Some(ClaimJobResponse {
        job_id: challenge_id,
        model_instance_id,
        model: model_name.to_owned(),
        model_weights_hash: model_weights_hash.to_owned(),
        encrypted_payload,
        payload_encoding: PayloadEncoding::Base64,
        tags: Vec::new(),
        estimated_input_tokens: limits.minimum_input_tokens,
        max_output_tokens: limits.maximum_output_tokens,
        attempt: 1,
        lease_expires_at,
        policy_check_required_before_execution: true,
        confidentiality: ConfidentialityMode::Standard,
        regulated_route_id: None,
        attestation_report_id: None,
        attestation_provider: None,
        tee_public_key: None,
    }))
}

fn postgres_timestamp_now() -> Result<OffsetDateTime, ApiError> {
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let rounded_to_microseconds = nanos.div_euclid(1_000) * 1_000;
    OffsetDateTime::from_unix_timestamp_nanos(rounded_to_microseconds)
        .map_err(|_| ApiError::internal())
}

struct ChallengeBindingInput<'a> {
    challenge_id: Uuid,
    model_id: Uuid,
    model_instance_id: Uuid,
    node_id: Uuid,
    model_weights_hash: &'a str,
    challenge_nonce_hash: &'a str,
    prompt_binding: &'a str,
    expected_binding: &'a str,
    issued_at: OffsetDateTime,
    challenge_issued_expires_at: OffsetDateTime,
    authorized_input_tokens: i32,
    authorized_max_output_tokens: i32,
    inference_seed: u32,
    private_binding: Option<PrivateChallengeBinding<'a>>,
}

enum PrivateChallengeBinding<'a> {
    Legacy(&'a PrivateChallengeMetadata),
    V2 {
        commitments: &'a PrivateV2Commitments,
        catalog_valid_until: OffsetDateTime,
    },
}

fn challenge_binding_hash(input: &ChallengeBindingInput<'_>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"mindone:hidden-challenge-binding:v1\0");
    digest.update(input.challenge_id.as_bytes());
    digest.update(input.model_id.as_bytes());
    digest.update(input.model_instance_id.as_bytes());
    digest.update(input.node_id.as_bytes());
    update_length_prefixed(&mut digest, input.model_weights_hash.as_bytes());
    update_length_prefixed(&mut digest, input.challenge_nonce_hash.as_bytes());
    update_length_prefixed(&mut digest, input.prompt_binding.as_bytes());
    update_length_prefixed(&mut digest, input.expected_binding.as_bytes());
    digest.update(input.issued_at.unix_timestamp_nanos().to_be_bytes());
    digest.update(
        input
            .challenge_issued_expires_at
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
    digest.update(input.authorized_input_tokens.to_be_bytes());
    digest.update(input.authorized_max_output_tokens.to_be_bytes());
    digest.update(input.inference_seed.to_be_bytes());
    match input.private_binding.as_ref() {
        Some(PrivateChallengeBinding::Legacy(metadata)) => {
            digest.update([1]);
            update_length_prefixed(&mut digest, metadata.catalog_id.as_bytes());
            update_length_prefixed(&mut digest, metadata.catalog_entry_id.as_bytes());
            update_length_prefixed(&mut digest, metadata.case_family.as_bytes());
            update_length_prefixed(&mut digest, metadata.catalog_commitment.as_bytes());
            update_length_prefixed(&mut digest, metadata.evaluator_id.as_bytes());
            update_length_prefixed(&mut digest, metadata.evaluator_key_fingerprint.as_bytes());
            digest.update(
                metadata
                    .catalog_valid_until
                    .unix_timestamp_nanos()
                    .to_be_bytes(),
            );
        }
        Some(PrivateChallengeBinding::V2 {
            commitments,
            catalog_valid_until,
        }) => {
            digest.update([2]);
            for commitment in [
                &commitments.catalog_statement,
                &commitments.catalog_id,
                &commitments.catalog_entry,
                &commitments.case_family,
                &commitments.evaluator_id,
                &commitments.evaluator_key,
                &commitments.prompt,
                &commitments.expected,
                &commitments.account,
                &commitments.device,
                &commitments.node,
            ] {
                update_length_prefixed(&mut digest, commitment.as_bytes());
            }
            digest.update(catalog_valid_until.unix_timestamp_nanos().to_be_bytes());
        }
        None => digest.update([0]),
    }
    hex::encode(digest.finalize())
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
}

/// 若 `job_id` 是隐藏评价，则在同一事务验证普通结果、服务端判分并完成质量审计。
pub(super) async fn submit_hidden_job_result(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
    request: &JobResultRequest,
) -> Result<Option<JobResultResponse>, ApiError> {
    let request_hash = submission_request_hash("result", request)?;
    let mut tx = state.pool.begin().await?;
    let row = hidden_job_row(&mut tx, job_id).await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let terminal_authorization =
        authorize_terminal_row(&row, state.private_evaluation_terminal_capability())?;
    let model_instance_id: Uuid = row.try_get("model_instance_id")?;
    lock_instance_canary_state(&mut tx, model_instance_id).await?;
    verify_worker_owner(&row, principal, request.node_id)?;
    if row
        .try_get::<Option<String>, _>("worker_submission_kind")?
        .is_some()
    {
        verify_idempotent_submission(&row, "result", &request.idempotency_key, &request_hash)?;
        let response = terminal_result_response(job_id, &row, true)?;
        finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
        tx.commit().await?;
        return Ok(Some(response));
    }
    let status: String = row.try_get("status")?;
    if matches!(status.as_str(), "failed" | "expired") {
        // expiry 是唯一不带 worker_submission_kind 的正常终态。后台 sweep 若在本次
        // 提交前先获锁，仍返回稳定的 lease_expired，并顺手修复旧版本遗留的 draining。
        finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
        tx.commit().await?;
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    if lease_is_expired(
        &status,
        row.try_get("lease_expires_at")?,
        OffsetDateTime::now_utc(),
    ) {
        complete_expired_failure(&mut tx, job_id, &row, terminal_authorization).await?;
        tx.commit().await?;
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    ensure_live_lease(&row)?;
    let kind = parse_kind(&row.try_get::<String, _>("challenge_kind")?)?;
    let seed = challenge_seed(&row)?;
    let authorization = verify_challenge_definition(&row, kind, &seed)?;
    let output = validate_and_extract_output(&row, &authorization, request)?;
    let normalized_output = output.trim();
    let passed = submitted_answer_matches(&row, normalized_output, terminal_authorization)?;
    let score_normalized = if passed { 1_000_000 } else { 0 };
    let result_hash = salted_commitment(job_id, &seed, request_hash.as_bytes());
    let model_id: Uuid = row.try_get("model_id")?;
    let update = model_quality_snapshot(&mut tx, model_id).await?;
    sqlx::query(
        r#"
        UPDATE model_evaluation_challenges
        SET challenge_seed=NULL,status=$2,result_hash=$3,score_normalized=$4,
            resulting_tier=$5,resulting_evaluation_samples=$6,completed_at=now(),
            worker_submission_kind='result',worker_idempotency_key=$7,
            worker_request_hash=$8
        WHERE id=$1
        "#,
    )
    .bind(job_id)
    .bind(if passed { "succeeded" } else { "failed" })
    .bind(&result_hash)
    .bind(score_normalized)
    .bind(&update.tier)
    .bind(update.evaluation_samples)
    .bind(&request.idempotency_key)
    .bind(&request_hash)
    .execute(&mut *tx)
    .await?;
    let (event_prompt_hash, event_commitments) = lifecycle_snapshot_from_row(&row)?;
    insert_lifecycle_event(
        &mut tx,
        job_id,
        "completed",
        event_prompt_hash.as_deref(),
        event_commitments.as_ref(),
        Some(&result_hash),
        Some(score_normalized),
    )
    .await?;
    record_private_authenticity_arbitration(
        &mut tx,
        job_id,
        model_id,
        model_instance_id,
        &row,
        passed,
        terminal_authorization,
    )
    .await?;
    record_instance_canary_signal(
        &mut tx,
        job_id,
        model_instance_id,
        passed,
        if passed {
            "answer_match"
        } else {
            "answer_mismatch"
        },
    )
    .await?;
    finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
    tx.commit().await?;
    Ok(Some(JobResultResponse {
        job_id,
        status: JobStatus::Succeeded,
        idempotent_replay: false,
    }))
}

/// 与普通 Standard 任务保持相同的“先校验结果协议、后校验租约绑定”顺序。
///
/// 普通任务的公开载荷可以在进入结算事务前校验；隐藏任务的载荷由 seed 重建，因此只在
/// 挑战仍处于 leased 状态时做同等预校验。终态重放仍由持久化的完整请求哈希验证，避免
/// 为了重放而保留已经销毁的私有 seed。
pub(super) async fn prevalidate_hidden_job_result(
    state: &AppState,
    job_id: Uuid,
    request: &JobResultRequest,
) -> Result<(), ApiError> {
    let mut tx = state.pool.begin().await?;
    let row = hidden_job_row(&mut tx, job_id)
        .await?
        .ok_or_else(ApiError::internal)?;
    if row.try_get::<String, _>("status")? == "leased" {
        let kind = parse_kind(&row.try_get::<String, _>("challenge_kind")?)?;
        let seed = challenge_seed(&row)?;
        let authorization = verify_challenge_definition(&row, kind, &seed)?;
        let _ = validate_and_extract_output(&row, &authorization, request)?;
    }
    tx.rollback().await?;
    Ok(())
}

/// 隐藏评价的执行失败同样使用普通 `/jobs/{id}/fail`，只保存 salted commitment。
pub(super) async fn submit_hidden_job_failure(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
    request: &JobFailRequest,
) -> Result<Option<JobFailResponse>, ApiError> {
    let request_hash = submission_request_hash("fail", request)?;
    let mut tx = state.pool.begin().await?;
    let row = hidden_job_row(&mut tx, job_id).await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };
    let terminal_authorization =
        authorize_terminal_row(&row, state.private_evaluation_terminal_capability())?;
    let model_instance_id: Uuid = row.try_get("model_instance_id")?;
    lock_instance_canary_state(&mut tx, model_instance_id).await?;
    verify_worker_owner(&row, principal, request.node_id)?;
    if row
        .try_get::<Option<String>, _>("worker_submission_kind")?
        .is_some()
    {
        verify_idempotent_submission(&row, "fail", &request.idempotency_key, &request_hash)?;
        finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
        tx.commit().await?;
        return Ok(Some(hidden_failure_response(job_id, true)));
    }
    let status: String = row.try_get("status")?;
    if matches!(status.as_str(), "failed" | "expired") {
        finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
        tx.commit().await?;
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    if lease_is_expired(
        &status,
        row.try_get("lease_expires_at")?,
        OffsetDateTime::now_utc(),
    ) {
        complete_expired_failure(&mut tx, job_id, &row, terminal_authorization).await?;
        tx.commit().await?;
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    ensure_live_lease(&row)?;
    let seed = challenge_seed(&row)?;
    let failure_hash = salted_commitment(job_id, &seed, request_hash.as_bytes());
    let update = model_quality_snapshot(&mut tx, row.try_get("model_id")?).await?;
    sqlx::query(
        r#"
        UPDATE model_evaluation_challenges
        SET challenge_seed=NULL,status='failed',result_hash=$2,score_normalized=0,
            resulting_tier=$3,resulting_evaluation_samples=$4,completed_at=now(),
            worker_submission_kind='fail',worker_idempotency_key=$5,
            worker_request_hash=$6
        WHERE id=$1
        "#,
    )
    .bind(job_id)
    .bind(&failure_hash)
    .bind(&update.tier)
    .bind(update.evaluation_samples)
    .bind(&request.idempotency_key)
    .bind(&request_hash)
    .execute(&mut *tx)
    .await?;
    let (event_prompt_hash, event_commitments) = lifecycle_snapshot_from_row(&row)?;
    insert_lifecycle_event(
        &mut tx,
        job_id,
        "worker_failed",
        event_prompt_hash.as_deref(),
        event_commitments.as_ref(),
        Some(&failure_hash),
        None,
    )
    .await?;
    insert_lifecycle_event(
        &mut tx,
        job_id,
        "completed",
        event_prompt_hash.as_deref(),
        event_commitments.as_ref(),
        Some(&failure_hash),
        Some(0),
    )
    .await?;
    record_private_authenticity_arbitration(
        &mut tx,
        job_id,
        row.try_get("model_id")?,
        model_instance_id,
        &row,
        false,
        terminal_authorization,
    )
    .await?;
    record_instance_canary_signal(&mut tx, job_id, model_instance_id, false, "worker_failed")
        .await?;
    finalize_draining_instance(&mut tx, Some(model_instance_id)).await?;
    tx.commit().await?;
    Ok(Some(hidden_failure_response(job_id, false)))
}

/// 普通 worker 会在长任务中自动续租，因此评价也必须走完全相同的续租 endpoint。
pub(super) enum HiddenRenewal {
    Renewed(RenewJobResponse),
    Expired,
}

pub(super) async fn renew_hidden_job(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    principal: &Principal,
    job_id: Uuid,
    node_id: Uuid,
) -> Result<Option<HiddenRenewal>, ApiError> {
    let row = hidden_job_row(tx, job_id).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let terminal_authorization =
        authorize_terminal_row(&row, state.private_evaluation_terminal_capability())?;
    // 普通任务使用一个包含 leased_to_node_id、status 与 lease 时效的查询，并把错误统一
    // 收口为 lease_not_renewable。隐藏任务必须保持同样的可观察结果，尤其不能让同账号
    // 的另一节点通过 403/409 差异探测挑战类型。
    if row.try_get::<Uuid, _>("user_id")? != principal.user_id
        || row.try_get::<Uuid, _>("node_id")? != node_id
        || row.try_get::<Option<Uuid>, _>("node_device_key_id")? != Some(principal.device_key_id)
        || !exact_claim_device_binding(
            principal,
            row.try_get("claimed_user_id")?,
            row.try_get("claimed_device_key_id")?,
            row.try_get("claim_device_binding_version")?,
        )
    {
        return Err(lease_not_renewable_error());
    }
    if row.try_get::<String, _>("status")? != "leased" {
        return Err(lease_not_renewable_error());
    }
    if row.try_get::<OffsetDateTime, _>("lease_expires_at")? <= OffsetDateTime::now_utc() {
        complete_expired_failure(tx, job_id, &row, terminal_authorization).await?;
        return Ok(Some(HiddenRenewal::Expired));
    }
    let now = OffsetDateTime::now_utc();
    let mut lease_expires_at = now
        .checked_add(
            time::Duration::try_from(state.config.lease_duration).map_err(|_| {
                tracing::error!("评价续租时长超出 time 支持范围");
                ApiError::internal()
            })?,
        )
        .ok_or_else(ApiError::internal)?;
    if let Some(catalog_valid_until) =
        row.try_get::<Option<OffsetDateTime>, _>("private_catalog_valid_until")?
    {
        if catalog_valid_until <= now {
            complete_expired_failure(tx, job_id, &row, terminal_authorization).await?;
            return Ok(Some(HiddenRenewal::Expired));
        }
        lease_expires_at = lease_expires_at.min(catalog_valid_until);
    }
    sqlx::query(
        "UPDATE model_evaluation_challenges SET lease_expires_at=$2 WHERE id=$1 AND status='leased'",
    )
    .bind(job_id)
    .bind(lease_expires_at)
    .execute(&mut **tx)
    .await?;
    Ok(Some(HiddenRenewal::Renewed(RenewJobResponse {
        job_id,
        lease_expires_at,
    })))
}

/// 在独立拥有的事务中持久化迟交/沉默逃避审计，避免随后返回 HTTP 冲突时回滚。
pub(super) async fn expire_hidden_job_if_needed(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
    node_id: Uuid,
) -> Result<bool, ApiError> {
    let mut tx = state.pool.begin().await?;
    let row = hidden_job_row(&mut tx, job_id).await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let terminal_authorization =
        authorize_terminal_row(&row, state.private_evaluation_terminal_capability())?;
    verify_worker_owner(&row, principal, node_id)?;
    let expired = lease_is_expired(
        &row.try_get::<String, _>("status")?,
        row.try_get("lease_expires_at")?,
        OffsetDateTime::now_utc(),
    );
    if expired {
        complete_expired_failure(&mut tx, job_id, &row, terminal_authorization).await?;
    }
    tx.commit().await?;
    Ok(expired)
}

/// 为同账号自调度场景合成普通任务详情，避免 hidden 直接 403 而 self-job 返回 200。
pub(super) async fn get_hidden_job_status(
    state: &AppState,
    principal: &Principal,
    job_id: Uuid,
) -> Result<Option<serde_json::Value>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT c.model_id,c.model_instance_id,c.node_id,c.status,c.lease_expires_at,
               c.worker_submission_kind,c.issued_at,c.completed_at,n.user_id
        FROM model_evaluation_challenges c JOIN nodes n ON n.id=c.node_id
        WHERE c.id=$1
        "#,
    )
    .bind(job_id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<Uuid, _>("user_id")? != principal.user_id {
        return Err(ApiError::forbidden("无权查看此任务"));
    }
    let internal_status: String = row.try_get("status")?;
    let submission_kind: Option<String> = row.try_get("worker_submission_kind")?;
    let status = if submission_kind.as_deref() == Some("result") {
        "succeeded"
    } else if submission_kind.as_deref() == Some("fail") || internal_status == "expired" {
        "failed"
    } else {
        internal_status.as_str()
    };
    let issued_at: OffsetDateTime = row.try_get("issued_at")?;
    let completed_at: Option<OffsetDateTime> = row.try_get("completed_at")?;
    Ok(Some(serde_json::json!({
        "job_id": job_id,
        "status": status,
        "model_id": row.try_get::<Uuid, _>("model_id")?,
        "model_instance_id": row.try_get::<Uuid, _>("model_instance_id")?,
        "tags": Vec::<String>::new(),
        "leased_to_node_id": row.try_get::<Uuid, _>("node_id")?,
        "lease_expires_at": row.try_get::<OffsetDateTime, _>("lease_expires_at")?,
        "attempt_count": 1,
        "max_attempts": state.config.max_job_retries.saturating_add(1).max(1),
        "actual_input_tokens": serde_json::Value::Null,
        "actual_output_tokens": serde_json::Value::Null,
        "result_ciphertext": serde_json::Value::Null,
        "confidentiality": "standard",
        "regulated_route_id": serde_json::Value::Null,
        "attestation_report_id": serde_json::Value::Null,
        "error_class": serde_json::Value::Null,
        "error_message": serde_json::Value::Null,
        "receipt_id": serde_json::Value::Null,
        "created_at": issued_at,
        "updated_at": completed_at.unwrap_or(issued_at),
        "completed_at": completed_at
    })))
}

async fn hidden_job_row(
    tx: &mut Transaction<'_, Postgres>,
    job_id: Uuid,
) -> Result<Option<sqlx::postgres::PgRow>, ApiError> {
    Ok(sqlx::query(
        r#"
        SELECT c.id,c.model_id,c.model_instance_id,c.node_id,c.challenge_kind,c.challenge_seed,
               c.prompt_hash,c.expected_hash,c.status,c.issued_at,c.lease_expires_at,
               c.score_normalized,c.resulting_tier,c.resulting_evaluation_samples,
               c.worker_submission_kind,c.worker_idempotency_key,c.worker_request_hash,
               c.model_weights_hash,c.challenge_nonce_hash,c.challenge_binding_hash,
               c.challenge_issued_expires_at,
               c.authorized_input_tokens,c.authorized_max_output_tokens,c.inference_seed,
               c.private_catalog_id,c.private_catalog_entry_id,c.private_case_family,
               c.private_catalog_commitment,c.private_evaluator_id,
               c.private_evaluator_key_fingerprint,c.private_catalog_valid_until,
               c.private_commitment_version,c.private_catalog_statement_commitment,
               c.private_catalog_id_commitment,c.private_catalog_entry_commitment,
               c.private_case_family_commitment,c.private_evaluator_id_commitment,
               c.private_evaluator_key_commitment,c.private_prompt_commitment,
               c.private_expected_commitment,c.private_account_commitment,
               c.private_device_commitment,c.private_node_commitment,
               c.claimed_user_id,c.claimed_device_key_id,c.claim_device_binding_version,
               n.user_id,n.device_key_id AS node_device_key_id,
               m.name AS model_name,m.weights_hash AS current_model_weights_hash
        FROM model_evaluation_challenges c
        JOIN nodes n ON n.id=c.node_id
        JOIN models m ON m.id=c.model_id
        WHERE c.id=$1
        FOR UPDATE OF c
        "#,
    )
    .bind(job_id)
    .fetch_optional(&mut **tx)
    .await?)
}

fn verify_worker_owner(
    row: &sqlx::postgres::PgRow,
    principal: &Principal,
    node_id: Uuid,
) -> Result<(), ApiError> {
    if row.try_get::<Uuid, _>("user_id")? != principal.user_id
        || row.try_get::<Uuid, _>("node_id")? != node_id
        || row.try_get::<Option<Uuid>, _>("node_device_key_id")? != Some(principal.device_key_id)
        || !exact_claim_device_binding(
            principal,
            row.try_get("claimed_user_id")?,
            row.try_get("claimed_device_key_id")?,
            row.try_get("claim_device_binding_version")?,
        )
    {
        return Err(ApiError::forbidden("任务租约不属于当前节点"));
    }
    Ok(())
}

fn ensure_live_lease(row: &sqlx::postgres::PgRow) -> Result<(), ApiError> {
    let status: String = row.try_get("status")?;
    if status != "leased" {
        return Err(ApiError::conflict("job_not_leased", "任务当前不接受提交"));
    }
    if lease_is_expired(
        &status,
        row.try_get("lease_expires_at")?,
        OffsetDateTime::now_utc(),
    ) {
        return Err(ApiError::conflict("lease_expired", "任务租约已经过期"));
    }
    Ok(())
}

fn lease_is_expired(status: &str, lease_expires_at: OffsetDateTime, now: OffsetDateTime) -> bool {
    status == "leased" && lease_expires_at <= now
}

fn lease_not_renewable_error() -> ApiError {
    ApiError::conflict(
        "lease_not_renewable",
        "任务租约不存在、已过期或不属于当前节点",
    )
}

fn verify_idempotent_submission(
    row: &sqlx::postgres::PgRow,
    kind: &str,
    idempotency_key: &str,
    request_hash: &str,
) -> Result<(), ApiError> {
    if row
        .try_get::<Option<String>, _>("worker_submission_kind")?
        .as_deref()
        != Some(kind)
        || row
            .try_get::<Option<String>, _>("worker_idempotency_key")?
            .as_deref()
            != Some(idempotency_key)
        || row
            .try_get::<Option<String>, _>("worker_request_hash")?
            .as_deref()
            != Some(request_hash)
    {
        return Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "任务幂等键已绑定到不同提交内容",
        ));
    }
    Ok(())
}

struct AuthorizedChallenge {
    model: String,
    minimum_input_tokens: i32,
    maximum_output_tokens: i32,
}

fn verify_challenge_definition(
    row: &sqlx::postgres::PgRow,
    kind: PrivateEvaluationKind,
    seed: &[u8; 32],
) -> Result<AuthorizedChallenge, ApiError> {
    let commitment_version: Option<i32> = row.try_get("private_commitment_version")?;
    let private_catalog_commitment: Option<String> = row.try_get("private_catalog_commitment")?;
    let generated = match commitment_version {
        Some(PRIVATE_COMMITMENT_VERSION) => {
            if kind != PrivateEvaluationKind::HiddenBenchmark
                || private_catalog_commitment.is_some()
                || private_v2_commitments_from_row(row)?.is_none()
            {
                return Err(ApiError::internal());
            }
            None
        }
        None if private_catalog_commitment.is_some() => {
            if kind != PrivateEvaluationKind::HiddenBenchmark {
                return Err(ApiError::internal());
            }
            None
        }
        None => {
            let generated = generate_legacy_challenge(kind, seed);
            verify_server_commitments(row, &generated)?;
            Some(generated)
        }
        Some(_) => return Err(ApiError::internal()),
    };
    verify_execution_binding_if_present(row, seed)?;

    let authorized_input_tokens: Option<i32> = row.try_get("authorized_input_tokens")?;
    let authorized_max_output_tokens: Option<i32> = row.try_get("authorized_max_output_tokens")?;
    match (authorized_input_tokens, authorized_max_output_tokens) {
        (Some(minimum_input_tokens), Some(maximum_output_tokens))
            if minimum_input_tokens > 0 && maximum_output_tokens > 0 =>
        {
            Ok(AuthorizedChallenge {
                model: "auto".to_owned(),
                minimum_input_tokens,
                maximum_output_tokens,
            })
        }
        (None, None) => {
            let generated = generated.ok_or_else(ApiError::internal)?;
            let model_name: String = row.try_get("model_name")?;
            let limits = generated
                .standard_payload(&model_name)
                .validated_limits()
                .map_err(|_| ApiError::internal())?;
            Ok(AuthorizedChallenge {
                model: limits.model,
                minimum_input_tokens: limits.minimum_input_tokens,
                maximum_output_tokens: limits.maximum_output_tokens,
            })
        }
        _ => Err(ApiError::internal()),
    }
}

fn validate_and_extract_output(
    _row: &sqlx::postgres::PgRow,
    authorization: &AuthorizedChallenge,
    request: &JobResultRequest,
) -> Result<Zeroizing<String>, ApiError> {
    let bytes = Zeroizing::new(
        BASE64_STANDARD
            .decode(&request.result_ciphertext)
            .map_err(|_| ApiError::bad_request("invalid_job_result", "任务结果 Base64 无效"))?,
    );
    if bytes.len() > 900_000 {
        return Err(ApiError::bad_request(
            "invalid_job_result",
            "任务结果超过允许大小",
        ));
    }
    let mut response =
        SensitiveChatCompletionsResponse(serde_json::from_slice(&bytes).map_err(|_| {
            ApiError::bad_request("invalid_job_result", "聊天任务结果不符合 OpenAI 响应协议")
        })?);
    if response.choices.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_job_result",
            "聊天任务结果缺少 choices",
        ));
    }
    if response.model != authorization.model {
        return Err(ApiError::bad_request(
            "model_binding_mismatch",
            "聊天任务结果模型与任务载荷不一致",
        ));
    }
    let mut content = std::mem::replace(
        &mut response.choices[0].message.content,
        MessageContent::Text(String::new()),
    );
    if !matches!(&content, MessageContent::Text(value) if !value.trim().is_empty()) {
        zeroize_message_content(&mut content);
        return Err(ApiError::bad_request(
            "invalid_job_result",
            "聊天任务结果必须包含非空文本",
        ));
    }
    let output = match std::mem::replace(&mut content, MessageContent::Text(String::new())) {
        MessageContent::Text(value) => Zeroizing::new(value),
        MessageContent::Parts(_) => return Err(ApiError::internal()),
    };
    let expected_total = response
        .usage
        .prompt_tokens
        .checked_add(response.usage.completion_tokens)
        .ok_or_else(|| ApiError::bad_request("invalid_job_result", "usage Token 总数溢出"))?;
    let prompt_tokens = i32::try_from(response.usage.prompt_tokens)
        .map_err(|_| ApiError::bad_request("invalid_job_result", "prompt_tokens 超出范围"))?;
    let completion_tokens = i32::try_from(response.usage.completion_tokens)
        .map_err(|_| ApiError::bad_request("invalid_job_result", "completion_tokens 超出范围"))?;
    if response.usage.total_tokens != expected_total
        || request.actual_input_tokens != prompt_tokens
        || request.actual_output_tokens != completion_tokens
    {
        return Err(ApiError::bad_request(
            "usage_binding_mismatch",
            "结果 usage 与节点上报的实际 Token 不一致",
        ));
    }
    if request.actual_input_tokens == 0 && request.actual_output_tokens == 0 {
        return Err(ApiError::bad_request(
            "invalid_usage",
            "Token 使用量不能为负数或全部为零",
        ));
    }
    if request.actual_input_tokens > authorization.minimum_input_tokens
        || request.actual_output_tokens > authorization.maximum_output_tokens
    {
        return Err(ApiError::bad_request(
            "usage_exceeds_authorized_limit",
            "节点上报的 Token 使用量超过任务授权上限",
        ));
    }
    Ok(output)
}

fn submitted_answer_matches(
    row: &sqlx::postgres::PgRow,
    normalized_output: &str,
    authorization: TerminalMutationAuthorization<'_>,
) -> Result<bool, ApiError> {
    match row.try_get::<Option<i32>, _>("private_commitment_version")? {
        None => {
            let expected_hash = row
                .try_get::<Option<String>, _>("expected_hash")?
                .ok_or_else(ApiError::internal)?;
            let submitted_answer_hash = sha256_hex(normalized_output.as_bytes());
            Ok(constant_time_equal(
                expected_hash.as_bytes(),
                submitted_answer_hash.as_bytes(),
            ))
        }
        Some(PRIVATE_COMMITMENT_VERSION) => {
            let TerminalMutationAuthorization::V2(capability) = authorization else {
                return Err(ApiError::internal());
            };
            let expected_commitment = row
                .try_get::<Option<String>, _>("private_expected_commitment")?
                .ok_or_else(ApiError::internal)?;
            let normalized_digest = Sha256::digest(normalized_output.as_bytes());
            private_evaluation_commitment_matches_hex(
                capability.hmac_key(),
                PrivateEvaluationCommitmentDomain::ExpectedBehavior,
                normalized_digest.as_ref(),
                &expected_commitment,
            )
            .map_err(|_| ApiError::internal())
        }
        Some(_) => Err(ApiError::internal()),
    }
}

fn verify_execution_binding_if_present(
    row: &sqlx::postgres::PgRow,
    seed: &[u8; 32],
) -> Result<(), ApiError> {
    let stored_binding: Option<String> = row.try_get("challenge_binding_hash")?;
    let Some(stored_binding) = stored_binding else {
        return Ok(());
    };
    let stored_nonce_hash = row
        .try_get::<Option<String>, _>("challenge_nonce_hash")?
        .ok_or_else(ApiError::internal)?;
    let actual_nonce_hash = sha256_hex(seed);
    if !constant_time_equal(stored_nonce_hash.as_bytes(), actual_nonce_hash.as_bytes()) {
        return Err(ApiError::internal());
    }
    let stored_weights_hash = row
        .try_get::<Option<String>, _>("model_weights_hash")?
        .ok_or_else(ApiError::internal)?;
    let current_weights_hash: String = row.try_get("current_model_weights_hash")?;
    if !constant_time_equal(
        stored_weights_hash.as_bytes(),
        current_weights_hash.as_bytes(),
    ) {
        return Err(ApiError::conflict(
            "model_binding_mismatch",
            "任务绑定的模型实例权重已经变化",
        ));
    }
    let inference_seed = row
        .try_get::<Option<i64>, _>("inference_seed")?
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(ApiError::internal)?;
    let private_metadata = private_metadata_from_row(row)?;
    let private_commitments = private_v2_commitments_from_row(row)?;
    let legacy_prompt_binding = if private_commitments.is_none() {
        Some(
            row.try_get::<Option<String>, _>("prompt_hash")?
                .ok_or_else(ApiError::internal)?,
        )
    } else {
        None
    };
    let legacy_expected_binding = if private_commitments.is_none() {
        Some(
            row.try_get::<Option<String>, _>("expected_hash")?
                .ok_or_else(ApiError::internal)?,
        )
    } else {
        None
    };
    let prompt_binding = private_commitments
        .as_ref()
        .map(|commitments| commitments.prompt.as_str())
        .or(legacy_prompt_binding.as_deref())
        .ok_or_else(ApiError::internal)?;
    let expected_binding_value = private_commitments
        .as_ref()
        .map(|commitments| commitments.expected.as_str())
        .or(legacy_expected_binding.as_deref())
        .ok_or_else(ApiError::internal)?;
    let private_binding = match (private_metadata.as_ref(), private_commitments.as_ref()) {
        (Some(metadata), None) => Some(PrivateChallengeBinding::Legacy(metadata)),
        (None, Some(commitments)) => Some(PrivateChallengeBinding::V2 {
            commitments,
            catalog_valid_until: row
                .try_get::<Option<OffsetDateTime>, _>("private_catalog_valid_until")?
                .ok_or_else(ApiError::internal)?,
        }),
        (None, None) => None,
        (Some(_), Some(_)) => return Err(ApiError::internal()),
    };
    let expected_binding = challenge_binding_hash(&ChallengeBindingInput {
        challenge_id: row.try_get("id")?,
        model_id: row.try_get("model_id")?,
        model_instance_id: row.try_get("model_instance_id")?,
        node_id: row.try_get("node_id")?,
        model_weights_hash: &stored_weights_hash,
        challenge_nonce_hash: &stored_nonce_hash,
        prompt_binding,
        expected_binding: expected_binding_value,
        issued_at: row.try_get("issued_at")?,
        challenge_issued_expires_at: row
            .try_get::<Option<OffsetDateTime>, _>("challenge_issued_expires_at")?
            .ok_or_else(ApiError::internal)?,
        authorized_input_tokens: row
            .try_get::<Option<i32>, _>("authorized_input_tokens")?
            .ok_or_else(ApiError::internal)?,
        authorized_max_output_tokens: row
            .try_get::<Option<i32>, _>("authorized_max_output_tokens")?
            .ok_or_else(ApiError::internal)?,
        inference_seed,
        private_binding,
    });
    if !constant_time_equal(stored_binding.as_bytes(), expected_binding.as_bytes()) {
        return Err(ApiError::internal());
    }
    Ok(())
}

fn private_metadata_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<PrivateChallengeMetadata>, ApiError> {
    if row
        .try_get::<Option<i32>, _>("private_commitment_version")?
        .is_some()
    {
        return Ok(None);
    }
    let catalog_commitment: Option<String> = row.try_get("private_catalog_commitment")?;
    let Some(catalog_commitment) = catalog_commitment else {
        return Ok(None);
    };
    Ok(Some(PrivateChallengeMetadata {
        catalog_id: row
            .try_get::<Option<String>, _>("private_catalog_id")?
            .ok_or_else(ApiError::internal)?,
        catalog_entry_id: row
            .try_get::<Option<String>, _>("private_catalog_entry_id")?
            .ok_or_else(ApiError::internal)?,
        case_family: row
            .try_get::<Option<String>, _>("private_case_family")?
            .ok_or_else(ApiError::internal)?,
        catalog_commitment,
        evaluator_id: row
            .try_get::<Option<String>, _>("private_evaluator_id")?
            .ok_or_else(ApiError::internal)?,
        evaluator_key_fingerprint: row
            .try_get::<Option<String>, _>("private_evaluator_key_fingerprint")?
            .ok_or_else(ApiError::internal)?,
        catalog_valid_until: row
            .try_get::<Option<OffsetDateTime>, _>("private_catalog_valid_until")?
            .ok_or_else(ApiError::internal)?,
    }))
}

fn private_v2_commitments_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<Option<PrivateV2Commitments>, ApiError> {
    match row.try_get::<Option<i32>, _>("private_commitment_version")? {
        None => Ok(None),
        Some(PRIVATE_COMMITMENT_VERSION) => Ok(Some(PrivateV2Commitments {
            catalog_statement: required_commitment(row, "private_catalog_statement_commitment")?,
            catalog_id: required_commitment(row, "private_catalog_id_commitment")?,
            catalog_entry: required_commitment(row, "private_catalog_entry_commitment")?,
            case_family: required_commitment(row, "private_case_family_commitment")?,
            evaluator_id: required_commitment(row, "private_evaluator_id_commitment")?,
            evaluator_key: required_commitment(row, "private_evaluator_key_commitment")?,
            prompt: required_commitment(row, "private_prompt_commitment")?,
            expected: required_commitment(row, "private_expected_commitment")?,
            account: required_commitment(row, "private_account_commitment")?,
            device: required_commitment(row, "private_device_commitment")?,
            node: required_commitment(row, "private_node_commitment")?,
        })),
        Some(_) => Err(ApiError::internal()),
    }
}

fn required_commitment(row: &sqlx::postgres::PgRow, column: &str) -> Result<String, ApiError> {
    let commitment = row
        .try_get::<Option<String>, _>(column)?
        .ok_or_else(ApiError::internal)?;
    if commitment.len() != 64
        || !commitment
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::internal());
    }
    Ok(commitment)
}

async fn record_private_authenticity_arbitration(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    model_id: Uuid,
    model_instance_id: Uuid,
    row: &sqlx::postgres::PgRow,
    passed: bool,
    authorization: TerminalMutationAuthorization<'_>,
) -> Result<(), ApiError> {
    let private_metadata = private_metadata_from_row(row)?;
    let private_commitments = private_v2_commitments_from_row(row)?;
    let (arbitration_version, evaluator_scope, case_scope) = match (
        private_metadata.as_ref(),
        private_commitments.as_ref(),
        authorization,
    ) {
        (Some(metadata), None, TerminalMutationAuthorization::Legacy) => (
            1_i32,
            metadata.evaluator_key_fingerprint.as_str(),
            metadata.case_family.as_str(),
        ),
        (None, Some(commitments), TerminalMutationAuthorization::V2(_)) => (
            PRIVATE_COMMITMENT_VERSION,
            commitments.evaluator_key.as_str(),
            commitments.case_family.as_str(),
        ),
        (None, None, TerminalMutationAuthorization::Legacy) => return Ok(()),
        _ => return Err(ApiError::internal()),
    };
    if row.try_get::<String, _>("challenge_kind")? != "hidden_benchmark" {
        return Err(ApiError::internal());
    };
    let model_weights_hash = row
        .try_get::<Option<String>, _>("model_weights_hash")?
        .ok_or_else(ApiError::internal)?;
    let challenge_binding_hash = row
        .try_get::<Option<String>, _>("challenge_binding_hash")?
        .ok_or_else(ApiError::internal)?;
    let arbitration_scope = private_arbitration_scope_key(
        arbitration_version,
        &model_weights_hash,
        evaluator_scope,
        case_scope,
    );
    sqlx::query(
        r#"
        SELECT pg_advisory_xact_lock(
            hashtextextended($1, 0)
        )
        "#,
    )
    .bind(arbitration_scope)
    .execute(&mut **tx)
    .await?;
    let previous = sqlx::query(
        r#"
        WITH latest_per_instance AS (
            SELECT DISTINCT ON (model_instance_id) model_instance_id,passed
            FROM model_authenticity_arbitration_events
            WHERE model_weights_hash=$1
              AND (
                  ($2=1 AND private_commitment_version IS NULL
                      AND private_evaluator_key_fingerprint=$3
                      AND private_case_family=$4)
                  OR
                  ($2=2 AND private_commitment_version=2
                      AND private_evaluator_key_commitment=$3
                      AND private_case_family_commitment=$4)
              )
              AND model_instance_id<>$5
            ORDER BY model_instance_id,created_at DESC,id DESC
        )
        SELECT COUNT(*)::bigint AS observed,
               COUNT(*) FILTER (WHERE passed)::bigint AS passed,
               COUNT(*) FILTER (WHERE NOT passed)::bigint AS failed
        FROM latest_per_instance
        "#,
    )
    .bind(&model_weights_hash)
    .bind(arbitration_version)
    .bind(evaluator_scope)
    .bind(case_scope)
    .bind(model_instance_id)
    .fetch_one(&mut **tx)
    .await?;
    let observed = previous
        .try_get::<i64, _>("observed")?
        .checked_add(1)
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(ApiError::internal)?;
    let passing = previous
        .try_get::<i64, _>("passed")?
        .checked_add(i64::from(passed))
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(ApiError::internal)?;
    let failing = previous
        .try_get::<i64, _>("failed")?
        .checked_add(i64::from(!passed))
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(ApiError::internal)?;
    let verdict = if observed < 2 {
        "pending"
    } else if failing == 0 && passing >= 2 {
        "corroborated"
    } else {
        "disputed"
    };
    sqlx::query(
        r#"
        INSERT INTO model_authenticity_arbitration_events
            (id,challenge_id,model_id,model_instance_id,model_weights_hash,
             private_evaluator_key_fingerprint,private_catalog_commitment,
             private_case_family,passed,
             observed_distinct_instances,passed_distinct_instances,
             failed_distinct_instances,verdict,challenge_binding_hash,
             private_commitment_version,private_catalog_statement_commitment,
             private_catalog_id_commitment,private_catalog_entry_commitment,
             private_case_family_commitment,private_evaluator_id_commitment,
             private_evaluator_key_commitment,private_prompt_commitment,
             private_expected_commitment,private_account_commitment,
             private_device_commitment,private_node_commitment)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                $15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(challenge_id)
    .bind(model_id)
    .bind(model_instance_id)
    .bind(model_weights_hash)
    .bind(
        private_metadata
            .as_ref()
            .map(|metadata| &metadata.evaluator_key_fingerprint),
    )
    .bind(
        private_metadata
            .as_ref()
            .map(|metadata| &metadata.catalog_commitment),
    )
    .bind(
        private_metadata
            .as_ref()
            .map(|metadata| &metadata.case_family),
    )
    .bind(passed)
    .bind(observed)
    .bind(passing)
    .bind(failing)
    .bind(verdict)
    .bind(challenge_binding_hash)
    .bind(
        private_commitments
            .as_ref()
            .map(|_| PRIVATE_COMMITMENT_VERSION),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.catalog_statement),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.catalog_id),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.catalog_entry),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.case_family),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.evaluator_id),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.evaluator_key),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.prompt),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.expected),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.account),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.device),
    )
    .bind(
        private_commitments
            .as_ref()
            .map(|commitments| &commitments.node),
    )
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn private_arbitration_scope_key(
    version: i32,
    model_weights_hash: &str,
    evaluator_key_fingerprint: &str,
    case_family: &str,
) -> String {
    let mut digest = Sha256::new();
    if version == 1 {
        digest.update(b"mindone:model-authenticity-arbitration-scope:v1\0");
    } else {
        digest.update(b"mindone:model-authenticity-arbitration-scope:v2\0");
        digest.update(version.to_be_bytes());
    }
    update_length_prefixed(&mut digest, model_weights_hash.as_bytes());
    update_length_prefixed(&mut digest, evaluator_key_fingerprint.as_bytes());
    update_length_prefixed(&mut digest, case_family.as_bytes());
    hex::encode(digest.finalize())
}

fn verify_server_commitments(
    row: &sqlx::postgres::PgRow,
    generated: &GeneratedChallenge,
) -> Result<(), ApiError> {
    let prompt_hash: String = row.try_get("prompt_hash")?;
    let expected_hash: String = row.try_get("expected_hash")?;
    if !constant_time_equal(
        prompt_hash.as_bytes(),
        sha256_hex(generated.prompt.as_bytes()).as_bytes(),
    ) || !constant_time_equal(
        expected_hash.as_bytes(),
        generated.expected_behavior_sha256.as_bytes(),
    ) {
        tracing::error!("私有评价 seed 与服务端承诺不一致");
        return Err(ApiError::internal());
    }
    Ok(())
}

fn challenge_seed(row: &sqlx::postgres::PgRow) -> Result<[u8; 32], ApiError> {
    row.try_get::<Option<Vec<u8>>, _>("challenge_seed")?
        .ok_or_else(ApiError::internal)?
        .try_into()
        .map_err(|_| ApiError::internal())
}

struct ModelQualitySnapshot {
    tier: String,
    evaluation_samples: i32,
}

/// 单个 Standard 实例的自报结果不是模型真实性证明；只写 exact-instance challenge
/// 审计，不直接升降共享 canonical model 的全局质量。
async fn model_quality_snapshot(
    tx: &mut Transaction<'_, Postgres>,
    model_id: Uuid,
) -> Result<ModelQualitySnapshot, ApiError> {
    let row = sqlx::query("SELECT tier,evaluation_samples FROM models WHERE id=$1 FOR SHARE")
        .bind(model_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(ModelQualitySnapshot {
        tier: row.try_get("tier")?,
        evaluation_samples: row.try_get("evaluation_samples")?,
    })
}

/// 与消费者路由共用的 exact-instance 事务锁，关闭“路由刚读到健康状态、另一事务立即
/// 隔离”的窗口。锁键只含公开 UUID 派生哈希，不包含 Prompt、结果或 Secret。
pub(crate) async fn lock_instance_canary_state(
    tx: &mut Transaction<'_, Postgres>,
    model_instance_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        SELECT pg_advisory_xact_lock(
            hashtextextended('mindone:instance-canary:' || $1::text, 0)
        )
        "#,
    )
    .bind(model_instance_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn instance_canary_quarantined(
    tx: &mut Transaction<'_, Postgres>,
    model_instance_id: Uuid,
) -> Result<bool, ApiError> {
    lock_instance_canary_state(tx, model_instance_id).await?;
    Ok(sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM model_instance_canary_state
            WHERE model_instance_id=$1 AND quarantined=TRUE
        )
        "#,
    )
    .bind(model_instance_id)
    .fetch_one(&mut **tx)
    .await?)
}

/// 把有限公开模板的结果只作为 exact-instance 风险信号处理。
///
/// 可变状态与挑战终态处于同一事务；每个信号和隔离/恢复转换另写只追加事件。这里不更新
/// canonical model 的质量或 Tier，因为 Standard worker 的自报输出不是模型执行证明。
async fn record_instance_canary_signal(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    model_instance_id: Uuid,
    passed: bool,
    reason_code: &str,
) -> Result<(), ApiError> {
    lock_instance_canary_state(tx, model_instance_id).await?;
    sqlx::query(
        r#"
        INSERT INTO model_instance_canary_state (model_instance_id)
        VALUES ($1)
        ON CONFLICT (model_instance_id) DO NOTHING
        "#,
    )
    .bind(model_instance_id)
    .execute(&mut **tx)
    .await?;
    let state = sqlx::query(
        r#"
        SELECT consecutive_failures,recovery_passes,quarantined
        FROM model_instance_canary_state
        WHERE model_instance_id=$1
        FOR UPDATE
        "#,
    )
    .bind(model_instance_id)
    .fetch_one(&mut **tx)
    .await?;
    let old_failures: i32 = state.try_get("consecutive_failures")?;
    let old_recovery_passes: i32 = state.try_get("recovery_passes")?;
    let was_quarantined: bool = state.try_get("quarantined")?;

    let (new_failures, observed_recovery_passes, new_quarantined) = if passed {
        let recovery_passes = if was_quarantined {
            old_recovery_passes.saturating_add(1).min(1_000_000)
        } else {
            0
        };
        (
            0,
            recovery_passes,
            was_quarantined && recovery_passes < RECOVERY_PASS_THRESHOLD,
        )
    } else {
        let failures = old_failures.saturating_add(1).min(1_000_000);
        (
            failures,
            0,
            was_quarantined || failures >= QUARANTINE_FAILURE_THRESHOLD,
        )
    };
    let state_recovery_passes = if new_quarantined {
        observed_recovery_passes
    } else {
        0
    };

    sqlx::query(
        r#"
        UPDATE model_instance_canary_state
        SET consecutive_failures=$2,recovery_passes=$3,quarantined=$4,
            last_challenge_id=$5,
            quarantined_at=CASE WHEN $4 AND NOT $6 THEN now() ELSE quarantined_at END,
            recovered_at=CASE WHEN NOT $4 AND $6 THEN now() ELSE recovered_at END,
            updated_at=now()
        WHERE model_instance_id=$1
        "#,
    )
    .bind(model_instance_id)
    .bind(new_failures)
    .bind(state_recovery_passes)
    .bind(new_quarantined)
    .bind(challenge_id)
    .bind(was_quarantined)
    .execute(&mut **tx)
    .await?;

    insert_canary_risk_event(
        tx,
        challenge_id,
        model_instance_id,
        if passed {
            "signal_passed"
        } else {
            "signal_failed"
        },
        reason_code,
        new_failures,
        observed_recovery_passes,
        new_quarantined,
    )
    .await?;

    if !was_quarantined && new_quarantined {
        insert_canary_risk_event(
            tx,
            challenge_id,
            model_instance_id,
            "quarantined",
            reason_code,
            new_failures,
            0,
            true,
        )
        .await?;
        tracing::warn!(
            %model_instance_id,
            %challenge_id,
            consecutive_failures = new_failures,
            "模型实例因连续 canary 风险信号进入路由隔离"
        );
    } else if was_quarantined && !new_quarantined {
        insert_canary_risk_event(
            tx,
            challenge_id,
            model_instance_id,
            "recovered",
            reason_code,
            0,
            observed_recovery_passes,
            false,
        )
        .await?;
        tracing::warn!(
            %model_instance_id,
            %challenge_id,
            recovery_passes = observed_recovery_passes,
            "模型实例通过连续 canary 后解除路由隔离"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_canary_risk_event(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    model_instance_id: Uuid,
    event_kind: &str,
    reason_code: &str,
    consecutive_failures: i32,
    recovery_passes: i32,
    quarantined: bool,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO model_instance_canary_events
            (id,model_instance_id,challenge_id,event_kind,reason_code,
             consecutive_failures,recovery_passes,quarantined)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(model_instance_id)
    .bind(challenge_id)
    .bind(event_kind)
    .bind(reason_code)
    .bind(consecutive_failures)
    .bind(recovery_passes)
    .bind(quarantined)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn expire_stale_challenges(
    state: &AppState,
    tx: &mut Transaction<'_, Postgres>,
    node_id: Uuid,
) -> Result<(), ApiError> {
    let expired = sqlx::query(
        r#"
        SELECT id,model_id,model_instance_id,challenge_kind,challenge_seed,prompt_hash,
               model_weights_hash,challenge_binding_hash,private_catalog_id,
               private_catalog_entry_id,private_case_family,private_catalog_commitment,
               private_evaluator_id,private_evaluator_key_fingerprint,
               private_catalog_valid_until,private_commitment_version,
               private_catalog_statement_commitment,private_catalog_id_commitment,
               private_catalog_entry_commitment,private_case_family_commitment,
               private_evaluator_id_commitment,private_evaluator_key_commitment,
               private_prompt_commitment,private_expected_commitment,
               private_account_commitment,private_device_commitment,
               private_node_commitment
        FROM model_evaluation_challenges
        WHERE node_id=$1 AND status='leased' AND lease_expires_at <= now()
        ORDER BY id
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .bind(node_id)
    .fetch_all(&mut **tx)
    .await?;
    for row in expired {
        let authorization =
            authorize_terminal_row(&row, state.private_evaluation_terminal_capability())?;
        complete_expired_failure(tx, row.try_get("id")?, &row, authorization).await?;
    }
    Ok(())
}

/// 请求路径之外的有界过期扫描。`SKIP LOCKED` 允许多个协调器副本并发运行，
/// 每个 challenge 的行锁和精确实例 advisory lock 仍保证终态与风险计数只提交一次。
pub(crate) async fn sweep_expired_hidden_jobs(
    pool: &PgPool,
    capability: Option<PrivateEvaluationTerminalCapability<'_>>,
    include_v2: bool,
) -> Result<u64, ApiError> {
    let mut tx = pool.begin().await?;
    let expired = sqlx::query(
        r#"
        SELECT id,model_id,model_instance_id,challenge_kind,challenge_seed,prompt_hash,
               model_weights_hash,challenge_binding_hash,private_catalog_id,
               private_catalog_entry_id,private_case_family,private_catalog_commitment,
               private_evaluator_id,private_evaluator_key_fingerprint,
               private_catalog_valid_until,private_commitment_version,
               private_catalog_statement_commitment,private_catalog_id_commitment,
               private_catalog_entry_commitment,private_case_family_commitment,
               private_evaluator_id_commitment,private_evaluator_key_commitment,
               private_prompt_commitment,private_expected_commitment,
               private_account_commitment,private_device_commitment,
               private_node_commitment
        FROM model_evaluation_challenges
        WHERE status='leased' AND lease_expires_at <= now()
          AND ($2::boolean OR private_commitment_version IS NULL)
        ORDER BY lease_expires_at,id
        FOR UPDATE SKIP LOCKED
        LIMIT $1
        "#,
    )
    .bind(EXPIRY_SWEEP_BATCH_SIZE)
    .bind(include_v2)
    .fetch_all(&mut *tx)
    .await?;
    let completed = u64::try_from(expired.len()).map_err(|_| ApiError::internal())?;
    for row in expired {
        let authorization = authorize_terminal_row(&row, capability)?;
        complete_expired_failure(&mut tx, row.try_get("id")?, &row, authorization).await?;
    }
    tx.commit().await?;
    Ok(completed)
}

async fn complete_expired_failure(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    row: &sqlx::postgres::PgRow,
    authorization: TerminalMutationAuthorization<'_>,
) -> Result<(), ApiError> {
    // capability 校验必须位于第一条持久化 mutation 之前；失败时不能写终态、事件或仲裁。
    verify_terminal_authorization(row, authorization)?;
    let model_instance_id: Uuid = row.try_get("model_instance_id")?;
    lock_instance_canary_state(tx, model_instance_id).await?;
    let seed = challenge_seed(row)?;
    let result_hash = salted_commitment(challenge_id, &seed, b"lease-expired");
    let update = model_quality_snapshot(tx, row.try_get("model_id")?).await?;
    sqlx::query(
        r#"
        UPDATE model_evaluation_challenges
        SET challenge_seed=NULL,status='failed',result_hash=$2,score_normalized=0,
            resulting_tier=$3,resulting_evaluation_samples=$4,completed_at=now()
        WHERE id=$1 AND status='leased'
        "#,
    )
    .bind(challenge_id)
    .bind(&result_hash)
    .bind(&update.tier)
    .bind(update.evaluation_samples)
    .execute(&mut **tx)
    .await?;
    let (event_prompt_hash, event_commitments) = lifecycle_snapshot_from_row(row)?;
    insert_lifecycle_event(
        tx,
        challenge_id,
        "expired",
        event_prompt_hash.as_deref(),
        event_commitments.as_ref(),
        None,
        None,
    )
    .await?;
    insert_lifecycle_event(
        tx,
        challenge_id,
        "completed",
        event_prompt_hash.as_deref(),
        event_commitments.as_ref(),
        Some(&result_hash),
        Some(0),
    )
    .await?;
    record_private_authenticity_arbitration(
        tx,
        challenge_id,
        row.try_get("model_id")?,
        model_instance_id,
        row,
        false,
        authorization,
    )
    .await?;
    record_instance_canary_signal(tx, challenge_id, model_instance_id, false, "lease_expired")
        .await?;
    finalize_draining_instance(tx, Some(model_instance_id)).await
}

async fn insert_lifecycle_event(
    tx: &mut Transaction<'_, Postgres>,
    challenge_id: Uuid,
    event_kind: &str,
    prompt_hash: Option<&str>,
    private_commitments: Option<&PrivateV2Commitments>,
    result_hash: Option<&str>,
    score_normalized: Option<i32>,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO model_evaluation_challenge_events
            (id,challenge_id,event_kind,prompt_hash,result_hash,score_normalized,
             private_commitment_version,private_catalog_statement_commitment,
             private_catalog_id_commitment,private_catalog_entry_commitment,
             private_case_family_commitment,private_evaluator_id_commitment,
             private_evaluator_key_commitment,private_prompt_commitment,
             private_expected_commitment,private_account_commitment,
             private_device_commitment,private_node_commitment)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
        ON CONFLICT (challenge_id,event_kind) DO NOTHING
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(challenge_id)
    .bind(event_kind)
    .bind(prompt_hash)
    .bind(result_hash)
    .bind(score_normalized)
    .bind(private_commitments.map(|_| PRIVATE_COMMITMENT_VERSION))
    .bind(private_commitments.map(|value| &value.catalog_statement))
    .bind(private_commitments.map(|value| &value.catalog_id))
    .bind(private_commitments.map(|value| &value.catalog_entry))
    .bind(private_commitments.map(|value| &value.case_family))
    .bind(private_commitments.map(|value| &value.evaluator_id))
    .bind(private_commitments.map(|value| &value.evaluator_key))
    .bind(private_commitments.map(|value| &value.prompt))
    .bind(private_commitments.map(|value| &value.expected))
    .bind(private_commitments.map(|value| &value.account))
    .bind(private_commitments.map(|value| &value.device))
    .bind(private_commitments.map(|value| &value.node))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn lifecycle_snapshot_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<(Option<String>, Option<PrivateV2Commitments>), ApiError> {
    let commitments = private_v2_commitments_from_row(row)?;
    if commitments.is_some() {
        if row.try_get::<Option<String>, _>("prompt_hash")?.is_some() {
            return Err(ApiError::internal());
        }
        Ok((None, commitments))
    } else {
        Ok((
            Some(
                row.try_get::<Option<String>, _>("prompt_hash")?
                    .ok_or_else(ApiError::internal)?,
            ),
            None,
        ))
    }
}

fn terminal_result_response(
    job_id: Uuid,
    row: &sqlx::postgres::PgRow,
    idempotent_replay: bool,
) -> Result<JobResultResponse, ApiError> {
    let status: String = row.try_get("status")?;
    if !matches!(status.as_str(), "succeeded" | "failed") {
        return Err(ApiError::conflict("job_not_leased", "任务当前不接受结果"));
    }
    Ok(JobResultResponse {
        job_id,
        status: JobStatus::Succeeded,
        idempotent_replay,
    })
}

fn hidden_failure_response(job_id: Uuid, idempotent_replay: bool) -> JobFailResponse {
    JobFailResponse {
        job_id,
        accepted: true,
        idempotent_replay,
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct GeneratedChallenge {
    prompt: String,
    expected_behavior_sha256: String,
    max_output_tokens: u32,
    temperature_tenths: u8,
    inference_seed: u32,
}

impl GeneratedChallenge {
    fn from_private_entry(entry: PrivateEvaluationCatalogEntry) -> Self {
        Self {
            prompt: entry.prompt.clone(),
            expected_behavior_sha256: entry.expected_behavior_sha256.clone(),
            max_output_tokens: entry.max_output_tokens,
            temperature_tenths: 0,
            inference_seed: entry.inference_seed,
        }
    }

    fn standard_payload(&self, _served_model: &str) -> StandardJobPayload {
        StandardJobPayload {
            endpoint: mindone_protocol::OPENAI_CHAT_COMPLETIONS.to_owned(),
            request: serde_json::json!({
                "model": "auto",
                "messages": [{"role": "user", "content": self.prompt}],
                "stream": false,
                "temperature": f64::from(self.temperature_tenths) / 10.0,
                "top_p": 1.0,
                "seed": self.inference_seed,
                "max_tokens": self.max_output_tokens
            }),
        }
    }
}

fn generate_public_canary(seed: &[u8; 32]) -> GeneratedChallenge {
    generate_legacy_challenge(PrivateEvaluationKind::Canary, seed)
}

/// 只用于公开 canary，以及滚动升级期间完成旧版本已经签发的有限模板 hidden 行。
/// 新 hidden benchmark 永远不能从此仓库内函数生成。
fn generate_legacy_challenge(kind: PrivateEvaluationKind, seed: &[u8; 32]) -> GeneratedChallenge {
    let max_output_tokens = [16_u32, 24, 32, 48, 64, 96][usize::from(seed[10] % 6)];
    let temperature_tenths = seed[11] % 4;
    let inference_seed = u32::from_be_bytes([seed[12], seed[13], seed[14], seed[15]]);
    match kind {
        PrivateEvaluationKind::HiddenBenchmark => {
            let left = u32::from(u16::from_be_bytes([seed[0], seed[1]])) % 9_000 + 1_000;
            let right = u32::from(u16::from_be_bytes([seed[2], seed[3]])) % 9_000 + 1_000;
            let small_left = left % 97 + 3;
            let small_right = right % 29 + 2;
            let (prompt, expected) = match seed[5] % 8 {
                0 => (
                    format!("请直接给出 {left} 与 {right} 的和，只写一个整数。"),
                    (left + right).to_string(),
                ),
                1 => (
                    format!("不展示步骤：{left} 加上 {right} 等于多少？仅回答数字。"),
                    (left + right).to_string(),
                ),
                2 => (
                    format!("算一下 {}-{}。回复中不要包含解释。", left + right, right),
                    left.to_string(),
                ),
                3 => (
                    format!("只写结果：{small_left} 乘以 {small_right}。"),
                    (small_left * small_right).to_string(),
                ),
                4 => (
                    format!("三个数 {left}、{right}、{} 中最大的是哪个？", left / 2),
                    left.max(right).to_string(),
                ),
                5 => (
                    format!("把 {left} 除以 10 后的整数余数告诉我，只回复余数。"),
                    (left % 10).to_string(),
                ),
                6 => (
                    format!("从 {right} 开始再向后数 {small_right} 个整数，最后一个是多少？"),
                    (right + small_right).to_string(),
                ),
                _ => (
                    format!("我只需要最终整数：把 {right} 增加 {left} 后是多少？"),
                    (left + right).to_string(),
                ),
            };
            GeneratedChallenge {
                prompt,
                expected_behavior_sha256: sha256_hex(expected.as_bytes()),
                max_output_tokens,
                temperature_tenths,
                inference_seed,
            }
        }
        PrivateEvaluationKind::Canary => {
            let letters = seed[..8]
                .iter()
                .map(|byte| char::from(b'A' + (byte % 26)))
                .collect::<String>();
            let reversed = letters.chars().rev().collect::<String>();
            let (prompt, expected) = match seed[8] % 8 {
                0 => (
                    format!("请把字符串 {letters} 原样回复，不要添加其他文字。"),
                    letters,
                ),
                1 => (format!("只输出这八个大写字母：{letters}"), letters),
                2 => (
                    format!("下面是我要核对的短码，回复短码本身即可：{letters}"),
                    letters,
                ),
                3 => (
                    format!("请在回答中仅保留括号内的内容（{letters}）。"),
                    letters,
                ),
                4 => (
                    format!("把 {letters} 按字符倒序输出，除此之外不要写内容。"),
                    reversed,
                ),
                5 => (
                    format!("将大写字符串 {letters} 转成小写后直接回复。"),
                    letters.to_ascii_lowercase(),
                ),
                6 => (
                    format!("字符串 {letters} 有几个字符？只回答整数。"),
                    letters.chars().count().to_string(),
                ),
                _ => (
                    format!("只回复 {letters} 的前三个字符。"),
                    letters.chars().take(3).collect(),
                ),
            };
            GeneratedChallenge {
                prompt,
                expected_behavior_sha256: sha256_hex(expected.as_bytes()),
                max_output_tokens,
                temperature_tenths,
                inference_seed,
            }
        }
    }
}

fn prompt_has_no_private_marker(prompt: &str) -> bool {
    let lower = prompt.to_ascii_lowercase();
    [
        "mindone",
        "evaluation",
        "benchmark",
        "canary",
        "评价",
        "评测",
    ]
    .iter()
    .all(|marker| !lower.contains(marker))
}

fn submission_request_hash<T: serde::Serialize>(
    kind: &str,
    request: &T,
) -> Result<String, ApiError> {
    let encoded = serde_json::to_vec(request).map_err(|_| ApiError::internal())?;
    let mut digest = Sha256::new();
    digest.update(b"mindone:hidden-job-submission:v1\0");
    digest.update(kind.as_bytes());
    digest.update([0]);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn salted_commitment(job_id: Uuid, seed: &[u8; 32], value: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"mindone:hidden-job-result:v1\0");
    digest.update(job_id.as_bytes());
    digest.update(seed);
    digest.update(value);
    hex::encode(digest.finalize())
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

const fn kind_name(kind: PrivateEvaluationKind) -> &'static str {
    match kind {
        PrivateEvaluationKind::HiddenBenchmark => "hidden_benchmark",
        PrivateEvaluationKind::Canary => "canary",
    }
}

fn parse_kind(value: &str) -> Result<PrivateEvaluationKind, ApiError> {
    match value {
        "hidden_benchmark" => Ok(PrivateEvaluationKind::HiddenBenchmark),
        "canary" => Ok(PrivateEvaluationKind::Canary),
        _ => Err(ApiError::internal()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluation_payload_and_generated_challenge_zeroize_owned_secrets() {
        let mut payload = SensitiveEvaluationPayload(StandardJobPayload {
            endpoint: "/v1/chat/completions".to_owned(),
            request: serde_json::json!({
                "messages": [{"role": "user", "content": "private prompt"}],
                "nested": {"secret-key": "private response"}
            }),
        });
        payload.zeroize_owned();
        assert!(payload.0.endpoint.is_empty());
        assert_eq!(payload.0.request, serde_json::Value::Null);

        let mut generated = GeneratedChallenge {
            prompt: "private prompt".to_owned(),
            expected_behavior_sha256: "a".repeat(64),
            max_output_tokens: 32,
            temperature_tenths: 2,
            inference_seed: 99,
        };
        generated.zeroize();
        assert!(generated.prompt.is_empty());
        assert!(generated.expected_behavior_sha256.is_empty());
        assert_eq!(generated.max_output_tokens, 0);
        assert_eq!(generated.temperature_tenths, 0);
        assert_eq!(generated.inference_seed, 0);
    }

    #[test]
    fn public_canary_prompts_are_randomized_natural_requests_without_markers() {
        for discriminator in 0..8_u8 {
            let mut seed = [7_u8; 32];
            seed[8] = discriminator;
            let generated = generate_public_canary(&seed);
            assert!(prompt_has_no_private_marker(&generated.prompt));
            assert_eq!(generated.expected_behavior_sha256.len(), 64);
        }
    }

    #[test]
    fn private_behavior_fingerprint_rejects_fixed_response() {
        let expected = "目标权重的私有行为";
        let generated = GeneratedChallenge::from_private_entry(PrivateEvaluationCatalogEntry {
            entry_id: "entry-private-a".to_owned(),
            case_family: "family-private".to_owned(),
            model_weights_sha256: "a".repeat(64),
            prompt: "仅测试使用的私有探针".to_owned(),
            expected_behavior_sha256: sha256_hex(expected.as_bytes()),
            inference_seed: 91,
            max_output_tokens: 32,
        });
        assert!(constant_time_equal(
            generated.expected_behavior_sha256.as_bytes(),
            sha256_hex(expected.trim().as_bytes()).as_bytes()
        ));
        assert!(!constant_time_equal(
            generated.expected_behavior_sha256.as_bytes(),
            sha256_hex(b"fixed-response").as_bytes()
        ));
    }

    #[test]
    fn hidden_claim_uses_only_public_claim_fields_without_private_markers() {
        let hidden = ClaimJobResponse {
            job_id: Uuid::from_u128(1),
            model_instance_id: Uuid::from_u128(2),
            model: "model".to_owned(),
            model_weights_hash: "11".repeat(32),
            encrypted_payload: "e30=".to_owned(),
            payload_encoding: PayloadEncoding::Base64,
            tags: Vec::new(),
            estimated_input_tokens: 1024,
            max_output_tokens: 32,
            attempt: 1,
            lease_expires_at: OffsetDateTime::UNIX_EPOCH,
            policy_check_required_before_execution: true,
            confidentiality: ConfidentialityMode::Standard,
            regulated_route_id: None,
            attestation_report_id: None,
            attestation_provider: None,
            tee_public_key: None,
        };
        let hidden_value = serde_json::to_value(hidden).expect("隐藏任务可序列化");
        let actual_keys = hidden_value
            .as_object()
            .expect("应为对象")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected_keys = [
            "attempt",
            "confidentiality",
            "encrypted_payload",
            "estimated_input_tokens",
            "job_id",
            "lease_expires_at",
            "max_output_tokens",
            "model",
            "model_instance_id",
            "model_weights_hash",
            "payload_encoding",
            "policy_check_required_before_execution",
            "tags",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual_keys, expected_keys);
        let wire = hidden_value.to_string().to_ascii_lowercase();
        for marker in ["evaluation", "benchmark", "canary", "challenge", "kind"] {
            assert!(!wire.contains(marker), "wire 泄露了标记 {marker}");
        }
    }

    #[test]
    fn result_commitment_and_idempotency_hash_bind_full_submission() {
        let job_id = Uuid::from_u128(1);
        let first = salted_commitment(job_id, &[1_u8; 32], b"same output");
        let second = salted_commitment(job_id, &[2_u8; 32], b"same output");
        assert_ne!(first, second);
        assert!(constant_time_equal(first.as_bytes(), first.as_bytes()));
        assert!(!constant_time_equal(first.as_bytes(), second.as_bytes()));
    }

    #[test]
    fn private_arbitration_scope_separates_evaluator_trust_domains() {
        let weights = "1".repeat(64);
        let first = private_arbitration_scope_key(1, &weights, &"2".repeat(64), "shared-family");
        let second = private_arbitration_scope_key(1, &weights, &"3".repeat(64), "shared-family");
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(
            first,
            private_arbitration_scope_key(2, &weights, &"2".repeat(64), "shared-family")
        );
    }

    #[test]
    fn v2_failure_without_prepared_capability_stops_before_all_terminal_writes() {
        let mut challenge_terminal_writes = 0;
        let mut lifecycle_event_writes = 0;
        let mut arbitration_writes = 0;
        let result =
            authorize_terminal_mutation(Some(PRIVATE_COMMITMENT_VERSION), None).map(|_| {
                challenge_terminal_writes += 1;
                lifecycle_event_writes += 2;
                arbitration_writes += 1;
            });
        assert!(result.is_err());
        assert_eq!(challenge_terminal_writes, 0);
        assert_eq!(lifecycle_event_writes, 0);
        assert_eq!(arbitration_writes, 0);
    }

    #[test]
    fn v2_expiry_without_prepared_capability_stops_before_events_and_arbitration() {
        let mut expired_event_writes = 0;
        let mut completed_event_writes = 0;
        let mut arbitration_writes = 0;
        let result =
            authorize_terminal_mutation(Some(PRIVATE_COMMITMENT_VERSION), None).map(|_| {
                expired_event_writes += 1;
                completed_event_writes += 1;
                arbitration_writes += 1;
            });
        assert!(result.is_err());
        assert_eq!(expired_event_writes, 0);
        assert_eq!(completed_event_writes, 0);
        assert_eq!(arbitration_writes, 0);
    }

    #[test]
    fn legacy_terminal_mutation_remains_authorized_without_private_capability() {
        assert!(matches!(
            authorize_terminal_mutation(None, None),
            Ok(TerminalMutationAuthorization::Legacy)
        ));
    }

    #[test]
    fn private_budget_caps_cooldown_and_reserve_fail_closed() {
        let budget = PrivateEvaluationBudgetConfig {
            catalog_hourly_limit: 10,
            account_hourly_limit: 4,
            device_hourly_limit: 3,
            node_hourly_limit: 2,
            cooldown: std::time::Duration::from_secs(60),
            global_reserve_entries: 2,
        };
        let allowed = PrivateBudgetSnapshot {
            catalog_hourly: 9,
            account_hourly: 3,
            device_hourly: 2,
            node_hourly: 1,
            identity_in_cooldown: false,
            remaining_catalog_entries: 3,
            account_seen_in_catalog: true,
            device_seen_in_catalog: true,
            node_seen_in_catalog: true,
        };
        assert!(private_budget_snapshot_allows(&budget, allowed));
        for denied in [
            PrivateBudgetSnapshot {
                catalog_hourly: 10,
                ..allowed
            },
            PrivateBudgetSnapshot {
                account_hourly: 4,
                ..allowed
            },
            PrivateBudgetSnapshot {
                device_hourly: 3,
                ..allowed
            },
            PrivateBudgetSnapshot {
                node_hourly: 2,
                ..allowed
            },
            PrivateBudgetSnapshot {
                identity_in_cooldown: true,
                ..allowed
            },
        ] {
            assert!(!private_budget_snapshot_allows(&budget, denied));
        }

        let reserve_boundary_for_new_identity = PrivateBudgetSnapshot {
            remaining_catalog_entries: 2,
            account_seen_in_catalog: false,
            device_seen_in_catalog: false,
            node_seen_in_catalog: false,
            ..allowed
        };
        assert!(private_budget_snapshot_allows(
            &budget,
            reserve_boundary_for_new_identity
        ));
        assert!(!private_budget_snapshot_allows(
            &budget,
            PrivateBudgetSnapshot {
                account_seen_in_catalog: true,
                ..reserve_boundary_for_new_identity
            }
        ));
        let reserve_disabled = PrivateEvaluationBudgetConfig {
            global_reserve_entries: 0,
            ..budget
        };
        assert!(private_budget_snapshot_allows(
            &reserve_disabled,
            PrivateBudgetSnapshot {
                remaining_catalog_entries: 0,
                account_seen_in_catalog: true,
                device_seen_in_catalog: true,
                node_seen_in_catalog: true,
                ..allowed
            }
        ));
    }

    #[test]
    fn v2_binding_separately_covers_initial_lease_and_catalog_validity() {
        let commitments = PrivateV2Commitments {
            catalog_statement: "01".repeat(32),
            catalog_id: "02".repeat(32),
            catalog_entry: "03".repeat(32),
            case_family: "04".repeat(32),
            evaluator_id: "05".repeat(32),
            evaluator_key: "06".repeat(32),
            prompt: "07".repeat(32),
            expected: "08".repeat(32),
            account: "09".repeat(32),
            device: "0a".repeat(32),
            node: "0b".repeat(32),
        };
        let issued_at = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(10);
        let initial_lease = issued_at + time::Duration::seconds(60);
        let catalog_validity = issued_at + time::Duration::hours(1);
        let binding = |initial_lease, catalog_validity| {
            challenge_binding_hash(&ChallengeBindingInput {
                challenge_id: Uuid::from_u128(1),
                model_id: Uuid::from_u128(2),
                model_instance_id: Uuid::from_u128(3),
                node_id: Uuid::from_u128(4),
                model_weights_hash: &"11".repeat(32),
                challenge_nonce_hash: &"12".repeat(32),
                prompt_binding: &commitments.prompt,
                expected_binding: &commitments.expected,
                issued_at,
                challenge_issued_expires_at: initial_lease,
                authorized_input_tokens: 128,
                authorized_max_output_tokens: 32,
                inference_seed: 7,
                private_binding: Some(PrivateChallengeBinding::V2 {
                    commitments: &commitments,
                    catalog_valid_until: catalog_validity,
                }),
            })
        };
        let original = binding(initial_lease, catalog_validity);
        assert_ne!(
            original,
            binding(initial_lease + time::Duration::seconds(1), catalog_validity)
        );
        assert_ne!(
            original,
            binding(initial_lease, catalog_validity + time::Duration::seconds(1))
        );
    }

    #[test]
    fn lease_expiry_boundary_is_inclusive_only_for_leased_work() {
        let boundary = OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(30);
        assert!(!lease_is_expired(
            "leased",
            boundary + time::Duration::nanoseconds(1),
            boundary
        ));
        assert!(lease_is_expired("leased", boundary, boundary));
        assert!(lease_is_expired(
            "leased",
            boundary - time::Duration::nanoseconds(1),
            boundary
        ));
        assert!(!lease_is_expired("failed", boundary, boundary));
    }
}
