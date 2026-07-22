use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use axum::{serve, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use futures_util::stream;
use mindone_accounting::{LedgerEntry, LedgerKind, LEDGER_HASH_VERSION};
use mindone_protocol::{
    CreateJobRequest, CreateJobResponse, CreateRegulatedJobRequest, JobErrorClass, JobResponse,
    JobStatus, JobStreamEvent, JobStreamReadResponse, LedgerEntryResponse, LedgerNamespace,
    LedgerRecomputationStatus, ModelListResponse, ModelsResponse, OpenAiError, OpenAiErrorResponse,
    OpenAiModel, PayloadEncoding, PrepareRegulatedJobRequest, PrepareRegulatedJobResponse,
    QuotaBalanceResponse, QuotaHistoryQuery, QuotaHistoryResponse, ReceiptResponse,
    RegulatedEnvelope, ReserveStatusResponse, StandardJobPayload, Validate,
    DEFAULT_NETWORK_MAX_OUTPUT_TOKENS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{ConfidentialityArg, QuotaHistoryArgs, QuotaReceiptArgs, QuotaUseArgs};
use crate::context::AppContext;
use crate::coordinator::CoordinatorClient;
use crate::error::{CliError, CliResult};
use crate::output::{CommandOutput, OutputMode};
use crate::vault::{CredentialBundle, SystemVault};

const JOB_WAIT_TIMEOUT: Duration = Duration::from_secs(600);
const JOB_POLL_INTERVAL: Duration = Duration::from_secs(1);
const STREAM_POLL_INTERVAL: Duration = Duration::from_millis(200);
const STREAM_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const STREAM_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
struct ProxyState {
    coordinator: CoordinatorClient,
    session: Arc<RwLock<CredentialBundle>>,
    vault: Arc<SystemVault>,
    default_model: String,
    confidentiality: ConfidentialityArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LocalLedgerVerification {
    CanonicalV2Verified,
    LegacyV1Unverifiable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifiedHistoryEntry {
    #[serde(flatten)]
    entry: LedgerEntryResponse,
    local_verification: LocalLedgerVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifiedHistoryResponse {
    entries: Vec<VerifiedHistoryEntry>,
    next_cursor: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct BalanceOutput {
    #[serde(flatten)]
    quota: QuotaBalanceResponse,
    reserve_total_inflow_micro: i64,
    reserve_total_outflow_micro: i64,
    reserve_ledger_entries: i64,
}

#[derive(Debug, Clone, Copy)]
struct InferenceMetadata {
    estimated_input_tokens: i32,
    max_output_tokens: i32,
    stream: bool,
}

enum ProxyStreamTerminal {
    Done,
    Error(String),
}

struct ProxyStreamState {
    proxy: ProxyState,
    job_id: Uuid,
    next_sequence: i32,
    pending: VecDeque<JobStreamEvent>,
    terminal: Option<ProxyStreamTerminal>,
    finished: bool,
    deadline: Instant,
    last_output: Instant,
    coordinator_failure_since: Option<Instant>,
}

struct SensitiveStandardJobPayload(StandardJobPayload);

impl std::ops::Deref for SensitiveStandardJobPayload {
    type Target = StandardJobPayload;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveStandardJobPayload {
    fn drop(&mut self) {
        self.0.endpoint.zeroize();
        zeroize_json_value(&mut self.0.request);
    }
}

struct SensitiveCreateJobRequest(CreateJobRequest);

impl std::ops::Deref for SensitiveCreateJobRequest {
    type Target = CreateJobRequest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveCreateJobRequest {
    fn drop(&mut self) {
        self.0.encrypted_payload.zeroize();
    }
}

struct SensitiveJsonValue(Value);

impl std::ops::Deref for SensitiveJsonValue {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveJsonValue {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

#[derive(Serialize)]
#[serde(transparent)]
struct SensitiveJsonResponse(Value);

impl Drop for SensitiveJsonResponse {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

fn zeroize_json_value(value: &mut Value) {
    match std::mem::take(value) {
        Value::String(mut text) => text.zeroize(),
        Value::Array(mut values) => {
            for nested in &mut values {
                zeroize_json_value(nested);
            }
        }
        Value::Object(values) => {
            for (mut key, mut nested) in values {
                key.zeroize();
                zeroize_json_value(&mut nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

pub async fn balance(context: &AppContext) -> CliResult<CommandOutput> {
    let response: QuotaBalanceResponse = context
        .authorized_get(mindone_protocol::QUOTA_BALANCE)
        .await?;
    let reserve: ReserveStatusResponse = context.authorized_get(mindone_protocol::RESERVE).await?;
    let tier = response
        .node_tier
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| "Unranked".to_owned());
    CommandOutput::new(
        format!(
            "可支配额度：{}\n已预留额度：{}\n当前可用额度：{}\n贡献值：{}\n节点等级：{}\n网络准备金流入：{}\n网络准备金流出：{}\n网络准备金余额：{}\n更新时间：{}",
            format_micro(response.spendable_micro),
            format_micro(response.reserved_micro),
            format_micro(response.available_micro),
            format_micro(response.contribution_micro),
            tier,
            format_micro(reserve.total_inflow_micro),
            format_micro(reserve.total_outflow_micro),
            format_micro(reserve.balance_micro),
            response.updated_at
        ),
        BalanceOutput {
            quota: response,
            reserve_total_inflow_micro: reserve.total_inflow_micro,
            reserve_total_outflow_micro: reserve.total_outflow_micro,
            reserve_ledger_entries: reserve.ledger_entries,
        },
    )
}

pub async fn history(context: &AppContext, args: &QuotaHistoryArgs) -> CliResult<CommandOutput> {
    validate_history_args(args)?;
    let mut cursor = None;
    let mut target = VerifiedHistoryResponse {
        entries: Vec::new(),
        next_cursor: None,
    };
    for current_page in 1..=args.page {
        let query = QuotaHistoryQuery {
            limit: Some(i64::from(args.page_size)),
            cursor,
            after: args.from.clone(),
            before: args.to.clone(),
        };
        let path = history_path(&query);
        let response: QuotaHistoryResponse = context.authorized_get(&path).await?;
        let response = verify_history_response(response)?;
        if current_page == args.page {
            target = response;
            break;
        }
        let Some(next_cursor) = response.next_cursor else {
            break;
        };
        cursor = Some(next_cursor);
    }

    let human = if target.entries.is_empty() {
        format!("第 {} 页没有账本记录", args.page)
    } else {
        let lines = target
            .entries
            .iter()
            .map(|item| {
                let receipt = item
                    .entry
                    .receipt_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_owned());
                let local_verification = match item.local_verification {
                    LocalLedgerVerification::CanonicalV2Verified => "canonical-v2-已本地复算",
                    LocalLedgerVerification::LegacyV1Unverifiable => {
                        "legacy-v1-不可按当前 schema 重算"
                    }
                };
                format!(
                    "{} | {} | {:?} | {} | {} | hash={} | receipt={}",
                    item.entry.created_at,
                    item.entry.id,
                    item.entry.ledger,
                    item.entry.entry_type,
                    format_micro(item.entry.delta_micro),
                    local_verification,
                    receipt
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "第 {} 页，共 {} 条\n{}",
            args.page,
            target.entries.len(),
            lines
        )
    };
    CommandOutput::new(human, target)
}

fn verify_history_response(response: QuotaHistoryResponse) -> CliResult<VerifiedHistoryResponse> {
    let entries = response
        .entries
        .into_iter()
        .map(|entry| {
            let local_verification = verify_history_entry(&entry)?;
            Ok(VerifiedHistoryEntry {
                entry,
                local_verification,
            })
        })
        .collect::<CliResult<Vec<_>>>()?;
    Ok(VerifiedHistoryResponse {
        entries,
        next_cursor: response.next_cursor,
    })
}

fn verify_history_entry(entry: &LedgerEntryResponse) -> CliResult<LocalLedgerVerification> {
    match entry.recomputation_status {
        LedgerRecomputationStatus::LegacyV1Unverifiable => {
            if entry.hash_version != 1 || !entry.metadata.is_empty() {
                return Err(CliError::General(format!(
                    "账本记录 {} 的 legacy v1 标记与版本或 metadata 不一致",
                    entry.id
                )));
            }
            Ok(LocalLedgerVerification::LegacyV1Unverifiable)
        }
        LedgerRecomputationStatus::CanonicalV2Recomputable => {
            if entry.hash_version != LEDGER_HASH_VERSION {
                return Err(CliError::General(format!(
                    "账本记录 {} 声称可按 canonical v2 重算，但 hash_version={}",
                    entry.id, entry.hash_version
                )));
            }
            let canonical = LedgerEntry {
                hash_version: entry.hash_version,
                id: entry.id,
                account_id: entry.account_id,
                request_id: entry.request_id,
                idempotency_key: entry.idempotency_key.clone(),
                kind: ledger_kind(entry)?,
                amount_micro: entry.delta_micro,
                balance_before_micro: entry.balance_before_micro,
                balance_after_micro: entry.balance_after_micro,
                created_at: entry.created_at,
                previous_hash: entry.prev_hash.clone(),
                metadata: entry.metadata.clone(),
                hash: entry.entry_hash.clone(),
            };
            canonical.validate().map_err(|error| {
                CliError::General(format!("账本记录 {} 本地重算失败：{error}", entry.id))
            })?;
            Ok(LocalLedgerVerification::CanonicalV2Verified)
        }
    }
}

fn ledger_kind(entry: &LedgerEntryResponse) -> CliResult<LedgerKind> {
    let kind = match (entry.ledger, entry.entry_type.as_str()) {
        (LedgerNamespace::Quota, "consumer_deduction") => LedgerKind::ConsumerDeduction,
        (LedgerNamespace::Quota, "node_reward") => LedgerKind::NodeQuotaCredit,
        (LedgerNamespace::Quota, "bootstrap_grant") => LedgerKind::BootstrapGrant,
        (LedgerNamespace::Quota, "operator_grant") => LedgerKind::OperatorGrant,
        (LedgerNamespace::Contribution, "node_contribution") => LedgerKind::ContributionCredit,
        (LedgerNamespace::Reserve, "settlement_inflow") => LedgerKind::ReserveInflow,
        (LedgerNamespace::Reserve, "verification" | "retry" | "bandwidth" | "peak_capacity") => {
            LedgerKind::ReserveRelease
        }
        _ => {
            return Err(CliError::General(format!(
                "账本记录 {} 的 scope 与 entry_type 组合不受 canonical v2 支持",
                entry.id
            )))
        }
    };
    Ok(kind)
}

pub async fn receipt(context: &AppContext, args: &QuotaReceiptArgs) -> CliResult<CommandOutput> {
    let receipt_id = Uuid::parse_str(&args.id)
        .map_err(|_| CliError::General("荣誉账单 ID 必须是合法 UUID".to_owned()))?;
    let response: ReceiptResponse = context
        .authorized_get(&mindone_protocol::quota_receipt(receipt_id))
        .await?;
    let performance_premium_micro =
        signed_performance_delta(response.user_deduction_micro, response.base_cost_micro)?;
    let billing_section = if let Some(billing) = response.billing.as_ref() {
        format!(
            "[ 服务器参考上界计费 ]\n计费合同      ：{}\nProfile       ：{}（版本 {}）\nProfile 指纹 ：{}\n证据哈希      ：{}\n模型权重哈希  ：{}\n参考硬件      ：{}\n授权 Token    ：输入 {} / 最大输出 {} / 计费上界 {}\n参考 GPU 时间：{} 微秒\n参考显存积分  ：{} MiB·微秒\nToken 分项    ：{}\nGPU 分项      ：{}\n显存分项      ：{}\n物理基础成本  ：{}\nProfile 有效期：{} 至 {}\n",
            billing.contract_version,
            billing.profile_id,
            billing.profile_version,
            billing.profile_fingerprint,
            billing.profile_evidence_hash,
            billing.model_weights_hash,
            billing.reference_hardware_class,
            billing.authorized_input_tokens,
            billing.authorized_max_output_tokens,
            billing.billable_tokens,
            billing.reference_gpu_time_us,
            billing.reference_vram_mib_microseconds,
            format_micro(billing.token_cost_micro),
            format_micro(billing.gpu_cost_micro),
            format_micro(billing.vram_cost_micro),
            format_micro(billing.base_cost_micro),
            billing.profile_valid_from,
            billing.profile_valid_until,
        )
    } else {
        "[ 历史计费 ]\n此账单早于服务器参考上界计费合同，仅保留旧版结算总额。\n".to_owned()
    };
    CommandOutput::new(
        format!(
            "==================================================\n          MINDONE HONOR RECEIPT（荣誉账单）\n==================================================\n账单 ID       ：{}\n任务 ID       ：{}\n模型          ：{}（{:?}）\n信任等级      ：{:?}\n结算时间      ：{}\n\n{}\n[ 成本拆解 ]\n基础算力成本  ：{}\n性能倍率差额  ：{}\n用户扣除      ：{}\n\n[ 节点收益 ]\n可用额度      ：{}\n贡献值        ：{}\n网络准备金流入：{}\n\n结算哈希      ：{}\n==================================================",
            response.receipt_id,
            response.job_id,
            response.model,
            response.tier,
            response.trust_level,
            response.created_at,
            billing_section,
            format_micro(response.base_cost_micro),
            format_micro(performance_premium_micro),
            format_micro(response.user_deduction_micro),
            format_micro(response.node_quota_micro),
            format_micro(response.contribution_micro),
            format_micro(response.reserve_micro),
            response.settlement_hash
        ),
        response,
    )
}

fn signed_performance_delta(user_deduction_micro: i64, base_cost_micro: i64) -> CliResult<i64> {
    user_deduction_micro
        .checked_sub(base_cost_micro)
        .ok_or_else(|| CliError::General("荣誉账单的性能倍率差额超出整数范围".to_owned()))
}

pub async fn use_proxy(
    context: &AppContext,
    args: &QuotaUseArgs,
    output_mode: OutputMode,
) -> CliResult<CommandOutput> {
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), args.port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| CliError::General(format!("无法监听 127.0.0.1:{}：{error}", args.port)))?;
    let session = context.vault.load_session()?;
    let state = ProxyState {
        coordinator: context.coordinator.clone(),
        session: Arc::new(RwLock::new(session)),
        vault: Arc::new(context.vault.clone()),
        default_model: args.model.clone(),
        confidentiality: args.confidentiality,
    };
    let app = Router::new()
        .route(mindone_protocol::OPENAI_MODELS, get(proxy_models))
        .route(mindone_protocol::OPENAI_CHAT_COMPLETIONS, post(proxy_chat))
        .route(
            mindone_protocol::OPENAI_COMPLETIONS,
            post(proxy_completions),
        )
        .with_state(state);
    let started = CommandOutput::new(
        format!(
            "MindOne OpenAI 兼容代理已启动\n地址：http://127.0.0.1:{}\n模型：{}\n机密模式：{}\n流式输出：{}\n{}",
            args.port,
            args.model,
            match args.confidentiality {
                ConfidentialityArg::Standard => "standard",
                ConfidentialityArg::Regulated => "regulated",
            },
            match args.confidentiality {
                ConfidentialityArg::Standard => "支持标准 SSE（含 [DONE]）",
                ConfidentialityArg::Regulated => "当前明确不支持（不会降级）",
            },
            match args.confidentiality {
                ConfidentialityArg::Standard => "注意：Standard 仅使用 Base64 JSON 路由，不提供端到端加密",
                ConfidentialityArg::Regulated => "Regulated 将逐请求本机复验硬件 evidence，并使用 X25519/HKDF/ChaCha20-Poly1305",
            }
        ),
        serde_json::json!({
            "address": format!("http://127.0.0.1:{}", args.port),
            "model": args.model,
            "stream_supported": matches!(args.confidentiality, ConfidentialityArg::Standard),
            "confidentiality": match args.confidentiality {
                ConfidentialityArg::Standard => "standard",
                ConfidentialityArg::Regulated => "regulated",
            },
        }),
    )?;
    if output_mode.json {
        eprintln!("{}", started.human);
    } else if !output_mode.quiet {
        println!("{}", started.human);
    }
    serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| CliError::General(format!("本地额度代理异常退出：{error}")))?;
    CommandOutput::message("MindOne OpenAI 兼容代理已停止")
}

async fn proxy_models(State(state): State<ProxyState>) -> Response {
    match authorized_get(&state, mindone_protocol::MODELS).await {
        Ok(value) => match decode_api_value::<ModelListResponse>(value, "读取模型列表") {
            Ok(response) => {
                let mut models = BTreeMap::new();
                for model in response.models {
                    models
                        .entry(model.name)
                        .and_modify(|published_at: &mut time::OffsetDateTime| {
                            *published_at = (*published_at).min(model.published_at);
                        })
                        .or_insert(model.published_at);
                }
                let response = ModelsResponse {
                    object: "list".to_owned(),
                    data: models
                        .into_iter()
                        .map(|(id, published_at)| OpenAiModel {
                            id,
                            object: "model".to_owned(),
                            created: published_at.unix_timestamp(),
                            owned_by: "mindone".to_owned(),
                        })
                        .collect(),
                };
                (StatusCode::OK, Json(response)).into_response()
            }
            Err(error) => proxy_error_response(error),
        },
        Err(error) => proxy_error_response(error),
    }
}

async fn proxy_chat(
    State(state): State<ProxyState>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    proxy_json_payload(state, mindone_protocol::OPENAI_CHAT_COMPLETIONS, payload).await
}

async fn proxy_completions(
    State(state): State<ProxyState>,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    proxy_json_payload(state, mindone_protocol::OPENAI_COMPLETIONS, payload).await
}

async fn proxy_json_payload(
    state: ProxyState,
    endpoint: &'static str,
    payload: Result<Json<Value>, JsonRejection>,
) -> Response {
    match payload {
        Ok(Json(body)) => proxy_inference(state, endpoint, SensitiveJsonValue(body)).await,
        Err(error) => openai_response(
            StatusCode::BAD_REQUEST,
            format!("请求体必须是合法 JSON：{error}"),
            "invalid_request_error",
        ),
    }
}

async fn proxy_inference(
    state: ProxyState,
    endpoint: &'static str,
    mut body: SensitiveJsonValue,
) -> Response {
    let Some(object) = body.as_object_mut() else {
        return openai_response(
            StatusCode::BAD_REQUEST,
            "请求体必须是 JSON 对象",
            "invalid_request_error",
        );
    };
    let requested_model = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(&state.default_model)
        .to_owned();
    object.insert("model".to_owned(), Value::String(requested_model.clone()));
    apply_output_token_default(endpoint, object);

    let metadata = match validate_inference_request(endpoint, &body) {
        Ok(metadata) => metadata,
        Err((message, kind)) => {
            return openai_response(StatusCode::BAD_REQUEST, message, kind);
        }
    };
    if metadata.stream {
        if state.confidentiality == ConfidentialityArg::Regulated {
            return openai_response(
                StatusCode::BAD_REQUEST,
                "Regulated 当前使用单次 AEAD 结果 envelope，不支持 SSE，且不会降级为 Standard",
                "unsupported_stream",
            );
        }
        return match create_standard_job(&state, &requested_model, endpoint, &body, metadata).await
        {
            Ok(created) => proxy_sse_response(state, created.job_id),
            Err(error) => proxy_error_response(error),
        };
    }
    match create_and_wait_job(&state, &requested_model, endpoint, &body, metadata).await {
        Ok(result) => (StatusCode::OK, Json(SensitiveJsonResponse(result))).into_response(),
        Err(error) => proxy_error_response(error),
    }
}

fn apply_output_token_default(endpoint: &str, object: &mut serde_json::Map<String, Value>) {
    let max_tokens_missing = object.get("max_tokens").is_none_or(Value::is_null);
    let completion_tokens_missing = object
        .get("max_completion_tokens")
        .is_none_or(Value::is_null);
    let needs_default = match endpoint {
        mindone_protocol::OPENAI_CHAT_COMPLETIONS => {
            max_tokens_missing && completion_tokens_missing
        }
        mindone_protocol::OPENAI_COMPLETIONS => max_tokens_missing,
        _ => false,
    };
    if needs_default {
        object.insert(
            "max_tokens".to_owned(),
            Value::from(DEFAULT_NETWORK_MAX_OUTPUT_TOKENS),
        );
    }
}

fn validate_inference_request(
    endpoint: &str,
    body: &Value,
) -> Result<InferenceMetadata, (String, &'static str)> {
    let payload = SensitiveStandardJobPayload(StandardJobPayload {
        endpoint: endpoint.to_owned(),
        request: body.clone(),
    });
    let limits = payload.validated_limits().map_err(|error| {
        let kind = if error.field == "stream" {
            "unsupported_stream"
        } else {
            "invalid_request_error"
        };
        (error.to_string(), kind)
    })?;
    Ok(InferenceMetadata {
        estimated_input_tokens: limits.minimum_input_tokens,
        max_output_tokens: limits.maximum_output_tokens,
        stream: limits.stream,
    })
}

async fn create_and_wait_job(
    state: &ProxyState,
    model: &str,
    endpoint: &str,
    request_body: &Value,
    metadata: InferenceMetadata,
) -> CliResult<Value> {
    match state.confidentiality {
        ConfidentialityArg::Standard => {
            create_and_wait_standard_job(state, model, endpoint, request_body, metadata).await
        }
        ConfidentialityArg::Regulated => {
            create_and_wait_regulated_job(state, model, endpoint, request_body, metadata).await
        }
    }
}

async fn create_and_wait_standard_job(
    state: &ProxyState,
    model: &str,
    endpoint: &str,
    request_body: &Value,
    metadata: InferenceMetadata,
) -> CliResult<Value> {
    let created = create_standard_job(state, model, endpoint, request_body, metadata).await?;
    wait_for_standard_job(state, created.job_id).await
}

async fn create_standard_job(
    state: &ProxyState,
    model: &str,
    endpoint: &str,
    request_body: &Value,
    metadata: InferenceMetadata,
) -> CliResult<CreateJobResponse> {
    let value = {
        let payload = SensitiveStandardJobPayload(StandardJobPayload {
            endpoint: endpoint.to_owned(),
            request: request_body.clone(),
        });
        let serialized_payload = Zeroizing::new(
            serde_json::to_vec(&*payload)
                .map_err(|error| CliError::General(format!("无法编码推理任务载荷：{error}")))?,
        );
        let request = SensitiveCreateJobRequest(CreateJobRequest {
            virtual_model: model.to_owned(),
            encrypted_payload: BASE64_STANDARD.encode(&*serialized_payload),
            payload_encoding: PayloadEncoding::Base64,
            tags: Vec::new(),
            estimated_input_tokens: metadata.estimated_input_tokens,
            max_output_tokens: metadata.max_output_tokens,
            idempotency_key: format!("proxy:{}", Uuid::now_v7()),
            priority: 0,
        });
        request
            .validate()
            .map_err(|error| CliError::General(error.to_string()))?;
        authorized_post(state, mindone_protocol::JOBS, &*request).await?
    };
    decode_api_value(value, "创建任务")
}

async fn wait_for_standard_job(state: &ProxyState, job_id: Uuid) -> CliResult<Value> {
    let deadline = Instant::now() + JOB_WAIT_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err(CliError::General(
                "网络推理任务等待超过 600 秒；任务租约将由协调器回收".to_owned(),
            ));
        }
        let value = authorized_get(state, &mindone_protocol::job(job_id)).await?;
        let mut job: JobResponse = decode_api_value(value, "读取任务")?;
        match job.status {
            JobStatus::Succeeded => {
                let result = decode_job_result(&job);
                if let Some(value) = job.result_ciphertext.as_mut() {
                    value.zeroize();
                }
                return result;
            }
            JobStatus::Failed => {
                return Err(failed_job_error(
                    job.job_id,
                    job.error_class,
                    job.error_message,
                ));
            }
            JobStatus::Cancelled => {
                return Err(CliError::General(format!(
                    "网络推理任务 {} 已取消",
                    job.job_id
                )));
            }
            JobStatus::Queued | JobStatus::Retry | JobStatus::Leased => {
                tokio::time::sleep(JOB_POLL_INTERVAL).await;
            }
        }
    }
}

async fn create_and_wait_regulated_job(
    state: &ProxyState,
    model: &str,
    endpoint: &str,
    request_body: &Value,
    metadata: InferenceMetadata,
) -> CliResult<Value> {
    let route_request = PrepareRegulatedJobRequest {
        virtual_model: model.to_owned(),
        tags: vec!["regulated".to_owned()],
        estimated_input_tokens: metadata.estimated_input_tokens,
        max_output_tokens: metadata.max_output_tokens,
        idempotency_key: format!("regulated-prepare:{}", Uuid::now_v7()),
        priority: 0,
    };
    route_request
        .validate()
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    let value = authorized_post(
        state,
        mindone_protocol::JOBS_REGULATED_PREPARE,
        &route_request,
    )
    .await?;
    let prepared: PrepareRegulatedJobResponse = decode_api_value(value, "准备 Regulated route")?;
    let verified = crate::e2ee::verify_prepared_route(prepared).await?;
    let session = crate::e2ee::RegulatedClientSession::new()?;
    let plaintext =
        {
            let payload = SensitiveStandardJobPayload(StandardJobPayload {
                endpoint: endpoint.to_owned(),
                request: request_body.clone(),
            });
            Zeroizing::new(serde_json::to_vec(&*payload).map_err(|error| {
                CliError::Attestation(format!("无法编码 Regulated 明文：{error}"))
            })?)
        };
    let envelope = session.encrypt_request(&verified, plaintext.as_slice())?;
    let create_request = CreateRegulatedJobRequest {
        route_id: verified.response.route_id,
        envelope,
        idempotency_key: format!("proxy-regulated:{}", Uuid::now_v7()),
    };
    create_request
        .validate()
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    let value = authorized_post(state, mindone_protocol::JOBS_REGULATED, &create_request).await?;
    let created: CreateJobResponse = decode_api_value(value, "创建 Regulated 任务")?;
    let deadline = Instant::now() + JOB_WAIT_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Attestation(
                "Regulated 任务等待超过 600 秒；本地临时解密密钥已销毁".to_owned(),
            ));
        }
        let value = authorized_get(state, &mindone_protocol::job(created.job_id)).await?;
        let job: JobResponse = decode_api_value(value, "读取 Regulated 任务")?;
        if job.confidentiality != mindone_protocol::ConfidentialityMode::Regulated
            || job.regulated_route_id != Some(verified.response.route_id)
            || job.attestation_report_id != Some(verified.response.attestation.report_id)
        {
            return Err(CliError::Attestation(
                "协调器返回的任务与本机 verified Regulated route 不匹配".to_owned(),
            ));
        }
        match job.status {
            JobStatus::Succeeded => {
                return decode_regulated_job_result(&job, &verified, &session);
            }
            JobStatus::Failed => {
                return Err(failed_job_error(
                    job.job_id,
                    job.error_class,
                    job.error_message,
                ));
            }
            JobStatus::Cancelled => {
                return Err(CliError::Attestation(format!(
                    "Regulated 网络推理任务 {} 已取消",
                    job.job_id
                )));
            }
            JobStatus::Queued | JobStatus::Retry | JobStatus::Leased => {
                tokio::time::sleep(JOB_POLL_INTERVAL).await;
            }
        }
    }
}

fn decode_regulated_job_result(
    job: &JobResponse,
    route: &crate::e2ee::VerifiedRegulatedRoute,
    session: &crate::e2ee::RegulatedClientSession,
) -> CliResult<Value> {
    let encoded = job
        .result_ciphertext
        .as_deref()
        .ok_or_else(|| CliError::Attestation("Regulated 任务完成但缺少 opaque 结果".to_owned()))?;
    let envelope: RegulatedEnvelope = serde_json::from_str(encoded).map_err(|_| {
        CliError::Attestation("协调器返回的 opaque 结果不是 Regulated envelope".to_owned())
    })?;
    let plaintext = session.decrypt_result(route, &envelope)?;
    serde_json::from_slice(plaintext.as_slice())
        .map_err(|error| CliError::Attestation(format!("TEE 结果明文不是合法 JSON：{error}")))
}

fn failed_job_error(
    job_id: Uuid,
    error_class: Option<JobErrorClass>,
    error_message: Option<String>,
) -> CliError {
    if error_class == Some(JobErrorClass::Policy) {
        return CliError::PolicyRejected(
            error_message.unwrap_or_else(|| format!("网络推理任务 {job_id} 被节点策略拒绝")),
        );
    }
    if error_class == Some(JobErrorClass::Attestation) {
        return CliError::Attestation(
            error_message
                .unwrap_or_else(|| format!("网络推理任务 {job_id} 的硬件证明或 E2EE 绑定已失效")),
        );
    }
    let detail = error_message
        .as_deref()
        .map(|message| format!("：{message}"))
        .unwrap_or_default();
    CliError::General(format!("网络推理任务 {job_id} 执行失败{detail}"))
}

fn decode_job_result(job: &JobResponse) -> CliResult<Value> {
    let encoded = job
        .result_ciphertext
        .as_deref()
        .ok_or_else(|| CliError::General("任务已完成但协调器响应缺少真实推理结果".to_owned()))?;
    let bytes = Zeroizing::new(
        BASE64_STANDARD
            .decode(encoded)
            .map_err(|error| CliError::General(format!("任务结果 Base64 无效：{error}")))?,
    );
    serde_json::from_slice(&bytes)
        .map_err(|error| CliError::General(format!("任务结果 JSON 无效：{error}")))
}

fn proxy_sse_response(proxy: ProxyState, job_id: Uuid) -> Response {
    let now = Instant::now();
    let state = ProxyStreamState {
        proxy,
        job_id,
        next_sequence: 0,
        pending: VecDeque::new(),
        terminal: None,
        finished: false,
        deadline: now + JOB_WAIT_TIMEOUT,
        last_output: now,
        coordinator_failure_since: None,
    };
    let output = stream::unfold(state, next_proxy_sse_chunk);
    let mut response = Body::from_stream(output).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response
        .headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
    response
}

async fn next_proxy_sse_chunk(
    mut state: ProxyStreamState,
) -> Option<(Result<Bytes, Infallible>, ProxyStreamState)> {
    if state.finished {
        return None;
    }
    loop {
        if let Some(mut event) = state.pending.pop_front() {
            let frame = Bytes::from(format!(
                "id: {}\ndata: {}\n\n",
                event.sequence, event.event_data
            ));
            event.event_data.zeroize();
            state.last_output = Instant::now();
            return Some((Ok(frame), state));
        }
        if let Some(terminal) = state.terminal.take() {
            state.finished = true;
            let frame = match terminal {
                ProxyStreamTerminal::Done => Bytes::from_static(b"data: [DONE]\n\n"),
                ProxyStreamTerminal::Error(message) => {
                    let error = openai_error(message, "stream_error");
                    let encoded = serde_json::to_string(&error).unwrap_or_else(|_| {
                        "{\"error\":{\"message\":\"SSE 失败\",\"type\":\"stream_error\",\"code\":\"stream_error\"}}".to_owned()
                    });
                    Bytes::from(format!("data: {encoded}\n\ndata: [DONE]\n\n"))
                }
            };
            return Some((Ok(frame), state));
        }
        let now = Instant::now();
        if now >= state.deadline {
            state.terminal = Some(ProxyStreamTerminal::Error(
                "网络推理任务等待超过 600 秒；未产生成功结算".to_owned(),
            ));
            continue;
        }
        let path = format!(
            "{}?from_sequence={}&limit=8",
            mindone_protocol::job_stream(state.job_id),
            state.next_sequence
        );
        match authorized_get(&state.proxy, &path).await {
            Ok(value) => {
                state.coordinator_failure_since = None;
                match decode_api_value::<JobStreamReadResponse>(value, "读取流式任务") {
                    Ok(response) => {
                        state.next_sequence = response.next_sequence;
                        state.pending.extend(response.events);
                        match response.status {
                            JobStatus::Succeeded if !response.has_more => {
                                state.terminal = Some(ProxyStreamTerminal::Done);
                            }
                            JobStatus::Failed | JobStatus::Cancelled => {
                                let detail = response.error_message.unwrap_or_else(|| {
                                    format!("网络推理任务 {} 未成功完成", state.job_id)
                                });
                                state.terminal = Some(ProxyStreamTerminal::Error(detail));
                            }
                            JobStatus::Retry => {
                                state.terminal = Some(ProxyStreamTerminal::Error(
                                    "流式任务违反单 attempt 合同，已拒绝拼接重试输出".to_owned(),
                                ));
                            }
                            JobStatus::Queued | JobStatus::Leased | JobStatus::Succeeded => {}
                        }
                        if !state.pending.is_empty() || state.terminal.is_some() {
                            continue;
                        }
                    }
                    Err(error) => {
                        state.terminal = Some(ProxyStreamTerminal::Error(error.to_string()));
                        continue;
                    }
                }
            }
            Err(error) => {
                let failure_since = *state.coordinator_failure_since.get_or_insert(now);
                if now.duration_since(failure_since) >= STREAM_RECOVERY_TIMEOUT {
                    state.terminal = Some(ProxyStreamTerminal::Error(format!(
                        "协调服务器流式游标在 30 秒内无法恢复：{error}"
                    )));
                    continue;
                }
            }
        }
        if now.duration_since(state.last_output) >= STREAM_KEEPALIVE_INTERVAL {
            state.last_output = now;
            return Some((Ok(Bytes::from_static(b": keep-alive\n\n")), state));
        }
        tokio::time::sleep(STREAM_POLL_INTERVAL).await;
    }
}

async fn authorized_get(state: &ProxyState, path: &str) -> CliResult<Value> {
    let token = state.session.read().await.access_token.clone();
    match state.coordinator.get(path, Some(&token)).await {
        Ok(value) => Ok(value),
        Err(CliError::Authentication(_)) => {
            refresh_proxy_session(state, &token).await?;
            let token = state.session.read().await.access_token.clone();
            state.coordinator.get(path, Some(&token)).await
        }
        Err(error) => Err(error),
    }
}

async fn authorized_post<B: Serialize + ?Sized>(
    state: &ProxyState,
    path: &str,
    body: &B,
) -> CliResult<Value> {
    let token = state.session.read().await.access_token.clone();
    match state.coordinator.post(path, Some(&token), body).await {
        Ok(value) => Ok(value),
        Err(CliError::Authentication(_)) => {
            refresh_proxy_session(state, &token).await?;
            let token = state.session.read().await.access_token.clone();
            state.coordinator.post(path, Some(&token), body).await
        }
        Err(error) => Err(error),
    }
}

async fn refresh_proxy_session(state: &ProxyState, rejected_access_token: &str) -> CliResult<()> {
    // 多个并发代理请求可能同时看到 401。持有写锁并比较失败 token，
    // 确保只有第一个请求消耗一次性 refresh token；其余请求直接复用新会话。
    let mut current = state.session.write().await;
    if current.access_token != rejected_access_token {
        return Ok(());
    }
    let updated =
        crate::auth::refresh_credential_bundle(&state.coordinator, &state.vault, current.clone())
            .await?;
    *current = updated;
    Ok(())
}

fn proxy_error_response(error: CliError) -> Response {
    let status = match &error {
        CliError::Authentication(_) => StatusCode::UNAUTHORIZED,
        CliError::InsufficientQuota(_) => StatusCode::PAYMENT_REQUIRED,
        CliError::PolicyRejected(_) => StatusCode::UNPROCESSABLE_ENTITY,
        CliError::Attestation(_) => StatusCode::UNPROCESSABLE_ENTITY,
        _ => StatusCode::BAD_GATEWAY,
    };
    openai_response(status, error.to_string(), error.error_type())
}

fn openai_response(
    status: StatusCode,
    message: impl Into<String>,
    kind: impl Into<String>,
) -> Response {
    (status, Json(openai_error(message, kind))).into_response()
}

fn openai_error(message: impl Into<String>, kind: impl Into<String>) -> OpenAiErrorResponse {
    let kind = kind.into();
    OpenAiErrorResponse {
        error: OpenAiError {
            message: message.into(),
            error_type: kind.clone(),
            param: None,
            code: Some(kind),
        },
    }
}

fn api_payload(value: Value) -> Value {
    value.get("data").cloned().unwrap_or(value)
}

fn decode_api_value<T: for<'de> Deserialize<'de>>(value: Value, operation: &str) -> CliResult<T> {
    serde_json::from_value(api_payload(value))
        .map_err(|error| CliError::General(format!("协调服务器{operation}响应不兼容：{error}")))
}

fn history_path(query: &QuotaHistoryQuery) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    if let Some(limit) = query.limit {
        serializer.append_pair("limit", &limit.to_string());
    }
    if let Some(cursor) = query.cursor {
        serializer.append_pair("cursor", &cursor.to_string());
    }
    if let Some(after) = &query.after {
        serializer.append_pair("after", after);
    }
    if let Some(before) = &query.before {
        serializer.append_pair("before", before);
    }
    format!(
        "{}?{}",
        mindone_protocol::QUOTA_HISTORY,
        serializer.finish()
    )
}

fn validate_history_args(args: &QuotaHistoryArgs) -> CliResult<()> {
    if args.page == 0 || args.page > 10_000 {
        return Err(CliError::General(
            "--page 必须在 1 到 10000 之间".to_owned(),
        ));
    }
    let after = parse_rfc3339_filter(args.from.as_deref(), "from")?;
    let before = parse_rfc3339_filter(args.to.as_deref(), "to")?;
    if after
        .zip(before)
        .is_some_and(|(after, before)| after >= before)
    {
        return Err(CliError::General("--from 必须早于 --to".to_owned()));
    }
    Ok(())
}

fn parse_rfc3339_filter(
    value: Option<&str>,
    name: &str,
) -> CliResult<Option<time::OffsetDateTime>> {
    value
        .map(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
                .map_err(|error| {
                    CliError::General(format!("--{name} 不是合法 RFC 3339 时间：{error}"))
                })
        })
        .transpose()
}

pub(crate) fn format_micro(value: i64) -> String {
    let magnitude = value.unsigned_abs();
    // 用户可见金额遵循 CLI 规范固定显示两位小数；内部和 JSON 协议仍完整保留
    // 整数 microquota。这里用整数做四舍五入，避免浮点误差和负零输出。
    let rounded_cents = (magnitude + 5_000) / 10_000;
    let sign = if value < 0 && rounded_cents != 0 {
        "-"
    } else {
        ""
    };
    format!("{sign}{}.{:02}", rounded_cents / 100, rounded_cents % 100)
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::warn!(%error, "无法注册 Ctrl-C 处理器");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use mindone_accounting::{LedgerEntry, LedgerKind, GENESIS_HASH};
    use serde_json::json;
    use time::macros::datetime;

    use super::{
        apply_output_token_default, failed_job_error, format_micro, openai_error,
        signed_performance_delta, validate_inference_request, verify_history_entry,
        LocalLedgerVerification, JOB_POLL_INTERVAL,
    };
    use crate::error::CliError;
    use mindone_protocol::{
        conservative_input_token_authorization, JobErrorClass, LedgerEntryResponse,
        LedgerNamespace, LedgerRecomputationStatus, DEFAULT_NETWORK_MAX_OUTPUT_TOKENS,
    };
    use uuid::Uuid;

    fn canonical_history_entry() -> LedgerEntryResponse {
        let ledger = LedgerEntry::new(
            Uuid::from_u128(1),
            Uuid::from_u128(2),
            Some(Uuid::from_u128(3)),
            "history-unit-test",
            LedgerKind::NodeQuotaCredit,
            250_000,
            1_000_000,
            1_250_000,
            datetime!(2026-07-17 10:00:00.123456 UTC),
            GENESIS_HASH,
            BTreeMap::from([("source".to_owned(), "unit_test".to_owned())]),
        )
        .expect("canonical 测试账本应有效");
        LedgerEntryResponse {
            ledger: LedgerNamespace::Quota,
            account_id: ledger.account_id,
            id: ledger.id,
            request_id: ledger.request_id,
            receipt_id: None,
            idempotency_key: ledger.idempotency_key,
            entry_type: "node_reward".to_owned(),
            delta_micro: ledger.amount_micro,
            balance_before_micro: ledger.balance_before_micro,
            balance_after_micro: ledger.balance_after_micro,
            created_at: ledger.created_at,
            prev_hash: ledger.previous_hash,
            hash_version: ledger.hash_version,
            metadata: ledger.metadata,
            recomputation_status: LedgerRecomputationStatus::CanonicalV2Recomputable,
            entry_hash: ledger.hash,
        }
    }

    #[test]
    fn formats_microquota_without_float() {
        assert_eq!(format_micro(1_500_000), "1.50");
        assert_eq!(format_micro(1_234_999), "1.23");
        assert_eq!(format_micro(1_235_000), "1.24");
        assert_eq!(format_micro(-5_000), "-0.01");
        assert_eq!(format_micro(-1), "0.00");
    }

    #[test]
    fn history_recomputes_canonical_v2_and_rejects_tampering() {
        let entry = canonical_history_entry();
        assert_eq!(
            verify_history_entry(&entry).expect("完整 canonical v2 应能本地复算"),
            LocalLedgerVerification::CanonicalV2Verified
        );

        let mut tampered = entry;
        tampered.balance_after_micro += 1;
        let error = verify_history_entry(&tampered).expect_err("篡改行必须被本地复算拒绝");
        assert!(error.to_string().contains("本地重算失败"));
    }

    #[test]
    fn history_marks_legacy_v1_unverifiable_without_claiming_recomputation() {
        let mut entry = canonical_history_entry();
        entry.hash_version = 1;
        entry.metadata.clear();
        entry.recomputation_status = LedgerRecomputationStatus::LegacyV1Unverifiable;
        assert_eq!(
            verify_history_entry(&entry).expect("legacy v1 应保留但不复算"),
            LocalLedgerVerification::LegacyV1Unverifiable
        );

        entry.recomputation_status = LedgerRecomputationStatus::CanonicalV2Recomputable;
        let error = verify_history_entry(&entry).expect_err("v1 不得伪装成 canonical v2");
        assert!(error.to_string().contains("hash_version=1"));
    }

    #[test]
    fn openai_error_shape_is_compatible() {
        let value = serde_json::to_value(openai_error("不支持流式", "unsupported_stream"))
            .expect("错误响应应可序列化");
        assert_eq!(value["error"]["type"], "unsupported_stream");
        assert_eq!(value["error"]["code"], "unsupported_stream");
    }

    #[test]
    fn low_tier_receipt_keeps_the_signed_performance_discount() {
        assert_eq!(
            signed_performance_delta(700_000, 1_000_000).ok(),
            Some(-300_000)
        );
        assert_eq!(format_micro(-300_000), "-0.30");
        assert!(signed_performance_delta(i64::MIN, i64::MAX).is_err());
    }

    #[test]
    fn standard_streaming_is_preserved_for_the_sse_path() {
        let body = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true
        });
        let metadata = validate_inference_request("/v1/chat/completions", &body)
            .expect("Standard 流式请求应进入真实 SSE 路径");
        assert!(metadata.stream);
    }

    #[test]
    fn input_token_estimate_is_positive_and_deterministic() {
        let body = json!({"prompt": "MindOne"});
        let first = conservative_input_token_authorization(&body).expect("请求应可编码");
        let second = conservative_input_token_authorization(&body).expect("请求应可编码");
        assert_eq!(first, second);
        assert!(first > 0);
    }

    #[test]
    fn input_token_authorization_is_conservative_for_chinese_and_templates() {
        let body = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "只回复：MindOne 已连接"}]
        });
        let serialized_bytes = serde_json::to_vec(&body).map(|bytes| bytes.len());
        let authorization = conservative_input_token_authorization(&body).expect("请求应可编码");
        assert!(matches!(
            serialized_bytes,
            Ok(bytes) if authorization >= i32::try_from(bytes + 1_024).unwrap_or(i32::MAX)
        ));
    }

    #[test]
    fn absent_output_limit_is_inserted_into_the_forwarded_request() {
        let mut body = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let object = body.as_object_mut().expect("测试请求应为对象");
        apply_output_token_default("/v1/chat/completions", object);
        assert_eq!(body["max_tokens"], DEFAULT_NETWORK_MAX_OUTPUT_TOKENS);
        let metadata =
            validate_inference_request("/v1/chat/completions", &body).expect("应通过请求校验");
        assert_eq!(
            metadata.max_output_tokens,
            DEFAULT_NETWORK_MAX_OUTPUT_TOKENS as i32
        );
    }

    #[test]
    fn cli_uses_protocol_output_multiplier_and_input_authorization() {
        let body = json!({
            "model": "auto",
            "prompt": ["hello", "MindOne"],
            "max_tokens": 40,
            "n": 3
        });
        let metadata =
            validate_inference_request("/v1/completions", &body).expect("规范请求应通过校验");
        assert_eq!(metadata.max_output_tokens, 120);
        assert_eq!(
            metadata.estimated_input_tokens,
            conservative_input_token_authorization(&body).expect("请求应可编码")
        );
    }

    #[test]
    fn cli_rejects_invalid_endpoint_model_and_ambiguous_output_limits() {
        let body = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let endpoint_error =
            validate_inference_request("/v1/embeddings", &body).expect_err("未知端点必须拒绝");
        assert_eq!(endpoint_error.1, "invalid_request_error");

        let invalid_model = json!({
            "model": "",
            "messages": [{"role": "user", "content": "hello"}]
        });
        let model_error = validate_inference_request("/v1/chat/completions", &invalid_model)
            .expect_err("空模型必须拒绝");
        assert_eq!(model_error.1, "invalid_request_error");

        let ambiguous = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 10,
            "max_completion_tokens": 20
        });
        let token_error = validate_inference_request("/v1/chat/completions", &ambiguous)
            .expect_err("互斥输出上限必须拒绝");
        assert_eq!(token_error.1, "invalid_request_error");

        let unknown = json!({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
            "unsupported": true
        });
        let unknown_error = validate_inference_request("/v1/chat/completions", &unknown)
            .expect_err("未知请求字段必须拒绝");
        assert_eq!(unknown_error.1, "invalid_request_error");
    }

    #[test]
    fn policy_failed_job_keeps_exit_code_50_for_the_proxy() {
        let error = failed_job_error(
            Uuid::nil(),
            Some(JobErrorClass::Policy),
            Some("本机策略拒绝此任务".to_owned()),
        );
        assert!(matches!(error, CliError::PolicyRejected(_)));
        assert_eq!(error.exit_code(), 50);
        assert_eq!(error.error_type(), "node_policy_rejected");
    }

    #[test]
    fn job_polling_does_not_exceed_sixty_requests_per_minute() {
        assert!(JOB_POLL_INTERVAL >= std::time::Duration::from_secs(1));
    }
}
