//! `mindone serve` 的受管回环代理。
//!
//! llama.cpp 仅绑定随机的内部回环端口。公开给本机应用的端口由本代理持有，
//! 从而能在每个真实推理响应到达终态后串行清理专属的本机 slot 0。贡献 worker
//! 使用 slot 1..=3，不经过本代理，二者不会互相擦除 KV sequence。
//! 本模块不记录、格式化或持久化 Prompt/Response；状态文件只包含计数和稳定错误码。

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use bytes::Bytes;
use futures_util::StreamExt;
use mindone_engine::{read_process_start_marker, ServeCleanupStatus, MANAGED_LLAMA_SLOT_ID};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CliError, CliResult};
use crate::storage::write_json_atomic;

const MAX_PROXY_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_ERASE_RESPONSE_BYTES: usize = 4 * 1024;
const RESPONSE_CHANNEL_CAPACITY: usize = 8;
const STATUS_FLUSH_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct ServeProxyConfig {
    pub listen_port: u16,
    pub backend_port: u16,
    pub target_pid: u32,
    pub target_marker: String,
    pub expected_command_parts: Vec<String>,
    pub status_path: PathBuf,
}

#[derive(Clone)]
struct ProxyState {
    config: ServeProxyConfig,
    client: Client,
    inference_gate: Arc<Semaphore>,
    cleanup_required: Arc<AtomicBool>,
    reporting_failed: Arc<AtomicBool>,
    zeroized_bytes: Arc<AtomicU64>,
    status: Arc<Mutex<ServeCleanupStatus>>,
}

struct SensitiveBody {
    bytes: Zeroizing<Vec<u8>>,
    zeroized_bytes: Arc<AtomicU64>,
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_value),
        Value::Object(values) => values.values_mut().for_each(zeroize_json_value),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

impl SensitiveBody {
    fn new(bytes: Vec<u8>, zeroized_bytes: Arc<AtomicU64>) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
            zeroized_bytes,
        }
    }
}

impl AsRef<[u8]> for SensitiveBody {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Drop for SensitiveBody {
    fn drop(&mut self) {
        let length = u64::try_from(self.bytes.len()).unwrap_or(u64::MAX);
        self.bytes.zeroize();
        self.zeroized_bytes.fetch_add(length, Ordering::SeqCst);
    }
}

#[derive(Debug, Deserialize)]
struct SlotEraseReceipt {
    id_slot: u32,
    n_erased: u64,
}

#[derive(Debug)]
struct ProxyFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ProxyFailure {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    fn response(self) -> Response {
        (
            self.status,
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            axum::Json(serde_json::json!({
                "error": {
                    "message": self.message,
                    "type": "serve_proxy_error",
                    "code": self.code,
                }
            })),
        )
            .into_response()
    }
}

pub async fn run_serve_proxy(config: ServeProxyConfig) -> CliResult<()> {
    validate_config(&config)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| CliError::EngineOrSandbox(format!("无法创建受管回环代理：{error}")))?;
    let proxy_pid = std::process::id();
    let proxy_marker = read_process_start_marker(proxy_pid)
        .map_err(|error| CliError::EngineOrSandbox(format!("无法读取代理进程身份：{error}")))?
        .ok_or_else(|| CliError::EngineOrSandbox("无法确认代理进程仍在运行".to_owned()))?;
    let initial_status = ServeCleanupStatus::new(proxy_pid, proxy_marker);
    write_json_atomic(&config.status_path, &initial_status)?;
    let state = Arc::new(ProxyState {
        config: config.clone(),
        client,
        inference_gate: Arc::new(Semaphore::new(1)),
        cleanup_required: Arc::new(AtomicBool::new(false)),
        reporting_failed: Arc::new(AtomicBool::new(false)),
        zeroized_bytes: Arc::new(AtomicU64::new(0)),
        status: Arc::new(Mutex::new(initial_status)),
    });
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.listen_port);
    let listener = TcpListener::bind(address).await.map_err(|error| {
        CliError::EngineOrSandbox(format!("受管回环代理无法绑定 {address}：{error}"))
    })?;
    let status_writer = tokio::spawn(flush_zeroized_status(state.clone()));
    let app = Router::new().fallback(any(proxy_request)).with_state(state);
    let result = axum::serve(listener, app)
        .await
        .map_err(|error| CliError::EngineOrSandbox(format!("受管回环代理退出：{error}")));
    status_writer.abort();
    result
}

async fn proxy_request(State(state): State<Arc<ProxyState>>, request: Request) -> Response {
    match proxy_request_inner(state, request).await {
        Ok(response) => response,
        Err(error) => error.response(),
    }
}

async fn proxy_request_inner(
    state: Arc<ProxyState>,
    request: Request,
) -> Result<Response, ProxyFailure> {
    ensure_target_identity(&state)?;
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let inference = method == Method::POST
        && matches!(path.as_str(), "/v1/chat/completions" | "/v1/completions");
    if !inference && !allowed_control_request(&method, &path) {
        return Err(ProxyFailure::new(
            StatusCode::NOT_FOUND,
            "unsupported_local_endpoint",
            "受管本地服务不开放此 llama.cpp 管理端点",
        ));
    }
    if state.reporting_failed.load(Ordering::SeqCst) {
        return Err(ProxyFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "cleanup_status_unavailable",
            "请求后清理状态无法安全持久化，代理已停止接收推理",
        ));
    }
    if method == Method::GET && path == "/health" && state.cleanup_required.load(Ordering::SeqCst) {
        return Err(ProxyFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "cleanup_required",
            "上一请求的 KV Cache 清理尚未确认，本地服务暂不健康",
        ));
    }
    let permit = if inference {
        Some(
            state
                .inference_gate
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    ProxyFailure::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "proxy_stopping",
                        "受管本地服务正在停止",
                    )
                })?,
        )
    } else {
        None
    };
    if inference {
        // 排队期间目标进程可能已经退出；把身份复核贴近真正转发，避免向端口
        // 被复用后的非受管进程发送 Prompt。
        ensure_target_identity(&state)?;
    }
    if inference && state.cleanup_required.load(Ordering::SeqCst) {
        match erase_slot(&state).await {
            Ok(tokens) => state.record_cleanup(true, None, tokens, false).await?,
            Err(code) => {
                state.record_cleanup(false, Some(code), 0, false).await?;
                return Err(ProxyFailure::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "cleanup_retry_failed",
                    "上一请求的 KV Cache 清理仍未确认，拒绝执行新推理",
                ));
            }
        }
    }
    forward_request(state, request, permit, inference).await
}

async fn forward_request(
    state: Arc<ProxyState>,
    request: Request,
    permit: Option<OwnedSemaphorePermit>,
    inference: bool,
) -> Result<Response, ProxyFailure> {
    let (parts, body) = request.into_parts();
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let url = format!(
        "http://127.0.0.1:{}{}",
        state.config.backend_port, path_and_query
    );
    let collected = to_bytes(body, MAX_PROXY_REQUEST_BYTES).await.map_err(|_| {
        ProxyFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
            format!("本地推理请求体超过 {MAX_PROXY_REQUEST_BYTES} bytes 安全上限"),
        )
    })?;
    let forwarded = if inference {
        let mut request_json = SensitiveJson(serde_json::from_slice(&collected).map_err(|_| {
            ProxyFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_inference_json",
                "本地推理请求必须是有效 JSON 对象",
            )
        })?);
        let object = request_json.0.as_object_mut().ok_or_else(|| {
            ProxyFailure::new(
                StatusCode::BAD_REQUEST,
                "invalid_inference_shape",
                "本地推理请求必须是 JSON 对象",
            )
        })?;
        object.insert("id_slot".to_owned(), Value::from(MANAGED_LLAMA_SLOT_ID));
        object.insert("cache_prompt".to_owned(), Value::Bool(false));
        let bytes = serde_json::to_vec(&request_json.0).map_err(|_| {
            ProxyFailure::new(
                StatusCode::BAD_REQUEST,
                "inference_json_encode_failed",
                "无法编码受管本地推理请求",
            )
        })?;
        if bytes.len() > MAX_PROXY_REQUEST_BYTES {
            return Err(ProxyFailure::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                format!("受管字段加入后请求体超过 {MAX_PROXY_REQUEST_BYTES} bytes 安全上限"),
            ));
        }
        bytes
    } else {
        collected.to_vec()
    };
    let sensitive = SensitiveBody::new(forwarded, state.zeroized_bytes.clone());
    best_effort_zero_bytes(collected, &state.zeroized_bytes);
    let upstream = state
        .client
        .request(parts.method, url)
        .headers(filtered_request_headers(&parts.headers))
        .body(Bytes::from_owner(sensitive));
    let response = match upstream.send().await {
        Ok(response) => response,
        Err(_) => {
            if inference {
                cleanup_after_terminal(&state, false).await?;
            }
            return Err(ProxyFailure::new(
                StatusCode::BAD_GATEWAY,
                "backend_request_failed",
                "本地 llama.cpp 请求失败（正文已隐藏）",
            ));
        }
    };
    let status = response.status();
    let headers = response.headers().clone();
    let mut upstream_stream = response.bytes_stream();
    let (sender, receiver) = mpsc::channel::<Result<Bytes, io::Error>>(RESPONSE_CHANNEL_CAPACITY);
    let task_state = state.clone();
    tokio::spawn(async move {
        let _permit = permit;
        let mut downstream_open = true;
        let mut stream_ok = true;
        while let Some(chunk) = upstream_stream.next().await {
            match chunk {
                Ok(chunk) => {
                    let sensitive =
                        SensitiveBody::new(chunk.to_vec(), task_state.zeroized_bytes.clone());
                    best_effort_zero_bytes(chunk, &task_state.zeroized_bytes);
                    if downstream_open
                        && sender.send(Ok(Bytes::from_owner(sensitive))).await.is_err()
                    {
                        downstream_open = false;
                    }
                }
                Err(_) => {
                    stream_ok = false;
                    if downstream_open {
                        let _ = sender
                            .send(Err(io::Error::other(
                                "本地 llama.cpp 响应流异常（正文已隐藏）",
                            )))
                            .await;
                    }
                    break;
                }
            }
        }
        drop(sender);
        if inference {
            let _ = cleanup_after_terminal(&task_state, stream_ok).await;
        }
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|item| (item, receiver))
    });
    let mut downstream = Response::new(Body::from_stream(stream));
    *downstream.status_mut() = status;
    copy_response_headers(&headers, downstream.headers_mut());
    Ok(downstream)
}

async fn cleanup_after_terminal(
    state: &Arc<ProxyState>,
    _upstream_stream_ok: bool,
) -> Result<(), ProxyFailure> {
    match erase_slot(state).await {
        Ok(tokens) => state.record_cleanup(true, None, tokens, true).await,
        Err(code) => state.record_cleanup(false, Some(code), 0, true).await,
    }
}

async fn erase_slot(state: &ProxyState) -> Result<u64, &'static str> {
    if ensure_target_identity(state).is_err() {
        return Err("engine_identity_mismatch");
    }
    let response = state
        .client
        .post(format!(
            "http://127.0.0.1:{}/slots/{MANAGED_LLAMA_SLOT_ID}?action=erase",
            state.config.backend_port
        ))
        .header(header::CONTENT_TYPE, "application/json")
        .body("{}")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|_| "erase_transport_failed")?;
    if !response.status().is_success() {
        return Err("erase_http_failed");
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERASE_RESPONSE_BYTES as u64)
    {
        return Err("erase_receipt_oversized");
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| "erase_receipt_read_failed")?;
    if bytes.len() > MAX_ERASE_RESPONSE_BYTES {
        return Err("erase_receipt_oversized");
    }
    let receipt: SlotEraseReceipt =
        serde_json::from_slice(&bytes).map_err(|_| "erase_receipt_invalid")?;
    if receipt.id_slot != MANAGED_LLAMA_SLOT_ID {
        return Err("erase_receipt_slot_mismatch");
    }
    Ok(receipt.n_erased)
}

impl ProxyState {
    async fn record_cleanup(
        &self,
        success: bool,
        error_code: Option<&'static str>,
        tokens_erased: u64,
        terminal_request: bool,
    ) -> Result<(), ProxyFailure> {
        self.cleanup_required.store(!success, Ordering::SeqCst);
        let mut status = self.status.lock().await;
        status.cleanup_attempts = status.cleanup_attempts.saturating_add(1);
        if terminal_request {
            status.requests_completed = status.requests_completed.saturating_add(1);
        }
        if success {
            status.cleanup_successes = status.cleanup_successes.saturating_add(1);
            status.tokens_erased = status.tokens_erased.saturating_add(tokens_erased);
            status.last_error_code = None;
        } else {
            status.cleanup_failures = status.cleanup_failures.saturating_add(1);
            status.last_error_code = error_code.map(str::to_owned);
        }
        status.cleanup_required = !success;
        status.owned_host_buffer_bytes_zeroed = self.zeroized_bytes.load(Ordering::SeqCst);
        status.updated_at_unix = time::OffsetDateTime::now_utc().unix_timestamp();
        if write_json_atomic(&self.config.status_path, &*status).is_err() {
            self.reporting_failed.store(true, Ordering::SeqCst);
            return Err(ProxyFailure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "cleanup_status_write_failed",
                "无法安全持久化请求后清理状态，代理已停止接收推理",
            ));
        }
        Ok(())
    }
}

async fn flush_zeroized_status(state: Arc<ProxyState>) {
    let mut interval = tokio::time::interval(STATUS_FLUSH_INTERVAL);
    loop {
        interval.tick().await;
        let observed = state.zeroized_bytes.load(Ordering::SeqCst);
        let mut status = state.status.lock().await;
        if observed == status.owned_host_buffer_bytes_zeroed {
            continue;
        }
        status.owned_host_buffer_bytes_zeroed = observed;
        status.updated_at_unix = time::OffsetDateTime::now_utc().unix_timestamp();
        if write_json_atomic(&state.config.status_path, &*status).is_err() {
            state.reporting_failed.store(true, Ordering::SeqCst);
        }
    }
}

fn ensure_target_identity(state: &ProxyState) -> Result<(), ProxyFailure> {
    let marker_matches = read_process_start_marker(state.config.target_pid)
        .is_ok_and(|marker| marker.as_deref() == Some(state.config.target_marker.as_str()));
    let target = Pid::from_u32(state.config.target_pid);
    let targets = [target];
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::Some(&targets), true);
    let command_matches = system.process(target).is_some_and(|process| {
        !matches!(
            process.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        ) && state.config.expected_command_parts.iter().all(|expected| {
            process.cmd().iter().any(|actual| {
                let actual = actual.to_string_lossy();
                actual == expected.as_str()
                    || Path::new(actual.as_ref()).file_name() == Path::new(expected).file_name()
            })
        })
    });
    if marker_matches && command_matches {
        Ok(())
    } else {
        Err(ProxyFailure::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "engine_identity_mismatch",
            "无法确认受管 llama.cpp 进程身份，拒绝代理请求",
        ))
    }
}

fn allowed_control_request(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/health") | (&Method::GET, "/metrics") | (&Method::GET, "/v1/models")
    )
}

fn filtered_request_headers(source: &HeaderMap) -> HeaderMap {
    let mut destination = HeaderMap::new();
    for (name, value) in source {
        if !hop_by_hop(name) && *name != header::HOST && *name != header::CONTENT_LENGTH {
            destination.append(name.clone(), value.clone());
        }
    }
    destination
}

fn copy_response_headers(source: &HeaderMap, destination: &mut HeaderMap) {
    for (name, value) in source {
        if !hop_by_hop(name) && *name != header::CONTENT_LENGTH {
            destination.append(name.clone(), value.clone());
        }
    }
}

fn hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn best_effort_zero_bytes(bytes: Bytes, counter: &AtomicU64) {
    if let Ok(mut bytes) = bytes.try_into_mut() {
        let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        bytes.as_mut().zeroize();
        counter.fetch_add(length, Ordering::SeqCst);
    }
}

fn validate_config(config: &ServeProxyConfig) -> CliResult<()> {
    if config.listen_port == 0
        || config.backend_port == 0
        || config.listen_port == config.backend_port
    {
        return Err(CliError::EngineOrSandbox(
            "受管回环代理端口配置无效".to_owned(),
        ));
    }
    if config.target_pid == 0
        || config.target_marker.trim().is_empty()
        || config.target_marker.len() > 256
        || config.expected_command_parts.is_empty()
        || config
            .expected_command_parts
            .iter()
            .any(|part| part.is_empty() || part.len() > 4_096 || part.chars().any(char::is_control))
    {
        return Err(CliError::EngineOrSandbox(
            "受管回环代理目标进程身份无效".to_owned(),
        ));
    }
    validate_absolute_normal_path(&config.status_path)
}

fn validate_absolute_normal_path(path: &Path) -> CliResult<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(CliError::EngineOrSandbox(format!(
            "受管清理状态路径必须是绝对规范路径：{}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run_serve_proxy, ServeProxyConfig};
    use mindone_engine::{read_process_start_marker, ServeCleanupStatus};
    use std::net::{Ipv4Addr, TcpListener as StdTcpListener};
    use std::time::Duration;
    use tempfile::TempDir;
    use wiremock::matchers::{body_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn unused_port() -> u16 {
        let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("应分配回环端口");
        listener.local_addr().expect("应读取回环端口").port()
    }

    async fn start_proxy(
        backend_port: u16,
        directory: &TempDir,
    ) -> (u16, std::path::PathBuf, tokio::task::JoinHandle<()>) {
        let listen_port = unused_port();
        let status_path = directory.path().join("cleanup.json");
        let pid = std::process::id();
        let marker = read_process_start_marker(pid)
            .expect("应探测测试进程")
            .expect("测试进程应存活");
        let expected_command = std::env::current_exe()
            .expect("应读取测试可执行文件")
            .file_name()
            .expect("测试可执行文件应有文件名")
            .to_string_lossy()
            .into_owned();
        let task_status_path = status_path.clone();
        let task = tokio::spawn(async move {
            run_serve_proxy(ServeProxyConfig {
                listen_port,
                backend_port,
                target_pid: pid,
                target_marker: marker,
                expected_command_parts: vec![expected_command],
                status_path: task_status_path,
            })
            .await
            .expect("测试代理不应异常退出");
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建测试客户端");
        for _ in 0..100 {
            if client
                .get(format!("http://127.0.0.1:{listen_port}/health"))
                .send()
                .await
                .is_ok()
            {
                return (listen_port, status_path, task);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("代理未及时启动");
    }

    async fn read_status(path: &std::path::Path, completed: u64) -> ServeCleanupStatus {
        for _ in 0..100 {
            if let Ok(bytes) = std::fs::read(path) {
                if let Ok(status) = serde_json::from_slice::<ServeCleanupStatus>(&bytes) {
                    if status.requests_completed >= completed {
                        return status;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("清理状态未及时更新");
    }

    #[tokio::test]
    async fn every_terminal_inference_erases_slot_and_persists_only_safe_status() {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(body_json(serde_json::json!({
                "prompt": "PROMPT_CANARY",
                "id_slot": 0,
                "cache_prompt": false
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "secret_response": "RESPONSE_CANARY"
            })))
            .expect(1)
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_slot": 0,
                "n_erased": 7
            })))
            .expect(1)
            .mount(&backend)
            .await;
        let directory = TempDir::new().expect("应创建临时目录");
        let (port, status_path, task) = start_proxy(backend.address().port(), &directory).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建客户端");
        let response = client
            .post(format!("http://127.0.0.1:{port}/v1/chat/completions"))
            .json(&serde_json::json!({
                "prompt": "PROMPT_CANARY",
                "id_slot": 3,
                "cache_prompt": true
            }))
            .send()
            .await
            .expect("代理请求应成功");
        assert!(response.status().is_success());
        assert!(response
            .text()
            .await
            .expect("应读取响应")
            .contains("RESPONSE_CANARY"));
        let status = read_status(&status_path, 1).await;
        assert_eq!(status.cleanup_successes, 1);
        assert_eq!(status.cleanup_failures, 0);
        assert_eq!(status.tokens_erased, 7);
        assert!(!status.cleanup_required);
        let persisted = std::fs::read_to_string(status_path).expect("应读取清理状态");
        assert!(!persisted.contains("PROMPT_CANARY"));
        assert!(!persisted.contains("RESPONSE_CANARY"));
        task.abort();
    }

    #[tokio::test]
    async fn cleanup_failure_is_reported_and_blocks_next_inference() {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("first"))
            .expect(1)
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(503))
            .expect(2)
            .mount(&backend)
            .await;
        let directory = TempDir::new().expect("应创建临时目录");
        let (port, status_path, task) = start_proxy(backend.address().port(), &directory).await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建客户端");
        let first = client
            .post(format!("http://127.0.0.1:{port}/v1/completions"))
            .body("{}")
            .send()
            .await
            .expect("首请求应返回真实响应");
        assert!(first.status().is_success());
        assert_eq!(first.text().await.expect("应读取响应"), "first");
        let failed = read_status(&status_path, 1).await;
        assert!(failed.cleanup_required);
        assert_eq!(failed.cleanup_failures, 1);
        assert_eq!(failed.last_error_code.as_deref(), Some("erase_http_failed"));

        let health = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .expect("代理应返回真实降级健康状态");
        assert_eq!(health.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        let second = client
            .post(format!("http://127.0.0.1:{port}/v1/completions"))
            .body("{}")
            .send()
            .await
            .expect("被阻止请求也应返回结构化错误");
        assert_eq!(second.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
        assert!(second
            .text()
            .await
            .expect("应读取错误")
            .contains("cleanup_retry_failed"));
        task.abort();
    }

    #[tokio::test]
    async fn dropping_consumer_response_does_not_cancel_terminal_cleanup() {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 256 * 1024]))
            .expect(1)
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .and(query_param("action", "erase"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_slot": 0,
                "n_erased": 5
            })))
            .expect(1)
            .mount(&backend)
            .await;
        let directory = TempDir::new().expect("应创建临时目录");
        let (port, status_path, task) = start_proxy(backend.address().port(), &directory).await;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建客户端")
            .post(format!("http://127.0.0.1:{port}/v1/chat/completions"))
            .body("{}")
            .send()
            .await
            .expect("应取得响应头");
        drop(response);
        let status = read_status(&status_path, 1).await;
        assert_eq!(status.cleanup_successes, 1);
        assert!(!status.cleanup_required);
        task.abort();
    }

    #[tokio::test]
    async fn backend_transport_failure_still_attempts_cleanup_and_records_dirty_state() {
        let unavailable_backend_port = unused_port();
        let directory = TempDir::new().expect("应创建临时目录");
        let (port, status_path, task) = start_proxy(unavailable_backend_port, &directory).await;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建客户端")
            .post(format!("http://127.0.0.1:{port}/v1/completions"))
            .body("{}")
            .send()
            .await
            .expect("代理应返回结构化上游错误");
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
        let status = read_status(&status_path, 1).await;
        assert_eq!(status.cleanup_attempts, 1);
        assert_eq!(status.cleanup_failures, 1);
        assert!(status.cleanup_required);
        assert_eq!(
            status.last_error_code.as_deref(),
            Some("erase_transport_failed")
        );
        task.abort();
    }

    #[tokio::test]
    async fn management_slot_endpoint_is_never_exposed_by_public_proxy() {
        let backend = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&backend)
            .await;
        Mock::given(method("POST"))
            .and(path("/slots/0"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&backend)
            .await;
        let directory = TempDir::new().expect("应创建临时目录");
        let (port, _, task) = start_proxy(backend.address().port(), &directory).await;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("应创建客户端")
            .post(format!("http://127.0.0.1:{port}/slots/0?action=erase"))
            .send()
            .await
            .expect("代理应返回拒绝");
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        task.abort();
    }
}
