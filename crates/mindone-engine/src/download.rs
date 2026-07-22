use crate::validation::{validate_model, ValidationError, ValidationReport, MAX_MODEL_BYTES};
use futures_util::StreamExt;
use reqwest::header::{CONTENT_RANGE, ETAG, RANGE};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::fs::File as StdFile;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::UnboundedSender;
use url::Url;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelPlatform {
    HuggingFace,
    ModelScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadProgress {
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub resumed: bool,
}

pub struct ModelDownloadRequest {
    pub platform: ModelPlatform,
    pub repository: String,
    pub branch: String,
    pub remote_file: String,
    pub output_name: String,
    pub models_directory: PathBuf,
    pub expected_sha256: Option<String>,
    pub progress: Option<UnboundedSender<DownloadProgress>>,
    /// 可选 HF 访问令牌；仅对 Hugging Face 请求设置 Bearer，不得记录或持久化。
    pub huggingface_token: Option<Zeroizing<String>>,
    /// 只供 loopback 集成测试；生产外部下载必须为 HTTPS。
    pub override_base_url: Option<Url>,
}

/// 仅验证远程模型下载能够开始；不会创建目录、部分文件或模型登记。
pub struct ModelDownloadProbeRequest {
    pub platform: ModelPlatform,
    pub repository: String,
    pub branch: String,
    pub remote_file: String,
    pub expected_sha256: Option<String>,
    /// 可选 HF 访问令牌；探测结束后随请求释放并清零。
    pub huggingface_token: Option<Zeroizing<String>>,
    /// 只供 loopback 集成测试；生产外部下载必须为 HTTPS。
    pub override_base_url: Option<Url>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelDownloadProbeReport {
    pub repository: String,
    pub branch: String,
    pub remote_file: String,
    pub bytes_received: u64,
    pub total_bytes: Option<u64>,
    pub range_supported: bool,
    pub checksum_confirmed: bool,
}

const DOWNLOAD_PROBE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("模型仓库、分支或文件路径无效")]
    UnsafePath,
    #[error("模型下载地址必须使用 HTTPS；仅 loopback 测试允许 HTTP")]
    InsecureUrl,
    #[error("下载目标已存在：{0}")]
    AlreadyExists(PathBuf),
    #[error("下载源没有可信 SHA-256；请提供 --sha256")]
    MissingChecksum,
    #[error("模型下载 HTTP 失败：{0}")]
    Http(#[from] reqwest::Error),
    #[error("模型下载返回 HTTP {0}")]
    HttpStatus(StatusCode),
    #[error("模型下载超过 {limit_bytes} 字节安全上限")]
    DownloadTooLarge { limit_bytes: u64 },
    #[error("模型下载文件操作失败：{0}")]
    Io(#[from] std::io::Error),
    #[error("模型下载后安全校验失败：{0}")]
    Validation(#[from] ValidationError),
}

pub async fn download_model(
    request: ModelDownloadRequest,
) -> Result<ValidationReport, DownloadError> {
    validate_request_paths(&request)?;
    fs::create_dir_all(&request.models_directory).await?;
    let models_directory = fs::canonicalize(&request.models_directory).await?;
    let target = models_directory.join(&request.output_name);
    if path_entry_exists(&target)? {
        return Err(DownloadError::AlreadyExists(target));
    }
    let extension = Path::new(&request.output_name)
        .extension()
        .and_then(|value| value.to_str())
        .ok_or(DownloadError::UnsafePath)?;
    let partial = models_directory.join(format!(
        ".{}.part.{extension}",
        request
            .output_name
            .trim_end_matches(&format!(".{extension}"))
    ));
    ensure_child(&models_directory, &partial)?;

    let url = build_download_url(&request)?;
    enforce_transport(&url)?;
    let client = Client::builder()
        .user_agent("MindOne/1.0.0")
        .redirect(https_redirect_policy())
        .build()?;
    let existing = safe_partial_length(&partial)?;
    let mut http_request = client.get(url);
    if request.platform == ModelPlatform::HuggingFace {
        if let Some(token) = request.huggingface_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }
    }
    if existing > 0 {
        http_request = http_request.header(RANGE, format!("bytes={existing}-"));
    }
    let response = http_request.send().await?;
    enforce_transport(response.url())?;
    let status = response.status();
    if status != StatusCode::OK && status != StatusCode::PARTIAL_CONTENT {
        return Err(DownloadError::HttpStatus(status));
    }
    let trusted_checksum = request
        .expected_sha256
        .as_deref()
        .and_then(normalize_sha256)
        .or_else(|| checksum_from_headers(response.headers()))
        .ok_or(DownloadError::MissingChecksum)?;
    let resumed = existing > 0 && status == StatusCode::PARTIAL_CONTENT;
    let start = if resumed { existing } else { 0 };
    let total = response_total(response.headers(), start, response.content_length());
    if total.is_some_and(|value| value > MAX_MODEL_BYTES) {
        return Err(DownloadError::DownloadTooLarge {
            limit_bytes: MAX_MODEL_BYTES,
        });
    }
    let file = open_partial_file(&partial, resumed)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut downloaded = start;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        downloaded = downloaded
            .checked_add(u64::try_from(chunk.len()).map_err(|_| DownloadError::UnsafePath)?)
            .ok_or(DownloadError::UnsafePath)?;
        if downloaded > MAX_MODEL_BYTES {
            return Err(DownloadError::DownloadTooLarge {
                limit_bytes: MAX_MODEL_BYTES,
            });
        }
        if let Some(progress) = &request.progress {
            let _ = progress.send(DownloadProgress {
                downloaded_bytes: downloaded,
                total_bytes: total,
                resumed,
            });
        }
    }
    file.flush().await?;
    file.sync_all().await?;
    drop(file);

    if let Err(error) = validate_model(&partial, Some(&trusted_checksum)) {
        let _ = fs::remove_file(&partial).await;
        return Err(DownloadError::Validation(error));
    }
    match fs::hard_link(&partial, &target).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(DownloadError::AlreadyExists(target));
        }
        Err(error) => return Err(DownloadError::Io(error)),
    }
    let final_report = match validate_model(&target, Some(&trusted_checksum)) {
        Ok(report) => report,
        Err(error) => {
            let _ = fs::remove_file(&target).await;
            let _ = fs::remove_file(&partial).await;
            return Err(DownloadError::Validation(error));
        }
    };
    if let Err(error) = fs::remove_file(&partial).await {
        let _ = fs::remove_file(&target).await;
        return Err(DownloadError::Io(error));
    }
    sync_directory(&models_directory)?;
    Ok(final_report)
}

/// 发起一个有界 Range 请求并在读取文件头后立即丢弃响应。
///
/// 即使远端忽略 Range 返回 200，也只消费首个响应分块中的有限字节；本函数
/// 从不打开本地文件，因此适合安装/发布前的低流量连通性探测。
pub async fn probe_model_download(
    request: ModelDownloadProbeRequest,
) -> Result<ModelDownloadProbeReport, DownloadError> {
    validate_probe_request_paths(&request)?;
    let url = build_download_url_parts(
        request.platform,
        &request.repository,
        &request.branch,
        &request.remote_file,
        request.override_base_url.as_ref(),
    )?;
    enforce_transport(&url)?;
    let client = Client::builder()
        .user_agent("MindOne/1.0.0")
        .redirect(https_redirect_policy())
        .build()?;
    let mut http_request = client
        .get(url)
        .header(RANGE, format!("bytes=0-{}", DOWNLOAD_PROBE_BYTES - 1));
    if request.platform == ModelPlatform::HuggingFace {
        if let Some(token) = request.huggingface_token.as_deref() {
            http_request = http_request.bearer_auth(token);
        }
    }
    let response = http_request.send().await?;
    enforce_transport(response.url())?;
    let status = response.status();
    if status != StatusCode::OK && status != StatusCode::PARTIAL_CONTENT {
        return Err(DownloadError::HttpStatus(status));
    }
    let header_checksum = checksum_from_headers(response.headers());
    let expected_checksum = request
        .expected_sha256
        .as_deref()
        .and_then(normalize_sha256);
    if request.expected_sha256.is_some() && expected_checksum.is_none() {
        return Err(DownloadError::MissingChecksum);
    }
    // Hugging Face 经 Xet/CDN 重定向后的 ETag 可能标识缓存对象或分块，而清单
    // LFS oid 才是完整文件 SHA-256。探测没有读取完整文件，不能把两者不相等
    // 判作内容损坏；真正下载仍会对整文件计算并核对清单 SHA-256。
    let range_supported = status == StatusCode::PARTIAL_CONTENT;
    let total_bytes = response_total(response.headers(), 0, response.content_length());
    if total_bytes.is_some_and(|value| value > MAX_MODEL_BYTES) {
        return Err(DownloadError::DownloadTooLarge {
            limit_bytes: MAX_MODEL_BYTES,
        });
    }
    let mut bytes_received = 0_u64;
    let mut prefix = Vec::with_capacity(8);
    let mut stream = response.bytes_stream();
    while bytes_received < DOWNLOAD_PROBE_BYTES {
        let Some(chunk) = stream.next().await else {
            break;
        };
        let chunk = chunk?;
        let remaining = DOWNLOAD_PROBE_BYTES.saturating_sub(bytes_received);
        let take = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        if prefix.len() < 8 {
            let prefix_take = (8 - prefix.len()).min(take);
            prefix.extend_from_slice(&chunk[..prefix_take]);
        }
        bytes_received = bytes_received
            .checked_add(u64::try_from(take).map_err(|_| DownloadError::UnsafePath)?)
            .ok_or(DownloadError::UnsafePath)?;
        if take < chunk.len() {
            break;
        }
    }
    validate_probe_prefix(&request.remote_file, &prefix, total_bytes)?;
    Ok(ModelDownloadProbeReport {
        repository: request.repository,
        branch: request.branch,
        remote_file: request.remote_file,
        bytes_received,
        total_bytes,
        range_supported,
        checksum_confirmed: expected_checksum.is_some()
            && header_checksum.as_ref() == expected_checksum.as_ref(),
    })
}

fn validate_probe_prefix(
    remote_file: &str,
    prefix: &[u8],
    total_bytes: Option<u64>,
) -> Result<(), DownloadError> {
    if remote_file.to_ascii_lowercase().ends_with(".gguf") {
        if prefix.len() < 4 || &prefix[..4] != b"GGUF" {
            return Err(DownloadError::Validation(ValidationError::InvalidGguf(
                "下载探测返回的文件头不是 GGUF".to_owned(),
            )));
        }
        return Ok(());
    }
    if remote_file.to_ascii_lowercase().ends_with(".safetensors") {
        if prefix.len() < 8 {
            return Err(DownloadError::Validation(
                ValidationError::InvalidSafetensors("下载探测未返回完整文件头".to_owned()),
            ));
        }
        let header_size = u64::from_le_bytes(
            prefix[..8]
                .try_into()
                .map_err(|_| DownloadError::UnsafePath)?,
        );
        let plausible = header_size > 1
            && header_size <= 100 * 1024 * 1024
            && total_bytes.is_none_or(|total| header_size.saturating_add(8) < total);
        if !plausible {
            return Err(DownloadError::Validation(
                ValidationError::InvalidSafetensors(
                    "下载探测返回的 safetensors 文件头无效".to_owned(),
                ),
            ));
        }
        return Ok(());
    }
    Err(DownloadError::UnsafePath)
}

fn path_entry_exists(path: &Path) -> Result<bool, DownloadError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(DownloadError::Io(error)),
    }
}

fn safe_partial_length(path: &Path) -> Result<u64, DownloadError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(DownloadError::UnsafePath);
            }
            if metadata.len() > MAX_MODEL_BYTES {
                return Err(DownloadError::DownloadTooLarge {
                    limit_bytes: MAX_MODEL_BYTES,
                });
            }
            Ok(metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(DownloadError::Io(error)),
    }
}

fn open_partial_file(path: &Path, resumed: bool) -> Result<StdFile, DownloadError> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true);
    if resumed {
        options.append(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn https_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("MindOne 拒绝超过 5 次的重定向");
        }
        // 初始 loopback HTTP 只供显式集成测试；任何重定向都必须继续保持 HTTPS，
        // 防止公开下载地址把客户端引向明文或本机服务。
        if attempt.url().scheme() == "https" {
            attempt.follow()
        } else {
            attempt.stop()
        }
    })
}

fn validate_request_paths(request: &ModelDownloadRequest) -> Result<(), DownloadError> {
    validate_slash_segments(&request.repository, true)?;
    validate_slash_segments(&request.remote_file, false)?;
    validate_single_segment(&request.branch)?;
    validate_single_segment(&request.output_name)?;
    let extension = Path::new(&request.output_name)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if !matches!(extension.as_deref(), Some("gguf" | "safetensors")) {
        return Err(DownloadError::UnsafePath);
    }
    Ok(())
}

fn validate_probe_request_paths(request: &ModelDownloadProbeRequest) -> Result<(), DownloadError> {
    validate_slash_segments(&request.repository, true)?;
    validate_slash_segments(&request.remote_file, false)?;
    validate_single_segment(&request.branch)?;
    let extension = Path::new(&request.remote_file)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if !matches!(extension.as_deref(), Some("gguf" | "safetensors")) {
        return Err(DownloadError::UnsafePath);
    }
    Ok(())
}

fn validate_slash_segments(value: &str, require_pair: bool) -> Result<(), DownloadError> {
    if value.is_empty() || contains_forbidden_path_character(value, false) {
        return Err(DownloadError::UnsafePath);
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || matches!(component, Component::ParentDir | Component::CurDir)
        })
    {
        return Err(DownloadError::UnsafePath);
    }
    let count = value.split('/').count();
    if (require_pair && count < 2) || count > 32 {
        return Err(DownloadError::UnsafePath);
    }
    Ok(())
}

fn validate_single_segment(value: &str) -> Result<(), DownloadError> {
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || contains_forbidden_path_character(value, true)
    {
        return Err(DownloadError::UnsafePath);
    }
    Ok(())
}

fn contains_forbidden_path_character(value: &str, slash_is_forbidden: bool) -> bool {
    value.chars().any(|character| {
        matches!(character, '\\' | '\0' | '\n' | '\r') || (slash_is_forbidden && character == '/')
    })
}

fn build_download_url(request: &ModelDownloadRequest) -> Result<Url, DownloadError> {
    build_download_url_parts(
        request.platform,
        &request.repository,
        &request.branch,
        &request.remote_file,
        request.override_base_url.as_ref(),
    )
}

fn build_download_url_parts(
    platform: ModelPlatform,
    repository: &str,
    branch: &str,
    remote_file: &str,
    override_base_url: Option<&Url>,
) -> Result<Url, DownloadError> {
    let mut url = if let Some(base) = override_base_url {
        base.clone()
    } else {
        match platform {
            ModelPlatform::HuggingFace => {
                Url::parse("https://huggingface.co/").map_err(|_| DownloadError::UnsafePath)?
            }
            ModelPlatform::ModelScope => Url::parse("https://modelscope.cn/models/")
                .map_err(|_| DownloadError::UnsafePath)?,
        }
    };
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| DownloadError::UnsafePath)?;
        // 两个平台的内置基址都以 `/` 结尾；保留该空 segment 后继续 push 会让
        // ModelScope `/models/` 变成 `/models//owner/repo`，官方 resolve 路径会失效。
        segments.pop_if_empty();
        for part in repository.split('/') {
            segments.push(part);
        }
        segments.push("resolve");
        segments.push(branch);
        for part in remote_file.split('/') {
            segments.push(part);
        }
    }
    Ok(url)
}

fn enforce_transport(url: &Url) -> Result<(), DownloadError> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if loopback {
        Ok(())
    } else {
        Err(DownloadError::InsecureUrl)
    }
}

fn checksum_from_headers(headers: &reqwest::header::HeaderMap) -> Option<String> {
    for name in ["x-checksum-sha256", "x-linked-etag"] {
        if let Some(value) = headers.get(name).and_then(|value| value.to_str().ok()) {
            if let Some(checksum) = normalize_sha256(value) {
                return Some(checksum);
            }
        }
    }
    headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_sha256)
}

fn normalize_sha256(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .trim_start_matches("W/")
        .trim_matches('"')
        .to_ascii_lowercase();
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(normalized)
    } else {
        None
    }
}

fn response_total(
    headers: &reqwest::header::HeaderMap,
    start: u64,
    content_length: Option<u64>,
) -> Option<u64> {
    if let Some(total) = headers
        .get(CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit('/').next())
        .and_then(|value| value.parse::<u64>().ok())
    {
        return Some(total);
    }
    content_length.and_then(|length| start.checked_add(length))
}

fn ensure_child(parent: &Path, child: &Path) -> Result<(), DownloadError> {
    if child.parent() == Some(parent) {
        Ok(())
    } else {
        Err(DownloadError::UnsafePath)
    }
}

fn sync_directory(path: &Path) -> Result<(), DownloadError> {
    #[cfg(unix)]
    {
        StdFile::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn builds_encoded_download_urls_without_traversal() {
        let request = ModelDownloadRequest {
            platform: ModelPlatform::HuggingFace,
            repository: "org/repo".to_owned(),
            branch: "main".to_owned(),
            remote_file: "models/tiny.gguf".to_owned(),
            output_name: "tiny.gguf".to_owned(),
            models_directory: PathBuf::from("/tmp/models"),
            expected_sha256: Some("0".repeat(64)),
            progress: None,
            huggingface_token: None,
            override_base_url: None,
        };
        let url = build_download_url(&request);
        assert!(matches!(
            url,
            Ok(value)
                if value.as_str()
                    == "https://huggingface.co/org/repo/resolve/main/models/tiny.gguf"
        ));
    }

    #[test]
    fn builds_official_modelscope_resolve_url() {
        let request = ModelDownloadRequest {
            platform: ModelPlatform::ModelScope,
            repository: "Qwen/QwQ-32B-GGUF".to_owned(),
            branch: "master".to_owned(),
            remote_file: "weights/qwq-32b-q4_k_m.gguf".to_owned(),
            output_name: "qwq.gguf".to_owned(),
            models_directory: PathBuf::from("/tmp/models"),
            expected_sha256: Some("0".repeat(64)),
            progress: None,
            huggingface_token: None,
            override_base_url: None,
        };
        let url = build_download_url(&request).expect("ModelScope 下载 URL 应可构造");
        assert_eq!(
            url.as_str(),
            "https://modelscope.cn/models/Qwen/QwQ-32B-GGUF/resolve/master/weights/qwq-32b-q4_k_m.gguf"
        );
    }

    #[test]
    fn rejects_traversal_and_non_tls_remote() {
        let mut request = ModelDownloadRequest {
            platform: ModelPlatform::HuggingFace,
            repository: "org/../repo".to_owned(),
            branch: "main".to_owned(),
            remote_file: "tiny.gguf".to_owned(),
            output_name: "tiny.gguf".to_owned(),
            models_directory: PathBuf::from("/tmp/models"),
            expected_sha256: Some("0".repeat(64)),
            progress: None,
            huggingface_token: None,
            override_base_url: None,
        };
        assert!(matches!(
            validate_request_paths(&request),
            Err(DownloadError::UnsafePath)
        ));
        request.repository = "org/repo".to_owned();
        request.override_base_url = Url::parse("http://example.com/").ok();
        let url = build_download_url(&request);
        assert!(url.is_ok());
        let Ok(url) = url else { return };
        assert!(matches!(
            enforce_transport(&url),
            Err(DownloadError::InsecureUrl)
        ));
    }

    #[test]
    fn accepts_loopback_http_for_integration_tests_only() {
        let url = Url::parse("http://127.0.0.1:3000/model.gguf");
        assert!(url.is_ok());
        let Ok(url) = url else { return };
        assert!(enforce_transport(&url).is_ok());
    }

    #[tokio::test]
    async fn probe_reads_a_bounded_prefix_and_never_creates_a_file() {
        let server = MockServer::start().await;
        let checksum = "a".repeat(64);
        let mut body = b"GGUF".to_vec();
        body.extend(std::iter::repeat_n(0_u8, 128 * 1024));
        Mock::given(method("GET"))
            .and(path("/org/repo/resolve/main/model.gguf"))
            .and(header("range", "bytes=0-65535"))
            .and(header("authorization", "Bearer hf_test_token"))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header("content-range", "bytes 0-65535/1048576")
                    .insert_header("x-linked-etag", checksum.as_str())
                    .set_body_bytes(body),
            )
            .expect(1)
            .mount(&server)
            .await;

        let report = probe_model_download(ModelDownloadProbeRequest {
            platform: ModelPlatform::HuggingFace,
            repository: "org/repo".to_owned(),
            branch: "main".to_owned(),
            remote_file: "model.gguf".to_owned(),
            expected_sha256: Some(checksum),
            huggingface_token: Some(Zeroizing::new("hf_test_token".to_owned())),
            override_base_url: Url::parse(&format!("{}/", server.uri())).ok(),
        })
        .await
        .expect("探测应在有界读取后成功");
        assert_eq!(report.bytes_received, DOWNLOAD_PROBE_BYTES);
        assert_eq!(report.total_bytes, Some(1_048_576));
        assert!(report.range_supported);
        assert!(report.checksum_confirmed);
    }

    #[tokio::test]
    async fn probe_rejects_spoofed_model_prefix() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(vec![0_u8; 32]))
            .expect(1)
            .mount(&server)
            .await;
        let error = probe_model_download(ModelDownloadProbeRequest {
            platform: ModelPlatform::HuggingFace,
            repository: "org/repo".to_owned(),
            branch: "main".to_owned(),
            remote_file: "model.gguf".to_owned(),
            expected_sha256: None,
            huggingface_token: None,
            override_base_url: Url::parse(&format!("{}/", server.uri())).ok(),
        })
        .await
        .expect_err("伪造文件头必须拒绝");
        assert!(matches!(error, DownloadError::Validation(_)));
    }

    #[cfg(unix)]
    #[test]
    fn partial_download_never_follows_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir();
        assert!(temp.is_ok());
        let Ok(temp) = temp else { return };
        let outside = temp.path().join("outside");
        let partial = temp.path().join(".model.part.gguf");
        assert!(std::fs::write(&outside, b"do-not-touch").is_ok());
        assert!(symlink(&outside, &partial).is_ok());
        assert!(matches!(
            safe_partial_length(&partial),
            Err(DownloadError::UnsafePath)
        ));
        assert!(open_partial_file(&partial, true).is_err());
        assert!(matches!(std::fs::read(&outside), Ok(bytes) if bytes == b"do-not-touch"));
    }
}
