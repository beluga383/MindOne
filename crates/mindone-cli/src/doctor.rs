use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::context::AppContext;
use crate::engine;
use crate::error::CliResult;
use crate::output::CommandOutput;
use mindone_engine::EngineInstaller;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: &'static str,
    status: CheckStatus,
    message: String,
}

impl DoctorCheck {
    fn pass(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Pass,
            message: message.into(),
        }
    }

    fn warning(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Warning,
            message: message.into(),
        }
    }

    fn fail(name: &'static str, message: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckStatus::Fail,
            message: message.into(),
        }
    }
}

pub async fn run(context: &AppContext, server_mode: bool) -> CliResult<CommandOutput> {
    let mut checks = vec![system_check(), runtime_dependency_check()];
    checks.push(data_directory_check(context));
    checks.push(keychain_check(context));
    checks.push(coordinator_check(context).await);
    checks.push(engine_check(context));
    checks.push(model_check(context));
    checks.extend(port_checks());
    checks.push(sandbox_check());
    checks.push(gpu_check());
    checks.push(cloudflared_check(context).await);
    if server_mode {
        checks.push(coordinator_ready_check(context).await);
    }
    let failures = checks
        .iter()
        .filter(|check| matches!(check.status, CheckStatus::Fail))
        .count();
    let warnings = checks
        .iter()
        .filter(|check| matches!(check.status, CheckStatus::Warning))
        .count();
    let trust_downgrades = checks
        .iter()
        .filter(|check| check.name == "沙盒能力" && matches!(check.status, CheckStatus::Warning))
        .count();
    let human = checks
        .iter()
        .map(|check| {
            let marker = match check.status {
                CheckStatus::Pass => "通过",
                CheckStatus::Warning => "警告",
                CheckStatus::Fail => "失败",
            };
            format!("[{marker}] {}：{}", check.name, check.message)
        })
        .chain(std::iter::once(format!(
            "诊断汇总：{} 项通过，{} 项警告，{} 项失败",
            checks.len().saturating_sub(warnings + failures),
            warnings,
            failures
        )))
        .collect::<Vec<_>>()
        .join("\n");
    // 失败永远优先于降级警告；其他普通警告不改变成功退出码。
    // 沙盒检查只在实际能力为 Standard-Limited/Experimental 时产生 Warning，
    // 因此这里的 31 是可由生产 capability 探测触发的真实信任降级。
    let exit_code = doctor_exit_code(failures, trust_downgrades);
    CommandOutput::new(
        human,
        serde_json::json!({
            "checks": checks,
            "summary": {
                "passed": checks.len().saturating_sub(warnings + failures),
                "warnings": warnings,
                "failures": failures,
                "trust_downgrades": trust_downgrades,
            }
        }),
    )
    .map(|output| output.with_exit_code(exit_code))
}

const fn doctor_exit_code(failures: usize, trust_downgrades: usize) -> u8 {
    if failures > 0 {
        1
    } else if trust_downgrades > 0 {
        31
    } else {
        0
    }
}

fn system_check() -> DoctorCheck {
    DoctorCheck::pass(
        "系统与架构",
        format!(
            "{} {} / {}",
            sysinfo::System::name().unwrap_or_else(|| std::env::consts::OS.to_owned()),
            sysinfo::System::os_version().unwrap_or_else(|| "未知版本".to_owned()),
            std::env::consts::ARCH
        ),
    )
}

fn runtime_dependency_check() -> DoctorCheck {
    let rust = Command::new("rustc").arg("--version").output();
    match rust {
        Ok(output) if output.status.success() => DoctorCheck::pass(
            "Rust/运行依赖",
            String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        ),
        _ => DoctorCheck::warning(
            "Rust/运行依赖",
            "未发现 rustc；发行版运行不依赖 Rust，但源码构建不可用",
        ),
    }
}

fn data_directory_check(context: &AppContext) -> DoctorCheck {
    match tempfile::NamedTempFile::new_in(&context.paths.runtime) {
        Ok(file) => {
            let path = file.path().display().to_string();
            DoctorCheck::pass(
                "数据目录权限",
                format!("{} 可读写（探测文件 {path}）", context.paths.home.display()),
            )
        }
        Err(error) => DoctorCheck::fail(
            "数据目录权限",
            format!("{} 不可写：{error}", context.paths.runtime.display()),
        ),
    }
}

fn keychain_check(context: &AppContext) -> DoctorCheck {
    match context.vault.available() {
        Ok(()) => DoctorCheck::pass("系统凭证库", "凭证入口可访问，未把 Token 写入配置文件"),
        Err(error) => DoctorCheck::fail("系统凭证库", error.to_string()),
    }
}

async fn coordinator_check(context: &AppContext) -> DoctorCheck {
    match context.coordinator.get::<Value>("/health", None).await {
        Ok(value) => DoctorCheck::pass(
            "网络、DNS 与协调服务器",
            format!(
                "{} /health 可访问：{}",
                context.coordinator.server_url(),
                compact_json(&value)
            ),
        ),
        Err(error) => DoctorCheck::fail(
            "网络、DNS 与协调服务器",
            format!("{}：{error}", context.coordinator.server_url()),
        ),
    }
}

async fn coordinator_ready_check(context: &AppContext) -> DoctorCheck {
    match context.coordinator.get::<Value>("/ready", None).await {
        Ok(value) => DoctorCheck::pass(
            "服务端数据库就绪",
            format!("协调服务器 /ready 已确认依赖：{}", compact_json(&value)),
        ),
        Err(error) => DoctorCheck::fail(
            "服务端数据库就绪",
            format!("CLI 不直连数据库；协调服务器 /ready 检查失败：{error}"),
        ),
    }
}

fn engine_check(context: &AppContext) -> DoctorCheck {
    let index = context.paths.engines.join("index.json");
    if !index.is_file() {
        return DoctorCheck::warning("推理引擎", "尚未安装推理引擎");
    }
    let installer = match EngineInstaller::new(
        context.paths.engines.clone(),
        context.paths.cache.clone(),
        index,
    ) {
        Ok(installer) => installer,
        Err(error) => {
            return DoctorCheck::fail("推理引擎", format!("无法初始化引擎登记：{error}"));
        }
    };
    let records = match installer.registry().list() {
        Ok(records) => records,
        Err(error) => return DoctorCheck::fail("推理引擎", format!("引擎登记损坏：{error}")),
    };
    if records.is_empty() {
        return DoctorCheck::warning("推理引擎", "引擎登记为空");
    }
    for record in &records {
        if let Err(error) = installer.registry().verify_record(record) {
            return DoctorCheck::fail(
                "推理引擎",
                format!("{} {} 完整性校验失败：{error}", record.name, record.version),
            );
        }
    }
    DoctorCheck::pass(
        "推理引擎",
        format!(
            "{} 个隔离引擎的路径、可执行文件与 SHA-256 均有效",
            records.len()
        ),
    )
}

fn model_check(context: &AppContext) -> DoctorCheck {
    let index = context.paths.models.join("index.json");
    if !index.is_file() {
        return DoctorCheck::warning("模型验证", "尚未下载模型");
    }
    let models = match mindone_engine::ModelRegistry::new(index).list() {
        Ok(models) => models,
        Err(error) => return DoctorCheck::fail("模型验证", format!("模型登记损坏：{error}")),
    };
    if models.is_empty() {
        return DoctorCheck::warning("模型验证", "模型登记为空");
    }
    let mut valid = 0_usize;
    for model in models {
        if !model.verification_is_current_in(&context.paths.models) {
            return DoctorCheck::fail(
                "模型验证",
                format!(
                    "{}：结构、大小、兼容性或 SHA-256 与登记记录不一致",
                    model.path.display()
                ),
            );
        }
        valid += 1;
    }
    DoctorCheck::pass(
        "模型验证",
        format!("{valid} 个模型通过实时结构与哈希前置检查"),
    )
}

fn port_checks() -> Vec<DoctorCheck> {
    [8080_u16, 9090_u16]
        .into_iter()
        .map(|port| {
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            match TcpListener::bind(address) {
                Ok(listener) => {
                    drop(listener);
                    DoctorCheck::pass("端口占用", format!("127.0.0.1:{port} 可用"))
                }
                Err(error) => {
                    DoctorCheck::warning("端口占用", format!("127.0.0.1:{port} 已占用：{error}"))
                }
            }
        })
        .collect()
}

fn sandbox_check() -> DoctorCheck {
    let report = std::env::current_exe()
        .map(|path| mindone_sandbox::detect_capabilities_with_supervisor(&path))
        .unwrap_or_else(|_| mindone_sandbox::detect_capabilities());
    let available = !report.applicable.is_empty();
    if available {
        let message = format!(
            "可应用机制：{}；实际最高信任：{:?}；{}",
            report
                .applicable
                .iter()
                .map(|value| format!("{value:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            report.trust_level,
            report.warnings.join("；")
        );
        if matches!(
            report.trust_level,
            mindone_sandbox::TrustLevel::StandardLimited
                | mindone_sandbox::TrustLevel::Experimental
        ) {
            DoctorCheck::warning("沙盒能力", message)
        } else {
            DoctorCheck::pass("沙盒能力", message)
        }
    } else {
        DoctorCheck::fail(
            "沙盒能力",
            format!(
                "没有可应用强化沙盒；实际等级：{:?}；{}",
                report.trust_level,
                report.warnings.join("；")
            ),
        )
    }
}

fn gpu_check() -> DoctorCheck {
    match engine::detect() {
        Ok(output) => {
            let gpu_names = output
                .data
                .get("gpus")
                .and_then(Value::as_array)
                .map(|gpus| {
                    gpus.iter()
                        .filter_map(|gpu| gpu.get("name").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let metal = output
                .data
                .get("metal_available")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let cuda = output
                .data
                .get("cuda_available")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !gpu_names.is_empty() || metal || cuda {
                DoctorCheck::pass(
                    "GPU/Metal/CUDA",
                    format!(
                        "GPU={}，Metal={metal}，CUDA={cuda}",
                        if gpu_names.is_empty() {
                            "平台未提供独立设备名".to_owned()
                        } else {
                            gpu_names.join(", ")
                        }
                    ),
                )
            } else {
                DoctorCheck::warning("GPU/Metal/CUDA", "未检测到可用 GPU 后端，将只能使用 CPU")
            }
        }
        Err(error) => DoctorCheck::fail("GPU/Metal/CUDA", error.to_string()),
    }
}

const MINDONE_COMPOSE_PROJECT: &str = "mindone";
const CLOUDFLARED_SERVICE: &str = "cloudflared";
const COORDINATOR_SERVICE: &str = "coordinator";
const CLOUDFLARED_IMAGE_PREFIX: &str = "cloudflare/cloudflared:";
const ORIGIN_READY_URL: &str = "http://127.0.0.1:8787/ready";
const DOCKER_OUTPUT_LIMIT: usize = 8 * 1024;
const READY_BODY_LIMIT: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainerHealth {
    Healthy,
    Starting,
    Unhealthy,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerRuntime {
    id: String,
    running: bool,
    health: ContainerHealth,
    image: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectorDiscovery {
    Unavailable,
    Missing,
    Ambiguous,
    Present(ContainerRuntime),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MindOneReady {
    status: String,
    service: String,
    version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicRouteReady {
    identity: MindOneReady,
    through_cloudflare: bool,
}

trait MindOneConnectorProbe {
    fn discover_connector(&self) -> ConnectorDiscovery;

    fn origin_ready(&self) -> Result<MindOneReady, String>;

    async fn public_ready(&self, hostname: &str) -> Result<PublicRouteReady, String>;
}

struct SystemConnectorProbe;

impl MindOneConnectorProbe for SystemConnectorProbe {
    fn discover_connector(&self) -> ConnectorDiscovery {
        find_mindone_container(CLOUDFLARED_SERVICE)
    }

    fn origin_ready(&self) -> Result<MindOneReady, String> {
        let coordinator = match find_mindone_container(COORDINATOR_SERVICE) {
            ConnectorDiscovery::Present(runtime) => runtime,
            ConnectorDiscovery::Missing => {
                return Err("未找到 MindOne coordinator 容器".to_owned());
            }
            ConnectorDiscovery::Unavailable => {
                return Err("Docker daemon 不可用，无法检查 origin".to_owned());
            }
            ConnectorDiscovery::Ambiguous => {
                return Err("MindOne coordinator 容器身份不唯一，拒绝选择 origin".to_owned());
            }
        };
        if !coordinator.running || coordinator.health != ContainerHealth::Healthy {
            return Err("MindOne coordinator 容器未达到 running/healthy".to_owned());
        }
        let output = docker_stdout(
            &[
                "exec",
                coordinator.id.as_str(),
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                ORIGIN_READY_URL,
            ],
            READY_BODY_LIMIT,
        )
        .map_err(|_| "coordinator 容器内 loopback /ready 请求失败".to_owned())?;
        parse_mindone_ready(&output)
            .map_err(|_| "coordinator 容器内 loopback /ready 返回不兼容内容".to_owned())
    }

    async fn public_ready(&self, hostname: &str) -> Result<PublicRouteReady, String> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mindone-doctor/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| "无法初始化公网 route 检查客户端".to_owned())?;
        let url = format!("https://{hostname}/ready");
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(|error| public_probe_error(&error))?;
        if !response.status().is_success() {
            return Err(format!(
                "公网 hostname /ready 返回 HTTP {}",
                response.status().as_u16()
            ));
        }
        let through_cloudflare = response
            .headers()
            .get("cf-ray")
            .and_then(|value| value.to_str().ok())
            .is_some_and(valid_cloudflare_ray);
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "无法读取公网 hostname /ready 响应".to_owned())?
        {
            if body.len().saturating_add(chunk.len()) > READY_BODY_LIMIT {
                return Err("公网 hostname /ready 响应超过 8 KiB 上限".to_owned());
            }
            body.extend_from_slice(&chunk);
        }
        let body = std::str::from_utf8(&body)
            .map_err(|_| "公网 hostname /ready 未返回 UTF-8".to_owned())?;
        Ok(PublicRouteReady {
            identity: parse_mindone_ready(body)
                .map_err(|_| "公网 hostname /ready 返回的不是 MindOne 就绪响应".to_owned())?,
            through_cloudflare,
        })
    }
}

async fn cloudflared_check(context: &AppContext) -> DoctorCheck {
    cloudflared_check_with_probe(
        &SystemConnectorProbe,
        context.config.cloudflare_hostname.as_deref(),
    )
    .await
}

async fn cloudflared_check_with_probe<P: MindOneConnectorProbe>(
    probe: &P,
    configured_hostname: Option<&str>,
) -> DoctorCheck {
    let connector = match probe.discover_connector() {
        ConnectorDiscovery::Unavailable => {
            return DoctorCheck::warning(
                "MindOne Cloudflare connector",
                "Docker daemon 或受控容器状态不可验证；没有把 cloudflared 已安装误报为 connector 就绪",
            );
        }
        ConnectorDiscovery::Missing => {
            return DoctorCheck::warning(
                "MindOne Cloudflare connector",
                "未找到 Compose project=mindone、service=cloudflared 的专用 connector 容器",
            );
        }
        ConnectorDiscovery::Ambiguous => {
            return DoctorCheck::fail(
                "MindOne Cloudflare connector",
                "专用 connector 容器身份不唯一或状态不可解析，拒绝检查其他 tunnel",
            );
        }
        ConnectorDiscovery::Present(runtime) => runtime,
    };
    if !connector.running || connector.health != ContainerHealth::Healthy {
        return DoctorCheck::fail(
            "MindOne Cloudflare connector",
            "专用 connector 容器存在，但未达到 running/healthy；installed 不等于 ready",
        );
    }
    if !valid_pinned_cloudflared_image(&connector.image) {
        return DoctorCheck::fail(
            "MindOne Cloudflare connector",
            "Compose service=cloudflared 未使用受控且 digest 固定的 Cloudflare connector 镜像",
        );
    }
    let Some(hostname) = configured_hostname else {
        return DoctorCheck::fail(
            "MindOne Cloudflare connector",
            "connector 已运行，但未配置 cloudflare_hostname，无法验证 Published application route",
        );
    };
    let origin = match probe.origin_ready() {
        Ok(ready) => ready,
        Err(error) => {
            return DoctorCheck::fail(
                "MindOne Cloudflare connector",
                format!("专用 connector 已连接，但 origin 未就绪：{error}"),
            );
        }
    };
    let public = match probe.public_ready(hostname).await {
        Ok(ready) => ready,
        Err(error) => {
            return DoctorCheck::fail(
                "MindOne Cloudflare connector",
                format!("hostname/route 无法验证：{error}"),
            );
        }
    };
    if !public.through_cloudflare {
        return DoctorCheck::fail(
            "MindOne Cloudflare connector",
            "公网 /ready 缺少 CF-Ray，hostname 未证明经由 Cloudflare route",
        );
    }
    if public.identity != origin {
        return DoctorCheck::fail(
            "MindOne Cloudflare connector",
            "公网 hostname 与本地 loopback origin 返回不同的 MindOne 身份，route 可能指向错误服务",
        );
    }
    DoctorCheck::pass(
        "MindOne Cloudflare connector",
        format!(
            "专用 connector running/healthy；loopback origin 与 https://{hostname}/ready 身份一致，且响应经 Cloudflare route"
        ),
    )
}

fn find_mindone_container(service: &str) -> ConnectorDiscovery {
    let project_filter = format!("label=com.docker.compose.project={MINDONE_COMPOSE_PROJECT}");
    let service_filter = format!("label=com.docker.compose.service={service}");
    let output = match docker_stdout(
        &[
            "ps",
            "--all",
            "--filter",
            project_filter.as_str(),
            "--filter",
            service_filter.as_str(),
            "--format",
            "{{.ID}}",
        ],
        DOCKER_OUTPUT_LIMIT,
    ) {
        Ok(output) => output,
        Err(()) => return ConnectorDiscovery::Unavailable,
    };
    let ids = output
        .lines()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return ConnectorDiscovery::Missing;
    }
    if ids.len() != 1 || !valid_container_id(ids[0]) {
        return ConnectorDiscovery::Ambiguous;
    }
    inspect_container(ids[0])
        .map(ConnectorDiscovery::Present)
        .unwrap_or(ConnectorDiscovery::Ambiguous)
}

fn inspect_container(id: &str) -> Result<ContainerRuntime, ()> {
    let output = docker_stdout(
        &[
            "inspect",
            "--format",
            "{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}|{{.Config.Image}}",
            id,
        ],
        256,
    )?;
    let mut state = output.trim().splitn(3, '|');
    let running = state.next().ok_or(())?;
    let health = state.next().ok_or(())?;
    let image = state.next().filter(|value| !value.is_empty()).ok_or(())?;
    let running = match running {
        "true" => true,
        "false" => false,
        _ => return Err(()),
    };
    let health = match health {
        "healthy" => ContainerHealth::Healthy,
        "starting" => ContainerHealth::Starting,
        "unhealthy" => ContainerHealth::Unhealthy,
        "missing" => ContainerHealth::Missing,
        _ => ContainerHealth::Unknown,
    };
    Ok(ContainerRuntime {
        id: id.to_owned(),
        running,
        health,
        image: image.to_owned(),
    })
}

fn docker_stdout(args: &[&str], maximum_bytes: usize) -> Result<String, ()> {
    let output = Command::new("docker").args(args).output().map_err(|_| ())?;
    if !output.status.success() || output.stdout.len() > maximum_bytes {
        return Err(());
    }
    String::from_utf8(output.stdout).map_err(|_| ())
}

fn valid_container_id(value: &str) -> bool {
    (12..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_pinned_cloudflared_image(value: &str) -> bool {
    let Some(version_and_digest) = value.strip_prefix(CLOUDFLARED_IMAGE_PREFIX) else {
        return false;
    };
    let Some((version, digest)) = version_and_digest.split_once("@sha256:") else {
        return false;
    };
    !version.is_empty() && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_cloudflare_ray(value: &str) -> bool {
    let Some((ray_id, colo)) = value.split_once('-') else {
        return false;
    };
    (16..=64).contains(&ray_id.len())
        && ray_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && colo.len() == 3
        && colo.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn parse_mindone_ready(raw: &str) -> Result<MindOneReady, ()> {
    if raw.len() > READY_BODY_LIMIT {
        return Err(());
    }
    let ready: MindOneReady = serde_json::from_str(raw).map_err(|_| ())?;
    if ready.status != "ready" || ready.service != "mindone-coordinator" || ready.version.is_empty()
    {
        return Err(());
    }
    Ok(ready)
}

fn public_probe_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "公网 hostname /ready 请求超时".to_owned()
    } else if error.is_connect() {
        "公网 hostname /ready 无法建立 TLS 连接".to_owned()
    } else {
        "公网 hostname /ready 请求失败".to_owned()
    }
}

fn compact_json(value: &Value) -> String {
    let raw = value.to_string();
    if raw.chars().count() > 200 {
        format!("{}…", raw.chars().take(200).collect::<String>())
    } else {
        raw
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::sandbox_check;
    use super::{
        cloudflared_check_with_probe, doctor_exit_code, valid_cloudflare_ray, CheckStatus,
        ConnectorDiscovery, ContainerHealth, ContainerRuntime, MindOneConnectorProbe, MindOneReady,
        PublicRouteReady,
    };

    #[derive(Clone)]
    struct FakeConnectorProbe {
        discovery: ConnectorDiscovery,
        origin: Result<MindOneReady, String>,
        public: Result<PublicRouteReady, String>,
        expected_hostname: Option<&'static str>,
    }

    impl MindOneConnectorProbe for FakeConnectorProbe {
        fn discover_connector(&self) -> ConnectorDiscovery {
            self.discovery.clone()
        }

        fn origin_ready(&self) -> Result<MindOneReady, String> {
            self.origin.clone()
        }

        async fn public_ready(&self, hostname: &str) -> Result<PublicRouteReady, String> {
            if let Some(expected) = self.expected_hostname {
                assert_eq!(hostname, expected);
            }
            self.public.clone()
        }
    }

    fn healthy_connector() -> ConnectorDiscovery {
        ConnectorDiscovery::Present(ContainerRuntime {
            id: "0123456789ab".to_owned(),
            running: true,
            health: ContainerHealth::Healthy,
            image: format!("cloudflare/cloudflared:2026.7.2@sha256:{}", "0".repeat(64)),
        })
    }

    fn ready(version: &str) -> MindOneReady {
        MindOneReady {
            status: "ready".to_owned(),
            service: "mindone-coordinator".to_owned(),
            version: version.to_owned(),
        }
    }

    fn fake_probe(discovery: ConnectorDiscovery) -> FakeConnectorProbe {
        let identity = ready("1.0.0");
        FakeConnectorProbe {
            discovery,
            origin: Ok(identity.clone()),
            public: Ok(PublicRouteReady {
                identity,
                through_cloudflare: true,
            }),
            expected_hostname: None,
        }
    }

    #[test]
    fn doctor_exit_code_prioritizes_failures_and_ignores_ordinary_warnings() {
        assert_eq!(doctor_exit_code(0, 0), 0);
        assert_eq!(doctor_exit_code(0, 1), 31);
        assert_eq!(doctor_exit_code(1, 0), 1);
        assert_eq!(doctor_exit_code(1, 1), 1);
    }

    #[test]
    fn cloudflare_ray_header_requires_expected_shape() {
        assert!(valid_cloudflare_ray("9f1234567890abcd-SJC"));
        assert!(!valid_cloudflare_ray("present"));
        assert!(!valid_cloudflare_ray("9f1234567890abcd-too-long"));
        assert!(!valid_cloudflare_ray("not-hexadecimal-SJC"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn real_macos_standard_limited_capability_reaches_exit_code_31_decision() {
        let sandbox = sandbox_check();
        assert!(matches!(sandbox.status, CheckStatus::Warning));
        assert!(sandbox.message.contains("StandardLimited"));
        assert_eq!(doctor_exit_code(0, 1), 31);
    }

    #[tokio::test]
    async fn connector_missing_is_warning_and_never_claims_installed_is_ready() {
        let check = cloudflared_check_with_probe(
            &fake_probe(ConnectorDiscovery::Missing),
            Some("api.example.com"),
        )
        .await;
        assert!(matches!(check.status, CheckStatus::Warning));
        assert!(check.message.contains("未找到"));
        assert!(!check.message.contains("已就绪"));
    }

    #[tokio::test]
    async fn connector_present_but_not_healthy_fails() {
        let check = cloudflared_check_with_probe(
            &fake_probe(ConnectorDiscovery::Present(ContainerRuntime {
                id: "0123456789ab".to_owned(),
                running: true,
                health: ContainerHealth::Starting,
                image: format!("cloudflare/cloudflared:2026.7.2@sha256:{}", "0".repeat(64)),
            })),
            Some("api.example.com"),
        )
        .await;
        assert!(matches!(check.status, CheckStatus::Fail));
        assert!(check.message.contains("未达到 running/healthy"));
        assert!(check.message.contains("installed 不等于 ready"));
    }

    #[tokio::test]
    async fn healthy_connector_without_hostname_configuration_fails_closed() {
        let check = cloudflared_check_with_probe(&fake_probe(healthy_connector()), None).await;
        assert!(matches!(check.status, CheckStatus::Fail));
        assert!(check.message.contains("未配置 cloudflare_hostname"));
        assert!(check
            .message
            .contains("无法验证 Published application route"));
    }

    #[tokio::test]
    async fn healthy_connector_with_failed_loopback_origin_fails() {
        let mut probe = fake_probe(healthy_connector());
        probe.origin = Err("loopback /ready 拒绝连接".to_owned());
        let check = cloudflared_check_with_probe(&probe, Some("api.example.com")).await;
        assert!(matches!(check.status, CheckStatus::Fail));
        assert!(check.message.contains("origin 未就绪"));
        assert!(check.message.contains("loopback /ready"));
    }

    #[tokio::test]
    async fn public_route_to_different_mindone_origin_fails() {
        let mut probe = fake_probe(healthy_connector());
        probe.origin = Ok(ready("1.0.0"));
        probe.public = Ok(PublicRouteReady {
            identity: ready("0.9.0"),
            through_cloudflare: true,
        });
        let check = cloudflared_check_with_probe(&probe, Some("api.example.com")).await;
        assert!(matches!(check.status, CheckStatus::Fail));
        assert!(check.message.contains("route 可能指向错误服务"));
    }

    #[tokio::test]
    async fn dedicated_connector_origin_hostname_and_route_can_be_ready() {
        let mut probe = fake_probe(healthy_connector());
        probe.expected_hostname = Some("api.example.com");
        let check = cloudflared_check_with_probe(&probe, Some("api.example.com")).await;
        assert!(matches!(check.status, CheckStatus::Pass));
        assert!(check.message.contains("running/healthy"));
        assert!(check.message.contains("https://api.example.com/ready"));
        assert!(check.message.contains("经 Cloudflare route"));
    }
}
