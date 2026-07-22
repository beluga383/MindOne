use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mindone_accounting::{
    optimize as build_optimization_advice, AdvicePriority, OptimizationMetrics,
    PerformanceTier as AccountingPerformanceTier, TierPolicy,
};
use mindone_engine::MANAGED_SHARE_MAX_CONCURRENT;
use mindone_protocol::{
    ModelListResponse, NodeStatsResponse, PerformanceTier as ProtocolPerformanceTier,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::cli::{NodePolicySetArgs, NodeThresholdSetArgs};
use crate::context::AppContext;
use crate::error::{CliError, CliResult};
use crate::output::CommandOutput;
use crate::storage::{read_json, write_json_atomic};

const POLICY_FILE: &str = "node-policy.json";
const METRICS_FILE: &str = "share-metrics.json";
const SHARE_STATE_FILE: &str = "share.json";
const LOCAL_OPTIMIZATION_POLICY_VERSION: &str = "local-observed-best-v1";
const HARDWARE_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const HARDWARE_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodePolicy {
    pub reject_tags: Vec<String>,
    pub max_concurrent: u16,
    pub gpu_temp_limit_c: Option<u16>,
    pub vram_reserve_gb: f64,
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self {
            reject_tags: Vec::new(),
            max_concurrent: MANAGED_SHARE_MAX_CONCURRENT,
            gpu_temp_limit_c: None,
            vram_reserve_gb: 0.0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardwareMetrics {
    pub gpu_temperature_c: Option<f64>,
    pub vram_total_bytes: Option<u64>,
    pub vram_used_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareMetrics {
    /// 将历史基线绑定到确切节点，防止重新发布后复用其他 worker 的指标。
    #[serde(default)]
    pub node_id: Option<Uuid>,
    /// 将历史基线绑定到确切模型实例。
    #[serde(default)]
    pub model_instance_id: Option<Uuid>,
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub uptime_seconds: u64,
    /// 同一受管 worker 从请求发送到首个非空生成 delta 到达的实测 TTFT。
    pub ttft_ms: Option<f64>,
    pub tps: Option<f64>,
    pub tier: String,
    pub trust_level: String,
    pub quota_earned_micro: i64,
    pub contribution_points_micro: i64,
    /// 同一受管 worker/模型在本机真实完成请求时观测到的最高 TPS。
    #[serde(default)]
    pub best_tps: Option<f64>,
    /// 同一受管 worker/模型在本机完成请求时观测到的最低首 Token TTFT。
    #[serde(default)]
    pub best_ttft_ms: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ActiveShareNode {
    node_id: Uuid,
    model_instance_id: Uuid,
    model_name: String,
}

#[derive(Debug, Serialize)]
struct OptimizationTargetSnapshot {
    policy_version: &'static str,
    basis: &'static str,
    target_tps: f64,
    maximum_ttft_ms: f64,
    maximum_error_rate: f64,
    minimum_samples: u64,
}

pub fn policy_show(context: &AppContext) -> CliResult<CommandOutput> {
    let policy = load_policy(context)?;
    CommandOutput::new(
        format!(
            "拒绝标签：{}\n最大并发：{}",
            if policy.reject_tags.is_empty() {
                "无".to_owned()
            } else {
                policy.reject_tags.join(", ")
            },
            policy.max_concurrent
        ),
        serde_json::json!({
            "reject_tags": policy.reject_tags,
            "max_concurrent": policy.max_concurrent,
        }),
    )
}

pub fn policy_set(context: &AppContext, args: &NodePolicySetArgs) -> CliResult<CommandOutput> {
    if args.reject_tags.is_none() && args.max_concurrent.is_none() {
        return Err(CliError::General(
            "至少提供 --reject-tags 或 --max-concurrent 中的一项".to_owned(),
        ));
    }
    let mut policy = load_policy(context)?;
    if let Some(tags) = &args.reject_tags {
        policy.reject_tags = normalize_tags(tags)?;
    }
    if let Some(max_concurrent) = args.max_concurrent {
        if !(1..=MANAGED_SHARE_MAX_CONCURRENT).contains(&max_concurrent) {
            return Err(CliError::General(
                format!(
                    "受管 llama.cpp 贡献并发必须在 1..={MANAGED_SHARE_MAX_CONCURRENT}；slot 0 保留给本机调用"
                ),
            ));
        }
        policy.max_concurrent = max_concurrent;
    }
    save_policy(context, &policy)?;
    CommandOutput::new(
        format!(
            "路由否决策略已更新\n拒绝标签：[{}]\n最大并发：{}",
            policy.reject_tags.join(", "),
            policy.max_concurrent
        ),
        serde_json::json!({
            "reject_tags": policy.reject_tags,
            "max_concurrent": policy.max_concurrent,
        }),
    )
}

pub fn threshold_show(context: &AppContext) -> CliResult<CommandOutput> {
    let policy = load_policy(context)?;
    let metrics = hardware_metrics();
    CommandOutput::new(
        format!(
            "GPU 温度上限：{}\n显存保留：{:.2} GB\n当前 GPU 温度：{}\n当前显存：{}",
            policy
                .gpu_temp_limit_c
                .map(|value| format!("{value}°C"))
                .unwrap_or_else(|| "未设置".to_owned()),
            policy.vram_reserve_gb,
            metrics
                .gpu_temperature_c
                .map(|value| format!("{value:.1}°C"))
                .unwrap_or_else(|| "平台不可用".to_owned()),
            format_vram(&metrics)
        ),
        serde_json::json!({
            "gpu_temp_limit_c": policy.gpu_temp_limit_c,
            "vram_reserve_gb": policy.vram_reserve_gb,
            "current": metrics,
        }),
    )
}

pub fn threshold_set(
    context: &AppContext,
    args: &NodeThresholdSetArgs,
) -> CliResult<CommandOutput> {
    if args.gpu_temp_limit.is_none() && args.vram_reserve.is_none() {
        return Err(CliError::General(
            "至少提供 --gpu-temp-limit 或 --vram-reserve 中的一项".to_owned(),
        ));
    }
    let mut policy = load_policy(context)?;
    if let Some(limit) = args.gpu_temp_limit {
        if !(30..=110).contains(&limit) {
            return Err(CliError::General(
                "GPU 温度上限必须在 30°C 到 110°C 之间".to_owned(),
            ));
        }
        policy.gpu_temp_limit_c = Some(limit);
    }
    if let Some(reserve) = args.vram_reserve {
        if !reserve.is_finite() || reserve < 0.0 {
            return Err(CliError::General("显存保留必须是非负有限数值".to_owned()));
        }
        policy.vram_reserve_gb = reserve;
    }
    save_policy(context, &policy)?;
    CommandOutput::new(
        format!(
            "硬件保护阈值已更新：GPU 温度超过 {} 或可用显存低于 {:.2} GB 时暂停领取任务",
            policy
                .gpu_temp_limit_c
                .map(|value| format!("{value}°C"))
                .unwrap_or_else(|| "未设置阈值".to_owned()),
            policy.vram_reserve_gb
        ),
        serde_json::json!({
            "gpu_temp_limit_c": policy.gpu_temp_limit_c,
            "vram_reserve_gb": policy.vram_reserve_gb,
        }),
    )
}

pub async fn optimize(context: &AppContext) -> CliResult<CommandOutput> {
    let path = context.paths.runtime.join(METRICS_FILE);
    let local: ShareMetrics = read_json(&path).map_err(|_| {
        CliError::General(
            "尚无真实共享指标；请先发布节点并完成请求，不能用随机文字生成建议".to_owned(),
        )
    })?;
    let active: ActiveShareNode = read_json(&context.paths.runtime.join(SHARE_STATE_FILE))
        .map_err(|_| CliError::General("本机没有活动的模型发布，无法核对权威 Tier".to_owned()))?;
    if local.node_id != Some(active.node_id)
        || local.model_instance_id != Some(active.model_instance_id)
    {
        return Err(CliError::General(
            "本地性能基线不属于当前节点和模型实例；请先完成新的真实请求".to_owned(),
        ));
    }
    let server: NodeStatsResponse = context
        .authorized_get(&mindone_protocol::node_stats(active.node_id))
        .await?;
    let model_query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("name", &active.model_name)
        .append_pair("limit", "200")
        .finish();
    let models: ModelListResponse = context
        .authorized_get(&format!("{}?{model_query}", mindone_protocol::MODELS))
        .await?;
    let current_tier = models
        .models
        .iter()
        .find(|model| {
            model.model_instance_id == active.model_instance_id && model.node_id == active.node_id
        })
        .map(|model| model.tier)
        .ok_or_else(|| {
            CliError::General(
                "服务端模型列表中没有当前发布实例，不能把节点最佳 Tier 冒充当前模型 Tier"
                    .to_owned(),
            )
        })?;
    optimization_output(&local, &server, current_tier)
}

fn optimization_output(
    local: &ShareMetrics,
    server: &NodeStatsResponse,
    current_tier: ProtocolPerformanceTier,
) -> CliResult<CommandOutput> {
    let observed = server.metrics.as_ref().ok_or_else(|| {
        CliError::General("服务端尚无本节点的 TPS、首 Token TTFT 与错误率指标".to_owned())
    })?;
    if observed.tps_milli <= 0 || observed.ttft_ms <= 0 {
        return Err(CliError::General(
            "TPS 或首 Token TTFT 尚未形成有效正数样本，不能生成优化建议".to_owned(),
        ));
    }
    if !(0..=1_000_000).contains(&observed.error_rate_ppm) {
        return Err(CliError::General(
            "协调服务器返回的错误率超出 0 到 1000000 ppm".to_owned(),
        ));
    }
    let measured_tps = observed.tps_milli as f64 / 1_000.0;
    let measured_ttft_ms = observed.ttft_ms as f64;
    let target_tps = valid_positive(local.best_tps)
        .unwrap_or(measured_tps)
        .max(measured_tps);
    let maximum_ttft_ms = valid_positive(local.best_ttft_ms)
        .unwrap_or(measured_ttft_ms)
        .min(measured_ttft_ms);
    let valid_samples = local.successes.saturating_add(local.failures);
    let minimum_samples = TierPolicy::default().minimum_samples;
    let error_rate = f64::from(observed.error_rate_ppm) / 1_000_000.0;
    let targets = OptimizationTargetSnapshot {
        policy_version: LOCAL_OPTIMIZATION_POLICY_VERSION,
        basis: "same_worker_model_observed_best",
        target_tps,
        maximum_ttft_ms,
        maximum_error_rate: 0.0,
        minimum_samples,
    };
    let algorithm_metrics = OptimizationMetrics {
        measured_tps,
        measured_ttft_ms,
        error_rate,
        current_tier: accounting_tier(current_tier),
        target_tps: targets.target_tps,
        maximum_ttft_ms: targets.maximum_ttft_ms,
        maximum_error_rate: targets.maximum_error_rate,
        valid_samples,
        minimum_samples: targets.minimum_samples,
    };
    let advice = build_optimization_advice(algorithm_metrics)
        .map_err(|error| CliError::General(format!("优化指标无效：{error}")))?;
    let advice_human = advice
        .iter()
        .map(|item| format!("- [{}] {}", advice_priority_zh(item.priority), item.message))
        .collect::<Vec<_>>()
        .join("\n");
    CommandOutput::new(
        format!(
            "权威模型 Tier：{:?}\n完成样本：{valid_samples}\n当前 TPS：{measured_tps:.3}\n当前首 Token TTFT：{measured_ttft_ms:.0}ms\n当前错误率：{:.2}%\n目标策略：{}（同一 worker/模型的本机已观测最佳基线）\nTPS 目标：{:.3}\nTTFT 上限：{:.0}ms\n错误率目标：0%\n说明：TTFT 来自受管 worker 的流式 HTTP 单调时钟实测；这些目标用于恢复已观测能力，不承诺 Tier 晋升；贡献 Tier 仍由服务端质量策略决定。\n建议：\n{advice_human}",
            current_tier,
            error_rate * 100.0,
            targets.policy_version,
            targets.target_tps,
            targets.maximum_ttft_ms,
        ),
        serde_json::json!({
            "node_id": server.node_id,
            "measured_at": observed.measured_at,
            "metrics": algorithm_metrics,
            "targets": targets,
            "advice": advice,
            "tier_promotion_claimed": false,
        }),
    )
}

fn valid_positive(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite() && *value > 0.0)
}

const fn accounting_tier(tier: ProtocolPerformanceTier) -> AccountingPerformanceTier {
    match tier {
        ProtocolPerformanceTier::High => AccountingPerformanceTier::High,
        ProtocolPerformanceTier::Medium => AccountingPerformanceTier::Medium,
        ProtocolPerformanceTier::Low => AccountingPerformanceTier::Low,
    }
}

const fn advice_priority_zh(priority: AdvicePriority) -> &'static str {
    match priority {
        AdvicePriority::High => "高",
        AdvicePriority::Medium => "中",
        AdvicePriority::Low => "低",
    }
}

pub fn load_policy(context: &AppContext) -> CliResult<NodePolicy> {
    load_policy_path(&context.paths.runtime.join(POLICY_FILE), true)
}

/// 活动 worker 的策略读取必须失败关闭。缺失、符号链接、非普通文件或损坏内容
/// 都不能回退为默认允许策略；默认策略只允许在 publish/显式配置的初始化路径创建。
pub fn load_persisted_policy(context: &AppContext) -> CliResult<NodePolicy> {
    load_policy_path(&context.paths.runtime.join(POLICY_FILE), false)
}

fn load_policy_path(path: &Path, allow_missing_default: bool) -> CliResult<NodePolicy> {
    let policy = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => read_json(path).map_err(|error| {
            CliError::PolicyRejected(format!(
                "节点策略文件无法安全读取或格式损坏，活动 worker 已失败关闭：{error}"
            ))
        })?,
        Ok(_) => {
            return Err(CliError::PolicyRejected(
                "节点策略路径不是普通文件或是符号链接，活动 worker 已失败关闭".to_owned(),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound && allow_missing_default => {
            NodePolicy::default()
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CliError::PolicyRejected(
                "节点策略文件缺失，活动 worker 已失败关闭；请停止共享后重新发布或显式设置策略"
                    .to_owned(),
            ));
        }
        Err(error) => {
            return Err(CliError::PolicyRejected(format!(
                "无法检查节点策略文件，活动 worker 已失败关闭：{error}"
            )));
        }
    };
    if !(1..=MANAGED_SHARE_MAX_CONCURRENT).contains(&policy.max_concurrent) {
        return Err(CliError::PolicyRejected(format!(
            "本地策略声明 max_concurrent={}，但受管贡献 slot 只允许 1..={MANAGED_SHARE_MAX_CONCURRENT}；请运行 mindone node policy set --max-concurrent <范围内数值>",
            policy.max_concurrent,
        )));
    }
    let normalized_tags = normalize_tags(&policy.reject_tags)
        .map_err(|_| CliError::PolicyRejected("节点策略包含无效或未规范化的拒绝标签".to_owned()))?;
    if normalized_tags != policy.reject_tags {
        return Err(CliError::PolicyRejected(
            "节点策略拒绝标签必须小写、去重并按稳定顺序保存".to_owned(),
        ));
    }
    if policy
        .gpu_temp_limit_c
        .is_some_and(|limit| !(30..=110).contains(&limit))
        || !policy.vram_reserve_gb.is_finite()
        || policy.vram_reserve_gb < 0.0
    {
        return Err(CliError::PolicyRejected(
            "节点策略硬件阈值超出允许范围".to_owned(),
        ));
    }
    Ok(policy)
}

pub fn evaluate_policy(
    policy: &NodePolicy,
    tags: &[String],
    active_requests: u16,
    metrics: &HardwareMetrics,
) -> CliResult<()> {
    if active_requests >= policy.max_concurrent {
        return Err(CliError::PolicyRejected(format!(
            "当前并发 {active_requests} 已达到上限 {}",
            policy.max_concurrent
        )));
    }
    if let Some(tag) = tags.iter().find(|tag| {
        policy
            .reject_tags
            .iter()
            .any(|rejected| rejected.eq_ignore_ascii_case(tag))
    }) {
        return Err(CliError::PolicyRejected(format!(
            "任务标签 {tag} 被节点路由否决策略拒绝"
        )));
    }
    if let Some(limit) = policy.gpu_temp_limit_c {
        let temperature = metrics.gpu_temperature_c.ok_or_else(|| {
            CliError::PolicyRejected(
                "已设置 GPU 温度阈值，但当前平台无法读取传感器；为保护硬件暂停领取任务".to_owned(),
            )
        })?;
        if temperature > f64::from(limit) {
            return Err(CliError::PolicyRejected(format!(
                "GPU 温度 {temperature:.1}°C 超过阈值 {limit}°C，暂停领取任务"
            )));
        }
    }
    if policy.vram_reserve_gb > 0.0 {
        let total = metrics.vram_total_bytes.ok_or_else(|| {
            CliError::PolicyRejected(
                "已设置显存保留阈值，但当前平台无法读取总显存；为保护宿主暂停领取任务".to_owned(),
            )
        })?;
        let used = metrics.vram_used_bytes.ok_or_else(|| {
            CliError::PolicyRejected(
                "已设置显存保留阈值，但当前平台无法读取已用显存；为保护宿主暂停领取任务".to_owned(),
            )
        })?;
        let free = total.saturating_sub(used) as f64;
        let reserve_bytes = policy.vram_reserve_gb * 1024.0 * 1024.0 * 1024.0;
        if free < reserve_bytes {
            return Err(CliError::PolicyRejected(format!(
                "可用显存 {:.2} GB 低于保留阈值 {:.2} GB",
                free / 1024.0 / 1024.0 / 1024.0,
                policy.vram_reserve_gb
            )));
        }
    }
    Ok(())
}

pub fn hardware_metrics() -> HardwareMetrics {
    let mut command = Command::new("nvidia-smi");
    command.args([
        "--query-gpu=temperature.gpu,memory.total,memory.used",
        "--format=csv,noheader,nounits",
    ]);
    let Some(output) = hardware_probe_output(&mut command) else {
        return HardwareMetrics::default();
    };
    if !output.status.success() {
        return HardwareMetrics::default();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut temperature: Option<f64> = None;
    let mut total_mib = Some(0_u64);
    let mut used_mib = Some(0_u64);
    let mut gpu_count = 0_u32;
    for line in text.lines() {
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        let (Some(gpu_temperature), Some(gpu_total), Some(gpu_used)) = (
            fields.first().and_then(|value| value.parse::<f64>().ok()),
            fields.get(1).and_then(|value| value.parse::<u64>().ok()),
            fields.get(2).and_then(|value| value.parse::<u64>().ok()),
        ) else {
            continue;
        };
        temperature = Some(temperature.unwrap_or(gpu_temperature).max(gpu_temperature));
        total_mib = total_mib.and_then(|value| value.checked_add(gpu_total));
        used_mib = used_mib.and_then(|value| value.checked_add(gpu_used));
        gpu_count = gpu_count.saturating_add(1);
    }
    if gpu_count == 0 {
        return HardwareMetrics::default();
    }
    // 多 GPU 节点统一使用设备集合总量；任务窗口采样和注册声明都采用同一 scope。
    // 这是主机可见设备级 best-effort 观测，不是当前 job 的独占显存归因。
    let total = total_mib.and_then(|mib| mib.checked_mul(1024 * 1024));
    let used = used_mib.and_then(|mib| mib.checked_mul(1024 * 1024));
    HardwareMetrics {
        gpu_temperature_c: temperature,
        vram_total_bytes: total,
        vram_used_bytes: used,
    }
}

/// 执行主机硬件探测命令。外部驱动工具若卡住，调用方必须在固定上限内降级为未知，
/// 不能阻塞任务显存采样器的 `finish` 或用户可见状态命令。
pub(crate) fn hardware_probe_output(command: &mut Command) -> Option<Output> {
    command_output_with_timeout(command, HARDWARE_PROBE_TIMEOUT)
        .ok()
        .flatten()
}

fn command_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<Option<Output>> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started_at = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output().map(Some);
        }
        let elapsed = started_at.elapsed();
        if elapsed >= timeout {
            let _ = child.kill();
            // 回收可能稍后才响应终止信号的探测进程，但不让调用方继续等待。
            let _ = thread::Builder::new()
                .name("mindone-hardware-probe-reaper".to_owned())
                .spawn(move || {
                    let _ = child.wait();
                });
            return Ok(None);
        }
        thread::sleep(HARDWARE_PROBE_POLL_INTERVAL.min(timeout - elapsed));
    }
}

pub fn write_metrics(path: &Path, metrics: &ShareMetrics) -> CliResult<()> {
    write_json_atomic(path, metrics)
}

pub fn save_policy(context: &AppContext, policy: &NodePolicy) -> CliResult<()> {
    write_json_atomic(&context.paths.runtime.join(POLICY_FILE), policy)
}

fn normalize_tags(tags: &[String]) -> CliResult<Vec<String>> {
    let mut normalized = Vec::new();
    for tag in tags {
        let tag = tag.trim().to_ascii_lowercase();
        if tag.is_empty()
            || !tag
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CliError::General(format!("无效路由标签：{tag}")));
        }
        if !normalized.contains(&tag) {
            normalized.push(tag);
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn format_vram(metrics: &HardwareMetrics) -> String {
    match (metrics.vram_used_bytes, metrics.vram_total_bytes) {
        (Some(used), Some(total)) => format!(
            "{:.2} / {:.2} GB",
            used as f64 / 1024.0 / 1024.0 / 1024.0,
            total as f64 / 1024.0 / 1024.0 / 1024.0
        ),
        _ => "平台不可用".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::process::Command;
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    use mindone_engine::MANAGED_SHARE_MAX_CONCURRENT;
    use mindone_protocol::{
        NodeMetrics, NodeStatsResponse, NodeStatus, PerformanceTier, TrustLevel,
    };
    use tempfile::TempDir;
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[cfg(unix)]
    use super::command_output_with_timeout;
    use super::{
        evaluate_policy, load_policy_path, optimization_output, HardwareMetrics, NodePolicy,
        ShareMetrics, LOCAL_OPTIMIZATION_POLICY_VERSION,
    };

    #[test]
    fn active_worker_policy_read_fails_closed_after_deletion_or_corruption() {
        let directory = TempDir::new().expect("应创建临时目录");
        let path = directory.path().join("node-policy.json");

        let initial = load_policy_path(&path, true).expect("初始化路径可使用默认策略");
        assert_eq!(initial.max_concurrent, MANAGED_SHARE_MAX_CONCURRENT);
        assert_eq!(
            load_policy_path(&path, false)
                .expect_err("活动 worker 不得把缺失策略降级为默认")
                .exit_code(),
            50
        );

        fs::write(
            &path,
            serde_json::to_vec(&NodePolicy::default()).expect("策略应可编码"),
        )
        .expect("应写入策略");
        load_policy_path(&path, false).expect("普通策略文件应可读取");
        fs::write(&path, b"{broken-json").expect("应写入损坏策略");
        assert_eq!(
            load_policy_path(&path, false)
                .expect_err("损坏策略必须失败关闭")
                .exit_code(),
            50
        );
        fs::remove_file(&path).expect("应删除临时策略");
        assert_eq!(
            load_policy_path(&path, false)
                .expect_err("运行期删除策略必须失败关闭")
                .exit_code(),
            50
        );
    }

    #[cfg(unix)]
    #[test]
    fn policy_reader_rejects_symbolic_links() {
        let directory = TempDir::new().expect("应创建临时目录");
        let target = directory.path().join("target.json");
        let link = directory.path().join("node-policy.json");
        fs::write(
            &target,
            serde_json::to_vec(&NodePolicy::default()).expect("策略应可编码"),
        )
        .expect("应写入策略目标");
        std::os::unix::fs::symlink(&target, &link).expect("应创建策略符号链接");

        assert_eq!(
            load_policy_path(&link, false)
                .expect_err("策略符号链接必须失败关闭")
                .exit_code(),
            50
        );
    }

    #[cfg(unix)]
    #[test]
    fn hardware_probe_timeout_returns_unknown_without_waiting_for_stuck_command() {
        let started_at = Instant::now();
        let output = command_output_with_timeout(
            Command::new("/bin/sleep").arg("5"),
            Duration::from_millis(50),
        )
        .expect("探测命令应可启动");

        assert!(output.is_none());
        assert!(started_at.elapsed() < Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_hardware_probe_preserves_successful_output() {
        let output = command_output_with_timeout(
            Command::new("/bin/sh").args(["-c", "printf probe-ok"]),
            Duration::from_secs(1),
        )
        .expect("探测命令应可启动")
        .expect("及时完成的探测不应降级");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"probe-ok");
    }

    #[test]
    fn policy_rejects_tag_and_concurrency() {
        let policy = NodePolicy {
            reject_tags: vec!["nsfw".to_owned()],
            max_concurrent: MANAGED_SHARE_MAX_CONCURRENT,
            ..NodePolicy::default()
        };
        assert_eq!(
            evaluate_policy(
                &policy,
                &["NSFW".to_owned()],
                0,
                &HardwareMetrics::default()
            )
            .expect_err("拒绝标签必须生效")
            .exit_code(),
            50
        );
        assert!(evaluate_policy(
            &policy,
            &[],
            MANAGED_SHARE_MAX_CONCURRENT,
            &HardwareMetrics::default()
        )
        .is_err());
    }

    #[test]
    fn configured_unreadable_temperature_fails_closed() {
        let policy = NodePolicy {
            gpu_temp_limit_c: Some(75),
            ..NodePolicy::default()
        };
        assert!(evaluate_policy(&policy, &[], 0, &HardwareMetrics::default()).is_err());
    }

    #[test]
    fn optimization_uses_authoritative_metrics_and_observed_baseline() {
        let local = ShareMetrics {
            node_id: Some(Uuid::from_u128(1)),
            model_instance_id: Some(Uuid::from_u128(2)),
            requests: 20,
            successes: 18,
            failures: 2,
            uptime_seconds: 3_600,
            ttft_ms: Some(1_500.0),
            tps: Some(8.0),
            tier: "Medium".to_owned(),
            trust_level: "Standard".to_owned(),
            quota_earned_micro: 0,
            contribution_points_micro: 0,
            best_tps: Some(10.0),
            best_ttft_ms: Some(1_000.0),
        };
        let now = OffsetDateTime::now_utc();
        let server = NodeStatsResponse {
            node_id: Uuid::from_u128(1),
            alias: "node-test".to_owned(),
            status: NodeStatus::Online,
            trust_level: TrustLevel::Standard,
            requests: 20,
            succeeded: 18,
            failed: 2,
            created_at: now,
            last_seen_at: Some(now),
            metrics: Some(NodeMetrics {
                tps_milli: 8_000,
                ttft_ms: 1_500,
                current_concurrent: 0,
                gpu_temp_c: None,
                vram_used_mib: None,
                vram_total_mib: None,
                error_rate_ppm: 100_000,
                coordinator_rtt_ms: Some(22),
                measured_at: now,
            }),
            uptime_seconds: Some(3_600),
            // 节点 stats 只给最佳 Tier；当前模型 Tier 必须由精确实例查询提供。
            tier: Some(PerformanceTier::High),
            spendable_earned_micro: Some(1_000_000),
            contribution_earned_micro: Some(1_500_000),
            honor: Default::default(),
            instance_canary_risk: Vec::new(),
        };

        let output = optimization_output(&local, &server, PerformanceTier::Low)
            .expect("真实指标应生成确定性建议");
        assert_eq!(
            output.data["targets"]["policy_version"],
            LOCAL_OPTIMIZATION_POLICY_VERSION
        );
        assert_eq!(output.data["targets"]["target_tps"], 10.0);
        assert_eq!(output.data["targets"]["maximum_ttft_ms"], 1_000.0);
        assert_eq!(output.data["metrics"]["current_tier"], "low");
        assert_eq!(output.data["tier_promotion_claimed"], false);
        let codes = output.data["advice"]
            .as_array()
            .expect("建议应为数组")
            .iter()
            .filter_map(|item| item["code"].as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"reduce_error_rate"));
        assert!(codes.contains(&"reduce_ttft"));
        assert!(codes.contains(&"improve_tps"));
        assert!(codes.contains(&"recover_tier"));
        assert!(output.human.contains("不承诺 Tier 晋升"));
        assert!(output.human.contains("流式 HTTP 单调时钟实测"));
    }
}
