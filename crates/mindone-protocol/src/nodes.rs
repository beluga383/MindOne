use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::{validate_identifier, validate_tags, TrustLevel, Validate};
use crate::ProtocolValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Online,
    Paused,
    Draining,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMechanism {
    Namespaces,
    SeccompBpf,
    Landlock,
    AppArmor,
    Seatbelt,
    AppSandbox,
    JobObjects,
    AppContainer,
    HyperV,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuProfile {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vram_total_mib: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute_capability: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardwareProfile {
    pub operating_system: String,
    pub operating_system_version: String,
    pub architecture: String,
    pub cpu_model: String,
    pub cpu_logical_cores: u32,
    pub ram_total_mib: u64,
    #[serde(default)]
    pub gpus: Vec<GpuProfile>,
    #[serde(default)]
    pub cuda_available: bool,
    #[serde(default)]
    pub metal_available: bool,
    #[serde(default)]
    pub sandbox_mechanisms: Vec<SandboxMechanism>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, Value>,
}

impl Validate for HardwareProfile {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("operating_system", &self.operating_system, 128)?;
        validate_identifier(
            "operating_system_version",
            &self.operating_system_version,
            128,
        )?;
        validate_identifier("architecture", &self.architecture, 64)?;
        validate_identifier("cpu_model", &self.cpu_model, 256)?;
        if self.cpu_logical_cores == 0 || self.ram_total_mib == 0 {
            return Err(ProtocolValidationError::new(
                "hardware_profile",
                "CPU 核心数和总内存必须大于零",
            ));
        }
        if self.gpus.len() > 32 {
            return Err(ProtocolValidationError::new(
                "hardware_profile.gpus",
                "GPU 数量超过 32 个",
            ));
        }
        for gpu in &self.gpus {
            validate_identifier("hardware_profile.gpus.name", &gpu.name, 256)?;
        }
        if self.sandbox_mechanisms.len() > 16 {
            return Err(ProtocolValidationError::new(
                "hardware_profile.sandbox_mechanisms",
                "沙盒机制数量超过 16 个",
            ));
        }
        let unique = self
            .sandbox_mechanisms
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if unique.len() != self.sandbox_mechanisms.len() {
            return Err(ProtocolValidationError::new(
                "hardware_profile.sandbox_mechanisms",
                "沙盒机制不得重复",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePolicyDto {
    #[serde(default)]
    pub reject_tags: Vec<String>,
    pub max_concurrent: u32,
    pub gpu_temp_limit_c: Option<u16>,
    pub vram_reserve_mib: u64,
}

impl Validate for NodePolicyDto {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_tags(&self.reject_tags)?;
        if !(1..=1_024).contains(&self.max_concurrent) {
            return Err(ProtocolValidationError::new(
                "max_concurrent",
                "必须在 1 到 1024 之间",
            ));
        }
        if self
            .gpu_temp_limit_c
            .is_some_and(|limit| !(30..=120).contains(&limit))
        {
            return Err(ProtocolValidationError::new(
                "gpu_temp_limit_c",
                "必须在 30 到 120 摄氏度之间",
            ));
        }
        if self.vram_reserve_mib > i64::MAX as u64 {
            return Err(ProtocolValidationError::new(
                "vram_reserve_mib",
                "超出协调服务器可结算范围",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterNodeRequest {
    pub alias: String,
    pub hardware_profile: HardwareProfile,
    #[serde(default)]
    pub reject_tags: Vec<String>,
    pub max_concurrent: u32,
    pub gpu_temp_limit_c: Option<u16>,
    #[serde(default)]
    pub vram_reserve_mib: u64,
}

impl Validate for RegisterNodeRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("alias", &self.alias, 64)?;
        self.hardware_profile.validate()?;
        NodePolicyDto {
            reject_tags: self.reject_tags.clone(),
            max_concurrent: self.max_concurrent,
            gpu_temp_limit_c: self.gpu_temp_limit_c,
            vram_reserve_mib: self.vram_reserve_mib,
        }
        .validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterNodeResponse {
    pub node_id: Uuid,
    pub status: NodeStatus,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HeartbeatRequest {
    #[serde(default)]
    pub tps_milli: i64,
    #[serde(default)]
    pub ttft_ms: i64,
    #[serde(default)]
    pub current_concurrent: i32,
    pub gpu_temp_c: Option<i32>,
    pub vram_used_mib: Option<i64>,
    pub vram_total_mib: Option<i64>,
    #[serde(default)]
    pub error_rate_ppm: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_rtt_ms: Option<i64>,
    #[serde(default)]
    pub draining: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<NodePolicyDto>,
}

impl Validate for HeartbeatRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.tps_milli < 0
            || self.ttft_ms < 0
            || self.current_concurrent < 0
            || !(0..=1_000_000).contains(&self.error_rate_ppm)
        {
            return Err(ProtocolValidationError::new(
                "metrics",
                "TPS、TTFT、并发不得为负，错误率必须在 0 到 1000000 ppm",
            ));
        }
        if self
            .gpu_temp_c
            .is_some_and(|value| !(0..=200).contains(&value))
        {
            return Err(ProtocolValidationError::new(
                "gpu_temp_c",
                "温度必须在 0 到 200 摄氏度之间",
            ));
        }
        if self
            .coordinator_rtt_ms
            .is_some_and(|value| !(1..=60_000).contains(&value))
        {
            return Err(ProtocolValidationError::new(
                "coordinator_rtt_ms",
                "协调服务器往返时延必须在 1 到 60000 毫秒之间",
            ));
        }
        if self.vram_used_mib.is_some_and(|value| value < 0)
            || self.vram_total_mib.is_some_and(|value| value < 0)
            || self
                .vram_used_mib
                .zip(self.vram_total_mib)
                .is_some_and(|(used, total)| used > total)
        {
            return Err(ProtocolValidationError::new(
                "vram",
                "显存指标不得为负且已用显存不得超过总显存",
            ));
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub node_id: Uuid,
    pub status: NodeStatus,
    pub accepting_jobs: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMetrics {
    pub tps_milli: i64,
    pub ttft_ms: i64,
    pub current_concurrent: i32,
    pub gpu_temp_c: Option<i32>,
    pub vram_used_mib: Option<i64>,
    pub vram_total_mib: Option<i64>,
    pub error_rate_ppm: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinator_rtt_ms: Option<i64>,
    pub measured_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeHonorStats {
    /// 固定统计口径版本，客户端不得根据展示文案反推算法。
    pub aggregation_version: String,
    /// 全网累计贡献节点 cohort 内的确定性 midrank percentile；隐私阈值不足时为 null。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_rank_percentile: Option<f64>,
    /// cohort 达到隐私阈值时的节点数；否则为 0，避免泄露精确小样本规模。
    pub contribution_rank_cohort_nodes: u64,
    pub contribution_rank_privacy_threshold: u64,
    /// 小于或等于当前累计贡献值的上一个十倍里程碑，首个里程碑前为 0。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_contribution_milestone_micro: Option<i64>,
    /// 严格大于当前累计贡献值的下一个十倍里程碑。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_contribution_milestone_micro: Option<i64>,
    /// UTC 日历日内至少一个终态任务且零失败，连续到今天或昨天的天数。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_failure_streak_days: Option<u64>,
    /// 不包含任何可链接个体标识或精确贡献值的全网荣誉榜。
    #[serde(default)]
    pub network_leaderboard: NetworkHonorLeaderboard,
}

impl Default for NodeHonorStats {
    fn default() -> Self {
        Self {
            aggregation_version: "unavailable".to_owned(),
            contribution_rank_percentile: None,
            contribution_rank_cohort_nodes: 0,
            contribution_rank_privacy_threshold: 0,
            previous_contribution_milestone_micro: None,
            next_contribution_milestone_micro: None,
            zero_failure_streak_days: None,
            network_leaderboard: NetworkHonorLeaderboard::default(),
        }
    }
}

/// 全网榜只公布稳定的匿名档位，不表示任何可识别的节点。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHonorLabel {
    Top1Percent,
    Top5Percent,
    Top10Percent,
    Top25Percent,
    Top50Percent,
    Contributor,
    ZeroFailure100Days,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHonorTiePolicy {
    /// 相同贡献值共享 midrank，因而必须进入同一档位。
    MidrankSharedBand,
}

impl Default for NetworkHonorTiePolicy {
    fn default() -> Self {
        Self::MidrankSharedBand
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkHonorLeaderboardEntry {
    pub label: NetworkHonorLabel,
    /// 达标节点数向下量化后的下界，始终是 count_granularity 的整倍数。
    pub qualifying_nodes_lower_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkHonorLeaderboard {
    pub aggregation_version: String,
    pub privacy_threshold: u64,
    /// 仅在 cohort 达到隐私阈值时发布精确总数；否则为 0。
    pub cohort_nodes: u64,
    pub count_granularity: u64,
    pub suppressed: bool,
    #[serde(default)]
    pub tie_policy: NetworkHonorTiePolicy,
    #[serde(default)]
    pub entries: Vec<NetworkHonorLeaderboardEntry>,
}

impl Default for NetworkHonorLeaderboard {
    fn default() -> Self {
        Self {
            aggregation_version: "unavailable".to_owned(),
            privacy_threshold: 0,
            cohort_nodes: 0,
            count_granularity: 0,
            suppressed: true,
            tie_policy: NetworkHonorTiePolicy::MidrankSharedBand,
            entries: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceCanaryRisk {
    pub model_instance_id: Uuid,
    pub alias: String,
    pub quarantined: bool,
    pub consecutive_failures: u32,
    pub recovery_passes: u32,
    pub quarantine_failure_threshold: u32,
    pub recovery_pass_threshold: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_at: Option<OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_at: Option<OffsetDateTime>,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatsResponse {
    pub node_id: Uuid,
    pub alias: String,
    pub status: NodeStatus,
    pub trust_level: TrustLevel,
    pub requests: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub created_at: OffsetDateTime,
    pub last_seen_at: Option<OffsetDateTime>,
    pub metrics: Option<NodeMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<crate::PerformanceTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spendable_earned_micro: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution_earned_micro: Option<i64>,
    #[serde(default)]
    pub honor: NodeHonorStats,
    /// exact-instance canary 风险状态；是运营信号，不是模型真实性证明。
    #[serde(default)]
    pub instance_canary_risk: Vec<InstanceCanaryRisk>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hardware() -> HardwareProfile {
        HardwareProfile {
            operating_system: "macos".to_owned(),
            operating_system_version: "15".to_owned(),
            architecture: "aarch64".to_owned(),
            cpu_model: "Apple Silicon".to_owned(),
            cpu_logical_cores: 10,
            ram_total_mib: 32_768,
            gpus: Vec::new(),
            cuda_available: false,
            metal_available: true,
            sandbox_mechanisms: vec![SandboxMechanism::Seatbelt],
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn validates_node_registration_and_metrics() {
        let request = RegisterNodeRequest {
            alias: "local-node".to_owned(),
            hardware_profile: hardware(),
            reject_tags: vec!["regulated".to_owned()],
            max_concurrent: 2,
            gpu_temp_limit_c: Some(85),
            vram_reserve_mib: 2_048,
        };
        assert!(request.validate().is_ok());
        let heartbeat = HeartbeatRequest {
            tps_milli: 12_500,
            ttft_ms: 300,
            current_concurrent: 1,
            gpu_temp_c: Some(70),
            vram_used_mib: Some(4_096),
            vram_total_mib: Some(8_192),
            error_rate_ppm: 10_000,
            coordinator_rtt_ms: Some(37),
            draining: false,
            policy: Some(NodePolicyDto {
                reject_tags: vec!["regulated".to_owned()],
                max_concurrent: 2,
                gpu_temp_limit_c: Some(85),
                vram_reserve_mib: 2_048,
            }),
        };
        assert!(heartbeat.validate().is_ok());
    }

    #[test]
    fn coordinator_rtt_accepts_boundaries_and_rejects_out_of_range_values() {
        for coordinator_rtt_ms in [1, 60_000] {
            let heartbeat = HeartbeatRequest {
                coordinator_rtt_ms: Some(coordinator_rtt_ms),
                ..HeartbeatRequest::default()
            };
            assert!(heartbeat.validate().is_ok());
        }
        for coordinator_rtt_ms in [-1, 0, 60_001] {
            let heartbeat = HeartbeatRequest {
                coordinator_rtt_ms: Some(coordinator_rtt_ms),
                ..HeartbeatRequest::default()
            };
            let error = heartbeat
                .validate()
                .expect_err("越界 RTT 必须被协议校验拒绝");
            assert_eq!(error.field, "coordinator_rtt_ms");
        }
    }

    #[test]
    fn legacy_heartbeat_json_omits_coordinator_rtt_compatibly() {
        let heartbeat: HeartbeatRequest = serde_json::from_value(serde_json::json!({
            "tps_milli": 12_500,
            "ttft_ms": 300,
            "current_concurrent": 1,
            "gpu_temp_c": null,
            "vram_used_mib": null,
            "vram_total_mib": null,
            "error_rate_ppm": 0,
            "draining": false
        }))
        .expect("旧版心跳 JSON 应继续反序列化");
        assert_eq!(heartbeat.coordinator_rtt_ms, None);
        let encoded = serde_json::to_value(heartbeat).expect("旧版心跳应可重新序列化");
        assert!(encoded.get("coordinator_rtt_ms").is_none());

        let metrics = NodeMetrics {
            tps_milli: 12_500,
            ttft_ms: 300,
            current_concurrent: 1,
            gpu_temp_c: None,
            vram_used_mib: None,
            vram_total_mib: None,
            error_rate_ppm: 0,
            coordinator_rtt_ms: None,
            measured_at: OffsetDateTime::UNIX_EPOCH,
        };
        let metrics_json = serde_json::to_value(metrics).expect("旧版节点指标应可序列化");
        assert!(metrics_json.get("coordinator_rtt_ms").is_none());
        let decoded: NodeMetrics =
            serde_json::from_value(metrics_json).expect("缺少 RTT 的旧版节点指标应继续反序列化");
        assert_eq!(decoded.coordinator_rtt_ms, None);
    }

    #[test]
    fn legacy_honor_stats_default_new_privacy_safe_fields() {
        let honor: NodeHonorStats = serde_json::from_value(serde_json::json!({
            "aggregation_version": "node-honor-v1",
            "contribution_rank_percentile": 0.75,
            "contribution_rank_cohort_nodes": 5,
            "contribution_rank_privacy_threshold": 5,
            "next_contribution_milestone_micro": 10_000_000,
            "zero_failure_streak_days": 3
        }))
        .expect("旧版荣誉统计应继续可反序列化");
        assert_eq!(honor.previous_contribution_milestone_micro, None);
        assert!(honor.network_leaderboard.suppressed);
        assert!(honor.network_leaderboard.entries.is_empty());
    }

    #[test]
    fn unset_temperature_and_dynamic_policy_have_stable_wire_shape() {
        let registration = RegisterNodeRequest {
            alias: "local-node".to_owned(),
            hardware_profile: hardware(),
            reject_tags: Vec::new(),
            max_concurrent: 1,
            gpu_temp_limit_c: None,
            vram_reserve_mib: 0,
        };
        let registration_json = serde_json::to_value(registration).expect("注册请求应可序列化");
        assert!(registration_json["gpu_temp_limit_c"].is_null());

        let heartbeat = HeartbeatRequest {
            policy: Some(NodePolicyDto {
                reject_tags: vec!["nsfw".to_owned()],
                max_concurrent: 2,
                gpu_temp_limit_c: None,
                vram_reserve_mib: 1_024,
            }),
            ..HeartbeatRequest::default()
        };
        let heartbeat_json = serde_json::to_value(heartbeat).expect("心跳应可序列化");
        assert_eq!(
            heartbeat_json["policy"]["reject_tags"],
            serde_json::json!(["nsfw"])
        );
        assert!(heartbeat_json["policy"]["gpu_temp_limit_c"].is_null());
    }

    #[test]
    fn rejects_impossible_vram_metrics() {
        let heartbeat = HeartbeatRequest {
            vram_used_mib: Some(9_000),
            vram_total_mib: Some(8_000),
            ..HeartbeatRequest::default()
        };
        assert!(heartbeat.validate().is_err());
    }

    #[test]
    fn rejects_duplicate_sandbox_mechanisms() {
        let mut profile = hardware();
        profile.sandbox_mechanisms.push(SandboxMechanism::Seatbelt);
        assert!(profile.validate().is_err());
    }
}
