use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common::{
    validate_identifier, validate_sha256, validate_tags, PerformanceTier, TrustLevel, Validate,
};
use crate::nodes::NodeStatus;
use crate::ProtocolValidationError;

/// v1 由协调器独占控制的每千 Token 基础成本。公开请求保留该字段用于协议兼容，
/// 但只能声明这一服务端版本值；协调器写库时使用本常量而不是信任请求值。
pub const V1_BASE_COST_PER_1K_MICRO: i64 = 1_000_000;
pub const MAX_BASE_COST_PER_1K_MICRO: i64 = V1_BASE_COST_PER_1K_MICRO;

#[must_use]
pub fn approved_base_cost_per_1k_micro(value: i64) -> bool {
    value == V1_BASE_COST_PER_1K_MICRO
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Gguf,
    Safetensors,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineName {
    #[serde(rename = "llama.cpp")]
    LlamaCpp,
    #[serde(rename = "vllm")]
    Vllm,
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "tensorrt-llm")]
    TensorRtLlm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelInstanceStatus {
    Published,
    Draining,
    Unpublished,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishModelRequest {
    pub node_id: Uuid,
    pub name: String,
    pub alias: String,
    pub format: ModelFormat,
    pub weights_hash: String,
    pub size_bytes: i64,
    pub context_length: i32,
    /// Reserved compatibility field. Public publishers must send zero; the server owns quality.
    #[serde(default)]
    pub benchmark_normalized: i32,
    /// Reserved compatibility field. Public publishers must send zero; the server owns quality.
    #[serde(default)]
    pub glicko_normalized: i32,
    /// Reserved compatibility field. Public publishers must send zero; the server owns quality.
    #[serde(default)]
    pub evaluation_samples: i32,
    pub base_cost_per_1k_micro: i64,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Validate for PublishModelRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        validate_identifier("name", &self.name, 128)?;
        validate_identifier("alias", &self.alias, 64)?;
        validate_sha256("weights_hash", &self.weights_hash)?;
        validate_tags(&self.tags)?;
        if self.size_bytes <= 0 {
            return Err(ProtocolValidationError::new(
                "size_bytes",
                "模型大小必须大于零",
            ));
        }
        if self.context_length <= 0 {
            return Err(ProtocolValidationError::new(
                "context_length",
                "上下文长度必须大于零",
            ));
        }
        if self.benchmark_normalized != 0
            || self.glicko_normalized != 0
            || self.evaluation_samples != 0
        {
            return Err(ProtocolValidationError::new(
                "quality",
                "公开发布不得自报质量；benchmark_normalized、glicko_normalized 和 evaluation_samples 必须为 0",
            ));
        }
        if !approved_base_cost_per_1k_micro(self.base_cost_per_1k_micro) {
            return Err(ProtocolValidationError::new(
                "base_cost_per_1k_micro",
                "基础计价必须等于协调器 v1 唯一受控基准",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishModelResponse {
    pub model_id: Uuid,
    pub model_instance_id: Uuid,
    pub tier: PerformanceTier,
    pub status: ModelInstanceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnpublishModelResponse {
    pub model_instance_id: Uuid,
    pub status: ModelInstanceStatus,
    pub active_jobs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ModelListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInstanceSummary {
    pub model_instance_id: Uuid,
    pub model_id: Uuid,
    pub name: String,
    pub alias: String,
    pub format: ModelFormat,
    pub weights_hash: String,
    pub size_bytes: i64,
    pub context_length: i32,
    pub tier: PerformanceTier,
    pub base_cost_per_1k_micro: i64,
    pub tags: Vec<String>,
    pub node_id: Uuid,
    pub node_status: NodeStatus,
    pub trust_level: TrustLevel,
    pub published_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelListResponse {
    pub models: Vec<ModelInstanceSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_safe_model_publication() {
        let request = PublishModelRequest {
            node_id: Uuid::from_u128(1),
            name: "tiny-model".to_owned(),
            alias: "tiny".to_owned(),
            format: ModelFormat::Gguf,
            weights_hash: "a".repeat(64),
            size_bytes: 1_024,
            context_length: 2_048,
            benchmark_normalized: 0,
            glicko_normalized: 0,
            evaluation_samples: 0,
            base_cost_per_1k_micro: 1_000_000,
            tags: vec!["coding".to_owned()],
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn rejects_publisher_supplied_quality() {
        let request = PublishModelRequest {
            node_id: Uuid::from_u128(1),
            name: "tiny-model".to_owned(),
            alias: "tiny".to_owned(),
            format: ModelFormat::Gguf,
            weights_hash: "a".repeat(64),
            size_bytes: 1_024,
            context_length: 2_048,
            benchmark_normalized: 1,
            glicko_normalized: 0,
            evaluation_samples: 0,
            base_cost_per_1k_micro: 1_000_000,
            tags: vec![],
        };
        let error = request.validate().expect_err("自报质量必须被拒绝");
        assert_eq!(error.field, "quality");
    }

    #[test]
    fn base_cost_must_equal_the_single_server_controlled_baseline() {
        assert!(approved_base_cost_per_1k_micro(1_000_000));
        assert!(!approved_base_cost_per_1k_micro(0));
        assert!(!approved_base_cost_per_1k_micro(1_000));
        assert!(!approved_base_cost_per_1k_micro(999_999));
        assert!(!approved_base_cost_per_1k_micro(
            MAX_BASE_COST_PER_1K_MICRO.saturating_add(1)
        ));
    }

    #[test]
    fn engine_names_preserve_external_contract() {
        assert_eq!(
            serde_json::to_string(&EngineName::LlamaCpp).expect("应可序列化"),
            "\"llama.cpp\""
        );
        assert_eq!(
            serde_json::to_string(&EngineName::TensorRtLlm).expect("应可序列化"),
            "\"tensorrt-llm\""
        );
    }
}
