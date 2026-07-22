use mindone_engine::{detect_hardware, HardwareProfile};
use serde::Serialize;

/// 用户确认的 Hugging Face 目标目录。仓库存在性、文件格式与完整性仍在用户端
/// 下载时通过实时清单和 LFS SHA-256 验证，不能用静态目录冒充远端状态。
pub const OFFICIAL_MODEL_REPOSITORIES: [&str; 65] = [
    "Qwen/Qwen3.6-27B",
    "Qwen/Qwen3.6-35B-A3B",
    "Qwen/Qwen3.5-0.8B",
    "Qwen/Qwen3.5-2B",
    "Qwen/Qwen3.5-4B",
    "Qwen/Qwen3.5-9B",
    "Qwen/Qwen3.5-27B",
    "Qwen/Qwen3.5-35B-A3B",
    "Qwen/Qwen3.5-122B-A10B",
    "Qwen/Qwen3.5-397B-A17B",
    "Qwen/Qwen3-0.6B",
    "Qwen/Qwen3-1.7B",
    "Qwen/Qwen3-4B",
    "Qwen/Qwen3-8B",
    "Qwen/Qwen3-14B",
    "Qwen/Qwen3-32B",
    "Qwen/Qwen3-30B-A3B",
    "Qwen/Qwen3-235B-A22B",
    "Qwen/Qwen3-4B-Instruct-2507",
    "Qwen/Qwen3-4B-Thinking-2507",
    "Qwen/Qwen3-30B-A3B-Instruct-2507",
    "Qwen/Qwen3-30B-A3B-Thinking-2507",
    "Qwen/Qwen3-235B-A22B-Instruct-2507",
    "Qwen/Qwen3-235B-A22B-Thinking-2507",
    "Qwen/Qwen2.5-0.5B-Instruct",
    "Qwen/Qwen2.5-1.5B-Instruct",
    "Qwen/Qwen2.5-7B-Instruct",
    "Qwen/Qwen2.5-14B-Instruct",
    "Qwen/Qwen2.5-32B-Instruct",
    "Qwen/Qwen2.5-Coder-0.5B-Instruct",
    "Qwen/Qwen2.5-Coder-1.5B-Instruct",
    "Qwen/Qwen2.5-Coder-3B-Instruct",
    "Qwen/Qwen2.5-Coder-7B-Instruct",
    "Qwen/Qwen2.5-Coder-14B-Instruct",
    "Qwen/Qwen2.5-Coder-32B-Instruct",
    "google/gemma-4-E2B-it",
    "google/gemma-4-E4B-it",
    "google/gemma-4-12B-it",
    "google/gemma-4-26B-A4B-it",
    "google/gemma-4-31B-it",
    "deepseek-ai/DeepSeek-V4-Flash",
    "deepseek-ai/DeepSeek-V4-Pro",
    "deepseek-ai/DeepSeek-V3.2-Exp",
    "deepseek-ai/DeepSeek-V3.2-Speciale",
    "deepseek-ai/DeepSeek-R1",
    "deepseek-ai/DeepSeek-R1-0528",
    "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",
    "zai-org/GLM-4.5-Air",
    "zai-org/GLM-4.5",
    "zai-org/GLM-4.7-Flash",
    "zai-org/GLM-4.7",
    "zai-org/GLM-5",
    "zai-org/GLM-5.1",
    "zai-org/GLM-5.2",
    "mistralai/Ministral-3-8B-Instruct-2512",
    "mistralai/Mistral-Small-3.1-24B-Instruct-2503",
    "mistralai/Mistral-Small-4-119B-2603",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "microsoft/Phi-4-reasoning-vision-15B",
    "microsoft/Phi-4-multimodal-instruct",
    "ibm-granite/granite-4.1-8b",
    "ibm-granite/granite-3.2-8b-instruct",
    "allenai/Olmo-3-7B-Instruct",
    "allenai/Olmo-3.1-32B-Instruct-DPO",
    "allenai/Olmo-3.1-32B-Think",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CatalogModel {
    pub repository: &'static str,
    pub provider: &'static str,
    pub parameter_tenths_billions: Option<u32>,
    pub estimated_q4_memory_bytes: Option<u64>,
    pub source: String,
    pub download_location: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModelRecommendation {
    pub rank: usize,
    pub repository: &'static str,
    pub estimated_q4_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub backend: String,
    pub rationale: String,
}

pub fn contains(repository: &str) -> bool {
    OFFICIAL_MODEL_REPOSITORIES.contains(&repository)
}

pub fn catalog(query: Option<&str>) -> Vec<CatalogModel> {
    let normalized = query.map(str::trim).filter(|value| !value.is_empty());
    OFFICIAL_MODEL_REPOSITORIES
        .iter()
        .copied()
        .filter(|repository| {
            normalized.is_none_or(|query| {
                repository
                    .to_ascii_lowercase()
                    .contains(&query.to_ascii_lowercase())
            })
        })
        .map(|repository| {
            let parameter_tenths_billions = parameter_tenths_billions(repository);
            CatalogModel {
                repository,
                provider: repository
                    .split_once('/')
                    .map_or("unknown", |value| value.0),
                parameter_tenths_billions,
                estimated_q4_memory_bytes: parameter_tenths_billions
                    .and_then(estimated_q4_memory_bytes),
                source: format!("https://huggingface.co/{repository}"),
                download_location: "client",
            }
        })
        .collect()
}

pub fn recommend(limit: usize) -> (HardwareProfile, Vec<ModelRecommendation>) {
    recommend_for_hardware(detect_hardware(), limit)
}

fn recommend_for_hardware(
    hardware: HardwareProfile,
    limit: usize,
) -> (HardwareProfile, Vec<ModelRecommendation>) {
    let dedicated_gpu_memory = hardware
        .gpus
        .iter()
        .filter(|gpu| !gpu.unified_memory)
        .filter_map(|gpu| gpu.memory_bytes)
        .max();
    let available_memory_bytes = dedicated_gpu_memory.unwrap_or(hardware.total_memory_bytes);
    // 为操作系统、KV cache 和推理引擎保留至少 30%，避免“勉强能装下”被描述为适合。
    let recommendation_budget = available_memory_bytes.saturating_mul(7) / 10;
    let mut candidates = OFFICIAL_MODEL_REPOSITORIES
        .iter()
        .copied()
        .filter(|repository| general_text_candidate(repository))
        .filter_map(|repository| {
            let required =
                parameter_tenths_billions(repository).and_then(estimated_q4_memory_bytes)?;
            (required <= recommendation_budget).then_some((repository, required))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| generation_score(right.0).cmp(&generation_score(left.0)))
            .then_with(|| left.0.cmp(right.0))
    });
    candidates.dedup_by_key(|candidate| candidate.0);
    let recommendations = candidates
        .into_iter()
        .take(limit)
        .enumerate()
        .map(|(index, (repository, required))| ModelRecommendation {
            rank: index + 1,
            repository,
            estimated_q4_memory_bytes: required,
            available_memory_bytes,
            backend: hardware.recommended_backend.clone(),
            rationale: format!(
                "保守 Q4 估算约需 {}，不超过可用设备内存的 70%；下载前仍会实时核验 HF 文件和运行后端",
                human_bytes(required)
            ),
        })
        .collect();
    (hardware, recommendations)
}

fn general_text_candidate(repository: &str) -> bool {
    let lower = repository.to_ascii_lowercase();
    !lower.contains("vision")
        && !lower.contains("multimodal")
        && !lower.contains("thinking")
        && !lower.contains("think")
        && !lower.contains("speciale")
}

fn generation_score(repository: &str) -> u8 {
    if repository.contains("Qwen3.6") {
        6
    } else if repository.contains("Qwen3.5") {
        5
    } else if repository.contains("Qwen3-") {
        4
    } else if repository.contains("gemma-4") {
        3
    } else {
        1
    }
}

fn parameter_tenths_billions(repository: &str) -> Option<u32> {
    let bytes = repository.as_bytes();
    let mut values = Vec::new();
    for index in 0..bytes.len() {
        if !matches!(bytes[index], b'B' | b'b') {
            continue;
        }
        let mut start = index;
        while start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
            start -= 1;
        }
        if start == index {
            continue;
        }
        let raw = std::str::from_utf8(&bytes[start..index]).ok()?;
        let value = raw.parse::<f64>().ok()?;
        let tenths = (value * 10.0).round();
        if tenths.is_finite() && tenths > 0.0 && tenths <= f64::from(u32::MAX) {
            values.push(tenths as u32);
        }
    }
    values.into_iter().max()
}

fn estimated_q4_memory_bytes(parameter_tenths_billions: u32) -> Option<u64> {
    // 0.65 byte/parameter 为含量化元数据的保守权重预算，另留 2 GiB runtime/KV 基线。
    u64::from(parameter_tenths_billions)
        .checked_mul(65_000_000)?
        .checked_add(2 * 1024 * 1024 * 1024)
}

fn human_bytes(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / (1024_f64 * 1024_f64 * 1024_f64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mindone_engine::GpuProfile;
    use std::collections::BTreeSet;

    #[test]
    fn official_catalog_has_exactly_sixty_five_unique_safe_hf_repositories() {
        let unique = OFFICIAL_MODEL_REPOSITORIES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), 65);
        for repository in unique {
            let Some((owner, name)) = repository.split_once('/') else {
                panic!("目录项必须为 owner/name：{repository}");
            };
            assert!(!owner.is_empty() && !name.is_empty());
            assert!(!repository.contains("..") && !repository.contains('\\'));
        }
    }

    #[test]
    fn parameter_parser_uses_total_not_active_parameter_count() {
        assert_eq!(parameter_tenths_billions("Qwen/Qwen3.5-0.8B"), Some(8));
        assert_eq!(
            parameter_tenths_billions("Qwen/Qwen3.5-397B-A17B"),
            Some(3_970)
        );
        assert_eq!(parameter_tenths_billions("google/gemma-4-E2B-it"), Some(20));
        assert_eq!(parameter_tenths_billions("zai-org/GLM-5.2"), None);
    }

    #[test]
    fn recommendation_reserves_memory_and_excludes_multimodal_models() {
        let hardware = HardwareProfile {
            os: "test".to_owned(),
            os_version: String::new(),
            kernel_version: String::new(),
            architecture: "x86_64".to_owned(),
            cpu_brand: "test".to_owned(),
            logical_cpu_count: 8,
            total_memory_bytes: 16 * 1024 * 1024 * 1024,
            gpus: vec![GpuProfile {
                name: "test".to_owned(),
                memory_bytes: Some(8 * 1024 * 1024 * 1024),
                temperature_celsius: None,
                unified_memory: false,
            }],
            metal_available: false,
            cuda_available: true,
            nvidia_driver_version: None,
            cuda_driver_version: None,
            recommended_backend: "cuda".to_owned(),
        };
        let (_, recommendations) = recommend_for_hardware(hardware, 3);
        assert_eq!(recommendations.len(), 3);
        assert!(recommendations.iter().all(|item| {
            !item.repository.to_ascii_lowercase().contains("vision")
                && item.estimated_q4_memory_bytes <= item.available_memory_bytes * 7 / 10
        }));
    }
}
