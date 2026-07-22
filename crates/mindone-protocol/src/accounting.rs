use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{PerformanceTier, TrustLevel};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaBalanceResponse {
    pub user_id: Uuid,
    pub spendable_micro: i64,
    pub reserved_micro: i64,
    pub available_micro: i64,
    pub contribution_micro: i64,
    pub node_tier: Option<PerformanceTier>,
    pub network_reserve_micro: i64,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct QuotaHistoryQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Uuid>,
    /// RFC 3339 inclusive lower bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    /// RFC 3339 exclusive upper bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerNamespace {
    Quota,
    Contribution,
    Reserve,
}

/// 账本行能否由当前公开的 canonical schema 本地重算。
///
/// migration 0027 之前的 v1 行缺少当时参与哈希的完整 metadata，因而只能保留原链
/// 关系，不能被客户端伪装成可按 v2 重算。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerRecomputationStatus {
    CanonicalV2Recomputable,
    LegacyV1Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntryResponse {
    /// Canonical hash 输入：账本 scope。
    pub ledger: LedgerNamespace,
    /// Canonical hash 输入：该 scope 下的账户 UUID。
    pub account_id: Uuid,
    /// Canonical hash 输入：稳定账本行 UUID。
    pub id: Uuid,
    /// Canonical hash 输入：关联请求 UUID；无关联请求时为 null。
    pub request_id: Option<Uuid>,
    /// 结算行可据此查询荣誉账单；不参与 canonical ledger hash。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<Uuid>,
    /// Canonical hash 输入：账本 writer 的稳定幂等键。
    pub idempotency_key: String,
    /// Canonical hash 输入：稳定英文账项类型。
    pub entry_type: String,
    /// Canonical hash 输入：有符号整数 microquota。
    pub delta_micro: i64,
    /// Canonical hash 输入：变动前余额。
    pub balance_before_micro: i64,
    /// Canonical hash 输入：变动后余额。
    pub balance_after_micro: i64,
    /// Canonical hash 输入：PostgreSQL 持久化后的微秒精度时间。
    pub created_at: OffsetDateTime,
    /// Canonical hash 输入：同一账户同一 scope 的前序哈希。
    pub prev_hash: String,
    /// Canonical hash 输入：当前公开可重算版本为 2。
    pub hash_version: i16,
    /// Canonical hash 输入：按 UTF-8 字节排序的受限字符串键值。
    pub metadata: BTreeMap<String, String>,
    /// 服务端明确声明该行是否可按当前 canonical schema 本地重算。
    pub recomputation_status: LedgerRecomputationStatus,
    pub entry_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaHistoryResponse {
    pub entries: Vec<LedgerEntryResponse>,
    pub next_cursor: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalBillingReceipt {
    pub contract_version: String,
    pub profile_id: Uuid,
    pub profile_version: i64,
    pub profile_fingerprint: String,
    pub model_weights_hash: String,
    pub reference_hardware_class: String,
    pub profile_evidence_hash: String,
    pub profile_valid_from: OffsetDateTime,
    pub profile_valid_until: OffsetDateTime,
    pub profile_max_input_tokens: i64,
    pub profile_max_output_tokens: i64,
    pub fixed_gpu_time_us: i64,
    pub gpu_time_us_per_1k_tokens: i64,
    pub reference_vram_mib: i64,
    pub token_rate_micro_per_1k: i64,
    pub gpu_rate_micro_per_second: i64,
    pub vram_rate_micro_per_gib_second: i64,
    pub authorized_input_tokens: i64,
    pub authorized_max_output_tokens: i64,
    pub billable_tokens: i64,
    pub reference_gpu_time_us: i64,
    pub reference_vram_mib_microseconds: i64,
    pub token_cost_micro: i64,
    pub gpu_cost_micro: i64,
    pub vram_cost_micro: i64,
    pub base_cost_micro: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptResponse {
    pub receipt_id: Uuid,
    pub job_id: Uuid,
    pub consumer_user_id: Uuid,
    pub node_user_id: Uuid,
    pub model: String,
    pub tier: PerformanceTier,
    pub trust_level: TrustLevel,
    /// `None` 仅用于读取升级前的历史账单；所有新任务必须冻结 v1 物理计费快照。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing: Option<PhysicalBillingReceipt>,
    pub base_cost_micro: i64,
    pub user_deduction_micro: i64,
    pub node_quota_micro: i64,
    pub contribution_micro: i64,
    pub contribution_weight_ppm: i32,
    pub reserve_micro: i64,
    pub settlement_hash: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReserveUse {
    #[serde(rename = "verification")]
    Verification,
    #[serde(rename = "retry")]
    Retry,
    #[serde(rename = "bandwidth")]
    Bandwidth,
    #[serde(rename = "peak_capacity")]
    PeakCapacity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveStatusResponse {
    pub balance_micro: i64,
    pub total_inflow_micro: i64,
    pub total_outflow_micro: i64,
    pub ledger_entries: i64,
    pub allowed_uses: Vec<ReserveUse>,
    pub updated_at: OffsetDateTime,
}

/// 仅供受控 operator 流程使用，不能作为普通用户 API 暴露。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveReleaseRequest {
    pub amount_micro: i64,
    pub purpose: ReserveUse,
    pub audit_reference: String,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveReleaseResponse {
    pub ledger_id: Uuid,
    pub amount_micro: i64,
    pub balance_before_micro: i64,
    pub balance_after_micro: i64,
    pub purpose: ReserveUse,
    pub audit_reference: String,
    pub idempotent_replay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_use_matches_wire_values() {
        let values = serde_json::to_value(vec![
            ReserveUse::Verification,
            ReserveUse::Retry,
            ReserveUse::Bandwidth,
            ReserveUse::PeakCapacity,
        ])
        .expect("应可序列化");
        assert_eq!(
            values,
            serde_json::json!(["verification", "retry", "bandwidth", "peak_capacity"])
        );
    }

    #[test]
    fn history_query_omits_unset_filters() {
        let value = serde_json::to_value(QuotaHistoryQuery::default()).expect("应可序列化");
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn history_entry_exposes_all_canonical_inputs_and_legacy_status() {
        let entry = LedgerEntryResponse {
            ledger: LedgerNamespace::Quota,
            account_id: Uuid::from_u128(1),
            id: Uuid::from_u128(2),
            request_id: Some(Uuid::from_u128(3)),
            receipt_id: Some(Uuid::from_u128(4)),
            idempotency_key: "result:job-3:consumer".to_owned(),
            entry_type: "consumer_deduction".to_owned(),
            delta_micro: -100,
            balance_before_micro: 1_000,
            balance_after_micro: 900,
            created_at: OffsetDateTime::UNIX_EPOCH,
            prev_hash: "0".repeat(64),
            hash_version: 2,
            metadata: BTreeMap::from([("job_id".to_owned(), "job-3".to_owned())]),
            recomputation_status: LedgerRecomputationStatus::CanonicalV2Recomputable,
            entry_hash: "1".repeat(64),
        };
        let value = serde_json::to_value(entry).expect("账本记录应可序列化");
        for field in [
            "ledger",
            "account_id",
            "id",
            "request_id",
            "idempotency_key",
            "entry_type",
            "delta_micro",
            "balance_before_micro",
            "balance_after_micro",
            "created_at",
            "prev_hash",
            "hash_version",
            "metadata",
            "entry_hash",
        ] {
            assert!(
                value.get(field).is_some(),
                "缺少 canonical 输入字段 {field}"
            );
        }
        assert_eq!(value["recomputation_status"], "canonical_v2_recomputable");
        assert_eq!(
            serde_json::to_value(LedgerRecomputationStatus::LegacyV1Unverifiable)
                .expect("legacy 状态应可序列化"),
            "legacy_v1_unverifiable"
        );
    }

    #[test]
    fn receipt_uses_stable_trust_and_integer_weight_wire_fields() {
        let receipt = ReceiptResponse {
            receipt_id: Uuid::nil(),
            job_id: Uuid::nil(),
            consumer_user_id: Uuid::nil(),
            node_user_id: Uuid::nil(),
            model: "qwen".to_owned(),
            tier: PerformanceTier::Medium,
            trust_level: TrustLevel::StandardLimited,
            billing: Some(PhysicalBillingReceipt {
                contract_version: "server_reference_upper_bound_v1".to_owned(),
                profile_id: Uuid::from_u128(5),
                profile_version: 1,
                profile_fingerprint: "1".repeat(64),
                model_weights_hash: "2".repeat(64),
                reference_hardware_class: "nvidia-l4".to_owned(),
                profile_evidence_hash: "3".repeat(64),
                profile_valid_from: OffsetDateTime::UNIX_EPOCH,
                profile_valid_until: OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
                profile_max_input_tokens: 4_096,
                profile_max_output_tokens: 1_024,
                fixed_gpu_time_us: 100_000,
                gpu_time_us_per_1k_tokens: 2_000_000,
                reference_vram_mib: 8_192,
                token_rate_micro_per_1k: 1_000_000,
                gpu_rate_micro_per_second: 2_000,
                vram_rate_micro_per_gib_second: 3_000,
                authorized_input_tokens: 40,
                authorized_max_output_tokens: 10,
                billable_tokens: 50,
                reference_gpu_time_us: 200_000,
                reference_vram_mib_microseconds: 1_638_400_000,
                token_cost_micro: 50_000,
                gpu_cost_micro: 400,
                vram_cost_micro: 4_800,
                base_cost_micro: 55_200,
            }),
            base_cost_micro: 55_200,
            user_deduction_micro: 55_200,
            node_quota_micro: 44_160,
            contribution_micro: 66_240,
            contribution_weight_ppm: 1_000_000,
            reserve_micro: 11_040,
            settlement_hash: "0".repeat(64),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let value = serde_json::to_value(receipt).expect("荣誉账单应可序列化");
        assert_eq!(value["trust_level"], "standard_limited");
        assert_eq!(value["contribution_weight_ppm"], 1_000_000);
        assert_eq!(
            value["billing"]["contract_version"],
            "server_reference_upper_bound_v1"
        );
        assert_eq!(value["billing"]["token_cost_micro"], 50_000);
        assert_eq!(value["billing"]["reference_gpu_time_us"], 200_000);
    }
}
