use uuid::Uuid;

pub const HEALTH: &str = "/health";
pub const READY: &str = "/ready";
pub const AUTH_DEVICE_START: &str = "/v1/auth/device/start";
pub const AUTH_DEVICE_POLL: &str = "/v1/auth/device/poll";
pub const AUTH_STATUS: &str = "/v1/auth/status";
pub const AUTH_REFRESH: &str = "/v1/auth/refresh";
pub const AUTH_LOGOUT: &str = "/v1/auth/logout";
pub const API_KEYS: &str = "/v1/api-keys";
pub const AUTH_ATTESTATION_CHALLENGE: &str = "/v1/auth/attestation/challenge";

pub const AUTH_ATTESTATION_SUBMIT: &str = "/v1/auth/attestation/submit";
pub const NODES_REGISTER: &str = "/v1/nodes/register";
pub const MODELS_PUBLISH: &str = "/v1/models/publish";
pub const MODELS: &str = "/v1/models";
pub const JOBS: &str = "/v1/jobs";
pub const JOBS_REGULATED_PREPARE: &str = "/v1/jobs/regulated/prepare";
pub const JOBS_REGULATED: &str = "/v1/jobs/regulated";
pub const JOBS_CLAIM: &str = "/v1/jobs/claim";
pub const QUOTA_BALANCE: &str = "/v1/quota/balance";
pub const QUOTA_HISTORY: &str = "/v1/quota/history";
pub const RESERVE: &str = "/v1/reserve";
pub const OPENAI_MODELS: &str = "/v1/models";
pub const OPENAI_CHAT_COMPLETIONS: &str = "/v1/chat/completions";
pub const OPENAI_COMPLETIONS: &str = "/v1/completions";

#[must_use]
pub fn node_heartbeat(node_id: Uuid) -> String {
    format!("/v1/nodes/{node_id}/heartbeat")
}

#[must_use]
pub fn node_stats(node_id: Uuid) -> String {
    format!("/v1/nodes/{node_id}/stats")
}

#[must_use]
pub fn model_instance(model_instance_id: Uuid) -> String {
    format!("/v1/models/{model_instance_id}")
}

#[must_use]
pub fn job(job_id: Uuid) -> String {
    format!("/v1/jobs/{job_id}")
}

#[must_use]
pub fn job_renew(job_id: Uuid) -> String {
    format!("/v1/jobs/{job_id}/renew")
}

#[must_use]
pub fn job_result(job_id: Uuid) -> String {
    format!("/v1/jobs/{job_id}/result")
}

#[must_use]
pub fn job_stream(job_id: Uuid) -> String {
    format!("/v1/jobs/{job_id}/stream")
}

#[must_use]
pub fn job_fail(job_id: Uuid) -> String {
    format!("/v1/jobs/{job_id}/fail")
}

#[must_use]
pub fn quota_receipt(receipt_id: Uuid) -> String {
    format!("/v1/quota/receipts/{receipt_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_paths_are_exact() {
        let id = Uuid::nil();
        assert_eq!(
            job_result(id),
            "/v1/jobs/00000000-0000-0000-0000-000000000000/result"
        );
        assert_eq!(
            job_stream(id),
            "/v1/jobs/00000000-0000-0000-0000-000000000000/stream"
        );
        assert_eq!(
            node_heartbeat(id),
            "/v1/nodes/00000000-0000-0000-0000-000000000000/heartbeat"
        );
    }
}
