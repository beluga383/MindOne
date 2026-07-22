use axum::{extract::State, http::HeaderMap, Json};
use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use mindone_protocol::{
    attestation_report_data, AttestationChallengeRequest, AttestationChallengeResponse,
    AttestationEvidenceKind, AttestationKeyOrigin, AttestationProvider, AttestationReportBinding,
    AttestationSubmitRequest, AttestationSubmitResponse, TrustLevel, Validate,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::Row;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    attestation::{VerificationClaims, VerificationInput},
    config::{Config, HardwareAttestationConfig},
    db::authenticate,
    device_binding::require_node_device_binding,
    error::ApiError,
    AppState,
};

pub async fn create_attestation_challenge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AttestationChallengeRequest>,
) -> Result<Json<AttestationChallengeResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request
        .validate()
        .map_err(|error| ApiError::attestation_failed(error.to_string()))?;
    let provider_config = provider_config(&state.config, request.provider)
        .ok_or_else(|| ApiError::attestation_failed("不支持该硬件证明提供者"))?;
    if !provider_config.deployable() {
        return Err(ApiError::attestation_unavailable(
            "协调服务器没有为该提供者配置固定 verifier、策略/运行时哈希和 TEE measurement allowlist",
        ));
    }
    if !provider_config
        .allowed_policy_hashes
        .contains(&request.sandbox_policy_hash)
        || !provider_config
            .allowed_runtime_hashes
            .contains(&request.runtime_binary_hash)
    {
        return Err(ApiError::attestation_failed(
            "当前沙盒策略或推理运行时不在服务器 Enhanced allowlist",
        ));
    }

    let row = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,mi.node_id,mi.status,m.weights_hash
        FROM nodes n
        JOIN model_instances mi ON mi.node_id = n.id
        JOIN models m ON m.id = mi.model_id
        WHERE n.id = $1 AND mi.id = $2
        "#,
    )
    .bind(request.node_id)
    .bind(request.model_instance_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| ApiError::not_found("节点绑定的模型实例"))?;
    require_node_device_binding(
        &principal,
        row.try_get("user_id")?,
        row.try_get("device_key_id")?,
    )?;
    if row.try_get::<Uuid, _>("node_id")? != request.node_id
        || row.try_get::<String, _>("status")? != "published"
    {
        return Err(ApiError::attestation_failed(
            "远程证明要求节点当前拥有已发布的模型实例",
        ));
    }
    let model_weights_hash: String = row.try_get("weights_hash")?;
    let challenge_id = Uuid::now_v7();
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let report_data = attestation_report_data(&AttestationReportBinding {
        challenge_id,
        node_id: request.node_id,
        model_instance_id: request.model_instance_id,
        nonce: &nonce,
        sandbox_policy_hash: &request.sandbox_policy_hash,
        runtime_binary_hash: &request.runtime_binary_hash,
        model_weights_hash: &model_weights_hash,
        ephemeral_public_key: &request.ephemeral_public_key,
        key_origin: request.key_origin,
    })
    .map_err(|error| ApiError::attestation_failed(error.to_string()))?;
    let nonce_hash = hex::encode(Sha256::digest(nonce));
    let report_data_hex = hex::encode(report_data);
    let now = OffsetDateTime::now_utc();
    let expires_at = now + duration_from_std(state.config.attestation_challenge_ttl)?;

    let mut tx = state.pool.begin().await?;
    sqlx::query(
        r#"
        UPDATE attestation_challenges
        SET status = 'expired', consumed_at = now()
        WHERE user_id = $1 AND status = 'pending' AND expires_at <= now()
        "#,
    )
    .bind(principal.user_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        INSERT INTO attestation_challenges
            (id,user_id,node_id,model_instance_id,provider,nonce,nonce_hash,
             sandbox_policy_hash,runtime_binary_hash,model_weights_hash,
             ephemeral_public_key,key_origin,report_data,expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(challenge_id)
    .bind(principal.user_id)
    .bind(request.node_id)
    .bind(request.model_instance_id)
    .bind(request.provider.as_str())
    .bind(nonce.as_slice())
    .bind(&nonce_hash)
    .bind(&request.sandbox_policy_hash)
    .bind(&request.runtime_binary_hash)
    .bind(&model_weights_hash)
    .bind(&request.ephemeral_public_key)
    .bind(key_origin_db(request.key_origin))
    .bind(&report_data_hex)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(AttestationChallengeResponse {
        challenge_id,
        node_id: request.node_id,
        model_instance_id: request.model_instance_id,
        provider: request.provider,
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        expires_at,
        sandbox_policy_hash: request.sandbox_policy_hash,
        runtime_binary_hash: request.runtime_binary_hash,
        model_weights_hash,
        ephemeral_public_key: request.ephemeral_public_key,
        key_origin: request.key_origin,
        report_data: report_data_hex,
    }))
}

pub async fn submit_attestation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AttestationSubmitRequest>,
) -> Result<Json<AttestationSubmitResponse>, ApiError> {
    let principal = authenticate(&state.pool, &state.tokens, &headers).await?;
    request
        .validate()
        .map_err(|error| ApiError::attestation_failed(error.to_string()))?;
    let evidence = BASE64_STANDARD
        .decode(&request.evidence)
        .map_err(|_| ApiError::attestation_failed("证明证据不是有效的标准 base64"))?;
    if evidence.is_empty() || evidence.len() > 576 * 1024 {
        return Err(ApiError::attestation_failed(
            "解码后的证明证据为空或超过 576 KiB",
        ));
    }
    let evidence_sha256 = hex::encode(Sha256::digest(&evidence));
    let now = OffsetDateTime::now_utc();
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query(
        r#"
        SELECT id,user_id,node_id,model_instance_id,provider,nonce_hash,
               sandbox_policy_hash,runtime_binary_hash,model_weights_hash,
               ephemeral_public_key,key_origin,report_data,status,created_at,expires_at,consumed_at
        FROM attestation_challenges
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(request.challenge_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::not_found("远程证明挑战"))?;
    if row.try_get::<Uuid, _>("user_id")? != principal.user_id {
        return Err(ApiError::forbidden("无权提交该远程证明挑战"));
    }
    let status: String = row.try_get("status")?;
    let consumed_at: Option<OffsetDateTime> = row.try_get("consumed_at")?;
    if status != "pending" || consumed_at.is_some() {
        return Err(ApiError::conflict(
            "attestation_replay",
            "远程证明挑战已消费，拒绝重放",
        ));
    }

    let node_id: Uuid = row.try_get("node_id")?;
    let model_instance_id: Uuid = row.try_get("model_instance_id")?;
    let challenge_provider_raw: String = row.try_get("provider")?;
    let challenge_provider = provider_from_db(&challenge_provider_raw)?;
    let nonce_hash: String = row.try_get("nonce_hash")?;
    let policy_hash: String = row.try_get("sandbox_policy_hash")?;
    let runtime_hash: String = row.try_get("runtime_binary_hash")?;
    let model_hash: String = row.try_get("model_weights_hash")?;
    let ephemeral_public_key: String = row.try_get("ephemeral_public_key")?;
    let key_origin = key_origin_from_db(row.try_get::<String, _>("key_origin")?.as_str())?;
    let expected_report_data: String = row.try_get("report_data")?;
    let created_at: OffsetDateTime = row.try_get("created_at")?;
    let challenge_expires_at: OffsetDateTime = row.try_get("expires_at")?;
    let provider_policy = provider_config(&state.config, challenge_provider)
        .ok_or_else(|| ApiError::attestation_failed("不支持该硬件证明提供者"))?;
    let bound_resource = sqlx::query(
        r#"
        SELECT n.user_id,n.device_key_id,mi.node_id,mi.status,m.weights_hash
        FROM nodes n
        JOIN model_instances mi ON mi.node_id = n.id
        JOIN models m ON m.id = mi.model_id
        WHERE n.id = $1 AND mi.id = $2
        FOR SHARE OF n,mi,m
        "#,
    )
    .bind(node_id)
    .bind(model_instance_id)
    .fetch_optional(&mut *tx)
    .await?;
    let resource_binding_current = if let Some(resource) = bound_resource.as_ref() {
        require_node_device_binding(
            &principal,
            resource.try_get("user_id")?,
            resource.try_get("device_key_id")?,
        )?;
        resource.try_get::<Uuid, _>("node_id")? == node_id
            && resource.try_get::<String, _>("status")? == "published"
            && resource.try_get::<String, _>("weights_hash")? == model_hash
    } else {
        false
    };

    let (claims, reason) = if challenge_expires_at <= now {
        (None, "challenge_expired")
    } else if request.provider != challenge_provider
        || !request.evidence_kind.matches_provider(challenge_provider)
    {
        (None, "provider_mismatch")
    } else if !resource_binding_current {
        (None, "resource_binding_changed")
    } else if !provider_policy.deployable()
        || !provider_policy.allowed_policy_hashes.contains(&policy_hash)
        || !provider_policy
            .allowed_runtime_hashes
            .contains(&runtime_hash)
    {
        (None, "server_policy_unavailable")
    } else {
        match state
            .attestation_verifier
            .verify(VerificationInput {
                provider: challenge_provider,
                evidence_kind: request.evidence_kind,
                evidence_base64: &request.evidence,
                expected_report_data: &expected_report_data,
            })
            .await
        {
            Ok(claims) => {
                let reason = evaluate_claims(
                    &claims,
                    challenge_provider,
                    request.evidence_kind,
                    &expected_report_data,
                    provider_policy,
                    now,
                );
                (Some(claims), reason)
            }
            Err(error) => (None, error.audit_code()),
        }
    };
    let verified = reason == "verified";
    let report_id = Uuid::now_v7();
    let report_expires_at = if verified {
        let configured_expiry = now + duration_from_std(state.config.attestation_report_ttl)?;
        claims
            .as_ref()
            .map(|value| value.collateral_expires_at.min(configured_expiry))
            .unwrap_or(configured_expiry)
    } else {
        challenge_expires_at
    };
    let report_status = if reason == "challenge_expired" {
        "expired"
    } else if verified {
        "verified"
    } else {
        "rejected"
    };
    let verifier_name = claims
        .as_ref()
        .map(|value| value.verifier_name.as_str())
        .unwrap_or("mindone-coordinator-fail-closed");
    let tee_measurement = claims.as_ref().map(|value| value.tee_measurement.as_str());
    let collateral_expires_at = claims.as_ref().map(|value| value.collateral_expires_at);
    let signature_verified = claims
        .as_ref()
        .is_some_and(|value| value.signature_verified);
    let certificate_chain_verified = claims
        .as_ref()
        .is_some_and(|value| value.certificate_chain_verified);
    let tcb_current = claims.as_ref().is_some_and(|value| value.tcb_current);
    let collateral_current = claims
        .as_ref()
        .is_some_and(|value| value.collateral_current);
    let verified_at = verified.then_some(now);

    sqlx::query(
        r#"
        INSERT INTO attestation_reports
            (id,node_id,provider,nonce_hash,policy_hash,runtime_hash,model_hash,
             issued_at,verified_at,expires_at,status,challenge_id,model_instance_id,
             evidence_kind,evidence_sha256,evidence_base64,report_data,tee_measurement,
             ephemeral_public_key,key_origin,verifier_name,signature_verified,
             certificate_chain_verified,tcb_current,collateral_current,
             collateral_expires_at,verdict_reason)
        VALUES
            ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
             $18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
        "#,
    )
    .bind(report_id)
    .bind(node_id)
    .bind(challenge_provider.as_str())
    .bind(&nonce_hash)
    .bind(&policy_hash)
    .bind(&runtime_hash)
    .bind(&model_hash)
    .bind(created_at)
    .bind(verified_at)
    .bind(report_expires_at)
    .bind(report_status)
    .bind(request.challenge_id)
    .bind(model_instance_id)
    .bind(evidence_kind_db(request.evidence_kind))
    .bind(&evidence_sha256)
    .bind(&request.evidence)
    .bind(&expected_report_data)
    .bind(tee_measurement)
    .bind(&ephemeral_public_key)
    .bind(key_origin_db(key_origin))
    .bind(verifier_name)
    .bind(signature_verified)
    .bind(certificate_chain_verified)
    .bind(tcb_current)
    .bind(collateral_current)
    .bind(collateral_expires_at)
    .bind(reason)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE attestation_challenges SET status = $2, consumed_at = now() WHERE id = $1")
        .bind(request.challenge_id)
        .bind(report_status)
        .execute(&mut *tx)
        .await?;
    if verified {
        sqlx::query(
            r#"
            UPDATE nodes
            SET trust_level = 'enhanced', attestation_report_id = $2,
                trust_expires_at = $3, updated_at = now()
            WHERE id = $1 AND user_id = $4
            "#,
        )
        .bind(node_id)
        .bind(report_id)
        .bind(report_expires_at)
        .bind(principal.user_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    if !verified {
        return Err(ApiError::attestation_failed(format!(
            "硬件远程证明未通过服务端验证（{reason}）"
        )));
    }
    Ok(Json(AttestationSubmitResponse {
        report_id,
        node_id,
        model_instance_id,
        provider: challenge_provider,
        trust_level: TrustLevel::Enhanced,
        verified_at: now,
        expires_at: report_expires_at,
        ephemeral_public_key,
        key_origin,
    }))
}

fn evaluate_claims(
    claims: &VerificationClaims,
    provider: AttestationProvider,
    evidence_kind: AttestationEvidenceKind,
    expected_report_data: &str,
    policy: &HardwareAttestationConfig,
    now: OffsetDateTime,
) -> &'static str {
    if claims.provider != provider || claims.evidence_kind != evidence_kind {
        return "verifier_provider_mismatch";
    }
    if claims.report_data != expected_report_data {
        return "report_data_mismatch";
    }
    if !policy
        .allowed_tee_measurements
        .contains(&claims.tee_measurement)
    {
        return "tee_measurement_not_allowed";
    }
    if !claims.signature_verified {
        return "signature_not_verified";
    }
    if !claims.certificate_chain_verified {
        return "certificate_chain_not_verified";
    }
    if !claims.tcb_current {
        return "tcb_not_current";
    }
    if !claims.collateral_current || claims.collateral_expires_at <= now {
        return "collateral_not_current";
    }
    if !claims.verified {
        return "verifier_rejected";
    }
    "verified"
}

fn provider_config(
    config: &Config,
    provider: AttestationProvider,
) -> Option<&HardwareAttestationConfig> {
    match provider {
        AttestationProvider::AmdSevSnp => Some(&config.amd_sev_snp_attestation),
        AttestationProvider::IntelTdx => Some(&config.intel_tdx_attestation),
        AttestationProvider::None => None,
    }
}

fn provider_from_db(value: &str) -> Result<AttestationProvider, ApiError> {
    match value {
        "amd_sev_snp" => Ok(AttestationProvider::AmdSevSnp),
        "intel_tdx" => Ok(AttestationProvider::IntelTdx),
        _ => {
            tracing::error!(provider = value, "数据库包含未知证明提供者");
            Err(ApiError::internal())
        }
    }
}

const fn evidence_kind_db(value: AttestationEvidenceKind) -> &'static str {
    match value {
        AttestationEvidenceKind::SnpExtendedReport => "snp_extended_report",
        AttestationEvidenceKind::TdxQuote => "tdx_quote",
    }
}

const fn key_origin_db(value: AttestationKeyOrigin) -> &'static str {
    match value {
        AttestationKeyOrigin::ControlSoftware => "control_software",
        AttestationKeyOrigin::TeeRuntime => "tee_runtime",
    }
}

fn key_origin_from_db(value: &str) -> Result<AttestationKeyOrigin, ApiError> {
    match value {
        "control_software" => Ok(AttestationKeyOrigin::ControlSoftware),
        "tee_runtime" => Ok(AttestationKeyOrigin::TeeRuntime),
        _ => {
            tracing::error!(key_origin = value, "数据库包含未知证明密钥来源");
            Err(ApiError::internal())
        }
    }
}

fn duration_from_std(value: std::time::Duration) -> Result<Duration, ApiError> {
    let seconds = i64::try_from(value.as_secs()).map_err(|_| ApiError::internal())?;
    Ok(Duration::seconds(seconds))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn policy(measurement: &str) -> HardwareAttestationConfig {
        HardwareAttestationConfig {
            verifier_path: Some("/test/verifier".into()),
            allowed_policy_hashes: BTreeSet::from(["11".repeat(32)]),
            allowed_runtime_hashes: BTreeSet::from(["22".repeat(32)]),
            allowed_tee_measurements: BTreeSet::from([measurement.to_owned()]),
        }
    }

    fn claims(now: OffsetDateTime) -> VerificationClaims {
        VerificationClaims {
            verifier_name: "known-test-vector".to_owned(),
            provider: AttestationProvider::AmdSevSnp,
            evidence_kind: AttestationEvidenceKind::SnpExtendedReport,
            verified: true,
            report_data: "33".repeat(64),
            tee_measurement: "44".repeat(48),
            signature_verified: true,
            certificate_chain_verified: true,
            tcb_current: true,
            collateral_current: true,
            collateral_expires_at: now + Duration::hours(1),
        }
    }

    #[test]
    fn verified_requires_every_server_checked_conclusion() {
        let now = OffsetDateTime::now_utc();
        let mut value = claims(now);
        let configured = policy(&value.tee_measurement);
        assert_eq!(
            evaluate_claims(
                &value,
                value.provider,
                value.evidence_kind,
                &value.report_data,
                &configured,
                now,
            ),
            "verified"
        );
        value.tcb_current = false;
        assert_eq!(
            evaluate_claims(
                &value,
                value.provider,
                value.evidence_kind,
                &value.report_data,
                &configured,
                now,
            ),
            "tcb_not_current"
        );
    }

    #[test]
    fn wrong_report_data_and_stale_collateral_fail_closed() {
        let now = OffsetDateTime::now_utc();
        let mut value = claims(now);
        let configured = policy(&value.tee_measurement);
        assert_eq!(
            evaluate_claims(
                &value,
                value.provider,
                value.evidence_kind,
                &"55".repeat(64),
                &configured,
                now,
            ),
            "report_data_mismatch"
        );
        value.collateral_expires_at = now;
        assert_eq!(
            evaluate_claims(
                &value,
                value.provider,
                value.evidence_kind,
                &value.report_data,
                &configured,
                now,
            ),
            "collateral_not_current"
        );
    }
}
