use std::process::Stdio;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use mindone_protocol::{
    device_key_fingerprint, device_key_possession_message, refresh_key_possession_message,
    AuthStatusResponse, DeviceBoundRefreshRequest, DeviceFlowStatus, DeviceKeyAlgorithm,
    DevicePollRequest, DevicePollResponse, DeviceStartRequest, DeviceStartResponse, LogoutRequest,
    LogoutResponse, RefreshResponse, DEVICE_KEY_CHALLENGE_BYTES, REFRESH_KEY_CHALLENGE_BYTES,
};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::{sleep, Instant};
use zeroize::Zeroizing;

use crate::cli::AuthLoginArgs;
use crate::context::AppContext;
use crate::coordinator::CoordinatorClient;
use crate::error::{CliError, CliResult};
use crate::output::{CommandOutput, OutputMode};
use crate::vault::{CredentialBundle, SystemVault};

pub async fn login(
    context: &AppContext,
    args: &AuthLoginArgs,
    output_mode: OutputMode,
) -> CliResult<CommandOutput> {
    context.vault.available()?;
    if context.vault.has_session()? {
        return Err(CliError::Authentication(
            "本机已有登录会话；如需切换账号，请先运行 mindone auth logout".to_owned(),
        ));
    }

    // 所有认证提供者（包括邮箱网页登录）统一经设备密钥绑定的 Device Flow。
    // Token 仅在 CLI 证明持有 Ed25519 私钥后由 poll 响应一次性交付。
    if !output_mode.quiet && !output_mode.json {
        println!("使用设备授权流程（Device Flow）登录...");
        println!();
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let public_bytes = signing_key.verifying_key().to_bytes();
    let public_key = hex::encode(public_bytes);
    let fingerprint = device_key_fingerprint(&public_bytes);
    let request = DeviceStartRequest {
        device_public_key: public_key,
        device_key_algorithm: DeviceKeyAlgorithm::Ed25519,
    };
    let value: Value = context
        .coordinator
        .post("/v1/auth/device/start", None, &request)
        .await
        .map_err(map_auth_error)?;
    let start: DeviceStartResponse = decode_api_value(value, "设备授权启动")?;
    if start.user_code.is_empty() || start.verification_uri.is_empty() || start.expires_in == 0 {
        return Err(CliError::Authentication(
            "协调服务器返回了不完整的设备授权信息".to_owned(),
        ));
    }
    let verification_uri =
        validate_verification_uri(&start.verification_uri, context.coordinator.server_url())?;
    let challenge = decode_device_challenge(&start.device_challenge)?;
    let possession_message = device_key_possession_message(
        start.flow_id,
        &challenge,
        &public_bytes,
        DeviceKeyAlgorithm::Ed25519,
    );
    let device_key_signature = hex::encode(signing_key.sign(&possession_message).to_bytes());

    show_device_instruction(output_mode, &start.user_code, verification_uri.as_str());
    if !args.no_open {
        if let Err(error) = open_browser(verification_uri.as_str()).await {
            eprintln!("警告：{error}");
        }
    }

    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    let mut interval = start.interval.clamp(1, 30);
    loop {
        if Instant::now() >= deadline {
            return Err(CliError::Authentication(
                "设备验证码已过期，请重新运行 mindone auth login".to_owned(),
            ));
        }
        sleep(Duration::from_secs(interval)).await;
        let request = DevicePollRequest {
            flow_id: start.flow_id,
            device_key_signature: device_key_signature.clone(),
        };
        let value: Value = context
            .coordinator
            .post("/v1/auth/device/poll", None, &request)
            .await
            .map_err(map_auth_error)?;
        let poll: DevicePollResponse = decode_api_value(value, "轮询设备授权")?;
        match poll.status {
            DeviceFlowStatus::Pending => {
                interval = poll.interval.unwrap_or(interval).clamp(1, 30);
            }
            DeviceFlowStatus::Authorized => {
                let tokens = poll.tokens.ok_or_else(|| {
                    CliError::Authentication("授权成功响应缺少 TokenPair".to_owned())
                })?;
                let user = poll.user.ok_or_else(|| {
                    CliError::Authentication("授权成功响应缺少用户信息".to_owned())
                })?;
                let server_fingerprint = poll.device_key_fingerprint.ok_or_else(|| {
                    CliError::Authentication("授权成功响应缺少设备密钥指纹".to_owned())
                })?;
                if server_fingerprint != fingerprint {
                    return Err(CliError::Authentication(
                        "协调服务器绑定的设备密钥指纹与本机密钥不一致，拒绝保存会话".to_owned(),
                    ));
                }
                let access_token = required_secret(Some(tokens.access_token), "access_token")?;
                let refresh_token = required_secret(Some(tokens.refresh_token), "refresh_token")?;
                let refresh_challenge = required_refresh_challenge(tokens.refresh_challenge)?;
                let login_at = OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .map_err(|error| {
                        CliError::Authentication(format!("无法记录登录时间：{error}"))
                    })?;
                let session = CredentialBundle {
                    access_token,
                    refresh_token,
                    refresh_challenge,
                    user: user.username,
                    uid: user.id.to_string(),
                    local_sandbox_trust_level: local_trust_level().to_owned(),
                    key_fingerprint: fingerprint,
                    login_at,
                };
                let private_key = Zeroizing::new(signing_key.to_bytes().to_vec());
                context.vault.store(&session, private_key.as_slice())?;
                return CommandOutput::new(
                    format!(
                        "登录成功\n用户：{}\nUID：{}\n本机沙盒能力等级：{}\n设备密钥指纹：{}\n说明：账户与节点信任等级请以 mindone auth status 的服务器结果为准",
                        session.user,
                        session.uid,
                        session.local_sandbox_trust_level,
                        session.key_fingerprint
                    ),
                    serde_json::json!({
                        "user": session.user,
                        "uid": session.uid,
                        "local_sandbox_trust_level": session.local_sandbox_trust_level,
                        "key_fingerprint": session.key_fingerprint,
                        "login_at": session.login_at,
                        "server_url": context.coordinator.server_url(),
                    }),
                );
            }
            DeviceFlowStatus::Denied => {
                return Err(CliError::Authentication("用户拒绝了设备授权".to_owned()));
            }
            DeviceFlowStatus::Expired => {
                return Err(CliError::Authentication(
                    "设备验证码已过期，请重新登录".to_owned(),
                ));
            }
        }
    }
}

fn local_trust_level() -> &'static str {
    match mindone_sandbox::detect_capabilities().trust_level {
        mindone_sandbox::TrustLevel::Enhanced => "Enhanced",
        mindone_sandbox::TrustLevel::Standard => "Standard",
        mindone_sandbox::TrustLevel::StandardLimited => "Standard-Limited",
        mindone_sandbox::TrustLevel::Experimental => "Experimental",
        mindone_sandbox::TrustLevel::Unverified => "Unverified",
    }
}

pub async fn logout(context: &AppContext) -> CliResult<CommandOutput> {
    if !context.vault.has_session()? {
        // 上次注销可能已完成服务端撤销而进程在本地清理后中断。
        // 凭证已不存在时应幂等成功，不能要求用户“先登录再注销”。
        context.vault.clear()?;
        return CommandOutput::message("本机没有有效登录会话，无需重复注销");
    }
    let mut session = context.vault.load_session()?;
    let response = match request_logout(context, &session).await {
        Ok(response) => response,
        Err(CliError::Authentication(_)) => {
            // 推理或长时间运行后 access token 可能已到期。先轮换 refresh
            // token，再撤销新会话；任一步失败都保留本地凭证，便于安全重试。
            session = refresh_session(context).await?;
            request_logout(context, &session).await?
        }
        Err(error) => return Err(error),
    };
    if !response.revoked {
        return Err(CliError::Authentication(
            "协调服务器未确认会话撤销，保留本机凭证以便重试".to_owned(),
        ));
    }
    context.vault.clear()?;
    CommandOutput::message("已撤销服务端会话、设备密钥绑定和本机安全凭证")
}

async fn request_logout(
    context: &AppContext,
    session: &CredentialBundle,
) -> CliResult<LogoutResponse> {
    let request = LogoutRequest {
        refresh_token: session.refresh_token.clone(),
    };
    let value: Value = context
        .coordinator
        .post("/v1/auth/logout", Some(&session.access_token), &request)
        .await
        .map_err(map_auth_error)?;
    decode_api_value(value, "注销会话")
}

pub async fn status(context: &AppContext) -> CliResult<CommandOutput> {
    let response: AuthStatusResponse = context
        .authorized_get(mindone_protocol::AUTH_STATUS)
        .await
        .map_err(map_auth_error)?;
    status_output(
        &response,
        local_trust_level(),
        context.coordinator.server_url(),
    )
}

fn status_output(
    response: &AuthStatusResponse,
    local_sandbox_trust: &str,
    coordinator_url: &str,
) -> CliResult<CommandOutput> {
    let fingerprint = response
        .device_key_fingerprint
        .as_deref()
        .unwrap_or("未绑定");
    let best_node_trust = response
        .best_node_trust_level
        .map(|trust| format!("{trust:?}"))
        .unwrap_or_else(|| "无已注册节点".to_owned());
    CommandOutput::new(
        format!(
            "用户（服务器确认）：{}\nUID（服务器确认）：{}\n账户信任等级（服务器）：{:?}\n最佳节点信任等级（服务器）：{}\n已注册节点：{}\n本机沙盒能力等级：{}\n设备密钥指纹（服务器绑定）：{}\n设备密钥已撤销：{}\n登录时间（服务器记录）：{}\n最近使用时间：{}\n协调服务器：{}\n会话：有效",
            response.user.username,
            response.user.id,
            response.trust_level,
            best_node_trust,
            response.registered_nodes,
            local_sandbox_trust,
            fingerprint,
            response
                .device_key_revoked
                .map(|revoked| if revoked { "是" } else { "否" })
                .unwrap_or("未知"),
            response.logged_in_at,
            response
                .last_used_at
                .map(|value| value.to_string())
                .unwrap_or_else(|| "暂无".to_owned()),
            coordinator_url
        ),
        serde_json::json!({
            "authenticated": true,
            "user": response.user.username,
            "uid": response.user.id,
            "trust_level": response.trust_level,
            "trust_source": "coordinator",
            "local_sandbox_trust_level": local_sandbox_trust,
            "key_fingerprint": response.device_key_fingerprint,
            "login_at": response.logged_in_at,
            "last_used_at": response.last_used_at,
            "device_key_revoked": response.device_key_revoked,
            "device_key_created_at": response.device_key_created_at,
            "device_key_rotated_at": response.device_key_rotated_at,
            "registered_nodes": response.registered_nodes,
            "best_node_trust_level": response.best_node_trust_level,
            "server_url": coordinator_url,
        }),
    )
}

pub async fn refresh_session(context: &AppContext) -> CliResult<CredentialBundle> {
    let session = context.vault.load_session()?;
    refresh_credential_bundle(&context.coordinator, &context.vault, session).await
}

pub(crate) async fn refresh_credential_bundle(
    coordinator: &CoordinatorClient,
    vault: &SystemVault,
    mut session: CredentialBundle,
) -> CliResult<CredentialBundle> {
    let device_private_key = vault.load_device_signing_key()?;
    let request = build_device_bound_refresh_request(&session, &device_private_key)?;
    let value: Value = coordinator
        .post("/v1/auth/refresh", None, &request)
        .await
        .map_err(map_auth_error)?;
    let refresh: RefreshResponse = decode_api_value(value, "刷新登录会话")?;
    if refresh.access_token.is_empty() || refresh.refresh_token.is_empty() {
        return Err(CliError::Authentication(
            "刷新响应缺少 access_token".to_owned(),
        ));
    }
    let next_refresh_challenge = required_refresh_challenge(refresh.refresh_challenge)?;
    session.access_token = refresh.access_token;
    session.refresh_token = refresh.refresh_token;
    session.refresh_challenge = next_refresh_challenge;
    vault.store_session(&session)?;
    Ok(session)
}

fn build_device_bound_refresh_request(
    session: &CredentialBundle,
    private_key: &[u8; 32],
) -> CliResult<DeviceBoundRefreshRequest> {
    let challenge = decode_refresh_challenge(&session.refresh_challenge)?;
    let signing_key = SigningKey::from_bytes(private_key);
    let public_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = device_key_fingerprint(&public_bytes);
    if fingerprint != session.key_fingerprint {
        return Err(CliError::Authentication(
            "系统凭证中的设备私钥与当前会话指纹不匹配，拒绝刷新".to_owned(),
        ));
    }
    let message = refresh_key_possession_message(
        &challenge,
        &session.refresh_token,
        &public_bytes,
        DeviceKeyAlgorithm::Ed25519,
    );
    Ok(DeviceBoundRefreshRequest {
        refresh_token: session.refresh_token.clone(),
        device_key_signature: hex::encode(signing_key.sign(&message).to_bytes()),
    })
}

pub async fn attest(_context: &AppContext) -> CliResult<CommandOutput> {
    #[cfg(target_os = "macos")]
    {
        Err(CliError::Attestation(
            "此 Mac 不支持 MindOne Enhanced 硬件远程证明；当前最高等级为 Standard-Limited"
                .to_owned(),
        ))
    }
    #[cfg(target_os = "windows")]
    {
        Err(CliError::Attestation(
            "当前 Windows 证明提供者不可用；节点保持 Experimental，未伪造 Enhanced 结果".to_owned(),
        ))
    }
    #[cfg(target_os = "linux")]
    {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use mindone_protocol::{
            attestation_report_data, AttestationChallengeRequest, AttestationChallengeResponse,
            AttestationKeyOrigin, AttestationProvider, AttestationReportBinding,
            AttestationSubmitRequest, AttestationSubmitResponse, TrustLevel, Validate,
        };

        let provider = match mindone_sandbox::detected_provider_name() {
            Some("amd-sev-snp") => AttestationProvider::AmdSevSnp,
            Some("intel-tdx") => AttestationProvider::IntelTdx,
            Some(_) | None => {
                return Err(CliError::Attestation(
                    "此 Linux 进程未检测到可访问的 /dev/tdx-guest 或 /dev/sev-guest 证明设备"
                        .to_owned(),
                ));
            }
        };
        let target = crate::share::load_attestation_target(_context).await?;
        let runtime = mindone_sandbox::ExternalTeeRuntime::from_environment(provider)
            .map_err(|error| CliError::Attestation(error.to_string()))?;
        let prepared_key = runtime
            .prepare(mindone_sandbox::TeePrepareRequest {
                node_id: target.node_id,
                model_instance_id: target.model_instance_id,
                sandbox_policy_hash: &target.sandbox_policy_hash,
                runtime_binary_hash: &target.runtime_binary_hash,
                model_weights_hash: &target.model_weights_hash,
            })
            .await
            .map_err(|error| CliError::Attestation(error.to_string()))?;
        let ephemeral_public_key = prepared_key.public_key.clone();
        let request = AttestationChallengeRequest {
            node_id: target.node_id,
            model_instance_id: target.model_instance_id,
            provider,
            sandbox_policy_hash: target.sandbox_policy_hash.clone(),
            runtime_binary_hash: target.runtime_binary_hash.clone(),
            ephemeral_public_key: ephemeral_public_key.clone(),
            key_origin: AttestationKeyOrigin::TeeRuntime,
        };
        request
            .validate()
            .map_err(|error| CliError::Attestation(error.to_string()))?;
        let challenge: AttestationChallengeResponse = _context
            .authorized_post(mindone_protocol::AUTH_ATTESTATION_CHALLENGE, &request)
            .await?;
        validate_challenge_response(&challenge, &request, &target.model_weights_hash)?;
        let nonce = URL_SAFE_NO_PAD
            .decode(&challenge.nonce)
            .map_err(|_| CliError::Attestation("服务端挑战 nonce 编码无效".to_owned()))?;
        let local_report_data = attestation_report_data(&AttestationReportBinding {
            challenge_id: challenge.challenge_id,
            node_id: target.node_id,
            model_instance_id: target.model_instance_id,
            nonce: &nonce,
            sandbox_policy_hash: &target.sandbox_policy_hash,
            runtime_binary_hash: &target.runtime_binary_hash,
            model_weights_hash: &target.model_weights_hash,
            ephemeral_public_key: &ephemeral_public_key,
            key_origin: AttestationKeyOrigin::TeeRuntime,
        })
        .map_err(|error| CliError::Attestation(error.to_string()))?;
        if hex::encode(local_report_data) != challenge.report_data {
            return Err(CliError::Attestation(
                "服务端挑战 REPORTDATA 与本机绑定字段不一致".to_owned(),
            ));
        }
        let challenge_expiry = challenge.expires_at.format(&Rfc3339).map_err(|error| {
            CliError::Attestation(format!("无法记录远程证明挑战有效期：{error}"))
        })?;
        let mut key_record = crate::vault::AttestationKeyRecord::pending_runtime(
            prepared_key.key_handle.clone(),
            ephemeral_public_key.clone(),
            challenge.challenge_id.to_string(),
            target.node_id.to_string(),
            target.model_instance_id.to_string(),
            challenge_expiry,
        );
        _context.vault.store_attestation_key(&key_record)?;

        let evidence = match runtime.attest(&prepared_key, &challenge.report_data).await {
            Ok(evidence) => evidence,
            Err(error) => {
                let _ = _context.vault.clear_attestation_key();
                return Err(CliError::Attestation(error.to_string()));
            }
        };
        let submit = AttestationSubmitRequest {
            challenge_id: challenge.challenge_id,
            provider: evidence.provider,
            evidence_kind: evidence.evidence_kind,
            evidence: evidence.evidence_base64,
        };
        submit
            .validate()
            .map_err(|error| CliError::Attestation(error.to_string()))?;
        let response: AttestationSubmitResponse = match _context
            .authorized_post(mindone_protocol::AUTH_ATTESTATION_SUBMIT, &submit)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let _ = _context.vault.clear_attestation_key();
                return Err(error);
            }
        };
        if response.node_id != target.node_id
            || response.model_instance_id != target.model_instance_id
            || response.provider != provider
            || response.trust_level != TrustLevel::Enhanced
            || response.ephemeral_public_key != ephemeral_public_key
            || response.key_origin != AttestationKeyOrigin::TeeRuntime
            || response.expires_at <= OffsetDateTime::now_utc()
        {
            let _ = _context.vault.clear_attestation_key();
            return Err(CliError::Attestation(
                "协调服务器返回的证明结果与当前节点绑定不一致".to_owned(),
            ));
        }
        let report_expiry = response
            .expires_at
            .format(&Rfc3339)
            .map_err(|error| CliError::Attestation(format!("无法记录远程证明有效期：{error}")))?;
        key_record.mark_verified(response.report_id.to_string(), report_expiry.clone());
        _context.vault.store_attestation_key(&key_record)?;
        CommandOutput::new(
            format!(
                "硬件远程证明已由协调服务器验证\nProvider：{}\n节点：{}\n模型实例：{}\n报告 ID：{}\nEnhanced 有效期：{}\nTEE X25519 公钥：{}\nRegulated 数据面：已启用（私钥不离开 TEE runtime adapter）",
                provider.as_str(),
                target.node_id,
                target.model_instance_id,
                response.report_id,
                report_expiry,
                ephemeral_public_key
            ),
            serde_json::json!({
                "verified": true,
                "provider": provider,
                "node_id": target.node_id,
                "model_instance_id": target.model_instance_id,
                "report_id": response.report_id,
                "trust_level": response.trust_level,
                "expires_at": response.expires_at,
                "ephemeral_public_key": ephemeral_public_key,
                "enhanced_envelope_enabled": true,
                "key_origin": response.key_origin
            }),
        )
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Err(CliError::Attestation(
            "当前平台不支持 Enhanced 硬件远程证明".to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn validate_challenge_response(
    challenge: &mindone_protocol::AttestationChallengeResponse,
    request: &mindone_protocol::AttestationChallengeRequest,
    model_weights_hash: &str,
) -> CliResult<()> {
    if challenge.node_id != request.node_id
        || challenge.model_instance_id != request.model_instance_id
        || challenge.provider != request.provider
        || challenge.sandbox_policy_hash != request.sandbox_policy_hash
        || challenge.runtime_binary_hash != request.runtime_binary_hash
        || challenge.model_weights_hash != model_weights_hash
        || challenge.ephemeral_public_key != request.ephemeral_public_key
        || challenge.key_origin != request.key_origin
        || challenge.expires_at <= OffsetDateTime::now_utc()
    {
        return Err(CliError::Attestation(
            "协调服务器挑战与当前活动节点、模型或运行时绑定不一致".to_owned(),
        ));
    }
    Ok(())
}

fn required_secret(value: Option<String>, field: &str) -> CliResult<String> {
    value
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| CliError::Authentication(format!("授权成功响应缺少 {field}")))
}

fn decode_api_value<T: for<'de> Deserialize<'de>>(value: Value, operation: &str) -> CliResult<T> {
    let payload = value.get("data").cloned().unwrap_or(value);
    serde_json::from_value(payload).map_err(|error| {
        CliError::Authentication(format!("协调服务器{operation}响应不兼容：{error}"))
    })
}

fn map_auth_error(error: CliError) -> CliError {
    match error {
        CliError::Authentication(_) => error,
        other => CliError::Authentication(other.to_string()),
    }
}

fn show_device_instruction(mode: OutputMode, code: &str, url: &str) {
    let message = format!("请在浏览器访问 {url} 并输入验证码：{code}");
    if mode.json {
        eprintln!("{message}");
    } else {
        println!("{message}");
    }
}

fn decode_device_challenge(encoded: &str) -> CliResult<[u8; DEVICE_KEY_CHALLENGE_BYTES]> {
    if encoded.len() != DEVICE_KEY_CHALLENGE_BYTES.saturating_mul(2)
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::Authentication(
            "协调服务器返回的设备持有证明 challenge 不是规范小写十六进制".to_owned(),
        ));
    }
    let mut challenge = [0_u8; DEVICE_KEY_CHALLENGE_BYTES];
    hex::decode_to_slice(encoded, &mut challenge).map_err(|_| {
        CliError::Authentication("协调服务器返回的设备持有证明 challenge 无效".to_owned())
    })?;
    Ok(challenge)
}

fn required_refresh_challenge(value: Option<String>) -> CliResult<String> {
    let challenge = value.filter(|value| !value.is_empty()).ok_or_else(|| {
        CliError::Authentication("登录会话缺少设备绑定 refresh challenge，请重新登录".to_owned())
    })?;
    decode_refresh_challenge(&challenge)?;
    Ok(challenge)
}

fn decode_refresh_challenge(encoded: &str) -> CliResult<[u8; REFRESH_KEY_CHALLENGE_BYTES]> {
    if encoded.len() != REFRESH_KEY_CHALLENGE_BYTES * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::Authentication(
            "refresh challenge 缺失或不是规范小写十六进制，请重新登录".to_owned(),
        ));
    }
    let mut challenge = [0_u8; REFRESH_KEY_CHALLENGE_BYTES];
    hex::decode_to_slice(encoded, &mut challenge)
        .map_err(|_| CliError::Authentication("refresh challenge 无效，请重新登录".to_owned()))?;
    Ok(challenge)
}

fn validate_verification_uri(raw: &str, coordinator_url: &str) -> CliResult<url::Url> {
    let url = url::Url::parse(raw)
        .map_err(|_| CliError::Authentication("协调服务器返回的浏览器验证地址无效".to_owned()))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::Authentication(
            "浏览器验证地址不得包含凭证、查询参数或片段".to_owned(),
        ));
    }

    let github = url.scheme() == "https"
        && url.host_str() == Some("github.com")
        && url.port_or_known_default() == Some(443)
        && url.path() == "/login/device";
    let coordinator = url::Url::parse(coordinator_url)
        .map_err(|_| CliError::Authentication("本机协调服务器地址无效".to_owned()))?;
    let local_development = coordinator.scheme() == "http"
        && is_loopback_host(coordinator.host_str())
        && url.scheme() == "http"
        && is_loopback_host(url.host_str())
        && same_origin(&coordinator, &url)
        && url.path() == "/local-development/authorize";
    let email_transport = coordinator.scheme() == "https"
        || (coordinator.scheme() == "http" && is_loopback_host(coordinator.host_str()));
    let email = email_transport && same_origin(&coordinator, &url) && url.path() == "/auth/login";
    if !github && !local_development && !email {
        return Err(CliError::Authentication(
            "浏览器验证地址不在允许的 GitHub、同源邮箱认证或本机开发边界内".to_owned(),
        ));
    }
    Ok(url)
}

fn same_origin(expected: &url::Url, candidate: &url::Url) -> bool {
    expected.scheme() == candidate.scheme()
        && expected.host_str() == candidate.host_str()
        && expected.port_or_known_default() == candidate.port_or_known_default()
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1"))
}

async fn open_browser(url: &str) -> CliResult<()> {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("/usr/bin/open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        // 不经过 cmd.exe；否则服务端控制的 URL 会被 `&|^%` 等元字符再次解释。
        let mut command = Command::new("explorer.exe");
        command.arg(url);
        command
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    return Err(CliError::Authentication(
        "当前平台不支持自动打开浏览器，请手动访问验证地址".to_owned(),
    ));

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let status = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|error| CliError::Authentication(format!("无法自动打开浏览器：{error}")))?;
        if !status.success() {
            return Err(CliError::Authentication(
                "系统浏览器启动命令失败，请手动访问验证地址".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signature, SigningKey};
    use mindone_protocol::{
        device_key_fingerprint, refresh_key_possession_message, AuthStatusResponse,
        AuthenticatedUser, DeviceKeyAlgorithm, TrustLevel,
    };
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{
        build_device_bound_refresh_request, decode_device_challenge, decode_refresh_challenge,
        status_output, validate_verification_uri,
    };
    use crate::vault::CredentialBundle;

    #[test]
    fn status_uses_authoritative_server_identity_and_separates_local_trust() {
        let response = AuthStatusResponse {
            user: AuthenticatedUser {
                id: Uuid::from_u128(7),
                username: "server-user".to_owned(),
            },
            trust_level: TrustLevel::Unverified,
            device_key_fingerprint: Some("server-fingerprint".to_owned()),
            logged_in_at: datetime!(2026-07-17 12:00 UTC),
            last_used_at: Some(datetime!(2026-07-17 12:01 UTC)),
            device_key_revoked: Some(false),
            device_key_created_at: Some(datetime!(2026-07-17 12:00 UTC)),
            device_key_rotated_at: None,
            registered_nodes: 1,
            best_node_trust_level: Some(TrustLevel::StandardLimited),
        };
        let output = status_output(&response, "Standard-Limited", "https://api.mindone.example")
            .expect("状态输出应可构造");
        assert_eq!(output.data["user"], "server-user");
        assert_eq!(output.data["trust_level"], "unverified");
        assert_eq!(output.data["local_sandbox_trust_level"], "Standard-Limited");
        assert_eq!(output.data["key_fingerprint"], "server-fingerprint");
        assert_eq!(output.data["trust_source"], "coordinator");
        assert_eq!(output.data["server_url"], "https://api.mindone.example");
    }

    #[test]
    fn verification_uri_is_strict_and_never_needs_a_command_shell() {
        assert!(validate_verification_uri(
            "https://github.com/login/device",
            "https://api.mindone.example"
        )
        .is_ok());
        assert!(validate_verification_uri(
            "http://127.0.0.1:8787/local-development/authorize",
            "http://127.0.0.1:8787"
        )
        .is_ok());
        assert!(validate_verification_uri(
            "https://api.mindone.example/auth/login",
            "https://api.mindone.example"
        )
        .is_ok());
        assert!(validate_verification_uri(
            "http://127.0.0.1:8787/auth/login",
            "http://127.0.0.1:8787"
        )
        .is_ok());
        assert!(validate_verification_uri(
            "https://github.com/login/device?next=%26calc.exe",
            "https://api.mindone.example"
        )
        .is_err());
        assert!(validate_verification_uri(
            "http://127.0.0.1:8787/local-development/authorize",
            "https://api.mindone.example"
        )
        .is_err());
        assert!(validate_verification_uri(
            "http://localhost:8787/local-development/authorize",
            "http://127.0.0.1:8787"
        )
        .is_err());
        assert!(validate_verification_uri(
            "http://127.0.0.1:8788/local-development/authorize",
            "http://127.0.0.1:8787"
        )
        .is_err());
        assert!(validate_verification_uri(
            "http://127.0.0.1:8787/local-development/authorize/",
            "http://127.0.0.1:8787"
        )
        .is_err());
        assert!(validate_verification_uri(
            "https://evil.example/auth/login",
            "https://api.mindone.example"
        )
        .is_err());
        assert!(validate_verification_uri(
            "http://api.mindone.example/auth/login",
            "http://api.mindone.example"
        )
        .is_err());
        assert!(validate_verification_uri(
            "https://api.mindone.example/auth/login?code=secret",
            "https://api.mindone.example"
        )
        .is_err());
        assert!(validate_verification_uri(
            "https://api.mindone.example/auth/login#code=secret",
            "https://api.mindone.example"
        )
        .is_err());
    }

    #[test]
    fn device_challenge_requires_canonical_lowercase_hex() {
        assert!(decode_device_challenge(&"ab".repeat(32)).is_ok());
        assert!(decode_device_challenge(&"AB".repeat(32)).is_err());
        assert!(decode_device_challenge("ab").is_err());
    }

    #[test]
    fn refresh_is_bound_to_current_token_challenge_and_device_key() {
        let private_key = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = signing_key.verifying_key().to_bytes();
        let session = CredentialBundle {
            access_token: "access".to_owned(),
            refresh_token: "refresh-current".to_owned(),
            refresh_challenge: "ab".repeat(32),
            user: "alice".to_owned(),
            uid: Uuid::nil().to_string(),
            local_sandbox_trust_level: "Unverified".to_owned(),
            key_fingerprint: device_key_fingerprint(&public_key),
            login_at: "2026-07-18T00:00:00Z".to_owned(),
        };

        let request = build_device_bound_refresh_request(&session, &private_key)
            .expect("正常会话应生成设备绑定刷新证明");
        let signature_bytes = hex::decode(&request.device_key_signature).expect("签名应为十六进制");
        let signature = Signature::from_slice(&signature_bytes).expect("签名长度应正确");
        let challenge =
            decode_refresh_challenge(&session.refresh_challenge).expect("challenge 应有效");
        let message = refresh_key_possession_message(
            &challenge,
            &session.refresh_token,
            &public_key,
            DeviceKeyAlgorithm::Ed25519,
        );
        signing_key
            .verifying_key()
            .verify_strict(&message, &signature)
            .expect("正常 refresh 证明应可验证");

        let wrong_private_key = [8_u8; 32];
        let error = build_device_bound_refresh_request(&session, &wrong_private_key)
            .expect_err("仅盗取 token 而没有绑定私钥时必须失败");
        assert!(error.to_string().contains("指纹不匹配"));
    }

    #[test]
    fn legacy_session_without_refresh_challenge_requires_relogin() {
        let private_key = [7_u8; 32];
        let public_key = SigningKey::from_bytes(&private_key)
            .verifying_key()
            .to_bytes();
        let session = CredentialBundle {
            access_token: "access".to_owned(),
            refresh_token: "refresh-current".to_owned(),
            refresh_challenge: String::new(),
            user: "alice".to_owned(),
            uid: Uuid::nil().to_string(),
            local_sandbox_trust_level: "Unverified".to_owned(),
            key_fingerprint: device_key_fingerprint(&public_key),
            login_at: "2026-07-18T00:00:00Z".to_owned(),
        };
        let error = build_device_bound_refresh_request(&session, &private_key)
            .expect_err("旧会话没有一次性 challenge 时必须要求重登");
        assert!(error.to_string().contains("重新登录"));
    }
}
