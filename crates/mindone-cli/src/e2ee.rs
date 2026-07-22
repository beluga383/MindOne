use base64::{
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use curve25519_dalek::montgomery::MontgomeryPoint;
use mindone_protocol::{
    attestation_report_data, regulated_aad, AttestationKeyOrigin, AttestationProvider,
    AttestationReportBinding, EnvelopeDirection, PrepareRegulatedJobResponse, RegulatedEnvelope,
    Validate, REGULATED_ALGORITHM, REGULATED_ENVELOPE_VERSION,
};
use rand::{rngs::OsRng, RngCore};
use ring::{aead, digest, hkdf};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{CliError, CliResult};

const MAX_REPORT_AGE: Duration = Duration::hours(24);
const MAX_CLOCK_SKEW: Duration = Duration::seconds(30);

pub struct VerifiedRegulatedRoute {
    pub response: PrepareRegulatedJobResponse,
}

pub struct RegulatedClientSession {
    private_key: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl RegulatedClientSession {
    pub fn new() -> CliResult<Self> {
        let mut private_key = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(private_key.as_mut());
        let public_key = MontgomeryPoint::mul_base_clamped(*private_key).to_bytes();
        if bool::from(public_key.ct_eq(&[0_u8; 32])) {
            return Err(CliError::Attestation(
                "消费者临时 X25519 公钥意外为全零值".to_owned(),
            ));
        }
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn encrypt_request(
        &self,
        route: &VerifiedRegulatedRoute,
        plaintext: &[u8],
    ) -> CliResult<RegulatedEnvelope> {
        let attestation = &route.response.attestation;
        let peer = decode_public_key(&attestation.ephemeral_public_key)?;
        seal(
            &self.private_key,
            &peer,
            &self.public_key,
            EnvelopeDirection::Request,
            route,
            plaintext,
        )
    }

    pub fn decrypt_result(
        &self,
        route: &VerifiedRegulatedRoute,
        envelope: &RegulatedEnvelope,
    ) -> CliResult<Zeroizing<Vec<u8>>> {
        envelope
            .validate()
            .map_err(|error| CliError::Attestation(error.to_string()))?;
        let attestation = &route.response.attestation;
        if envelope.direction != EnvelopeDirection::Result
            || envelope.route_id != route.response.route_id
            || envelope.report_id != attestation.report_id
            || envelope.model_instance_id != route.response.model_instance_id
            || envelope.sender_public_key != attestation.ephemeral_public_key
        {
            return Err(CliError::Attestation(
                "Regulated 结果 envelope 与 prepared route 或硬件报告不匹配".to_owned(),
            ));
        }
        let peer = decode_public_key(&envelope.sender_public_key)?;
        open(
            &self.private_key,
            &peer,
            EnvelopeDirection::Result,
            route,
            envelope,
        )
    }
}

pub async fn verify_prepared_route(
    response: PrepareRegulatedJobResponse,
) -> CliResult<VerifiedRegulatedRoute> {
    let now = OffsetDateTime::now_utc();
    let report = &response.attestation;
    if response.model_instance_id != report.model_instance_id
        || response.node_id != report.node_id
        || response.expires_at <= now
        || response.expires_at > report.expires_at
        || report.issued_at > report.verified_at
        || report.verified_at > now + MAX_CLOCK_SKEW
        || report.verified_at < now - MAX_REPORT_AGE
        || report.expires_at <= now
        || report.collateral_expires_at <= now
        || report.provider == AttestationProvider::None
        || !report.evidence_kind.matches_provider(report.provider)
    {
        return Err(CliError::Attestation(
            "prepared route 的报告身份或时效无效".to_owned(),
        ));
    }
    report
        .validate_static_fields()
        .map_err(CliError::Attestation)?;
    let evidence = BASE64_STANDARD
        .decode(&report.evidence)
        .map_err(|_| CliError::Attestation("prepared route 的硬件 evidence 编码无效".to_owned()))?;
    if evidence.is_empty() || evidence.len() > 576 * 1024 {
        return Err(CliError::Attestation(
            "prepared route 的硬件 evidence 为空或超过限制".to_owned(),
        ));
    }
    let evidence_hash = hex::encode(Sha256::digest(&evidence));
    if evidence_hash != report.evidence_sha256 {
        return Err(CliError::Attestation(
            "prepared route 的硬件 evidence 摘要不匹配".to_owned(),
        ));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&report.challenge_nonce)
        .map_err(|_| CliError::Attestation("prepared route 的 challenge nonce 无效".to_owned()))?;
    let local_report_data = attestation_report_data(&AttestationReportBinding {
        challenge_id: report.challenge_id,
        node_id: report.node_id,
        model_instance_id: report.model_instance_id,
        nonce: &nonce,
        sandbox_policy_hash: &report.sandbox_policy_hash,
        runtime_binary_hash: &report.runtime_binary_hash,
        model_weights_hash: &report.model_weights_hash,
        ephemeral_public_key: &report.ephemeral_public_key,
        key_origin: AttestationKeyOrigin::TeeRuntime,
    })
    .map_err(|error| CliError::Attestation(error.to_string()))?;
    if hex::encode(local_report_data) != report.report_data {
        return Err(CliError::Attestation(
            "prepared route 的 REPORTDATA 与节点、模型、runtime 或 TEE 公钥绑定不一致".to_owned(),
        ));
    }
    let verifier = mindone_sandbox::ClientEvidenceVerifier::from_environment(report.provider)
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    let claims = verifier
        .verify(mindone_sandbox::ClientVerificationInput {
            evidence_kind: report.evidence_kind,
            evidence_base64: &report.evidence,
            expected_report_data: &report.report_data,
            sandbox_policy_hash: &report.sandbox_policy_hash,
            runtime_binary_hash: &report.runtime_binary_hash,
            expected_measurement: &report.tee_measurement,
            now,
        })
        .await
        .map_err(|error| CliError::Attestation(error.to_string()))?;
    if claims.tee_measurement != report.tee_measurement
        || claims.collateral_expires_at != report.collateral_expires_at
    {
        return Err(CliError::Attestation(
            "本机 verifier 结论与 prepared route 报告不一致".to_owned(),
        ));
    }
    Ok(VerifiedRegulatedRoute { response })
}

trait ReportStaticValidation {
    fn validate_static_fields(&self) -> Result<(), String>;
}

impl ReportStaticValidation for mindone_protocol::RegulatedRouteAttestation {
    fn validate_static_fields(&self) -> Result<(), String> {
        for (name, value, length) in [
            ("evidence_sha256", self.evidence_sha256.as_str(), 64),
            ("report_data", self.report_data.as_str(), 128),
            ("sandbox_policy_hash", self.sandbox_policy_hash.as_str(), 64),
            ("runtime_binary_hash", self.runtime_binary_hash.as_str(), 64),
            ("model_weights_hash", self.model_weights_hash.as_str(), 64),
            (
                "ephemeral_public_key",
                self.ephemeral_public_key.as_str(),
                64,
            ),
        ] {
            if value.len() != length || !is_lower_hex(value) {
                return Err(format!("prepared route 的 {name} 格式无效"));
            }
        }
        if !(64..=128).contains(&self.tee_measurement.len())
            || !self.tee_measurement.len().is_multiple_of(2)
            || !is_lower_hex(&self.tee_measurement)
        {
            return Err("prepared route 的 TEE measurement 格式无效".to_owned());
        }
        if self.ephemeral_public_key.bytes().all(|byte| byte == b'0') {
            return Err("prepared route 的 TEE 公钥不能是全零值".to_owned());
        }
        Ok(())
    }
}

fn seal(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    sender_public_key: &[u8; 32],
    direction: EnvelopeDirection,
    route: &VerifiedRegulatedRoute,
    plaintext: &[u8],
) -> CliResult<RegulatedEnvelope> {
    if plaintext.is_empty() || plaintext.len() > 899_000 {
        return Err(CliError::Attestation(
            "Regulated 明文为空或超过本地加密上限".to_owned(),
        ));
    }
    let aad = route_aad(direction, route)?;
    let key = derive_key(private_key, peer_public_key, &aad)?;
    let mut nonce_bytes = [0_u8; 12];
    loop {
        OsRng.fill_bytes(&mut nonce_bytes);
        if !bool::from(nonce_bytes.ct_eq(&[0_u8; 12])) {
            break;
        }
    }
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
    let mut ciphertext = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(nonce, aead::Aad::from(aad.as_slice()), &mut *ciphertext)
        .map_err(|_| CliError::Attestation("Regulated AEAD 加密失败".to_owned()))?;
    let report = &route.response.attestation;
    Ok(RegulatedEnvelope {
        version: REGULATED_ENVELOPE_VERSION,
        algorithm: REGULATED_ALGORITHM.to_owned(),
        direction,
        route_id: route.response.route_id,
        report_id: report.report_id,
        model_instance_id: route.response.model_instance_id,
        sender_public_key: hex::encode(sender_public_key),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext.as_slice()),
    })
}

fn open(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    direction: EnvelopeDirection,
    route: &VerifiedRegulatedRoute,
    envelope: &RegulatedEnvelope,
) -> CliResult<Zeroizing<Vec<u8>>> {
    let aad = route_aad(direction, route)?;
    let key = derive_key(private_key, peer_public_key, &aad)?;
    let nonce_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.nonce)
        .map_err(|_| CliError::Attestation("Regulated 结果 nonce 编码无效".to_owned()))?;
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| CliError::Attestation("Regulated 结果 nonce 长度无效".to_owned()))?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_array);
    let mut ciphertext = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| CliError::Attestation("Regulated 结果 ciphertext 编码无效".to_owned()))?,
    );
    let plaintext_len = {
        let plaintext = key
            .open_in_place(nonce, aead::Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| {
                CliError::Attestation("Regulated 结果认证失败，可能被篡改或 AAD 不匹配".to_owned())
            })?;
        plaintext.len()
    };
    ciphertext.truncate(plaintext_len);
    Ok(ciphertext)
}

fn derive_key(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    aad: &[u8],
) -> CliResult<aead::LessSafeKey> {
    let mut shared = Zeroizing::new(
        MontgomeryPoint(*peer_public_key)
            .mul_clamped(*private_key)
            .to_bytes(),
    );
    if bool::from(shared.ct_eq(&[0_u8; 32])) {
        return Err(CliError::Attestation(
            "X25519 共享秘密为全零值，拒绝 Regulated 会话".to_owned(),
        ));
    }
    let salt_digest = digest::digest(&digest::SHA256, aad);
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt_digest.as_ref());
    let prk = salt.extract(shared.as_slice());
    let info = [b"MindOne Regulated E2EE key v1\0".as_slice(), aad];
    let okm = prk
        .expand(&info, &aead::CHACHA20_POLY1305)
        .map_err(|_| CliError::Attestation("Regulated HKDF 参数无效".to_owned()))?;
    let mut key_bytes = Zeroizing::new([0_u8; 32]);
    okm.fill(key_bytes.as_mut())
        .map_err(|_| CliError::Attestation("Regulated HKDF 派生失败".to_owned()))?;
    shared.zeroize();
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key_bytes.as_slice())
        .map_err(|_| CliError::Attestation("Regulated AEAD 密钥无效".to_owned()))?;
    Ok(aead::LessSafeKey::new(unbound))
}

fn route_aad(direction: EnvelopeDirection, route: &VerifiedRegulatedRoute) -> CliResult<Vec<u8>> {
    regulated_aad(
        direction,
        route.response.route_id,
        route.response.attestation.report_id,
        route.response.model_instance_id,
        &route.response.attestation.model_weights_hash,
    )
    .map_err(|error| CliError::Attestation(error.to_string()))
}

fn decode_public_key(value: &str) -> CliResult<[u8; 32]> {
    let decoded =
        hex::decode(value).map_err(|_| CliError::Attestation("X25519 公钥编码无效".to_owned()))?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| CliError::Attestation("X25519 公钥长度无效".to_owned()))?;
    if bool::from(key.ct_eq(&[0_u8; 32])) {
        return Err(CliError::Attestation("X25519 公钥为全零值".to_owned()));
    }
    Ok(key)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mindone_protocol::{
        AttestationEvidenceKind, PrepareRegulatedJobResponse, RegulatedRouteAttestation,
    };
    use uuid::Uuid;

    fn route(server_public: [u8; 32]) -> VerifiedRegulatedRoute {
        let now = OffsetDateTime::now_utc();
        VerifiedRegulatedRoute {
            response: PrepareRegulatedJobResponse {
                route_id: Uuid::from_u128(1),
                model_id: Uuid::from_u128(2),
                model_instance_id: Uuid::from_u128(3),
                node_id: Uuid::from_u128(4),
                expires_at: now + Duration::minutes(1),
                idempotent_replay: false,
                attestation: RegulatedRouteAttestation {
                    report_id: Uuid::from_u128(5),
                    challenge_id: Uuid::from_u128(6),
                    node_id: Uuid::from_u128(4),
                    model_instance_id: Uuid::from_u128(3),
                    provider: AttestationProvider::IntelTdx,
                    evidence_kind: AttestationEvidenceKind::TdxQuote,
                    evidence: "YWJj".to_owned(),
                    evidence_sha256: hex::encode(Sha256::digest(b"abc")),
                    challenge_nonce: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                    report_data: "11".repeat(64),
                    tee_measurement: "22".repeat(48),
                    sandbox_policy_hash: "33".repeat(32),
                    runtime_binary_hash: "44".repeat(32),
                    model_weights_hash: "55".repeat(32),
                    ephemeral_public_key: hex::encode(server_public),
                    issued_at: now,
                    verified_at: now,
                    expires_at: now + Duration::minutes(2),
                    collateral_expires_at: now + Duration::minutes(2),
                },
            },
        }
    }

    #[test]
    fn chacha_round_trip_and_ciphertext_tamper_fail() {
        let client = RegulatedClientSession::new().expect("客户端密钥应可生成");
        let server_private = [9_u8; 32];
        let server_public = MontgomeryPoint::mul_base_clamped(server_private).to_bytes();
        let route = route(server_public);
        let request = client
            .encrypt_request(&route, br#"{"prompt":"secret"}"#)
            .expect("请求应可加密");
        assert!(!request.ciphertext.contains("secret"));

        let result = seal(
            &server_private,
            &client.public_key,
            &server_public,
            EnvelopeDirection::Result,
            &route,
            br#"{"ok":true}"#,
        )
        .expect("TEE 结果应可回封");
        let plaintext = client
            .decrypt_result(&route, &result)
            .expect("消费者应可解密结果");
        assert_eq!(plaintext.as_slice(), br#"{"ok":true}"#);

        let mut tampered = result;
        let mut bytes = URL_SAFE_NO_PAD
            .decode(&tampered.ciphertext)
            .expect("测试密文应可解码");
        bytes[0] ^= 1;
        tampered.ciphertext = URL_SAFE_NO_PAD.encode(bytes);
        assert!(client.decrypt_result(&route, &tampered).is_err());
    }

    #[test]
    fn aad_route_mismatch_is_rejected() {
        let client = RegulatedClientSession::new().expect("客户端密钥应可生成");
        let server_private = [8_u8; 32];
        let server_public = MontgomeryPoint::mul_base_clamped(server_private).to_bytes();
        let route = route(server_public);
        let mut result = seal(
            &server_private,
            &client.public_key,
            &server_public,
            EnvelopeDirection::Result,
            &route,
            b"result",
        )
        .expect("结果应可加密");
        result.route_id = Uuid::from_u128(99);
        assert!(client.decrypt_result(&route, &result).is_err());
    }
}
