//! Standard 模式在协调器数据库中的静态数据保护。
//!
//! API 线协议仍是 Base64/Base64URL；只有数据库列使用此版本化 AEAD envelope。
//! 错误故意不携带密钥、明文或 envelope 内容。

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM},
    hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

pub const ENVELOPE_PREFIX: &str = "mindone-standard-aead-v1:";
pub const FINGERPRINT_PREFIX: &str = "mindone-standard-hmac-v1:";
pub const STORAGE_VERSION: i16 = 1;

const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MAX_STORED_VALUE_BYTES: usize = 1_300_000;
const MIGRATION_LOCK_ID: i64 = 7_132_022;
const MIGRATION_BATCH_SIZE: i64 = 100;
const ENCRYPTION_KEY_INFO: &[u8] = b"MindOne Standard AEAD encryption key v1";
const FINGERPRINT_KEY_INFO: &[u8] = b"MindOne Standard fingerprint HMAC key v1";
const COMMITMENT_KEY_INFO: &[u8] = b"MindOne Standard key commitment key v1";

#[derive(Clone, Copy)]
struct SubkeyLength;

impl hkdf::KeyType for SubkeyLength {
    fn len(&self) -> usize {
        32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageDirection {
    Payload,
    Result,
    StreamEvent {
        attempt_number: i32,
        sequence_number: i32,
    },
}

#[derive(Debug, Error)]
#[error("Standard 数据静态保护失败")]
pub struct StandardDataError;

#[derive(Debug, Error)]
pub enum StandardDataMigrationError {
    #[error("数据库结构迁移失败")]
    Schema(#[source] sqlx::migrate::MigrateError),
    #[error("Standard 数据静态保护迁移的数据库操作失败")]
    Database(#[source] sqlx::Error),
    #[error("Standard 数据静态保护迁移失败")]
    Protection(#[source] StandardDataError),
}

pub fn encrypt_for_storage(
    key: &[u8; 32],
    job_id: Uuid,
    direction: StorageDirection,
    plaintext: &[u8],
) -> Result<String, StandardDataError> {
    if plaintext.is_empty() || plaintext.len() > MAX_STORED_VALUE_BYTES {
        return Err(StandardDataError);
    }
    let encryption_key = derive_subkey(key, ENCRYPTION_KEY_INFO)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &*encryption_key).map_err(|_| StandardDataError)?,
    );
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| StandardDataError)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut sealed = Zeroizing::new(plaintext.to_vec());
    let tag = key
        .seal_in_place_separate_tag(nonce, Aad::from(aad(job_id, direction)), &mut sealed)
        .map_err(|_| StandardDataError)?;
    sealed.extend_from_slice(tag.as_ref());
    let mut envelope = Vec::with_capacity(NONCE_LENGTH + sealed.len());
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&sealed);
    let encoded = URL_SAFE_NO_PAD.encode(envelope);
    Ok(format!("{ENVELOPE_PREFIX}{encoded}"))
}

pub fn decrypt_from_storage(
    key: &[u8; 32],
    job_id: Uuid,
    direction: StorageDirection,
    envelope: &str,
) -> Result<Zeroizing<Vec<u8>>, StandardDataError> {
    let encoded = envelope
        .strip_prefix(ENVELOPE_PREFIX)
        .ok_or(StandardDataError)?;
    if encoded.is_empty() || encoded.len() > MAX_STORED_VALUE_BYTES.saturating_mul(2) {
        return Err(StandardDataError);
    }
    let mut sealed = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StandardDataError)?,
    );
    if sealed.len() <= NONCE_LENGTH + TAG_LENGTH {
        return Err(StandardDataError);
    }
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    nonce_bytes.copy_from_slice(&sealed[..NONCE_LENGTH]);
    sealed.drain(..NONCE_LENGTH);
    let encryption_key = derive_subkey(key, ENCRYPTION_KEY_INFO)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &*encryption_key).map_err(|_| StandardDataError)?,
    );
    let plaintext_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad(job_id, direction)),
            &mut sealed,
        )
        .map_err(|_| StandardDataError)?
        .len();
    sealed.truncate(plaintext_len);
    Ok(sealed)
}

/// 保留 v1 原有请求序列化指纹语义，但用独立密钥 HMAC，阻止数据库离线枚举低熵请求。
pub fn request_fingerprint(
    key: &[u8; 32],
    serialized_request: &[u8],
) -> Result<String, StandardDataError> {
    let mut digest = Sha256::new();
    digest.update(b"MindOne Standard create idempotency fingerprint v1\0");
    digest.update(serialized_request);
    let raw_digest = digest.finalize();
    fingerprint_from_legacy_digest(key, &raw_digest)
}

fn fingerprint_from_legacy_digest(
    key: &[u8; 32],
    legacy_digest: &[u8],
) -> Result<String, StandardDataError> {
    if legacy_digest.len() != 32 {
        return Err(StandardDataError);
    }
    let fingerprint_key = derive_subkey(key, FINGERPRINT_KEY_INFO)?;
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &*fingerprint_key);
    let mut context = Vec::with_capacity(64);
    context.extend_from_slice(b"MindOne Standard request fingerprint storage v1\0");
    context.extend_from_slice(legacy_digest);
    let tag = hmac::sign(&signing_key, &context);
    Ok(format!("{FINGERPRINT_PREFIX}{}", hex::encode(tag.as_ref())))
}

fn derive_subkey(
    master_key: &[u8; 32],
    purpose: &'static [u8],
) -> Result<Zeroizing<[u8; 32]>, StandardDataError> {
    let salt = hkdf::Salt::new(
        hkdf::HKDF_SHA256,
        b"MindOne Standard data at-rest HKDF salt v1",
    );
    let prk = salt.extract(master_key);
    let info = [purpose];
    let okm = prk
        .expand(&info, SubkeyLength)
        .map_err(|_| StandardDataError)?;
    let mut output = Zeroizing::new([0_u8; 32]);
    okm.fill(&mut *output).map_err(|_| StandardDataError)?;
    Ok(output)
}

fn key_commitment(master_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, StandardDataError> {
    let commitment_key = derive_subkey(master_key, COMMITMENT_KEY_INFO)?;
    let signing_key = hmac::Key::new(hmac::HMAC_SHA256, &*commitment_key);
    let tag = hmac::sign(&signing_key, b"MindOne Standard database key commitment v1");
    let mut commitment = Zeroizing::new([0_u8; 32]);
    commitment.copy_from_slice(tag.as_ref());
    Ok(commitment)
}

fn valid_lower_hex(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn aad(job_id: Uuid, direction: StorageDirection) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(b"MindOne Standard database AEAD v1\0");
    aad.extend_from_slice(job_id.as_bytes());
    aad.push(0);
    match direction {
        StorageDirection::Payload => aad.extend_from_slice(b"payload"),
        StorageDirection::Result => aad.extend_from_slice(b"result"),
        StorageDirection::StreamEvent {
            attempt_number,
            sequence_number,
        } => {
            aad.extend_from_slice(b"stream-event");
            aad.push(0);
            aad.extend_from_slice(&attempt_number.to_be_bytes());
            aad.extend_from_slice(&sequence_number.to_be_bytes());
        }
    }
    aad
}

/// 在 SQL 结构迁移后、服务开始接流量前，把旧 Standard 明文列原地升级为 v1。
///
/// 整个过程持有事务级 advisory lock 和行锁；任何行失败都会回滚并令启动失败。
pub async fn migrate_legacy_rows(
    pool: &PgPool,
    key: &[u8; 32],
) -> Result<(), StandardDataMigrationError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(StandardDataMigrationError::Database)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK_ID)
        .execute(&mut *tx)
        .await
        .map_err(StandardDataMigrationError::Database)?;
    let expected_commitment =
        key_commitment(key).map_err(StandardDataMigrationError::Protection)?;
    sqlx::query(
        r#"
        INSERT INTO standard_data_key_state (singleton,envelope_version,key_commitment)
        VALUES (TRUE,1,$1)
        ON CONFLICT (singleton) DO NOTHING
        "#,
    )
    .bind(hex::encode(*expected_commitment))
    .execute(&mut *tx)
    .await
    .map_err(StandardDataMigrationError::Database)?;
    let stored_commitment: String = sqlx::query_scalar(
        "SELECT key_commitment FROM standard_data_key_state WHERE singleton=TRUE FOR UPDATE",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(StandardDataMigrationError::Database)?;
    let mut stored_commitment_bytes = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(stored_commitment.as_bytes(), &mut *stored_commitment_bytes)
        .map_err(|_| StandardDataMigrationError::Protection(StandardDataError))?;
    if expected_commitment
        .as_slice()
        .ct_eq(stored_commitment_bytes.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(StandardDataMigrationError::Protection(StandardDataError));
    }

    loop {
        let rows = sqlx::query(
            r#"
            SELECT id,encrypted_payload,result_ciphertext,standard_request_fingerprint,
                   standard_payload_storage_version,standard_result_storage_version
            FROM jobs
            WHERE confidentiality_mode='standard'
              AND (
                standard_payload_storage_version=0
                OR standard_result_storage_version=0
                OR standard_request_fingerprint IS NULL
                OR standard_request_fingerprint NOT LIKE 'mindone-standard-hmac-v1:%'
              )
            ORDER BY id
            LIMIT $1
            FOR UPDATE
            "#,
        )
        .bind(MIGRATION_BATCH_SIZE)
        .fetch_all(&mut *tx)
        .await
        .map_err(StandardDataMigrationError::Database)?;
        if rows.is_empty() {
            break;
        }

        for row in rows {
            let job_id: Uuid = row
                .try_get("id")
                .map_err(StandardDataMigrationError::Database)?;
            let payload_version: i16 = row
                .try_get("standard_payload_storage_version")
                .map_err(StandardDataMigrationError::Database)?;
            let result_version: Option<i16> = row
                .try_get("standard_result_storage_version")
                .map_err(StandardDataMigrationError::Database)?;
            let payload = Zeroizing::new(
                row.try_get::<String, _>("encrypted_payload")
                    .map_err(StandardDataMigrationError::Database)?,
            );
            let result = row
                .try_get::<Option<String>, _>("result_ciphertext")
                .map_err(StandardDataMigrationError::Database)?
                .map(Zeroizing::new);
            let fingerprint: Option<String> = row
                .try_get("standard_request_fingerprint")
                .map_err(StandardDataMigrationError::Database)?;

            let stored_payload = if payload_version == 0 {
                encrypt_for_storage(key, job_id, StorageDirection::Payload, payload.as_bytes())
                    .map_err(StandardDataMigrationError::Protection)?
            } else if payload_version == STORAGE_VERSION && payload.starts_with(ENVELOPE_PREFIX) {
                payload.to_string()
            } else {
                return Err(StandardDataMigrationError::Protection(StandardDataError));
            };
            let stored_result = match (result_version, result.as_deref()) {
                (Some(0), Some(value)) => Some(
                    encrypt_for_storage(key, job_id, StorageDirection::Result, value.as_bytes())
                        .map_err(StandardDataMigrationError::Protection)?,
                ),
                (Some(STORAGE_VERSION), Some(value)) if value.starts_with(ENVELOPE_PREFIX) => {
                    Some(value.to_owned())
                }
                (None, None) => None,
                _ => return Err(StandardDataMigrationError::Protection(StandardDataError)),
            };
            let stored_fingerprint = match fingerprint {
                Some(value) if value.starts_with(FINGERPRINT_PREFIX) => {
                    let suffix = value
                        .strip_prefix(FINGERPRINT_PREFIX)
                        .ok_or(StandardDataError)
                        .map_err(StandardDataMigrationError::Protection)?;
                    if !valid_lower_hex(suffix, 64) {
                        return Err(StandardDataMigrationError::Protection(StandardDataError));
                    }
                    value
                }
                Some(value) => {
                    let mut legacy = Zeroizing::new([0_u8; 32]);
                    hex::decode_to_slice(value.as_bytes(), &mut *legacy)
                        .map_err(|_| StandardDataMigrationError::Protection(StandardDataError))?;
                    fingerprint_from_legacy_digest(key, &*legacy)
                        .map_err(StandardDataMigrationError::Protection)?
                }
                None => return Err(StandardDataMigrationError::Protection(StandardDataError)),
            };
            sqlx::query(
                r#"
                UPDATE jobs
                SET encrypted_payload=$2,standard_payload_storage_version=1,
                    result_ciphertext=$3,
                    standard_result_storage_version=CASE WHEN $3::text IS NULL THEN NULL ELSE 1 END,
                    standard_request_fingerprint=$4
                WHERE id=$1
                "#,
            )
            .bind(job_id)
            .bind(stored_payload)
            .bind(stored_result)
            .bind(stored_fingerprint)
            .execute(&mut *tx)
            .await
            .map_err(StandardDataMigrationError::Database)?;
        }
    }

    let legacy_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint FROM jobs
        WHERE confidentiality_mode='standard'
          AND (
            standard_payload_storage_version IS DISTINCT FROM 1
            OR encrypted_payload NOT LIKE 'mindone-standard-aead-v1:%'
            OR (result_ciphertext IS NOT NULL AND (
                standard_result_storage_version IS DISTINCT FROM 1
                OR result_ciphertext NOT LIKE 'mindone-standard-aead-v1:%'
            ))
            OR standard_request_fingerprint IS NULL
            OR standard_request_fingerprint NOT LIKE 'mindone-standard-hmac-v1:%'
          )
        "#,
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(StandardDataMigrationError::Database)?;
    if legacy_count != 0 {
        return Err(StandardDataMigrationError::Protection(StandardDataError));
    }
    tx.commit()
        .await
        .map_err(StandardDataMigrationError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        decrypt_from_storage, derive_subkey, encrypt_for_storage, request_fingerprint,
        valid_lower_hex, StorageDirection, COMMITMENT_KEY_INFO, ENCRYPTION_KEY_INFO,
        ENVELOPE_PREFIX, FINGERPRINT_KEY_INFO, FINGERPRINT_PREFIX,
    };
    use uuid::Uuid;

    #[test]
    fn round_trip_is_randomized_and_bound_to_job_and_direction() {
        let key = [7_u8; 32];
        let other_key = [8_u8; 32];
        let job_id = Uuid::new_v4();
        let plaintext = br#"eyJwcm9tcHQiOiJzZWNyZXQifQ=="#;
        let first = encrypt_for_storage(&key, job_id, StorageDirection::Payload, plaintext)
            .expect("应能加密 Standard payload");
        let second = encrypt_for_storage(&key, job_id, StorageDirection::Payload, plaintext)
            .expect("应能用随机 nonce 再次加密");
        assert!(first.starts_with(ENVELOPE_PREFIX));
        assert_ne!(first, second);
        assert!(!first.contains(std::str::from_utf8(plaintext).expect("测试值是 UTF-8")));
        assert_eq!(
            &*decrypt_from_storage(&key, job_id, StorageDirection::Payload, &first)
                .expect("同一 AAD 应解密"),
            plaintext
        );
        assert!(
            decrypt_from_storage(&key, Uuid::new_v4(), StorageDirection::Payload, &first).is_err()
        );
        assert!(decrypt_from_storage(&key, job_id, StorageDirection::Result, &first).is_err());
        assert!(
            decrypt_from_storage(&other_key, job_id, StorageDirection::Payload, &first).is_err()
        );
    }

    #[test]
    fn tampering_is_rejected_and_fingerprint_is_keyed() {
        let key = [9_u8; 32];
        let job_id = Uuid::new_v4();
        let mut envelope =
            encrypt_for_storage(&key, job_id, StorageDirection::Result, b"c2Vuc2l0aXZl")
                .expect("应能加密结果");
        envelope.push('A');
        assert!(decrypt_from_storage(&key, job_id, StorageDirection::Result, &envelope).is_err());
        let fingerprint =
            request_fingerprint(&key, br#"{"prompt":"guessable"}"#).expect("应能生成 HMAC 指纹");
        assert!(fingerprint.starts_with(FINGERPRINT_PREFIX));
        assert!(!fingerprint.contains("guessable"));
        assert_ne!(
            fingerprint,
            request_fingerprint(&[10_u8; 32], br#"{"prompt":"guessable"}"#)
                .expect("另一密钥也应生成指纹")
        );
        assert_ne!(
            &*derive_subkey(&key, ENCRYPTION_KEY_INFO).expect("应派生加密子键"),
            &*derive_subkey(&key, FINGERPRINT_KEY_INFO).expect("应派生指纹子键")
        );
        assert_ne!(
            &*derive_subkey(&key, FINGERPRINT_KEY_INFO).expect("应派生指纹子键"),
            &*derive_subkey(&key, COMMITMENT_KEY_INFO).expect("应派生承诺子键")
        );
        assert!(valid_lower_hex(&"a".repeat(64), 64));
        assert!(!valid_lower_hex(&"A".repeat(64), 64));
        assert!(!valid_lower_hex(&"a".repeat(63), 64));
    }

    #[test]
    fn stream_event_envelope_is_bound_to_attempt_and_sequence() {
        let key = [11_u8; 32];
        let job_id = Uuid::new_v4();
        let direction = StorageDirection::StreamEvent {
            attempt_number: 1,
            sequence_number: 7,
        };
        let plaintext = r#"{"delta":"真实输出"}"#;
        let envelope = encrypt_for_storage(&key, job_id, direction, plaintext.as_bytes())
            .expect("应加密 SSE 输出");
        assert!(decrypt_from_storage(&key, job_id, direction, &envelope).is_ok());
        assert!(decrypt_from_storage(
            &key,
            job_id,
            StorageDirection::StreamEvent {
                attempt_number: 1,
                sequence_number: 8,
            },
            &envelope,
        )
        .is_err());
        assert!(decrypt_from_storage(
            &key,
            job_id,
            StorageDirection::StreamEvent {
                attempt_number: 2,
                sequence_number: 7,
            },
            &envelope,
        )
        .is_err());
    }
}
