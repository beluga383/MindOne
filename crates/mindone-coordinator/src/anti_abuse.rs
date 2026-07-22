//! Privacy-minimized, server-derived anti-abuse signals and deterministic decisions.
//!
//! Callers must derive [`TrustedNetworkSignal`] from the accepted socket and trusted proxy
//! metadata. There is intentionally no deserializable client request type for IP or ASN input.

use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const DEVICE_BLOCK_USERS: i32 = 3;
const IP_PREFIX_SHARED_USERS: i32 = 3;
const IP_PREFIX_LARGE_SHARED_USERS: i32 = 5;
const ASN_SHARED_USERS: i32 = 10;
const ASN_LARGE_SHARED_USERS: i32 = 25;
const RECIPROCAL_BLOCK_REQUESTS: i64 = 10;

pub trait ControlledAsnResolver: Send + Sync {
    fn lookup(&self, address: IpAddr) -> Option<u32>;
}

#[derive(Debug, Default)]
pub struct NoAsnResolver;

impl ControlledAsnResolver for NoAsnResolver {
    fn lookup(&self, _address: IpAddr) -> Option<u32> {
        None
    }
}

const MAX_ASN_MAP_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ASN_MAP_ENTRIES: usize = 100_000;

/// A startup-loaded, deployment-controlled IP-prefix to ASN map.
///
/// The resolver performs no network requests and never accepts ASN input from an HTTP request.
/// Prefixes remain in process memory only; only a peppered ASN hash reaches the abuse tables.
#[derive(Debug)]
pub struct LocalAsnResolver {
    entries: Vec<AsnPrefix>,
}

impl LocalAsnResolver {
    pub fn from_file(path: &Path) -> Result<Self, AsnMapError> {
        let metadata = std::fs::symlink_metadata(path).map_err(AsnMapError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(AsnMapError::UnsafeFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0 {
                return Err(AsnMapError::UnsafePermissions);
            }
        }
        if metadata.len() > MAX_ASN_MAP_BYTES {
            return Err(AsnMapError::TooLarge);
        }
        let bytes = std::fs::read(path).map_err(AsnMapError::Read)?;
        if bytes.len() as u64 > MAX_ASN_MAP_BYTES {
            return Err(AsnMapError::TooLarge);
        }
        Self::from_json(&bytes)
    }

    fn from_json(bytes: &[u8]) -> Result<Self, AsnMapError> {
        let document: AsnMapDocument =
            serde_json::from_slice(bytes).map_err(AsnMapError::InvalidJson)?;
        if document.version != 1 {
            return Err(AsnMapError::UnsupportedVersion(document.version));
        }
        if document.entries.is_empty() || document.entries.len() > MAX_ASN_MAP_ENTRIES {
            return Err(AsnMapError::InvalidEntryCount);
        }
        let mut seen = BTreeSet::new();
        let mut entries = Vec::with_capacity(document.entries.len());
        for entry in document.entries {
            if entry.asn == 0 || entry.asn == u32::MAX {
                return Err(AsnMapError::InvalidAsn);
            }
            let prefix = AsnPrefix::from_cidr(&entry.cidr, entry.asn)?;
            if !seen.insert(prefix.identity()) {
                return Err(AsnMapError::DuplicatePrefix(entry.cidr));
            }
            entries.push(prefix);
        }
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.prefix_len()));
        Ok(Self { entries })
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl ControlledAsnResolver for LocalAsnResolver {
    fn lookup(&self, address: IpAddr) -> Option<u32> {
        self.entries
            .iter()
            .find_map(|entry| entry.contains(address).then_some(entry.asn()))
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AsnMapDocument {
    version: u8,
    entries: Vec<AsnMapEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AsnMapEntry {
    cidr: String,
    asn: u32,
}

#[derive(Debug)]
enum AsnPrefix {
    V4 {
        network: u32,
        prefix_len: u8,
        asn: u32,
    },
    V6 {
        network: u128,
        prefix_len: u8,
        asn: u32,
    },
}

impl AsnPrefix {
    fn from_cidr(value: &str, asn: u32) -> Result<Self, AsnMapError> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| AsnMapError::InvalidCidr(value.to_owned()))?;
        let address =
            IpAddr::from_str(address).map_err(|_| AsnMapError::InvalidCidr(value.to_owned()))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| AsnMapError::InvalidCidr(value.to_owned()))?;
        match address {
            IpAddr::V4(address) if prefix <= 32 => {
                let address = u32::from(address);
                let mask = v4_mask(prefix);
                if address & mask != address {
                    return Err(AsnMapError::NonCanonicalCidr(value.to_owned()));
                }
                Ok(Self::V4 {
                    network: address,
                    prefix_len: prefix,
                    asn,
                })
            }
            IpAddr::V6(address) if prefix <= 128 => {
                let address = u128::from(address);
                let mask = v6_mask(prefix);
                if address & mask != address {
                    return Err(AsnMapError::NonCanonicalCidr(value.to_owned()));
                }
                Ok(Self::V6 {
                    network: address,
                    prefix_len: prefix,
                    asn,
                })
            }
            _ => Err(AsnMapError::InvalidCidr(value.to_owned())),
        }
    }

    const fn prefix_len(&self) -> u8 {
        match self {
            Self::V4 { prefix_len, .. } | Self::V6 { prefix_len, .. } => *prefix_len,
        }
    }

    const fn asn(&self) -> u32 {
        match self {
            Self::V4 { asn, .. } | Self::V6 { asn, .. } => *asn,
        }
    }

    const fn identity(&self) -> (u8, u128, u8) {
        match self {
            Self::V4 {
                network,
                prefix_len,
                ..
            } => (4, *network as u128, *prefix_len),
            Self::V6 {
                network,
                prefix_len,
                ..
            } => (6, *network, *prefix_len),
        }
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self, address) {
            (
                Self::V4 {
                    network,
                    prefix_len,
                    ..
                },
                IpAddr::V4(address),
            ) => u32::from(address) & v4_mask(*prefix_len) == *network,
            (
                Self::V6 {
                    network,
                    prefix_len,
                    ..
                },
                IpAddr::V6(address),
            ) => u128::from(address) & v6_mask(*prefix_len) == *network,
            _ => false,
        }
    }
}

const fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Debug, Error)]
pub enum AsnMapError {
    #[error("无法读取受控 ASN 映射文件：{0}")]
    Read(std::io::Error),
    #[error("受控 ASN 映射必须是普通文件且不得为符号链接")]
    UnsafeFile,
    #[error("受控 ASN 映射不得允许组或其他用户写入")]
    UnsafePermissions,
    #[error("受控 ASN 映射超过 8 MiB 上限")]
    TooLarge,
    #[error("受控 ASN 映射不是严格 JSON：{0}")]
    InvalidJson(serde_json::Error),
    #[error("不支持 ASN 映射版本 {0}")]
    UnsupportedVersion(u8),
    #[error("ASN 映射条目数必须在 1 到 100000 之间")]
    InvalidEntryCount,
    #[error("ASN 必须在 1 到 4294967294 之间")]
    InvalidAsn,
    #[error("CIDR 无效：{0}")]
    InvalidCidr(String),
    #[error("CIDR 必须使用规范网络地址：{0}")]
    NonCanonicalCidr(String),
    #[error("CIDR 重复：{0}")]
    DuplicatePrefix(String),
}

#[derive(Clone)]
pub struct TrustedNetworkSignal {
    ip_prefix_hash: String,
    asn_hash: Option<String>,
    source: NetworkSignalSource,
}

impl fmt::Debug for TrustedNetworkSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedNetworkSignal")
            .field("ip_prefix_hash", &"[REDACTED]")
            .field("asn_present", &self.asn_hash.is_some())
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkSignalSource {
    DirectPeer,
    TrustedCloudflare,
}

impl NetworkSignalSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DirectPeer => "direct_peer",
            Self::TrustedCloudflare => "trusted_cloudflare",
        }
    }
}

impl TrustedNetworkSignal {
    /// Derives a minimized signal from server connection metadata.
    ///
    /// `CF-Connecting-IP` is accepted only when the direct peer exactly matches the deployment's
    /// trusted-proxy allowlist. A caller-provided header from any other peer is ignored, including
    /// arbitrary private-network peers.
    pub fn from_connection(
        peer: Option<SocketAddr>,
        headers: &HeaderMap,
        pepper: &str,
        asn_resolver: &dyn ControlledAsnResolver,
        trusted_proxy_ips: &BTreeSet<IpAddr>,
    ) -> Result<Option<Self>, AntiAbuseError> {
        let Some(peer) = peer else {
            return Ok(None);
        };
        let (address, source) = if trusted_proxy_ips.contains(&peer.ip()) {
            let Some(address) = parse_cloudflare_address(headers) else {
                return Ok(None);
            };
            (address, NetworkSignalSource::TrustedCloudflare)
        } else {
            (peer.ip(), NetworkSignalSource::DirectPeer)
        };
        let prefix = minimized_ip_prefix(address);
        let ip_prefix_hash = keyed_hash(pepper, b"mindone:abuse:ip-prefix:v1\0", &prefix)?;
        let asn_hash = asn_resolver
            .lookup(address)
            .map(|asn| keyed_hash(pepper, b"mindone:abuse:asn:v1\0", &asn.to_be_bytes()))
            .transpose()?;
        Ok(Some(Self {
            ip_prefix_hash,
            asn_hash,
            source,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiAbuseDisposition {
    Allow,
    Block,
}

impl AntiAbuseDisposition {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntiAbuseDecision {
    pub disposition: AntiAbuseDisposition,
    pub risk_score_ppm: i32,
    pub contribution_weight_ppm: i32,
    pub reason_codes: Vec<String>,
}

impl AntiAbuseDecision {
    #[must_use]
    pub const fn allowed(&self) -> bool {
        matches!(self.disposition, AntiAbuseDisposition::Allow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskCounts {
    pub device_user_count: Option<i32>,
    pub ip_user_count: Option<i32>,
    pub asn_user_count: Option<i32>,
    pub reciprocal_edge_requests: i64,
    pub require_network_signal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Normal,
    Verification,
}

#[derive(Debug, Error)]
pub enum AntiAbuseError {
    #[error("反滥用输入无效：{0}")]
    InvalidInput(String),
    #[error("会话缺少有效设备绑定")]
    MissingDeviceBinding,
    #[error("反滥用评估幂等键已用于不同请求")]
    IdempotencyConflict,
    #[error("反滥用数据库操作失败：{0}")]
    Database(#[from] sqlx::Error),
}

/// Derives the stable, bounded decision key shared by job creation and settlement.
///
/// The public idempotency key is length-delimited and hashed, so arbitrary request text is not
/// copied into the abuse audit and every valid job key fits the database constraint.
pub fn job_assessment_key(
    user_id: Uuid,
    job_idempotency_key: &str,
) -> Result<String, AntiAbuseError> {
    if job_idempotency_key.trim().is_empty() || job_idempotency_key.len() > 200 {
        return Err(AntiAbuseError::InvalidInput(
            "任务幂等键必须为 1 到 200 字节".to_owned(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"mindone:abuse:job-assessment:v1\0");
    digest.update(user_id.as_bytes());
    digest.update(
        u64::try_from(job_idempotency_key.len())
            .map_err(|_| AntiAbuseError::InvalidInput("任务幂等键长度超出范围".to_owned()))?
            .to_be_bytes(),
    );
    digest.update(job_idempotency_key.as_bytes());
    Ok(format!("job:{}", hex::encode(digest.finalize())))
}

/// Records minimized signals and returns an idempotent, deterministic pre-create decision.
///
/// # Integration point
///
/// Call this after access-token authentication and before reserving quota in `create_job`. In
/// production, pass `require_network_signal = true`; a missing connection-derived signal blocks
/// the request instead of trusting client-supplied IP or ASN fields.
pub async fn assess_before_create(
    pool: &PgPool,
    pepper: &str,
    user_id: Uuid,
    session_id: Uuid,
    assessment_key: &str,
    network: Option<&TrustedNetworkSignal>,
    require_network_signal: bool,
) -> Result<AntiAbuseDecision, AntiAbuseError> {
    let mut tx = pool.begin().await?;
    let decision = assess_before_create_in_transaction(
        &mut tx,
        pepper,
        user_id,
        session_id,
        assessment_key,
        network,
        require_network_signal,
    )
    .await?;
    tx.commit().await?;
    Ok(decision)
}

/// Records minimized signals and returns an idempotent, deterministic pre-create decision
/// inside the caller-owned PostgreSQL transaction.
///
/// This is the transaction-safe variant of [`assess_before_create`]. It intentionally never
/// starts, commits, or rolls back a transaction, so callers can atomically bind the accepted
/// decision to a quota reservation and job row. The user/key advisory lock remains transaction
/// scoped and protects both the assessment and the caller's subsequent writes.
pub async fn assess_before_create_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    pepper: &str,
    user_id: Uuid,
    session_id: Uuid,
    assessment_key: &str,
    network: Option<&TrustedNetworkSignal>,
    require_network_signal: bool,
) -> Result<AntiAbuseDecision, AntiAbuseError> {
    validate_assessment_key(assessment_key)?;
    let request_hash = assessment_request_hash(
        pepper,
        user_id,
        session_id,
        assessment_key,
        network,
        require_network_signal,
    )?;
    let lock_domain = format!("{user_id}:{assessment_key}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 882104))")
        .bind(&lock_domain)
        .execute(&mut **tx)
        .await?;
    if let Some((existing_hash, existing)) =
        load_existing_decision(&mut *tx, user_id, assessment_key).await?
    {
        if !constant_time_equal(existing_hash.as_bytes(), request_hash.as_bytes()) {
            return Err(AntiAbuseError::IdempotencyConflict);
        }
        return Ok(existing);
    }
    let device_fingerprint: Option<String> = sqlx::query_scalar(
        r#"
        SELECT dk.fingerprint FROM sessions s
        JOIN device_keys dk ON dk.id=s.device_key_id AND dk.revoked_at IS NULL
        WHERE s.id=$1 AND s.user_id=$2 AND s.revoked_at IS NULL
        "#,
    )
    .bind(session_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    let device_fingerprint = device_fingerprint.ok_or(AntiAbuseError::MissingDeviceBinding)?;
    let device_hash = keyed_hash(
        pepper,
        b"mindone:abuse:device:v1\0",
        device_fingerprint.as_bytes(),
    )?;
    let observation_id = if let Some(network) = network {
        let observation_id = Uuid::now_v7();
        sqlx::query(
            r#"
            INSERT INTO abuse_network_observations
                (id,user_id,session_id,device_hash,ip_prefix_hash,asn_hash,network_source)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            "#,
        )
        .bind(observation_id)
        .bind(user_id)
        .bind(session_id)
        .bind(&device_hash)
        .bind(&network.ip_prefix_hash)
        .bind(&network.asn_hash)
        .bind(network.source.as_str())
        .execute(&mut **tx)
        .await?;
        Some(observation_id)
    } else {
        None
    };

    let device_user_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT user_id)::bigint FROM device_keys WHERE fingerprint=$1",
    )
    .bind(&device_fingerprint)
    .fetch_one(&mut **tx)
    .await?;
    let ip_user_count = if let Some(network) = network {
        Some(
            sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM abuse_network_observations
                WHERE ip_prefix_hash=$1 AND observed_at > now()-interval '24 hours'
                "#,
            )
            .bind(&network.ip_prefix_hash)
            .fetch_one(&mut **tx)
            .await?,
        )
    } else {
        None
    };
    let asn_user_count = if let Some(asn_hash) = network.and_then(|value| value.asn_hash.as_ref()) {
        Some(
            sqlx::query_scalar::<_, i64>(
                r#"
                SELECT COUNT(DISTINCT user_id)::bigint FROM abuse_network_observations
                WHERE asn_hash=$1 AND observed_at > now()-interval '24 hours'
                "#,
            )
            .bind(asn_hash)
            .fetch_one(&mut **tx)
            .await?,
        )
    } else {
        None
    };
    let reciprocal_edge_requests: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(MAX(LEAST(
            outbound.normal_requests + outbound.verification_requests,
            reciprocal.normal_requests + reciprocal.verification_requests
        )),0)::bigint
        FROM abuse_call_edges outbound
        JOIN abuse_call_edges reciprocal
          ON reciprocal.consumer_user_id=outbound.node_user_id
         AND reciprocal.node_user_id=outbound.consumer_user_id
        WHERE outbound.consumer_user_id=$1
        "#,
    )
    .bind(user_id)
    .fetch_one(&mut **tx)
    .await?;
    let counts = RiskCounts {
        device_user_count: Some(count_i32(device_user_count)?),
        ip_user_count: ip_user_count.map(count_i32).transpose()?,
        asn_user_count: asn_user_count.map(count_i32).transpose()?,
        reciprocal_edge_requests,
        require_network_signal,
    };
    let decision = deterministic_decision(counts);
    sqlx::query(
        r#"
        INSERT INTO abuse_decisions
            (id,assessment_key,request_hash,user_id,session_id,observation_id,decision,risk_score_ppm,
             contribution_weight_ppm,reason_codes,device_user_count,ip_user_count,
             asn_user_count,reciprocal_edge_requests)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
        "#,
    )
    .bind(Uuid::now_v7())
    .bind(assessment_key)
    .bind(&request_hash)
    .bind(user_id)
    .bind(session_id)
    .bind(observation_id)
    .bind(decision.disposition.as_str())
    .bind(decision.risk_score_ppm)
    .bind(decision.contribution_weight_ppm)
    .bind(&decision.reason_codes)
    .bind(counts.device_user_count)
    .bind(counts.ip_user_count)
    .bind(counts.asn_user_count)
    .bind(reciprocal_edge_requests)
    .execute(&mut **tx)
    .await?;
    Ok(decision)
}

/// Returns the contribution multiplier to use during settlement.
///
/// # Integration point
///
/// Call while holding the settlement transaction, before appending quota/contribution ledgers.
/// Self-dealing contributes zero; server-marked verification traffic and established reciprocal
/// call loops contribute only 10%. User quota deduction remains unchanged.
pub async fn settlement_contribution_weight(
    tx: &mut Transaction<'_, Postgres>,
    consumer_user_id: Uuid,
    node_user_id: Uuid,
    traffic_class: TrafficClass,
) -> Result<i32, AntiAbuseError> {
    if consumer_user_id == node_user_id {
        return Ok(0);
    }
    if traffic_class == TrafficClass::Verification {
        return Ok(100_000);
    }
    let reciprocal: Option<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT outbound.normal_requests + outbound.verification_requests,
               reciprocal.normal_requests + reciprocal.verification_requests
        FROM abuse_call_edges outbound
        JOIN abuse_call_edges reciprocal
          ON reciprocal.consumer_user_id=outbound.node_user_id
         AND reciprocal.node_user_id=outbound.consumer_user_id
        WHERE outbound.consumer_user_id=$1 AND outbound.node_user_id=$2
        "#,
    )
    .bind(consumer_user_id)
    .bind(node_user_id)
    .fetch_optional(&mut **tx)
    .await?;
    if reciprocal
        .is_some_and(|(outbound, inbound)| outbound.min(inbound) >= RECIPROCAL_BLOCK_REQUESTS)
    {
        Ok(100_000)
    } else {
        Ok(1_000_000)
    }
}

/// Appends one settled request to the minimized consumer-to-node-owner graph aggregate.
pub async fn record_settled_edge(
    tx: &mut Transaction<'_, Postgres>,
    consumer_user_id: Uuid,
    node_user_id: Uuid,
    traffic_class: TrafficClass,
) -> Result<(), AntiAbuseError> {
    let (normal_increment, verification_increment) = match traffic_class {
        TrafficClass::Normal => (1_i64, 0_i64),
        TrafficClass::Verification => (0_i64, 1_i64),
    };
    sqlx::query(
        r#"
        INSERT INTO abuse_call_edges
            (consumer_user_id,node_user_id,normal_requests,verification_requests)
        VALUES ($1,$2,$3,$4)
        ON CONFLICT (consumer_user_id,node_user_id) DO UPDATE
        SET normal_requests=abuse_call_edges.normal_requests + EXCLUDED.normal_requests,
            verification_requests=abuse_call_edges.verification_requests + EXCLUDED.verification_requests,
            last_seen_at=now()
        "#,
    )
    .bind(consumer_user_id)
    .bind(node_user_id)
    .bind(normal_increment)
    .bind(verification_increment)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[must_use]
pub fn deterministic_decision(counts: RiskCounts) -> AntiAbuseDecision {
    let mut risk_score_ppm = 0_i32;
    let mut reason_codes = Vec::new();
    let mut independent_risk_categories = 0_u8;
    if counts.device_user_count.is_none() {
        risk_score_ppm = 1_000_000;
        reason_codes.push("missing_device_signal".to_owned());
    } else if counts
        .device_user_count
        .is_some_and(|count| count >= DEVICE_BLOCK_USERS)
    {
        risk_score_ppm = 1_000_000;
        reason_codes.push("device_sybil_cluster".to_owned());
    } else if counts.device_user_count == Some(2) {
        risk_score_ppm = risk_score_ppm.saturating_add(350_000);
        independent_risk_categories = independent_risk_categories.saturating_add(1);
        reason_codes.push("shared_device".to_owned());
    }
    if counts.require_network_signal && counts.ip_user_count.is_none() {
        risk_score_ppm = 1_000_000;
        reason_codes.push("missing_network_signal".to_owned());
    } else if counts
        .ip_user_count
        .is_some_and(|count| count >= IP_PREFIX_LARGE_SHARED_USERS)
    {
        risk_score_ppm = risk_score_ppm.saturating_add(400_000).min(1_000_000);
        independent_risk_categories = independent_risk_categories.saturating_add(1);
        reason_codes.push("large_shared_ip_prefix".to_owned());
    } else if counts
        .ip_user_count
        .is_some_and(|count| count >= IP_PREFIX_SHARED_USERS)
    {
        risk_score_ppm = risk_score_ppm.saturating_add(250_000).min(1_000_000);
        independent_risk_categories = independent_risk_categories.saturating_add(1);
        reason_codes.push("shared_ip_prefix".to_owned());
    }
    if counts.asn_user_count.is_none() {
        reason_codes.push("asn_signal_unavailable".to_owned());
    } else if counts
        .asn_user_count
        .is_some_and(|count| count >= ASN_LARGE_SHARED_USERS)
    {
        // ASN 与共享网段高度相关，只作弱佐证，永远不能单独触发阻断。
        risk_score_ppm = risk_score_ppm.saturating_add(200_000).min(1_000_000);
        reason_codes.push("large_shared_asn".to_owned());
    } else if counts
        .asn_user_count
        .is_some_and(|count| count >= ASN_SHARED_USERS)
    {
        risk_score_ppm = risk_score_ppm.saturating_add(100_000).min(1_000_000);
        reason_codes.push("shared_asn_cluster".to_owned());
    }
    if counts.reciprocal_edge_requests >= RECIPROCAL_BLOCK_REQUESTS {
        risk_score_ppm = 1_000_000;
        reason_codes.push("reciprocal_call_loop".to_owned());
    } else if counts.reciprocal_edge_requests >= 5 {
        risk_score_ppm = risk_score_ppm.saturating_add(350_000).min(1_000_000);
        independent_risk_categories = independent_risk_categories.saturating_add(1);
        reason_codes.push("emerging_reciprocal_loop".to_owned());
    }
    let hard_block = counts.device_user_count.is_none()
        || counts
            .device_user_count
            .is_some_and(|count| count >= DEVICE_BLOCK_USERS)
        || (counts.require_network_signal && counts.ip_user_count.is_none())
        || counts.reciprocal_edge_requests >= RECIPROCAL_BLOCK_REQUESTS;
    let corroborated_block = independent_risk_categories >= 2 && risk_score_ppm >= 700_000;
    let disposition = if hard_block || corroborated_block {
        AntiAbuseDisposition::Block
    } else {
        AntiAbuseDisposition::Allow
    };
    let contribution_weight_ppm = match disposition {
        AntiAbuseDisposition::Block => 0,
        AntiAbuseDisposition::Allow if risk_score_ppm >= 250_000 => 500_000,
        AntiAbuseDisposition::Allow => 1_000_000,
    };
    AntiAbuseDecision {
        disposition,
        risk_score_ppm,
        contribution_weight_ppm,
        reason_codes,
    }
}

async fn load_existing_decision(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    assessment_key: &str,
) -> Result<Option<(String, AntiAbuseDecision)>, AntiAbuseError> {
    let row = sqlx::query(
        r#"
        SELECT request_hash,decision,risk_score_ppm,contribution_weight_ppm,reason_codes
        FROM abuse_decisions WHERE user_id=$1 AND assessment_key=$2
        "#,
    )
    .bind(user_id)
    .bind(assessment_key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        let disposition = match row.try_get::<String, _>("decision")?.as_str() {
            "allow" => AntiAbuseDisposition::Allow,
            "block" => AntiAbuseDisposition::Block,
            _ => {
                return Err(AntiAbuseError::InvalidInput(
                    "数据库包含未知反滥用决定".to_owned(),
                ));
            }
        };
        Ok((
            row.try_get("request_hash")?,
            AntiAbuseDecision {
                disposition,
                risk_score_ppm: row.try_get("risk_score_ppm")?,
                contribution_weight_ppm: row.try_get("contribution_weight_ppm")?,
                reason_codes: row.try_get("reason_codes")?,
            },
        ))
    })
    .transpose()
}

fn parse_cloudflare_address(headers: &HeaderMap) -> Option<IpAddr> {
    let value = headers.get("cf-connecting-ip")?.to_str().ok()?;
    if value.len() > 64 || value.trim() != value {
        return None;
    }
    value.parse().ok()
}

fn minimized_ip_prefix(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            vec![4, 24, octets[0], octets[1], octets[2]]
        }
        IpAddr::V6(address) => {
            let octets = address.octets();
            let mut prefix = Vec::with_capacity(9);
            prefix.extend_from_slice(&[6, 56]);
            prefix.extend_from_slice(&octets[..7]);
            prefix
        }
    }
}

fn keyed_hash(pepper: &str, domain: &[u8], value: &[u8]) -> Result<String, AntiAbuseError> {
    if pepper.len() < 32 {
        return Err(AntiAbuseError::InvalidInput(
            "反滥用哈希 pepper 至少需要 32 字节".to_owned(),
        ));
    }
    let mut mac = HmacSha256::new_from_slice(pepper.as_bytes())
        .map_err(|_| AntiAbuseError::InvalidInput("反滥用哈希 pepper 无效".to_owned()))?;
    mac.update(domain);
    mac.update(value);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn assessment_request_hash(
    pepper: &str,
    user_id: Uuid,
    session_id: Uuid,
    assessment_key: &str,
    network: Option<&TrustedNetworkSignal>,
    require_network_signal: bool,
) -> Result<String, AntiAbuseError> {
    let mut value = Vec::with_capacity(256);
    value.extend_from_slice(user_id.as_bytes());
    value.extend_from_slice(session_id.as_bytes());
    value.extend_from_slice(assessment_key.as_bytes());
    value.push(u8::from(require_network_signal));
    if let Some(network) = network {
        value.extend_from_slice(network.ip_prefix_hash.as_bytes());
        if let Some(asn_hash) = network.asn_hash.as_deref() {
            value.extend_from_slice(asn_hash.as_bytes());
        }
        value.extend_from_slice(network.source.as_str().as_bytes());
    }
    keyed_hash(pepper, b"mindone:abuse:assessment:v1\0", &value)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn validate_assessment_key(value: &str) -> Result<(), AntiAbuseError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(byte))
    {
        return Err(AntiAbuseError::InvalidInput(
            "assessment_key 只允许 1 到 128 字节的 ASCII 字母、数字及 -_.:".to_owned(),
        ));
    }
    Ok(())
}

fn count_i32(value: i64) -> Result<i32, AntiAbuseError> {
    i32::try_from(value)
        .map_err(|_| AntiAbuseError::InvalidInput("反滥用聚类计数超出范围".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serial_test::serial;
    use std::env;

    const TEST_PEPPER: &str = "anti-abuse-test-pepper-at-least-32-bytes";

    struct FixedAsn(u32);

    impl ControlledAsnResolver for FixedAsn {
        fn lookup(&self, _address: IpAddr) -> Option<u32> {
            Some(self.0)
        }
    }

    fn trusted_loopback() -> BTreeSet<IpAddr> {
        [
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn controlled_asn_map_uses_longest_prefix_without_network_access() {
        let resolver = LocalAsnResolver::from_json(
            br#"{
                "version": 1,
                "entries": [
                    {"cidr":"203.0.113.0/24","asn":64500},
                    {"cidr":"203.0.113.128/25","asn":64501},
                    {"cidr":"2001:db8::/32","asn":64502}
                ]
            }"#,
        )
        .expect("受控 ASN 映射应可解析");
        assert_eq!(resolver.entry_count(), 3);
        assert_eq!(
            resolver.lookup("203.0.113.7".parse().expect("IPv4")),
            Some(64_500)
        );
        assert_eq!(
            resolver.lookup("203.0.113.200".parse().expect("IPv4")),
            Some(64_501)
        );
        assert_eq!(
            resolver.lookup("2001:db8::1".parse().expect("IPv6")),
            Some(64_502)
        );
        assert_eq!(resolver.lookup("198.51.100.1".parse().expect("IPv4")), None);
    }

    #[test]
    fn controlled_asn_map_rejects_ambiguous_or_noncanonical_input() {
        let duplicate = br#"{
            "version":1,
            "entries":[
                {"cidr":"203.0.113.0/24","asn":64500},
                {"cidr":"203.0.113.0/24","asn":64501}
            ]
        }"#;
        assert!(matches!(
            LocalAsnResolver::from_json(duplicate),
            Err(AsnMapError::DuplicatePrefix(_))
        ));
        let host_bits = br#"{
            "version":1,
            "entries":[{"cidr":"203.0.113.7/24","asn":64500}]
        }"#;
        assert!(matches!(
            LocalAsnResolver::from_json(host_bits),
            Err(AsnMapError::NonCanonicalCidr(_))
        ));
    }

    #[test]
    fn untrusted_peer_cannot_spoof_cloudflare_address() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
        let direct = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([198, 51, 100, 7], 443))),
            &headers,
            TEST_PEPPER,
            &FixedAsn(64_500),
            &trusted_loopback(),
        )
        .expect("信号应可派生")
        .expect("应存在 peer");
        let expected = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([198, 51, 100, 99], 443))),
            &HeaderMap::new(),
            TEST_PEPPER,
            &FixedAsn(64_500),
            &trusted_loopback(),
        )
        .expect("信号应可派生")
        .expect("应存在 peer");
        assert_eq!(direct.ip_prefix_hash, expected.ip_prefix_hash);
        assert_eq!(direct.source, NetworkSignalSource::DirectPeer);
        assert!(!format!("{direct:?}").contains("198.51.100"));
    }

    #[test]
    fn loopback_proxy_uses_minimized_cloudflare_prefix_and_controlled_asn() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
        let first = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([127, 0, 0, 1], 54321))),
            &headers,
            TEST_PEPPER,
            &FixedAsn(64_501),
            &trusted_loopback(),
        )
        .expect("信号应可派生")
        .expect("应存在 peer");
        headers.insert(
            "cf-connecting-ip",
            HeaderValue::from_static("203.0.113.200"),
        );
        let same_prefix = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([127, 0, 0, 1], 54322))),
            &headers,
            TEST_PEPPER,
            &FixedAsn(64_501),
            &trusted_loopback(),
        )
        .expect("信号应可派生")
        .expect("应存在 peer");
        assert_eq!(first.ip_prefix_hash, same_prefix.ip_prefix_hash);
        assert_eq!(first.asn_hash, same_prefix.asn_hash);
        assert_eq!(first.source, NetworkSignalSource::TrustedCloudflare);
    }

    #[test]
    fn private_peer_cannot_spoof_without_exact_allowlist_entry() {
        let peer = SocketAddr::from(([192, 168, 65, 1], 54321));
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.9"));
        let untrusted = TrustedNetworkSignal::from_connection(
            Some(peer),
            &headers,
            TEST_PEPPER,
            &NoAsnResolver,
            &trusted_loopback(),
        )
        .expect("私网 peer 应按直连信号处理")
        .expect("直连 peer 应产生信号");
        assert_eq!(untrusted.source, NetworkSignalSource::DirectPeer);

        let trusted = TrustedNetworkSignal::from_connection(
            Some(peer),
            &headers,
            TEST_PEPPER,
            &NoAsnResolver,
            &[peer.ip()].into_iter().collect(),
        )
        .expect("精确白名单 peer 应可提供代理头")
        .expect("可信代理头应产生信号");
        assert_eq!(trusted.source, NetworkSignalSource::TrustedCloudflare);
        assert_ne!(trusted.ip_prefix_hash, untrusted.ip_prefix_hash);
    }

    #[test]
    fn deterministic_policy_blocks_missing_or_clustered_trusted_signals() {
        let missing = deterministic_decision(RiskCounts {
            device_user_count: Some(1),
            ip_user_count: None,
            asn_user_count: None,
            reciprocal_edge_requests: 0,
            require_network_signal: true,
        });
        assert!(!missing.allowed());
        assert!(missing
            .reason_codes
            .contains(&"missing_network_signal".to_owned()));

        let reciprocal = deterministic_decision(RiskCounts {
            device_user_count: Some(1),
            ip_user_count: Some(1),
            asn_user_count: None,
            reciprocal_edge_requests: 10,
            require_network_signal: true,
        });
        assert!(!reciprocal.allowed());
        assert_eq!(reciprocal.contribution_weight_ppm, 0);

        let shared_ip_only = deterministic_decision(RiskCounts {
            device_user_count: Some(1),
            ip_user_count: Some(500),
            asn_user_count: Some(1),
            reciprocal_edge_requests: 0,
            require_network_signal: true,
        });
        assert!(shared_ip_only.allowed());
        assert_eq!(shared_ip_only.contribution_weight_ppm, 500_000);

        let corroborated = deterministic_decision(RiskCounts {
            device_user_count: Some(2),
            ip_user_count: Some(5),
            asn_user_count: Some(1),
            reciprocal_edge_requests: 0,
            require_network_signal: true,
        });
        assert!(!corroborated.allowed());
    }

    #[test]
    fn unavailable_asn_degrades_without_trusting_client_input() {
        let decision = deterministic_decision(RiskCounts {
            device_user_count: Some(1),
            ip_user_count: Some(1),
            asn_user_count: None,
            reciprocal_edge_requests: 0,
            require_network_signal: true,
        });
        assert!(decision.allowed());
        assert!(decision
            .reason_codes
            .contains(&"asn_signal_unavailable".to_owned()));
    }

    #[test]
    fn common_asn_is_only_weak_evidence_and_never_blocks_by_itself() {
        let decision = deterministic_decision(RiskCounts {
            device_user_count: Some(1),
            ip_user_count: Some(1),
            asn_user_count: Some(100_000),
            reciprocal_edge_requests: 0,
            require_network_signal: true,
        });
        assert!(decision.allowed());
        assert_eq!(decision.risk_score_ppm, 200_000);
        assert_eq!(decision.contribution_weight_ppm, 1_000_000);
        assert!(decision
            .reason_codes
            .contains(&"large_shared_asn".to_owned()));
    }

    #[test]
    fn loopback_proxy_without_trusted_client_header_has_no_network_signal() {
        let signal = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([127, 0, 0, 1], 54321))),
            &HeaderMap::new(),
            TEST_PEPPER,
            &NoAsnResolver,
            &trusted_loopback(),
        )
        .expect("缺少可信头应安全降级");
        assert!(signal.is_none());
    }

    #[test]
    fn job_assessment_keys_are_bounded_user_scoped_and_length_delimited() {
        let first_user = Uuid::from_u128(1);
        let second_user = Uuid::from_u128(2);
        let first = job_assessment_key(first_user, "ab:c").expect("幂等键应有效");
        let same = job_assessment_key(first_user, "ab:c").expect("幂等键应有效");
        let other_text = job_assessment_key(first_user, "a:bc").expect("幂等键应有效");
        let other_user = job_assessment_key(second_user, "ab:c").expect("幂等键应有效");
        assert_eq!(first, same);
        assert_ne!(first, other_text);
        assert_ne!(first, other_user);
        assert_eq!(first.len(), 68);
    }

    #[tokio::test]
    #[serial]
    async fn caller_transaction_rolls_back_or_commits_assessment_writes() {
        let Ok(database_url) = env::var("DATABASE_URL") else {
            eprintln!("跳过反滥用事务持久化测试：未设置 DATABASE_URL");
            return;
        };
        let mut config = crate::config::Config::development_for_tests(database_url);
        let suffix = Uuid::now_v7();
        config.dev_username = format!("anti-abuse-transaction-{suffix}");
        let pool = crate::db::connect(&config)
            .await
            .expect("应连接测试 PostgreSQL");
        crate::db::migrate(&pool, &config.standard_data_key)
            .await
            .expect("应应用测试 PostgreSQL 迁移");

        let user_id = Uuid::now_v7();
        let device_key_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO users (id,provider,provider_subject,username) VALUES ($1,$2,$3,$4)",
        )
        .bind(user_id)
        .bind("anti_abuse_test")
        .bind(format!("subject-{suffix}"))
        .bind(format!("user-{suffix}"))
        .execute(&pool)
        .await
        .expect("应创建反滥用测试账户");
        sqlx::query(
            "INSERT INTO device_keys (id,user_id,fingerprint,public_key) VALUES ($1,$2,$3,$4)",
        )
        .bind(device_key_id)
        .bind(user_id)
        .bind(format!("fingerprint-{suffix}"))
        .bind(format!("public-key-{suffix}"))
        .execute(&pool)
        .await
        .expect("应创建设备绑定");
        sqlx::query(
            r#"
            INSERT INTO sessions
                (id,user_id,access_token_hash,refresh_token_hash,access_expires_at,
                 refresh_expires_at,device_key_id)
            VALUES ($1,$2,$3,$4,now()+interval '1 hour',now()+interval '2 hours',$5)
            "#,
        )
        .bind(session_id)
        .bind(user_id)
        .bind(format!("access-{suffix}"))
        .bind(format!("refresh-{suffix}"))
        .bind(device_key_id)
        .execute(&pool)
        .await
        .expect("应创建设备绑定会话");

        let network = TrustedNetworkSignal::from_connection(
            Some(SocketAddr::from(([198, 51, 100, 7], 443))),
            &HeaderMap::new(),
            TEST_PEPPER,
            &NoAsnResolver,
            &trusted_loopback(),
        )
        .expect("应派生测试网络信号")
        .expect("直接 peer 应产生测试网络信号");
        let rollback_key = format!("rollback-{suffix}");
        let mut rollback_tx = pool.begin().await.expect("应开始回滚事务");
        let rollback_decision = assess_before_create_in_transaction(
            &mut rollback_tx,
            TEST_PEPPER,
            user_id,
            session_id,
            &rollback_key,
            Some(&network),
            true,
        )
        .await
        .expect("回滚事务内应完成评估");
        assert!(rollback_decision.allowed());
        rollback_tx.rollback().await.expect("应回滚评估事务");
        let rolled_back_observations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM abuse_network_observations WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("应查询回滚后的网络观察");
        let rolled_back_decisions: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM abuse_decisions WHERE user_id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("应查询回滚后的评估决定");
        assert_eq!(rolled_back_observations, 0);
        assert_eq!(rolled_back_decisions, 0);

        let commit_key = format!("commit-{suffix}");
        let mut commit_tx = pool.begin().await.expect("应开始提交事务");
        let committed_decision = assess_before_create_in_transaction(
            &mut commit_tx,
            TEST_PEPPER,
            user_id,
            session_id,
            &commit_key,
            Some(&network),
            true,
        )
        .await
        .expect("提交事务内应完成评估");
        assert!(committed_decision.allowed());
        commit_tx.commit().await.expect("应提交评估事务");
        let committed_observations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM abuse_network_observations WHERE user_id=$1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("应查询提交后的网络观察");
        let committed_decisions: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM abuse_decisions WHERE user_id=$1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("应查询提交后的评估决定");
        assert_eq!(committed_observations, 1);
        assert_eq!(committed_decisions, 1);
    }
}
