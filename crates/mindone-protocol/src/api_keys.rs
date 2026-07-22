use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{common::validate_identifier, ProtocolValidationError, Validate};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

impl Validate for CreateApiKeyRequest {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        let trimmed = self.name.trim();
        if trimmed != self.name {
            return Err(ProtocolValidationError::new(
                "name",
                "API Key 名称首尾不能有空白",
            ));
        }
        validate_identifier("name", &self.name, 64)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeySummary {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub record: ApiKeySummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyListResponse {
    pub data: Vec<ApiKeySummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeApiKeyResponse {
    pub id: Uuid,
    pub revoked: bool,
}
