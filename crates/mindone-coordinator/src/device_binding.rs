use uuid::Uuid;

use crate::{auth::Principal, error::ApiError};

pub(crate) const DEVICE_BINDING_VERSION: i32 = 1;

pub(crate) fn require_node_device_binding(
    principal: &Principal,
    node_user_id: Uuid,
    node_device_key_id: Option<Uuid>,
) -> Result<(), ApiError> {
    if node_user_id != principal.user_id || node_device_key_id != Some(principal.device_key_id) {
        return Err(ApiError::forbidden("当前设备无权操作此节点"));
    }
    Ok(())
}

pub(crate) fn exact_claim_device_binding(
    principal: &Principal,
    claimed_user_id: Option<Uuid>,
    claimed_device_key_id: Option<Uuid>,
    binding_version: Option<i32>,
) -> bool {
    claimed_user_id == Some(principal.user_id)
        && claimed_device_key_id == Some(principal.device_key_id)
        && binding_version == Some(DEVICE_BINDING_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal() -> Principal {
        Principal {
            user_id: Uuid::from_u128(1),
            username: "worker".to_owned(),
            session_id: Uuid::from_u128(2),
            device_key_id: Uuid::from_u128(3),
        }
    }

    #[test]
    fn node_binding_requires_same_account_and_exact_device() {
        let principal = principal();
        assert!(require_node_device_binding(
            &principal,
            principal.user_id,
            Some(principal.device_key_id)
        )
        .is_ok());
        assert!(require_node_device_binding(
            &principal,
            principal.user_id,
            Some(Uuid::from_u128(4))
        )
        .is_err());
        assert!(require_node_device_binding(&principal, principal.user_id, None).is_err());
        assert!(require_node_device_binding(
            &principal,
            Uuid::from_u128(5),
            Some(principal.device_key_id)
        )
        .is_err());
    }

    #[test]
    fn claim_binding_requires_all_fields_and_v1() {
        let principal = principal();
        assert!(exact_claim_device_binding(
            &principal,
            Some(principal.user_id),
            Some(principal.device_key_id),
            Some(DEVICE_BINDING_VERSION)
        ));
        assert!(!exact_claim_device_binding(
            &principal,
            Some(principal.user_id),
            Some(Uuid::from_u128(4)),
            Some(DEVICE_BINDING_VERSION)
        ));
        assert!(!exact_claim_device_binding(
            &principal,
            Some(principal.user_id),
            Some(principal.device_key_id),
            Some(2)
        ));
        assert!(!exact_claim_device_binding(&principal, None, None, None));
    }
}
