use crate::signing;
use crate::{
    AwsCredentialMaterial, CredentialScopeV1, CredentialUseError, HttpRequestV1, SigV4ParametersV1,
    SignRequestV1, SignResponseV1,
};

/// Execute-only credential-use request; callers cannot construct this type directly.
pub struct CredentialUseRequest<'a> {
    request: &'a SignRequestV1,
    verified_at_epoch_seconds: u64,
    effective_expiry_epoch_seconds: u64,
}

impl<'a> CredentialUseRequest<'a> {
    pub(crate) const fn new(
        request: &'a SignRequestV1,
        verified_at_epoch_seconds: u64,
        effective_expiry_epoch_seconds: u64,
    ) -> Self {
        Self {
            request,
            verified_at_epoch_seconds,
            effective_expiry_epoch_seconds,
        }
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }

    #[must_use]
    pub fn credential_ref(&self) -> &str {
        &self.request.request.input.credential_ref
    }

    #[must_use]
    pub const fn scope(&self) -> &CredentialScopeV1 {
        &self.request.request.input.scope
    }

    #[must_use]
    pub const fn http_request(&self) -> &HttpRequestV1 {
        &self.request.request.input.request
    }

    #[must_use]
    pub const fn parameters(&self) -> &SigV4ParametersV1 {
        &self.request.request.input.parameters
    }

    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.effective_expiry_epoch_seconds
    }

    #[must_use]
    pub const fn verified_at_epoch_seconds(&self) -> u64 {
        self.verified_at_epoch_seconds
    }

    pub(crate) const fn envelope(&self) -> &SignRequestV1 {
        self.request
    }
}

/// Crowsi-facing port for one authorized, replay-protected credential operation.
///
/// Implementations must enforce subject/device/workload/grant scope and reject reuse of the
/// request identifier before resolving credential material.
pub trait CredentialUsePort {
    /// # Errors
    ///
    /// Returns a closed error when authorization, resolution, or signing fails.
    fn sign(
        &self,
        request: &CredentialUseRequest<'_>,
    ) -> Result<SignResponseV1, CredentialUseError>;
}

/// Reference `SigV4` implementation for a trusted in-process port adapter.
///
/// Credential material remains non-serializable and is zeroized on drop.
///
/// # Errors
///
/// Returns a closed signing failure without exposing credential or provider details.
pub fn sign_with_material(
    request: &CredentialUseRequest<'_>,
    credentials: &AwsCredentialMaterial,
) -> Result<SignResponseV1, CredentialUseError> {
    signing::sign(request, credentials)
}
