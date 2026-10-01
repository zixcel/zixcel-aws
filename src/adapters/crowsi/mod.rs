//! Dependency-free core used by the separately composed Crowsi runtime adapter.

mod bundle;
mod context;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::execute::execute_with_clock_and_expiry;
use crate::{
    AwsCredentialMaterial, AwsError, CredentialUseError, CredentialUsePort, CredentialUseRequest,
    SIGN_REQUEST_SCHEMA_V1, SIGN_RESPONSE_SCHEMA_V1, SignResponseV1, TrustedClock,
    parse_sign_request, sign_with_material,
};

pub use bundle::credential_bundle;
use bundle::parse_credential_bundle;
pub use context::{CrowsiBindingV1, CrowsiOperationContextV1, DerivedOperationOutput};

pub const ADAPTER: &str = "zixcel-aws";
pub const ALGORITHM: &str = "aws4-hmac-sha256";
pub const DELIVERY: &str = "ipc-response";
pub const USE_ACTION: &str = "use-credential";

struct BorrowedCredentialPort<'a>(&'a AwsCredentialMaterial);

impl CredentialUsePort for BorrowedCredentialPort<'_> {
    fn sign(
        &self,
        request: &CredentialUseRequest<'_>,
    ) -> Result<SignResponseV1, CredentialUseError> {
        sign_with_material(request, self.0)
    }
}

/// Executes a Crowsi-borrowed credential operation without linking sibling repositories.
///
/// # Errors
///
/// Rejects an invalid operation, identity binding, credential bundle, or signing result.
pub fn execute_operation<C: TrustedClock>(
    context: &CrowsiOperationContextV1<'_>,
    borrowed_secret: &[u8],
    clock: &C,
) -> Result<DerivedOperationOutput, AwsError> {
    validate_operation(context)?;
    let expected_body = operation_input_digest(context.operation_input);
    if context.operation_body_sha256 != expected_body {
        return Err(AwsError::invalid(
            "operation_body_sha256",
            "digest mismatch",
        ));
    }
    let request = parse_sign_request(context.operation_input)?;
    validate_binding(context, &request)?;
    let credentials = parse_credential_bundle(borrowed_secret)?;
    let response = execute_with_clock_and_expiry(
        &request,
        &BorrowedCredentialPort(&credentials),
        clock,
        context.expires_at_epoch_seconds,
    )?;
    let payload = Zeroizing::new(serde_json::to_vec(&response).map_err(|_| AwsError::Encoding)?);
    DerivedOperationOutput::new(payload)
}

/// Crowsi's domain-separated operation input digest.
#[must_use]
pub fn operation_input_digest(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"crowsi:credential-runtime-operation-input:v1\0");
    hasher.update(input);
    format!("sha256:{:x}", hasher.finalize())
}

/// Crowsi resource identifier derived from a canonical credential reference.
#[must_use]
pub fn credential_resource(canonical_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"crowsi:credential-resource:v1\0");
    hasher.update(canonical_id.as_bytes());
    format!("credential-{:x}", hasher.finalize())
}

fn validate_operation(context: &CrowsiOperationContextV1<'_>) -> Result<(), AwsError> {
    let valid = context.adapter == ADAPTER
        && context.operation_kind == "sign"
        && context.algorithm == ALGORITHM
        && context.delivery == DELIVERY
        && context.operation_input_schema == SIGN_REQUEST_SCHEMA_V1
        && context.output_schema == SIGN_RESPONSE_SCHEMA_V1
        && context.service == "zixcel-aws";
    if valid {
        Ok(())
    } else {
        Err(AwsError::invalid(
            "crowsi_operation",
            "operation contract mismatch",
        ))
    }
}

fn validate_binding(
    context: &CrowsiOperationContextV1<'_>,
    request: &crate::SignRequestV1,
) -> Result<(), AwsError> {
    let input = &request.request.input;
    let expected_ref = format!("secret://aws/{}", context.credential_ref);
    let (tenant, service, purpose, audience, _) =
        crate::scope_validation::secret_ref_components(&expected_ref)?;
    let binding = &context.binding;
    let exact = request.request_id == context.request_id
        && input.credential_ref == expected_ref
        && context.tenant == tenant
        && context.service == service
        && context.purpose == purpose
        && context.audience == audience
        && input.scope.subject == binding.subject
        && input.scope.device == binding.device
        && input.scope.workload == binding.workload
        && input.scope.grant == binding.grant
        && input.scope.audience == audience
        && input.scope.purpose == purpose
        && input.request.host == context.host
        && binding.resource == credential_resource(context.credential_ref)
        && binding.action == USE_ACTION
        && context.expires_at_epoch_seconds <= input.expires_at_epoch_seconds;
    if exact {
        Ok(())
    } else {
        Err(AwsError::invalid(
            "crowsi_binding",
            "identity or operation mismatch",
        ))
    }
}
