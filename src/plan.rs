use serde::Serialize;

use crate::digest::request_digest;
use crate::{AwsError, OperationModeV1, SignRequestV1, canonical_preview};

/// One local preparation step; this crate never transmits the HTTP request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningPlanStepV1 {
    pub sequence: u32,
    pub action: &'static str,
    pub effect: &'static str,
    pub credential_use_required: bool,
    pub external_network_required: bool,
}

/// Deterministic preparation result for observe, propose, or explicit execute mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningPlanV1 {
    pub schema: &'static str,
    pub plan_id: String,
    pub request_id: String,
    pub mode: OperationModeV1,
    pub request_digest: String,
    pub audience: String,
    pub service: String,
    pub canonical_request_sha256: String,
    pub steps: Vec<SigningPlanStepV1>,
}

/// Validates and canonicalizes without resolving credentials or invoking a port.
///
/// # Errors
///
/// Rejects an invalid request or a value that cannot be canonicalized.
pub fn prepare(request: &SignRequestV1) -> Result<SigningPlanV1, AwsError> {
    request.validate()?;
    let preview = canonical_preview(request)?;
    let request_digest = request_digest(request)?;
    let digest_suffix = request_digest
        .strip_prefix("sha256:")
        .ok_or(AwsError::Encoding)?;
    let execute = request.request.input.mode == OperationModeV1::Execute;
    let mut steps = vec![SigningPlanStepV1 {
        sequence: 1,
        action: "validate-signing-contract",
        effect: "none",
        credential_use_required: false,
        external_network_required: false,
    }];
    steps.push(SigningPlanStepV1 {
        sequence: 2,
        action: if execute {
            "request-credential-use"
        } else {
            "preview-canonical-request"
        },
        effect: if execute { "sign" } else { "none" },
        credential_use_required: execute,
        external_network_required: false,
    });
    Ok(SigningPlanV1 {
        schema: "zixcel://aws/sign-plan/v1",
        plan_id: format!("plan-aws-{}", &digest_suffix[..16]),
        request_id: request.request_id.clone(),
        mode: request.request.input.mode,
        request_digest,
        audience: request.request.input.scope.audience.clone(),
        service: request.request.input.parameters.service.clone(),
        canonical_request_sha256: preview.canonical_request_sha256,
        steps,
    })
}
