use std::fmt;

use serde::{Deserialize, Serialize};

use crate::http_request::SigV4ParametersV1;
use crate::scope_validation::{identifier, secret_ref_components, workload_id};
use crate::time_validation::timestamp_epoch;
use crate::{AwsError, HttpRequestV1, SIGN_REQUEST_SCHEMA_V1};

const MAX_REQUEST_BYTES: usize = 1_048_576;

/// Requested effect boundary. There is deliberately no default mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationModeV1 {
    Observe,
    Propose,
    Execute,
}

/// Identity and intent bound to an opaque credential reference.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScopeV1 {
    pub subject: String,
    pub device: String,
    pub workload: String,
    pub grant: String,
    pub audience: String,
    pub purpose: String,
}

/// Closed provider-neutral input for an AWS4-HMAC-SHA256 operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignInputV1 {
    pub mode: OperationModeV1,
    pub credential_ref: String,
    pub scope: CredentialScopeV1,
    pub algorithm: String,
    pub expires_at_epoch_seconds: u64,
    pub parameters: SigV4ParametersV1,
    pub request: HttpRequestV1,
}

/// Named operation wrapper reserved for future AWS credential-use operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignOperationV1 {
    pub operation: String,
    pub input: SignInputV1,
}

/// One finite stdin request. Credential values are not representable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequestV1 {
    pub protocol: String,
    pub request_id: String,
    pub request: SignOperationV1,
}

impl SignRequestV1 {
    /// Validates schema, scope, target, and the absence of credential material.
    ///
    /// # Errors
    ///
    /// Rejects a malformed, ambiguous, or cross-scope request.
    pub fn validate(&self) -> Result<(), AwsError> {
        if self.protocol != SIGN_REQUEST_SCHEMA_V1 {
            return Err(AwsError::invalid("protocol", "unexpected request schema"));
        }
        identifier("request_id", &self.request_id)?;
        if self.request.operation != "sign" {
            return Err(AwsError::invalid("request.operation", "must be sign"));
        }
        let input = &self.request.input;
        let (_, _, reference_purpose, reference_audience, _) =
            secret_ref_components(&input.credential_ref)?;
        identifier("scope.subject", &input.scope.subject)?;
        identifier("scope.device", &input.scope.device)?;
        workload_id(&input.scope.workload)?;
        identifier("scope.grant", &input.scope.grant)?;
        identifier("scope.audience", &input.scope.audience)?;
        identifier("scope.purpose", &input.scope.purpose)?;
        if input.algorithm != "aws4-hmac-sha256" {
            return Err(AwsError::invalid(
                "request.input.algorithm",
                "must be aws4-hmac-sha256",
            ));
        }
        input.parameters.validate()?;
        input.request.validate()?;
        let signed_at = timestamp_epoch(&input.parameters.timestamp)
            .map_err(|_| AwsError::invalid("parameters.timestamp", "invalid timestamp"))?;
        let expires_at = i64::try_from(input.expires_at_epoch_seconds)
            .map_err(|_| AwsError::invalid("expires_at_epoch_seconds", "out of range"))?;
        if expires_at <= signed_at || expires_at - signed_at > 300 {
            return Err(AwsError::invalid(
                "expires_at_epoch_seconds",
                "must be 1..=300 seconds after the signing timestamp",
            ));
        }
        if input.scope.audience != reference_audience || input.scope.purpose != reference_purpose {
            return Err(AwsError::invalid(
                "credential_ref",
                "purpose and audience must match the explicit scope",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for CredentialScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialScopeV1")
            .field("subject", &"<redacted>")
            .field("device", &self.device)
            .field("workload", &self.workload)
            .field("grant", &self.grant)
            .field("audience", &self.audience)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl fmt::Debug for SignInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignInputV1")
            .field("mode", &self.mode)
            .field("credential_ref", &"<redacted>")
            .field("scope", &self.scope)
            .field("algorithm", &self.algorithm)
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("parameters", &self.parameters)
            .field("request", &self.request)
            .finish()
    }
}

/// Parses a bounded, closed JSON request.
///
/// # Errors
///
/// Rejects oversized, malformed, unknown-field, or invalid request documents.
pub fn parse_sign_request(source: &[u8]) -> Result<SignRequestV1, AwsError> {
    if source.len() > MAX_REQUEST_BYTES {
        return Err(AwsError::invalid("request", "document exceeds 1 MiB"));
    }
    let request: SignRequestV1 = serde_json::from_slice(source)
        .map_err(|_| AwsError::invalid("request", "invalid closed v1 JSON"))?;
    request.validate()?;
    Ok(request)
}
