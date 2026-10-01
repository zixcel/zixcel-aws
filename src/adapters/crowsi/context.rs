use zeroize::Zeroizing;

use crate::AwsError;

/// Identity fields projected from Crowsi `IdentityBindingV1`.
pub struct CrowsiBindingV1<'a> {
    pub subject: &'a str,
    pub device: &'a str,
    pub workload: &'a str,
    pub grant: &'a str,
    pub resource: &'a str,
    pub action: &'a str,
}

/// Borrowed projection of Crowsi `CredentialOperationContext`.
pub struct CrowsiOperationContextV1<'a> {
    pub request_id: &'a str,
    pub credential_ref: &'a str,
    pub tenant: &'a str,
    pub audience: &'a str,
    pub host: &'a str,
    pub binding: CrowsiBindingV1<'a>,
    pub service: &'a str,
    pub purpose: &'a str,
    pub adapter: &'a str,
    pub operation_kind: &'a str,
    pub algorithm: &'a str,
    pub delivery: &'a str,
    pub operation_input_schema: &'a str,
    pub operation_input: &'a [u8],
    pub operation_body_sha256: &'a str,
    pub output_schema: &'a str,
    pub expires_at_epoch_seconds: u64,
}

/// Zeroizing derived output passed immediately to Crowsi `ExecutorOutput::derived`.
pub struct DerivedOperationOutput {
    payload: Zeroizing<Vec<u8>>,
}

impl DerivedOperationOutput {
    pub(crate) fn new(payload: Zeroizing<Vec<u8>>) -> Result<Self, AwsError> {
        if payload.is_empty() || payload.len() > 64 * 1_024 {
            Err(AwsError::invalid(
                "derived_output",
                "must contain at most 64 KiB",
            ))
        } else {
            Ok(Self { payload })
        }
    }

    /// Transfers the payload directly into the runtime-owned zeroizing output.
    pub fn consume<T>(mut self, build: impl FnOnce(&str, &str, Vec<u8>) -> T) -> T {
        let payload = std::mem::take(&mut *self.payload);
        build(crate::SIGN_RESPONSE_SCHEMA_V1, "application/json", payload)
    }

    #[must_use]
    pub fn payload_for_immediate_stdout(&self) -> &[u8] {
        &self.payload
    }
}
