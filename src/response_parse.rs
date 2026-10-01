use serde::Deserialize;
use zeroize::Zeroizing;

use crate::canonical::canonicalize;
use crate::digest::{request_digest, signed_result_digest};
use crate::{AwsError, SIGN_RESPONSE_SCHEMA_V1, SignRequestV1, SignResponseV1, SigningReceiptV1};

const MAX_RESPONSE_BYTES: usize = 64 * 1_024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    protocol: String,
    request_id: String,
    result: WireResult,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResult {
    headers: Vec<WireHeader>,
    receipt: SigningReceiptV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHeader {
    name: String,
    value: Zeroizing<String>,
}

/// Parses and verifies a short-lived response against the exact originating request.
///
/// # Errors
///
/// Rejects malformed, expired, tampered, or differently scoped responses.
pub fn parse_sign_response(
    source: &[u8],
    request: &SignRequestV1,
    now_epoch_seconds: u64,
) -> Result<SignResponseV1, AwsError> {
    request.validate()?;
    if source.is_empty() || source.len() > MAX_RESPONSE_BYTES {
        return Err(AwsError::invalid("response", "must contain at most 64 KiB"));
    }
    let wire: WireResponse = serde_json::from_slice(source)
        .map_err(|_| AwsError::invalid("response", "invalid closed v1 JSON"))?;
    if wire.protocol != SIGN_RESPONSE_SCHEMA_V1 || wire.request_id != request.request_id {
        return Err(AwsError::invalid(
            "response",
            "schema or request ID mismatch",
        ));
    }
    let mut headers = Vec::with_capacity(wire.result.headers.len());
    for mut header in wire.result.headers {
        headers.push((header.name, std::mem::take(&mut *header.value)));
    }
    verify_receipt(request, now_epoch_seconds, &headers, &wire.result.receipt)?;
    SignResponseV1::new(wire.request_id, headers, wire.result.receipt)
}

fn verify_receipt(
    request: &SignRequestV1,
    now: u64,
    headers: &[(String, String)],
    receipt: &SigningReceiptV1,
) -> Result<(), AwsError> {
    let input = &request.request.input;
    let names: Vec<String> = headers.iter().map(|(name, _)| name.clone()).collect();
    let token = headers
        .iter()
        .find(|(name, _)| name == "x-amz-security-token")
        .map(|(_, value)| value.as_str());
    let canonical = canonicalize(&input.request, token, &input.parameters.timestamp)?;
    let expected_request = request_digest(request)?;
    let expected_result = signed_result_digest(
        &expected_request,
        &input.scope.audience,
        &input.parameters.service,
        receipt.expires_at_epoch_seconds,
        headers,
    )?;
    let exact = receipt.request_digest == expected_request
        && receipt.canonical_request_digest == format!("sha256:{}", canonical.hash)
        && receipt.audience == input.scope.audience
        && receipt.service == input.parameters.service
        && receipt.expires_at_epoch_seconds > now
        && receipt.expires_at_epoch_seconds <= input.expires_at_epoch_seconds
        && receipt.result_digest == expected_result
        && receipt.signed_header_names == names;
    if exact {
        Ok(())
    } else {
        Err(AwsError::invalid("response.receipt", "binding mismatch"))
    }
}
