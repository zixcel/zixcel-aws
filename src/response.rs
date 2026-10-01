use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AwsError;

const MAX_SIGNED_HEADER_VALUE: usize = 32_768;
const MAX_SIGNED_HEADER_BYTES: usize = 60 * 1_024;

/// Sensitive operation output with explicit access and redacted diagnostics.
pub struct SensitiveHeaderValue(Zeroizing<String>);

impl SensitiveHeaderValue {
    pub(crate) fn new(value: String) -> Result<Self, AwsError> {
        if value.is_empty()
            || value.len() > MAX_SIGNED_HEADER_VALUE
            || value.chars().any(|char| char == '\r' || char == '\n')
        {
            Err(AwsError::invalid(
                "signed_header",
                "invalid signed header value",
            ))
        } else {
            Ok(Self(Zeroizing::new(value)))
        }
    }

    /// Explicitly exposes the short-lived value to the immediate HTTP caller.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SensitiveHeaderValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Safe evidence bound to one signed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningReceiptV1 {
    pub request_digest: String,
    pub canonical_request_digest: String,
    pub audience: String,
    pub service: String,
    pub expires_at_epoch_seconds: u64,
    pub result_digest: String,
    pub signed_header_names: Vec<String>,
}

pub(crate) struct SignedHeader {
    pub(crate) name: String,
    pub(crate) value: SensitiveHeaderValue,
}

/// One short-lived `SigV4` result. Custom serialization is the sole wire release point.
pub struct SignResponseV1 {
    pub(crate) request_id: String,
    pub(crate) headers: Vec<SignedHeader>,
    pub(crate) receipt: SigningReceiptV1,
}

impl SignResponseV1 {
    pub(crate) fn new(
        request_id: String,
        headers: Vec<(String, String)>,
        receipt: SigningReceiptV1,
    ) -> Result<Self, AwsError> {
        let mut signed = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            if !matches!(
                name.as_str(),
                "authorization" | "x-amz-date" | "x-amz-security-token"
            ) || signed.iter().any(|item: &SignedHeader| item.name == name)
            {
                return Err(AwsError::invalid(
                    "result.headers",
                    "invalid signed header set",
                ));
            }
            signed.push(SignedHeader {
                name,
                value: SensitiveHeaderValue::new(value)?,
            });
        }
        let encoded_bytes: usize = signed
            .iter()
            .map(|header| header.name.len() + header.value.expose().len())
            .sum();
        if encoded_bytes > MAX_SIGNED_HEADER_BYTES {
            return Err(AwsError::invalid(
                "result.headers",
                "signed header output exceeds 60 KiB",
            ));
        }
        if !signed.iter().any(|item| item.name == "authorization")
            || !signed.iter().any(|item| item.name == "x-amz-date")
        {
            return Err(AwsError::invalid(
                "result.headers",
                "missing required signed header",
            ));
        }
        Ok(Self {
            request_id,
            headers: signed,
            receipt,
        })
    }

    #[must_use]
    pub fn header(&self, name: &str) -> Option<&SensitiveHeaderValue> {
        self.headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| &header.value)
    }

    #[must_use]
    pub const fn receipt(&self) -> &SigningReceiptV1 {
        &self.receipt
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
}

impl fmt::Debug for SignResponseV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        formatter
            .debug_struct("SignResponseV1")
            .field("request_id", &self.request_id)
            .field("headers", &names)
            .field("values", &"<redacted>")
            .field("receipt", &self.receipt)
            .finish()
    }
}
