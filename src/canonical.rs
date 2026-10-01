use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::digest::sha256_hex;
use crate::{AwsError, HeaderV1, HttpRequestV1, SignRequestV1};

/// Safe preview of canonicalization. Header and query values are represented by a digest only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalPreviewV1 {
    pub canonical_request_sha256: String,
    pub signed_header_names: Vec<String>,
    pub session_token_header_included: bool,
}

pub(crate) struct CanonicalData {
    pub hash: String,
    pub signed_headers: Vec<String>,
}

impl CanonicalData {
    pub(crate) fn signed_headers_text(&self) -> String {
        self.signed_headers.join(";")
    }
}

/// Builds a value-redacted canonical preview without resolving a credential.
///
/// # Errors
///
/// Rejects an invalid request or a value that cannot be canonicalized.
pub fn canonical_preview(request: &SignRequestV1) -> Result<CanonicalPreviewV1, AwsError> {
    request.validate()?;
    let canonical = canonicalize(
        &request.request.input.request,
        None,
        &request.request.input.parameters.timestamp,
    )?;
    Ok(CanonicalPreviewV1 {
        canonical_request_sha256: canonical.hash,
        signed_header_names: canonical.signed_headers,
        session_token_header_included: false,
    })
}

pub(crate) fn canonicalize(
    request: &HttpRequestV1,
    session_token: Option<&str>,
    timestamp: &str,
) -> Result<CanonicalData, AwsError> {
    request.validate()?;
    let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for HeaderV1 { name, value } in &request.headers {
        headers
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(normalize_header_value(value));
    }
    headers.insert("host".to_owned(), vec![request.host.clone()]);
    headers.insert("x-amz-date".to_owned(), vec![timestamp.to_owned()]);
    if let Some(token) = session_token {
        headers.insert("x-amz-security-token".to_owned(), vec![token.to_owned()]);
    }
    let signed_headers: Vec<String> = headers.keys().cloned().collect();
    let mut canonical_headers = String::new();
    for (name, values) in &headers {
        writeln!(&mut canonical_headers, "{name}:{}", values.join(","))
            .map_err(|_| AwsError::Encoding)?;
    }
    let canonical = Zeroizing::new(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method,
        encode_path(&request.path),
        canonical_query(request),
        canonical_headers,
        signed_headers.join(";"),
        request.payload_sha256
    ));
    let hash = sha256_hex(canonical.as_bytes());
    Ok(CanonicalData {
        hash,
        signed_headers,
    })
}

fn canonical_query(request: &HttpRequestV1) -> String {
    let mut pairs: Vec<(String, String)> = request
        .query
        .iter()
        .map(|pair| (uri_encode(&pair.name, true), uri_encode(&pair.value, true)))
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn encode_path(path: &str) -> String {
    uri_encode(path, false)
}

fn uri_encode(value: &str, encode_slash: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (byte == b'/' && !encode_slash)
        {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn normalize_header_value(value: &str) -> String {
    value.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}
