use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{AwsError, SignRequestV1};

pub(crate) fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    hex_lower(&digest)
}

pub(crate) fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn request_digest(request: &SignRequestV1) -> Result<String, AwsError> {
    let bytes = serde_json::to_vec(request).map_err(|_| AwsError::Encoding)?;
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

pub(crate) fn result_digest<T: Serialize>(value: &T) -> Result<String, AwsError> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| AwsError::Encoding)?);
    Ok(format!("sha256:{}", sha256_hex(&bytes)))
}

pub(crate) fn signed_result_digest(
    request_digest: &str,
    audience: &str,
    service: &str,
    expires_at_epoch_seconds: u64,
    headers: &[(String, String)],
) -> Result<String, AwsError> {
    let headers: Vec<DigestHeader<'_>> = headers
        .iter()
        .map(|(name, value)| DigestHeader { name, value })
        .collect();
    result_digest(&DigestSeed {
        request_digest,
        audience,
        service,
        expires_at_epoch_seconds,
        headers,
    })
}

#[derive(Serialize)]
struct DigestSeed<'a> {
    request_digest: &'a str,
    audience: &'a str,
    service: &'a str,
    expires_at_epoch_seconds: u64,
    headers: Vec<DigestHeader<'a>>,
}

#[derive(Serialize)]
struct DigestHeader<'a> {
    name: &'a str,
    value: &'a str,
}
