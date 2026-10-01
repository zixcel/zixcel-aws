use zeroize::Zeroizing;

use crate::{AwsCredentialMaterial, AwsError};

const MAGIC: &[u8] = b"ZIXCEL-AWS-CREDENTIAL\0\x01";

/// Encodes one credential for enrollment without implementing `Serialize` on credential types.
///
/// # Errors
///
/// Returns an encoding error when a credential field exceeds the binary contract limit.
pub fn credential_bundle(
    credentials: &AwsCredentialMaterial,
) -> Result<Zeroizing<Vec<u8>>, AwsError> {
    let access = credentials.access_key_id().as_bytes();
    let secret = credentials.secret_access_key().as_bytes();
    let token = credentials.session_token().unwrap_or_default().as_bytes();
    let access_len = u16::try_from(access.len()).map_err(|_| AwsError::Encoding)?;
    let secret_len = u16::try_from(secret.len()).map_err(|_| AwsError::Encoding)?;
    let token_len = u32::try_from(token.len()).map_err(|_| AwsError::Encoding)?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        MAGIC.len() + 8 + access.len() + secret.len() + token.len(),
    ));
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&access_len.to_be_bytes());
    output.extend_from_slice(&secret_len.to_be_bytes());
    output.extend_from_slice(&token_len.to_be_bytes());
    output.extend_from_slice(access);
    output.extend_from_slice(secret);
    output.extend_from_slice(token);
    Ok(output)
}

pub(crate) fn parse_credential_bundle(value: &[u8]) -> Result<AwsCredentialMaterial, AwsError> {
    if value.len() < MAGIC.len() + 8 || !value.starts_with(MAGIC) {
        return Err(AwsError::invalid(
            "credential_bundle",
            "invalid binary schema",
        ));
    }
    let lengths = &value[MAGIC.len()..MAGIC.len() + 8];
    let access_len = usize::from(u16::from_be_bytes([lengths[0], lengths[1]]));
    let secret_len = usize::from(u16::from_be_bytes([lengths[2], lengths[3]]));
    let token_len = usize::try_from(u32::from_be_bytes([
        lengths[4], lengths[5], lengths[6], lengths[7],
    ]))
    .map_err(|_| AwsError::Encoding)?;
    let start = MAGIC.len() + 8;
    let secret_start = start.checked_add(access_len).ok_or(AwsError::Encoding)?;
    let token_start = secret_start
        .checked_add(secret_len)
        .ok_or(AwsError::Encoding)?;
    let end = token_start
        .checked_add(token_len)
        .ok_or(AwsError::Encoding)?;
    if end != value.len() {
        return Err(AwsError::invalid("credential_bundle", "length mismatch"));
    }
    let access = text(&value[start..secret_start])?;
    let secret = text(&value[secret_start..token_start])?;
    let token = (token_len > 0)
        .then(|| text(&value[token_start..end]))
        .transpose()?;
    AwsCredentialMaterial::from_borrowed(access, secret, token)
}

fn text(value: &[u8]) -> Result<&str, AwsError> {
    std::str::from_utf8(value)
        .map_err(|_| AwsError::invalid("credential_bundle", "contains non-UTF-8 text"))
}
