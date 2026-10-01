use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::canonical::canonicalize;
use crate::digest::{hex_lower, request_digest, signed_result_digest};
use crate::{
    AwsCredentialMaterial, CredentialUseError, CredentialUseErrorCode, CredentialUseRequest,
    SignResponseV1, SigningReceiptV1,
};

type HmacSha256 = Hmac<Sha256>;

pub(crate) fn sign(
    request: &CredentialUseRequest<'_>,
    credentials: &AwsCredentialMaterial,
) -> Result<SignResponseV1, CredentialUseError> {
    sign_inner(request, credentials)
        .map_err(|_| CredentialUseError::new(CredentialUseErrorCode::SigningFailed))
}

fn sign_inner(
    request: &CredentialUseRequest<'_>,
    credentials: &AwsCredentialMaterial,
) -> Result<SignResponseV1, crate::AwsError> {
    let parameters = request.parameters();
    let canonical = canonicalize(
        request.http_request(),
        credentials.session_token(),
        &parameters.timestamp,
    )?;
    let date = &parameters.timestamp[..8];
    let aws_scope = format!(
        "{date}/{}/{}/aws4_request",
        parameters.region, parameters.service
    );
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        parameters.timestamp, aws_scope, canonical.hash
    );
    let signature = derive_signature(
        credentials.secret_access_key(),
        date,
        parameters,
        &string_to_sign,
    )?;
    let authorization = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        credentials.access_key_id(),
        aws_scope,
        canonical.signed_headers_text(),
        hex_lower(&signature)
    ));
    let request_digest = request_digest(request.envelope())?;
    let mut added_headers = vec![
        ("authorization".to_owned(), authorization.to_string()),
        ("x-amz-date".to_owned(), parameters.timestamp.clone()),
    ];
    if let Some(token) = credentials.session_token() {
        added_headers.push(("x-amz-security-token".to_owned(), token.to_owned()));
    }
    let result_digest = signed_result_digest(
        &request_digest,
        &request.scope().audience,
        &parameters.service,
        request.expires_at_epoch_seconds(),
        &added_headers,
    )?;
    let result_header_names = added_headers.iter().map(|(name, _)| name.clone()).collect();
    let receipt = SigningReceiptV1 {
        request_digest,
        canonical_request_digest: format!("sha256:{}", canonical.hash),
        audience: request.scope().audience.clone(),
        service: parameters.service.clone(),
        expires_at_epoch_seconds: request.expires_at_epoch_seconds(),
        result_digest,
        signed_header_names: result_header_names,
    };
    SignResponseV1::new(request.request_id().to_owned(), added_headers, receipt)
}

fn derive_signature(
    secret: &str,
    date: &str,
    parameters: &crate::SigV4ParametersV1,
    string_to_sign: &str,
) -> Result<[u8; 32], crate::AwsError> {
    let root = Zeroizing::new(format!("AWS4{secret}"));
    let date_key = Zeroizing::new(hmac_bytes(root.as_bytes(), date.as_bytes())?);
    let region_key = Zeroizing::new(hmac_bytes(&*date_key, parameters.region.as_bytes())?);
    let service_key = Zeroizing::new(hmac_bytes(&*region_key, parameters.service.as_bytes())?);
    let signing_key = Zeroizing::new(hmac_bytes(&*service_key, b"aws4_request")?);
    hmac_bytes(&*signing_key, string_to_sign.as_bytes())
}

fn hmac_bytes(key: &[u8], value: &[u8]) -> Result<[u8; 32], crate::AwsError> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| crate::AwsError::Encoding)?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().into())
}
