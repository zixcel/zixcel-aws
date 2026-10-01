use zeroize::Zeroizing;

use crate::AwsError;

/// AWS credential material available only inside a trusted credential-use adapter.
///
/// This type intentionally implements neither `Debug`, `Clone`, nor `Serialize`.
///
/// ```compile_fail
/// let value = zixcel_aws::AwsCredentialMaterial::new("access".into(), "secret".into(), None)?;
/// let _ = format!("{value:?}");
/// # Ok::<(), zixcel_aws::AwsError>(())
/// ```
///
/// ```compile_fail
/// let value = zixcel_aws::AwsCredentialMaterial::new("access".into(), "secret".into(), None)?;
/// let _ = serde_json::to_string(&value)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct AwsCredentialMaterial {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl AwsCredentialMaterial {
    /// Moves credential values into zeroizing storage.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, or control-character-bearing credential fields.
    pub fn new(
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Result<Self, AwsError> {
        sensitive_value("access_key_id", &access_key_id, 16_384)?;
        sensitive_value("secret_access_key", &secret_access_key, 16_384)?;
        if let Some(token) = session_token.as_deref() {
            sensitive_value("session_token", token, 32_768)?;
        }
        Ok(Self {
            access_key_id: Zeroizing::new(access_key_id),
            secret_access_key: Zeroizing::new(secret_access_key),
            session_token: session_token.map(Zeroizing::new),
        })
    }

    pub(crate) fn access_key_id(&self) -> &str {
        self.access_key_id.as_str()
    }

    pub(crate) fn from_borrowed(
        access_key_id: &str,
        secret_access_key: &str,
        session_token: Option<&str>,
    ) -> Result<Self, AwsError> {
        sensitive_value("access_key_id", access_key_id, 16_384)?;
        sensitive_value("secret_access_key", secret_access_key, 16_384)?;
        if let Some(token) = session_token {
            sensitive_value("session_token", token, 32_768)?;
        }
        Ok(Self {
            access_key_id: Zeroizing::new(access_key_id.to_owned()),
            secret_access_key: Zeroizing::new(secret_access_key.to_owned()),
            session_token: session_token.map(|value| Zeroizing::new(value.to_owned())),
        })
    }

    pub(crate) fn secret_access_key(&self) -> &str {
        self.secret_access_key.as_str()
    }

    pub(crate) fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref().map(String::as_str)
    }
}

fn sensitive_value(field: &str, value: &str, maximum: usize) -> Result<(), AwsError> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err(AwsError::invalid(
            field,
            "credential value has an invalid shape",
        ))
    } else {
        Ok(())
    }
}
