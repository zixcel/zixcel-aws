use std::fmt;

/// Stable failure categories returned by a credential-use boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialUseErrorCode {
    Unavailable,
    Unauthorized,
    NotFound,
    ScopeMismatch,
    Expired,
    SigningFailed,
}

/// Sanitized port failure that cannot carry provider error text or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialUseError {
    pub code: CredentialUseErrorCode,
}

impl CredentialUseError {
    #[must_use]
    pub const fn new(code: CredentialUseErrorCode) -> Self {
        Self { code }
    }
}

impl fmt::Display for CredentialUseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "credential-use port rejected the operation: {:?}",
            self.code
        )
    }
}

impl std::error::Error for CredentialUseError {}

/// Fail-closed validation, execution, or credential-use failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwsError {
    Invalid { field: String, message: String },
    ExecuteModeRequired,
    CredentialUse(CredentialUseError),
    Encoding,
}

impl AwsError {
    pub(crate) fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Invalid {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for AwsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field, message } => write!(formatter, "{field}: {message}"),
            Self::ExecuteModeRequired => write!(formatter, "mode must be execute"),
            Self::CredentialUse(error) => error.fmt(formatter),
            Self::Encoding => write!(formatter, "could not encode the signing contract"),
        }
    }
}

impl std::error::Error for AwsError {}

impl From<CredentialUseError> for AwsError {
    fn from(value: CredentialUseError) -> Self {
        Self::CredentialUse(value)
    }
}
