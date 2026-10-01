use std::time::{SystemTime, UNIX_EPOCH};

use crate::time_validation::timestamp_epoch;
use crate::{
    AwsError, CredentialUsePort, CredentialUseRequest, OperationModeV1, SignRequestV1,
    SignResponseV1,
};

/// Trusted time source used to reject stale or future signing requests.
pub trait TrustedClock {
    /// # Errors
    ///
    /// Returns an error when the trusted clock cannot produce Unix time.
    fn now_epoch_seconds(&self) -> Result<u64, AwsError>;
}

/// Operating-system clock used by the finite signer command.
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now_epoch_seconds(&self) -> Result<u64, AwsError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| AwsError::invalid("clock", "system time is before the Unix epoch"))
    }
}

/// Performs exactly one credential-use operation after explicit execute-mode validation.
///
/// # Errors
///
/// Rejects invalid, stale, non-execute, or unauthorized operations.
pub fn execute<P: CredentialUsePort>(
    request: &SignRequestV1,
    port: &P,
) -> Result<SignResponseV1, AwsError> {
    execute_with_clock(request, port, &SystemClock)
}

/// Deterministic clock-injected form for composed runtimes and tests.
///
/// # Errors
///
/// Rejects invalid, stale, non-execute, or unauthorized operations.
pub fn execute_with_clock<P: CredentialUsePort, C: TrustedClock>(
    request: &SignRequestV1,
    port: &P,
    clock: &C,
) -> Result<SignResponseV1, AwsError> {
    execute_with_clock_and_expiry(
        request,
        port,
        clock,
        request.request.input.expires_at_epoch_seconds,
    )
}

pub(crate) fn execute_with_clock_and_expiry<P: CredentialUsePort, C: TrustedClock>(
    request: &SignRequestV1,
    port: &P,
    clock: &C,
    effective_expiry: u64,
) -> Result<SignResponseV1, AwsError> {
    request.validate()?;
    if request.request.input.mode != OperationModeV1::Execute {
        return Err(AwsError::ExecuteModeRequired);
    }
    let now = clock.now_epoch_seconds()?;
    validate_window(request, now)?;
    if effective_expiry > request.request.input.expires_at_epoch_seconds || now >= effective_expiry
    {
        return Err(AwsError::invalid(
            "effective_expiry",
            "must be live and no later than the requested expiry",
        ));
    }
    let credential_use = CredentialUseRequest::new(request, now, effective_expiry);
    port.sign(&credential_use).map_err(AwsError::from)
}

fn validate_window(request: &SignRequestV1, now: u64) -> Result<(), AwsError> {
    let signed_at = timestamp_epoch(&request.request.input.parameters.timestamp)
        .map_err(|_| AwsError::invalid("parameters.timestamp", "invalid timestamp"))?;
    let signed_at = u64::try_from(signed_at)
        .map_err(|_| AwsError::invalid("parameters.timestamp", "pre-epoch timestamp"))?;
    let expires_at = request.request.input.expires_at_epoch_seconds;
    if signed_at > now.saturating_add(60) {
        return Err(AwsError::invalid(
            "parameters.timestamp",
            "is outside the trusted future clock window",
        ));
    }
    if now >= expires_at {
        return Err(AwsError::invalid(
            "expires_at_epoch_seconds",
            "operation has expired",
        ));
    }
    Ok(())
}
