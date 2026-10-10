use crowsi_credential_broker::SecretValue;
use crowsi_credential_runtime::{
    CredentialOperationContext, CredentialOperationExecutor, ExecutorOutput, RuntimeError,
    RuntimeResult,
};
use zixcel_aws::TrustedClock;
use zixcel_aws::adapters::crowsi::execute_operation;

use crate::projection;

/// Trusted adapter that keeps plaintext credential access inside one operation call.
pub struct ZixcelAwsCredentialExecutor<C> {
    clock: C,
}
impl<C> ZixcelAwsCredentialExecutor<C> {
    #[must_use]
    pub const fn new(clock: C) -> Self {
        Self { clock }
    }
}

impl<C: TrustedClock> CredentialOperationExecutor for ZixcelAwsCredentialExecutor<C> {
    fn execute(
        &mut self,
        context: &CredentialOperationContext<'_>,
        secret: &SecretValue,
    ) -> RuntimeResult<ExecutorOutput> {
        let projected = projection::from_runtime(context)?;
        let derived = secret
            .expose(|value| execute_operation(&projected, value, &self.clock))
            .map_err(|_| RuntimeError::OperationRejected)?;
        derived.consume(ExecutorOutput::derived)
    }
}
