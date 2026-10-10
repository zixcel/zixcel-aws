use crowsi_credential_runtime::{
    CredentialOperationContext, CredentialOperationV1, RuntimeError, RuntimeResult,
};
use zixcel_aws::adapters::crowsi::{CrowsiBindingV1, CrowsiOperationContextV1};

pub(crate) fn from_runtime<'a>(
    context: &'a CredentialOperationContext<'a>,
) -> RuntimeResult<CrowsiOperationContextV1<'a>> {
    let CredentialOperationV1::Sign {
        adapter,
        algorithm,
        delivery,
        output_schema,
    } = context.operation()
    else {
        return Err(RuntimeError::OperationRejected);
    };
    let binding = context.binding();
    Ok(CrowsiOperationContextV1 {
        request_id: context.request_id(),
        credential_ref: context.credential_ref(),
        tenant: context.tenant(),
        audience: context.audience(),
        host: context.host(),
        binding: CrowsiBindingV1 {
            subject: binding.pairwise_subject(),
            device: binding.device_id(),
            workload: binding.workload_id(),
            grant: binding.grant_id(),
            resource: binding.resource(),
            action: binding.action(),
        },
        service: context.service(),
        purpose: context.purpose(),
        adapter,
        operation_kind: context.operation().kind(),
        algorithm,
        delivery,
        operation_input_schema: context.operation_input_schema(),
        operation_input: context.operation_input(),
        operation_body_sha256: context.operation_body_sha256(),
        output_schema,
        expires_at_epoch_seconds: context.expires_at_epoch_s(),
    })
}
