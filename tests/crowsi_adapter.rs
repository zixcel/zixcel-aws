mod support;

use zixcel_aws::adapters::crowsi::{
    ADAPTER, ALGORITHM, CrowsiBindingV1, CrowsiOperationContextV1, DELIVERY, USE_ACTION,
    credential_bundle, credential_resource, execute_operation, operation_input_digest,
};
use zixcel_aws::{
    AwsCredentialMaterial, OperationModeV1, SIGN_REQUEST_SCHEMA_V1, SIGN_RESPONSE_SCHEMA_V1,
    parse_sign_response,
};

use support::{FixedClock, SIGNED_AT, request};

#[test]
fn executes_the_exact_crowsi_runtime_projection() {
    let request = request(OperationModeV1::Execute);
    let input = serde_json::to_vec(&request).expect("request JSON");
    let digest = operation_input_digest(&input);
    let canonical_ref = concat!(
        "tenant-001/zixcel-aws/request-signing/",
        "aws/credential-001"
    );
    let resource = credential_resource(canonical_ref);
    assert_eq!(
        resource,
        "credential-6f00fe6ccf23347d8805cfbd4d8bfd9f11020966a5ce3b7a01365c06781291c9"
    );
    let context = context(&request, &input, &digest, canonical_ref, &resource);
    let credentials = AwsCredentialMaterial::new(
        "AKIDEXAMPLE".to_owned(),
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
        None,
    )
    .expect("credential material");
    let bundle = credential_bundle(&credentials).expect("binary credential bundle");
    let output = execute_operation(&context, &bundle, &FixedClock(SIGNED_AT))
        .expect("derived signing output");
    let response = parse_sign_response(output.payload_for_immediate_stdout(), &request, SIGNED_AT)
        .expect("verified response");
    assert!(response.header("authorization").is_some());
    assert_eq!(response.receipt().expires_at_epoch_seconds, SIGNED_AT + 240);
}

#[test]
fn rejects_digest_and_identity_binding_changes() {
    let request = request(OperationModeV1::Execute);
    let input = serde_json::to_vec(&request).expect("request JSON");
    let canonical_ref = concat!(
        "tenant-001/zixcel-aws/request-signing/",
        "aws/credential-001"
    );
    let resource = credential_resource(canonical_ref);
    let mut context = context(&request, &input, "sha256:invalid", canonical_ref, &resource);
    let credentials = AwsCredentialMaterial::new("access".into(), "secret".into(), None)
        .expect("credential material");
    let bundle = credential_bundle(&credentials).expect("bundle");
    assert!(execute_operation(&context, &bundle, &FixedClock(SIGNED_AT)).is_err());
    let digest = operation_input_digest(&input);
    context.operation_body_sha256 = &digest;
    context.binding.subject = "different-subject";
    assert!(execute_operation(&context, &bundle, &FixedClock(SIGNED_AT)).is_err());
}

fn context<'a>(
    request: &'a zixcel_aws::SignRequestV1,
    input: &'a [u8],
    digest: &'a str,
    credential_ref: &'a str,
    resource: &'a str,
) -> CrowsiOperationContextV1<'a> {
    let scope = &request.request.input.scope;
    CrowsiOperationContextV1 {
        request_id: &request.request_id,
        credential_ref,
        tenant: "tenant-001",
        audience: &scope.audience,
        host: &request.request.input.request.host,
        binding: CrowsiBindingV1 {
            subject: &scope.subject,
            device: &scope.device,
            workload: &scope.workload,
            grant: &scope.grant,
            resource,
            action: USE_ACTION,
        },
        service: "zixcel-aws",
        purpose: &scope.purpose,
        adapter: ADAPTER,
        operation_kind: "sign",
        algorithm: ALGORITHM,
        delivery: DELIVERY,
        operation_input_schema: SIGN_REQUEST_SCHEMA_V1,
        operation_input: input,
        operation_body_sha256: digest,
        output_schema: SIGN_RESPONSE_SCHEMA_V1,
        expires_at_epoch_seconds: SIGNED_AT + 240,
    }
}
