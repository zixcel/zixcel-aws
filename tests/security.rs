mod support;

use std::sync::atomic::{AtomicUsize, Ordering};

use zixcel_aws::{
    CredentialUseError, CredentialUseErrorCode, CredentialUsePort, CredentialUseRequest,
    OperationModeV1, SignResponseV1, execute_with_clock, parse_sign_request, prepare,
};

use support::{FixedClock, FixturePort, SIGNED_AT, request};

struct CountingPort(AtomicUsize);

impl CredentialUsePort for CountingPort {
    fn sign(
        &self,
        _request: &CredentialUseRequest<'_>,
    ) -> Result<SignResponseV1, CredentialUseError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(CredentialUseError::new(CredentialUseErrorCode::Unavailable))
    }
}

#[test]
fn observe_and_propose_never_invoke_credential_use() {
    let port = CountingPort(AtomicUsize::new(0));
    for mode in [OperationModeV1::Observe, OperationModeV1::Propose] {
        let value = request(mode);
        let plan = prepare(&value).expect("offline plan");
        assert!(
            plan.steps
                .iter()
                .all(|step| !step.external_network_required)
        );
        assert!(execute_with_clock(&value, &port, &FixedClock(SIGNED_AT)).is_err());
    }
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}

#[test]
fn rejects_invalid_reference_scope_and_host() {
    let mut value = request(OperationModeV1::Execute);
    value.request.input.credential_ref = "plain-secret".to_owned();
    assert!(value.validate().is_err());
    value.request.input.credential_ref = "secret://github/example/key".to_owned();
    assert!(value.validate().is_err());
    value.request.input.credential_ref = "secret://aws/example/../key".to_owned();
    assert!(value.validate().is_err());
    value.request.input.credential_ref =
        "secret://aws/tenant-001/aws/request-signing/aws/credential-001".to_owned();
    assert!(value.validate().is_err());

    let mut value = request(OperationModeV1::Execute);
    value.request.input.scope.audience = "other".to_owned();
    assert!(value.validate().is_err());
    value.request.input.scope.audience = "aws".to_owned();
    value.request.input.scope.purpose = "other-purpose".to_owned();
    assert!(value.validate().is_err());
    value.request.input.scope.purpose = "request-signing".to_owned();
    value.request.input.request.host = "Example.AmazonAWS.com".to_owned();
    assert!(value.validate().is_err());
    value.request.input.request.host = "bedrock.us-east-1.amazonaws.com".to_owned();
    assert!(value.validate().is_ok());
}

#[test]
fn rejects_credential_fields_headers_and_stale_requests() {
    let value = serde_json::to_value(request(OperationModeV1::Execute)).expect("request JSON");
    let mut with_secret = value.clone();
    with_secret["request"]["input"]["secret_access_key"] = serde_json::json!("no");
    assert!(parse_sign_request(&serde_json::to_vec(&with_secret).expect("JSON")).is_err());

    let mut with_header = request(OperationModeV1::Execute);
    with_header
        .request
        .input
        .request
        .headers
        .push(zixcel_aws::HeaderV1 {
            name: "Authorization".to_owned(),
            value: "credential".to_owned(),
        });
    assert!(with_header.validate().is_err());

    let port = CountingPort(AtomicUsize::new(0));
    let expired = request(OperationModeV1::Execute);
    assert!(execute_with_clock(&expired, &port, &FixedClock(SIGNED_AT + 300)).is_err());
    assert_eq!(port.0.load(Ordering::SeqCst), 0);
}

#[test]
fn diagnostics_redact_references_identities_and_signed_values() {
    let request = request(OperationModeV1::Execute);
    let request_debug = format!("{request:?}");
    assert!(!request_debug.contains(&request.request.input.credential_ref));
    assert!(!request_debug.contains(&request.request.input.scope.subject));
    let response = execute_with_clock(&request, &FixturePort::session(), &FixedClock(SIGNED_AT))
        .expect("signed response");
    let response_debug = format!("{response:?}");
    assert!(!response_debug.contains("AKIDEXAMPLE"));
    assert!(!response_debug.contains("fixture-session-token"));
    assert!(!response_debug.contains("Signature="));
}
