mod support;

use zixcel_aws::{OperationModeV1, execute_with_clock, parse_sign_response};

use support::{FixedClock, FixturePort, SIGNED_AT, request};

#[test]
fn accepts_only_a_response_bound_to_the_request() {
    let request = request(OperationModeV1::Execute);
    let response = execute_with_clock(&request, &FixturePort::session(), &FixedClock(SIGNED_AT))
        .expect("signed response");
    let wire = serde_json::to_vec(&response).expect("response JSON");
    let parsed = parse_sign_response(&wire, &request, SIGNED_AT).expect("verified response");
    assert_eq!(parsed.request_id(), request.request_id);
}

#[test]
fn rejects_a_tampered_signed_header() {
    let request = request(OperationModeV1::Execute);
    let response = execute_with_clock(&request, &FixturePort::permanent(), &FixedClock(SIGNED_AT))
        .expect("signed response");
    let mut wire = serde_json::to_value(&response).expect("response JSON");
    wire["result"]["headers"][0]["value"] = serde_json::Value::String("tampered".into());
    let encoded = serde_json::to_vec(&wire).expect("tampered JSON");
    assert!(parse_sign_response(&encoded, &request, SIGNED_AT).is_err());
}
