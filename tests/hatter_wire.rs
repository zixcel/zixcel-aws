mod support;

use zixcel_aws::{execute_with_clock, parse_sign_request, parse_sign_response};

use support::{FixedClock, FixturePort, SIGNED_AT};

const REQUEST: &[u8] = include_bytes!("fixtures/hatter-sign-request-v1.json");
const RESPONSE: &[u8] = include_bytes!("fixtures/hatter-sign-response-v1.json");

#[test]
fn hatter_request_and_zixcel_response_are_wire_stable() {
    let request = parse_sign_request(REQUEST).expect("Hatter request fixture");
    let response = execute_with_clock(&request, &FixturePort::session(), &FixedClock(SIGNED_AT))
        .expect("signed response");
    let actual = serde_json::to_value(&response).expect("actual response");
    let expected: serde_json::Value = serde_json::from_slice(RESPONSE).expect("response fixture");
    assert_eq!(actual, expected);
    parse_sign_response(RESPONSE, &request, SIGNED_AT).expect("verified fixture response");
}
