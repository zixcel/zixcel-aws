mod support;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zixcel_aws::{OperationModeV1, execute_with_clock};

use support::{FixedClock, FixturePort, SIGNED_AT, request};

#[test]
fn matches_aws_sigv4_get_vanilla_signature() {
    let response = execute_with_clock(
        &request(OperationModeV1::Execute),
        &FixturePort::permanent(),
        &FixedClock(SIGNED_AT),
    )
    .expect("signed response");
    assert_eq!(
        response
            .header("authorization")
            .expect("authorization")
            .expose(),
        concat!(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, ",
            "SignedHeaders=host;x-amz-date, ",
            "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        )
    );
}

#[test]
fn response_digest_binds_headers_scope_and_expiry() {
    let response = execute_with_clock(
        &request(OperationModeV1::Execute),
        &FixturePort::session(),
        &FixedClock(SIGNED_AT),
    )
    .expect("signed response");
    let encoded = serde_json::to_value(&response).expect("wire response");
    let result = &encoded["result"];
    let receipt = &result["receipt"];
    let seed = DigestSeed {
        request_digest: receipt["request_digest"].as_str().expect("request digest"),
        audience: receipt["audience"].as_str().expect("audience"),
        service: receipt["service"].as_str().expect("service"),
        expires_at_epoch_seconds: receipt["expires_at_epoch_seconds"]
            .as_u64()
            .expect("expiry"),
        headers: serde_json::from_value(result["headers"].clone()).expect("headers"),
    };
    let digest = Sha256::digest(serde_json::to_vec(&seed).expect("seed"));
    let hex = hex_lower(&digest);
    assert_eq!(receipt["result_digest"], format!("sha256:{hex}"));
}

fn hex_lower(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Serialize)]
struct DigestSeed<'a> {
    request_digest: &'a str,
    audience: &'a str,
    service: &'a str,
    expires_at_epoch_seconds: u64,
    headers: Vec<DigestHeader>,
}

#[derive(serde::Deserialize, Serialize)]
struct DigestHeader {
    name: String,
    value: String,
}
