use crate::{
    CredentialScopeV1, HttpRequestV1, OperationModeV1, SIGN_REQUEST_SCHEMA_V1, SigV4ParametersV1,
    SignInputV1, SignOperationV1, SignRequestV1,
};

/// Non-secret inputs used by the optional Bedrock Mantle adapter.
pub struct BedrockMantleInput {
    pub request_id: String,
    pub credential_ref: String,
    pub subject: String,
    pub device: String,
    pub workload: String,
    pub grant: String,
    pub region: String,
    pub timestamp: String,
    pub expires_at_epoch_seconds: u64,
    pub payload_sha256: String,
}

/// Adapts Bedrock Mantle's endpoint into the generic `SigV4` contract.
#[must_use]
pub fn sign_request(input: BedrockMantleInput) -> SignRequestV1 {
    let host = format!("bedrock-mantle.{}.api.aws", input.region);
    SignRequestV1 {
        protocol: SIGN_REQUEST_SCHEMA_V1.to_owned(),
        request_id: input.request_id,
        request: SignOperationV1 {
            operation: "sign".to_owned(),
            input: SignInputV1 {
                mode: OperationModeV1::Execute,
                credential_ref: input.credential_ref,
                scope: CredentialScopeV1 {
                    subject: input.subject,
                    device: input.device,
                    workload: input.workload,
                    grant: input.grant,
                    audience: "aws".to_owned(),
                    purpose: "amazon-bedrock-model-request".to_owned(),
                },
                algorithm: "aws4-hmac-sha256".to_owned(),
                expires_at_epoch_seconds: input.expires_at_epoch_seconds,
                parameters: SigV4ParametersV1 {
                    region: input.region,
                    service: "bedrock-mantle".to_owned(),
                    timestamp: input.timestamp,
                },
                request: HttpRequestV1 {
                    method: "POST".to_owned(),
                    scheme: "https".to_owned(),
                    host,
                    path: "/openai/v1/responses".to_owned(),
                    query: Vec::new(),
                    headers: Vec::new(),
                    payload_sha256: input.payload_sha256,
                },
            },
        },
    }
}
