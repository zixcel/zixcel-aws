#![allow(dead_code)]

use zixcel_aws::{
    AwsCredentialMaterial, CredentialScopeV1, CredentialUseError, CredentialUsePort,
    CredentialUseRequest, HttpRequestV1, OperationModeV1, SIGN_REQUEST_SCHEMA_V1,
    SigV4ParametersV1, SignInputV1, SignOperationV1, SignRequestV1, SignResponseV1, TrustedClock,
    sign_with_material,
};

pub const SIGNED_AT: u64 = 1_440_938_160;

pub fn request(mode: OperationModeV1) -> SignRequestV1 {
    SignRequestV1 {
        protocol: SIGN_REQUEST_SCHEMA_V1.to_owned(),
        request_id: "request-aws-001".to_owned(),
        request: SignOperationV1 {
            operation: "sign".to_owned(),
            input: SignInputV1 {
                mode,
                credential_ref: concat!(
                    "secret://aws/tenant-001/zixcel-aws/",
                    "request-signing/aws/credential-001"
                )
                .to_owned(),
                scope: CredentialScopeV1 {
                    subject: "subject-001".to_owned(),
                    device: "device-001".to_owned(),
                    workload: "spiffe://zixcel.local/workload/example".to_owned(),
                    grant: "grant-001".to_owned(),
                    audience: "aws".to_owned(),
                    purpose: "request-signing".to_owned(),
                },
                algorithm: "aws4-hmac-sha256".to_owned(),
                expires_at_epoch_seconds: SIGNED_AT + 300,
                parameters: SigV4ParametersV1 {
                    region: "us-east-1".to_owned(),
                    service: "service".to_owned(),
                    timestamp: "20150830T123600Z".to_owned(),
                },
                request: HttpRequestV1 {
                    method: "GET".to_owned(),
                    scheme: "https".to_owned(),
                    host: "example.amazonaws.com".to_owned(),
                    path: "/".to_owned(),
                    query: Vec::new(),
                    headers: Vec::new(),
                    payload_sha256:
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                            .to_owned(),
                },
            },
        },
    }
}

pub struct FixedClock(pub u64);

impl TrustedClock for FixedClock {
    fn now_epoch_seconds(&self) -> Result<u64, zixcel_aws::AwsError> {
        Ok(self.0)
    }
}

pub struct FixturePort {
    credentials: AwsCredentialMaterial,
}

impl FixturePort {
    pub fn permanent() -> Self {
        Self {
            credentials: AwsCredentialMaterial::new(
                "AKIDEXAMPLE".to_owned(),
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
                None,
            )
            .expect("valid fixture credential"),
        }
    }

    pub fn session() -> Self {
        Self {
            credentials: AwsCredentialMaterial::new(
                "AKIDEXAMPLE".to_owned(),
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
                Some("fixture-session-token".to_owned()),
            )
            .expect("valid fixture credential"),
        }
    }
}

impl CredentialUsePort for FixturePort {
    fn sign(
        &self,
        request: &CredentialUseRequest<'_>,
    ) -> Result<SignResponseV1, CredentialUseError> {
        sign_with_material(request, &self.credentials)
    }
}
