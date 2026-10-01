#![forbid(unsafe_code)]
#![doc = "Credential-reference and `SigV4` boundary for independent AWS integrations."]

pub mod adapters;
mod canonical;
mod credential;
mod digest;
mod error;
mod execute;
mod http_request;
mod plan;
mod port;
mod request;
mod response;
mod response_parse;
mod response_wire;
mod scope_validation;
mod signing;
mod time_validation;
mod validation;

pub use canonical::{CanonicalPreviewV1, canonical_preview};
pub use credential::AwsCredentialMaterial;
pub use error::{AwsError, CredentialUseError, CredentialUseErrorCode};
pub use execute::{SystemClock, TrustedClock, execute, execute_with_clock};
pub use http_request::{HeaderV1, HttpRequestV1, QueryParameterV1, SigV4ParametersV1};
pub use plan::{SigningPlanStepV1, SigningPlanV1, prepare};
pub use port::{CredentialUsePort, CredentialUseRequest, sign_with_material};
pub use request::{
    CredentialScopeV1, OperationModeV1, SignInputV1, SignOperationV1, SignRequestV1,
    parse_sign_request,
};
pub use response::{SensitiveHeaderValue, SignResponseV1, SigningReceiptV1};
pub use response_parse::parse_sign_response;

/// Closed request contract accepted on stdin by the finite signer command.
pub const SIGN_REQUEST_SCHEMA_V1: &str = "zixcel://aws/sign-request/v1";
/// Closed response contract emitted by an authorized signer implementation.
pub const SIGN_RESPONSE_SCHEMA_V1: &str = "zixcel://aws/sign-response/v1";
