use std::fmt;

use serde::{Deserialize, Serialize};

use crate::AwsError;
use crate::scope_validation::identifier;
use crate::time_validation::timestamp;
use crate::validation::{header_name, header_value, host, method, path};

/// One unencoded query pair; duplicates are retained and sorted canonically.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParameterV1 {
    pub name: String,
    pub value: String,
}

/// One safe caller-provided header. Signing-owned headers are rejected.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderV1 {
    pub name: String,
    pub value: String,
}

/// HTTP components used by `SigV4` without an embedded body or URL parser ambiguity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestV1 {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub query: Vec<QueryParameterV1>,
    #[serde(default)]
    pub headers: Vec<HeaderV1>,
    pub payload_sha256: String,
}

impl fmt::Debug for QueryParameterV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QueryParameterV1")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for HeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderV1")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for HttpRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names: Vec<&str> = self
            .headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        formatter
            .debug_struct("HttpRequestV1")
            .field("method", &self.method)
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("query", &"<redacted>")
            .field("header_names", &header_names)
            .field("payload_sha256", &self.payload_sha256)
            .finish()
    }
}

/// Region, service, and timestamp that define the AWS signing key scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigV4ParametersV1 {
    pub region: String,
    pub service: String,
    pub timestamp: String,
}

impl SigV4ParametersV1 {
    pub(crate) fn validate(&self) -> Result<(), AwsError> {
        identifier("parameters.region", &self.region)?;
        identifier("parameters.service", &self.service)?;
        timestamp("parameters.timestamp", &self.timestamp)
    }
}

impl HttpRequestV1 {
    pub(crate) fn validate(&self) -> Result<(), AwsError> {
        method(&self.method)?;
        if self.scheme != "https" {
            return Err(AwsError::invalid("request.scheme", "must be https"));
        }
        host(&self.host)?;
        path(&self.path)?;
        if self.query.len() > 128 {
            return Err(AwsError::invalid("request.query", "exceeds 128 pairs"));
        }
        for (index, pair) in self.query.iter().enumerate() {
            query_value(&format!("request.query[{index}].name"), &pair.name)?;
            query_value(&format!("request.query[{index}].value"), &pair.value)?;
            reject_signing_query_name(index, &pair.name)?;
        }
        if self.headers.len() > 64 {
            return Err(AwsError::invalid("request.headers", "exceeds 64 entries"));
        }
        for (index, header) in self.headers.iter().enumerate() {
            header_name(index, &header.name)?;
            header_value(index, &header.value)?;
        }
        if self.payload_sha256.len() != 64
            || !self
                .payload_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(AwsError::invalid(
                "request.payload_sha256",
                "must be a lowercase SHA-256 digest",
            ));
        }
        Ok(())
    }
}

fn query_value(field: &str, value: &str) -> Result<(), AwsError> {
    if value.len() > 2_048 || value.chars().any(char::is_control) {
        Err(AwsError::invalid(field, "contains an invalid query value"))
    } else {
        Ok(())
    }
}

fn reject_signing_query_name(index: usize, name: &str) -> Result<(), AwsError> {
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "x-amz-algorithm" | "x-amz-credential" | "x-amz-security-token" | "x-amz-signature"
    ) {
        Err(AwsError::invalid(
            format!("request.query[{index}].name"),
            "signing-owned query fields are forbidden",
        ))
    } else {
        Ok(())
    }
}
