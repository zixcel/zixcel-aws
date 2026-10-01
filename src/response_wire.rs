use serde::Serialize;
use serde::ser::SerializeStruct;

use crate::{SIGN_RESPONSE_SCHEMA_V1, SignResponseV1};

impl Serialize for SignResponseV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SignResponseV1", 3)?;
        state.serialize_field("protocol", SIGN_RESPONSE_SCHEMA_V1)?;
        state.serialize_field("request_id", &self.request_id)?;
        state.serialize_field("result", &WireResult { response: self })?;
        state.end()
    }
}

struct WireResult<'a> {
    response: &'a SignResponseV1,
}

impl Serialize for WireResult<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let headers: Vec<WireHeader<'_>> = self
            .response
            .headers
            .iter()
            .map(|header| WireHeader {
                name: &header.name,
                value: header.value.expose(),
            })
            .collect();
        let mut state = serializer.serialize_struct("SignResultV1", 2)?;
        state.serialize_field("headers", &headers)?;
        state.serialize_field("receipt", &self.response.receipt)?;
        state.end()
    }
}

#[derive(Serialize)]
struct WireHeader<'a> {
    name: &'a str,
    value: &'a str,
}
