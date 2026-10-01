use time::PrimitiveDateTime;
use time::macros::format_description;

use crate::AwsError;

const SIGV4_TIMESTAMP: &[time::format_description::FormatItem<'static>] =
    format_description!("[year][month][day]T[hour][minute][second]Z");

pub(crate) fn timestamp(field: &str, value: &str) -> Result<(), AwsError> {
    timestamp_epoch(value)
        .map(|_| ())
        .map_err(|_| AwsError::invalid(field, "must use YYYYMMDDTHHMMSSZ with a valid UTC date"))
}

pub(crate) fn timestamp_epoch(value: &str) -> Result<i64, time::error::Parse> {
    PrimitiveDateTime::parse(value, SIGV4_TIMESTAMP)
        .map(PrimitiveDateTime::assume_utc)
        .map(time::OffsetDateTime::unix_timestamp)
}
