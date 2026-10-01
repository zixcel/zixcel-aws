use crate::AwsError;

pub(crate) fn host(value: &str) -> Result<(), AwsError> {
    if value.is_empty() || value.len() > 253 || !value.contains('.') || value.ends_with('.') {
        return Err(AwsError::invalid(
            "request.host",
            "must be a canonical DNS name",
        ));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.starts_with(|char: char| char.is_ascii_alphanumeric())
            || !label.ends_with(|char: char| char.is_ascii_alphanumeric())
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AwsError::invalid(
                "request.host",
                "contains an invalid DNS label",
            ));
        }
    }
    Ok(())
}

pub(crate) fn method(value: &str) -> Result<(), AwsError> {
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        Err(AwsError::invalid(
            "request.method",
            "must be an uppercase HTTP method",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn path(value: &str) -> Result<(), AwsError> {
    if !value.starts_with('/')
        || value.len() > 2_048
        || value.contains(['?', '#'])
        || value.contains("//")
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        Err(AwsError::invalid(
            "request.path",
            "must be an unambiguous raw path",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn header_name(index: usize, value: &str) -> Result<(), AwsError> {
    let normalized = value.to_ascii_lowercase();
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        ..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
                )
        });
    let reserved = matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "host"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-amz-date"
            | "x-amz-security-token"
    );
    if valid && !reserved {
        Ok(())
    } else {
        Err(AwsError::invalid(
            format!("request.headers[{index}].name"),
            "invalid or credential-bearing header name",
        ))
    }
}

pub(crate) fn header_value(index: usize, value: &str) -> Result<(), AwsError> {
    if value.len() > 8_192 || value.chars().any(|char| char != '\t' && char.is_control()) {
        Err(AwsError::invalid(
            format!("request.headers[{index}].value"),
            "contains an invalid header value",
        ))
    } else {
        Ok(())
    }
}
