use crate::AwsError;

pub(crate) fn identifier(field: &str, value: &str) -> Result<(), AwsError> {
    if component(value, 128).is_err() {
        Err(AwsError::invalid(
            field,
            "must be a lowercase ASCII identifier",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn workload_id(value: &str) -> Result<(), AwsError> {
    let Some(path) = value.strip_prefix("spiffe://") else {
        return Err(AwsError::invalid("scope.workload", "must be a SPIFFE ID"));
    };
    if path.is_empty()
        || value.len() > 255
        || path.contains(['?', '#'])
        || path.bytes().any(|byte| byte.is_ascii_whitespace())
        || path.chars().any(char::is_control)
    {
        Err(AwsError::invalid(
            "scope.workload",
            "contains an invalid SPIFFE ID",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn secret_ref_components(
    value: &str,
) -> Result<(&str, &str, &str, &str, &str), AwsError> {
    let Some(path) = value.strip_prefix("secret://aws/") else {
        return Err(AwsError::invalid(
            "credential_ref",
            "must use the secret://aws/ namespace",
        ));
    };
    let segments: Vec<&str> = path.split('/').collect();
    let valid = segments.len() == 5
        && component(segments[0], 64).is_ok()
        && segments[1] == "zixcel-aws"
        && component(segments[2], 96).is_ok()
        && component(segments[3], 96).is_ok()
        && component(segments[4], 96).is_ok();
    if !valid {
        return Err(AwsError::invalid(
            "credential_ref",
            "must encode tenant/zixcel-aws/purpose/audience/credential-id",
        ));
    }
    Ok((
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
    ))
}

fn component(value: &str, maximum: usize) -> Result<(), ()> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        });
    valid.then_some(()).ok_or(())
}
