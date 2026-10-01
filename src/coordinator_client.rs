use std::io::{Read, Write};
use std::net::Shutdown;
use std::time::Duration;

use zeroize::Zeroizing;
use zixcel_aws::{SignRequestV1, SignResponseV1, parse_sign_response};

use crate::CliError;
use crate::secure_socket::{connect_owner_local, coordinator_socket_path};

const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1_024;

pub(crate) fn sign_via_coordinator(
    request: &SignRequestV1,
    now: u64,
) -> Result<SignResponseV1, CliError> {
    let path = coordinator_socket_path()?;
    let mut stream = connect_owner_local(&path)?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    let payload = serde_json::to_vec(request).map_err(|_| CliError::RequestRejected)?;
    write_frame(&mut stream, &payload)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    let response = read_frame(&mut stream)?;
    parse_sign_response(&response, request, now).map_err(|_| CliError::ResponseRejected)
}

fn write_frame(stream: &mut impl Write, value: &[u8]) -> Result<(), CliError> {
    let length = u32::try_from(value.len()).map_err(|_| CliError::CoordinatorProtocol)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(value))
        .and_then(|()| stream.flush())
        .map_err(|_| CliError::CoordinatorUnavailable)
}

fn read_frame(stream: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    let length =
        usize::try_from(u32::from_be_bytes(length)).map_err(|_| CliError::CoordinatorProtocol)?;
    if length == 0 || length > MAX_RESPONSE_BYTES {
        return Err(CliError::CoordinatorProtocol);
    }
    let mut value = Zeroizing::new(vec![0_u8; length]);
    stream
        .read_exact(&mut value)
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    Ok(value)
}
