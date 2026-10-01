mod coordinator_client;
mod secure_socket;

use std::io::{Read, Write};

use zixcel_aws::{OperationModeV1, SystemClock, TrustedClock, parse_sign_request};

use coordinator_client::sign_via_coordinator;

const MAX_REQUEST_BYTES: u64 = 1_048_576;

fn main() {
    if let Err(error) = run() {
        eprintln!("zixcel-aws: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), CliError> {
    validate_args()?;
    let mut source = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut source)
        .map_err(|_| CliError::Stdin)?;
    if source.len() > usize::try_from(MAX_REQUEST_BYTES).map_err(|_| CliError::Stdin)? {
        return Err(CliError::RequestRejected);
    }
    let request = parse_sign_request(&source).map_err(|_| CliError::RequestRejected)?;
    if request.request.input.mode != OperationModeV1::Execute {
        return Err(CliError::ExecuteRequired);
    }
    let now = SystemClock
        .now_epoch_seconds()
        .map_err(|_| CliError::ClockUnavailable)?;
    let response = sign_via_coordinator(&request, now)?;
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|_| CliError::Output)?;
    stdout.write_all(b"\n").map_err(|_| CliError::Output)
}

fn validate_args() -> Result<(), CliError> {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next()) {
        (Some(command), None) if command == "sign" => Ok(()),
        _ => Err(CliError::Usage),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum CliError {
    Usage,
    Stdin,
    RequestRejected,
    ExecuteRequired,
    ClockUnavailable,
    SocketConfiguration,
    SocketSecurity,
    CoordinatorUnavailable,
    CoordinatorProtocol,
    ResponseRejected,
    Output,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::Usage => "usage: zixcel-aws sign",
            Self::Stdin => "stdin-unavailable",
            Self::RequestRejected => "sign-request-rejected",
            Self::ExecuteRequired => "execute-mode-required",
            Self::ClockUnavailable => "trusted-clock-unavailable",
            Self::SocketConfiguration => "coordinator-socket-configuration-invalid",
            Self::SocketSecurity => "coordinator-socket-security-rejected",
            Self::CoordinatorUnavailable => "coordinator-unavailable",
            Self::CoordinatorProtocol => "coordinator-protocol-rejected",
            Self::ResponseRejected => "sign-response-rejected",
            Self::Output => "stdout-unavailable",
        };
        formatter.write_str(code)
    }
}
