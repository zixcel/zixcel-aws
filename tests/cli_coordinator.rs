mod support;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use time::macros::format_description;
use zixcel_aws::{OperationModeV1, execute_with_clock, parse_sign_request, parse_sign_response};

use support::{FixedClock, FixturePort, request};

#[test]
fn finite_cli_uses_only_the_owner_local_coordinator() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let mut request = request(OperationModeV1::Execute);
    request.request.input.parameters.timestamp = timestamp(now);
    request.request.input.expires_at_epoch_seconds = now + 240;
    let request_wire = serde_json::to_vec(&request).expect("request JSON");
    let directory =
        std::env::temp_dir().join(format!("zixcel-aws-cli-{}-{now}", std::process::id()));
    std::fs::create_dir(&directory).expect("private test directory");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("directory permissions");
    let socket = directory.join("coordinator.sock");
    let listener = UnixListener::bind(&socket).expect("test coordinator");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .expect("socket permissions");
    let coordinator = std::thread::spawn(move || serve_once(&listener, now));
    let mut child = Command::new(env!("CARGO_BIN_EXE_zixcel-aws"))
        .arg("sign")
        .env("ZIXCEL_AWS_COORDINATOR_SOCKET", &socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start CLI");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(&request_wire)
        .expect("write request");
    let output = child.wait_with_output().expect("CLI output");
    coordinator.join().expect("coordinator thread");
    assert!(
        output.status.success(),
        "CLI stderr must be diagnostic only"
    );
    let parsed_request = parse_sign_request(&request_wire).expect("request");
    parse_sign_response(&output.stdout, &parsed_request, now).expect("verified CLI response");
    std::fs::remove_file(socket).expect("remove socket");
    std::fs::remove_dir(directory).expect("remove test directory");
}

fn serve_once(listener: &UnixListener, now: u64) {
    let (mut stream, _) = listener.accept().expect("accept CLI");
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).expect("request frame");
    let mut body = vec![0_u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut body).expect("request body");
    let request = parse_sign_request(&body).expect("coordinator request");
    let response = execute_with_clock(&request, &FixturePort::session(), &FixedClock(now))
        .expect("coordinator signing");
    let response = serde_json::to_vec(&response).expect("response JSON");
    let length = u32::try_from(response.len()).expect("response length");
    stream.write_all(&length.to_be_bytes()).expect("length");
    stream.write_all(&response).expect("response");
}

fn timestamp(epoch: u64) -> String {
    let epoch = i64::try_from(epoch).expect("epoch in signed range");
    let time = time::OffsetDateTime::from_unix_timestamp(epoch).expect("valid epoch");
    time.format(format_description!(
        "[year][month][day]T[hour][minute][second]Z"
    ))
    .expect("SigV4 timestamp")
}
