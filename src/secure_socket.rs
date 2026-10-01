use std::fs::Metadata;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::Uid;

use crate::CliError;

const SOCKET_ENV: &str = "ZIXCEL_AWS_COORDINATOR_SOCKET";

pub(crate) fn coordinator_socket_path() -> Result<PathBuf, CliError> {
    if let Some(path) = std::env::var_os(SOCKET_ENV) {
        return validate_absolute(PathBuf::from(path));
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
        || PathBuf::from(format!("/run/user/{}", Uid::current().as_raw())),
        PathBuf::from,
    );
    validate_absolute(runtime.join("zixcel-aws/coordinator.sock"))
}

pub(crate) fn connect_owner_local(path: &Path) -> Result<UnixStream, CliError> {
    validate_path_security(path)?;
    let stream = UnixStream::connect(path).map_err(|_| CliError::CoordinatorUnavailable)?;
    let peer = getsockopt(&stream, PeerCredentials).map_err(|_| CliError::SocketSecurity)?;
    if peer.uid() != Uid::current().as_raw() {
        return Err(CliError::SocketSecurity);
    }
    Ok(stream)
}

fn validate_absolute(path: PathBuf) -> Result<PathBuf, CliError> {
    if !path.is_absolute() || path.file_name().is_none() {
        Err(CliError::SocketConfiguration)
    } else {
        Ok(path)
    }
}

fn validate_path_security(path: &Path) -> Result<(), CliError> {
    let parent = path.parent().ok_or(CliError::SocketConfiguration)?;
    let canonical_parent = parent
        .canonicalize()
        .map_err(|_| CliError::CoordinatorUnavailable)?;
    if canonical_parent != parent {
        return Err(CliError::SocketSecurity);
    }
    let parent_meta =
        std::fs::symlink_metadata(parent).map_err(|_| CliError::CoordinatorUnavailable)?;
    let socket_meta =
        std::fs::symlink_metadata(path).map_err(|_| CliError::CoordinatorUnavailable)?;
    if !socket_meta.file_type().is_socket()
        || !is_owner_private(&parent_meta, 0o700)
        || !is_owner_private(&socket_meta, 0o600)
    {
        return Err(CliError::SocketSecurity);
    }
    Ok(())
}

fn is_owner_private(metadata: &Metadata, expected_mode: u32) -> bool {
    metadata.uid() == Uid::current().as_raw() && metadata.mode() & 0o777 == expected_mode
}
