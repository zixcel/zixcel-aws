#![forbid(unsafe_code)]
#![doc = "Trusted, in-process Crowsi-to-Zixcel AWS credential-use adapter."]

mod executor;
mod projection;

pub use executor::ZixcelAwsCredentialExecutor;
