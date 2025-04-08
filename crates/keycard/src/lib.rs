// mod application;
mod commands;
mod constants;
mod crypto;
mod error;
mod secrets;
mod secure_channel;
mod session;
mod types;

// pub use application::Keycard;
pub use commands::generate_key::*;
pub use commands::init::*;
pub use commands::mutually_authenticate::*;
pub use commands::open_secure_channel::*;
pub use commands::pair::*;
pub use commands::pin::*;
pub use commands::select::*;
pub use commands::sign::*;
pub use crypto::Challenge;
pub use error::{Error, Result};
pub use secrets::Secrets;
pub use secure_channel::KeycardSCP;
pub use types::{ApplicationInfo, ApplicationStatus, PairingInfo};

pub use constants::*;

/// Represents the version of the applet protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppletVersion {
    /// Versions before 3.1
    Legacy,
    /// Version 3.1 and above
    V3_1,
}

/// Create a Keycard instance AID with the specified index
pub fn keycard_instance_aid(index: u8) -> Vec<u8> {
    assert!(index >= 1);
    let mut aid = Vec::from(KEYCARD_AID);
    aid.push(index);
    aid
}
