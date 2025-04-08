use thiserror::Error;

use crate::VerifyPinError;

/// Result type for Keycard operations
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for Keycard operations
#[derive(Debug, Error)]
pub enum Error {
    /// APDU-related errors
    #[error(transparent)]
    Apdu(#[from] nexum_apdu_core::Error),

    /// Transport-related errors
    #[error(transparent)]
    TransportError(#[from] nexum_apdu_core::transport::TransportError),

    /// Command-related errors
    #[error(transparent)]
    Command(#[from] nexum_apdu_core::command::error::CommandError),

    /// Response-related errors
    #[error(transparent)]
    Response(#[from] nexum_apdu_core::response::error::ResponseError),

    /// Status errors (for status words)
    #[error(transparent)]
    Status(#[from] nexum_apdu_core::response::error::StatusError),

    /// Processor-related errors
    #[error(transparent)]
    Processor(#[from] nexum_apdu_core::processor::ProcessorError),

    /// Secure protocol related errors
    #[error(transparent)]
    SecureProtocol(#[from] nexum_apdu_core::processor::SecureProtocolError),

    /// Secure channel not supported
    #[error("Secure channel not supported")]
    SecureChannelNotSupported,

    #[error("Already initialised")]
    AlreadyInitialised,

    #[error("No available pairing slots")]
    NoAvailablePairingSlots,

    // #[error("Invalid response data")]
    // InvalidResponseData,
    #[error("PIN verification required")]
    PinVerificationRequired,

    #[error(transparent)]
    Pin(#[from] VerifyPinError),

    #[error("Pairing failed")]
    PairingFailed,

    #[error("Mutual authentication failed")]
    MutualAuthenticationFailed,

    #[error("BIP32 path parsing error")]
    Bip32PathParsingError(coins_bip32::Bip32Error),

    #[error("Invalid derivation path length")]
    InvalidDerivationPathLength,

    #[error("Invalid data")]
    InvalidData(&'static str),

    #[error("Unpad error")]
    UnpadError(#[from] cipher::block_padding::UnpadError),

    #[error("Pad error")]
    PadError(#[from] cipher::inout::PadError),

    #[error("Invalid derivation arguments: {0}")]
    InvalidDerivationArguments(String),

    #[error("Unknown error")]
    Unknown,
}

// Implement From for bip32::Error to allow using .into()
impl From<coins_bip32::Bip32Error> for Error {
    fn from(err: coins_bip32::Bip32Error) -> Self {
        Error::Bip32PathParsingError(err)
    }
}

// impl From<Error> for nexum_apdu_core::processor::ProcessorError {
//     fn from(err: Error) -> Self {
//         match err {
//             // Map specific error types directly when possible
//             Error::TransportError(e) => Self::Transport(e),
//             Error::Response(e) => Self::InvalidResponse(e),
//             Error::PinVerificationRequired => {
//                 Self::authentication_failed("PIN verification required")
//             }
//             Error::WrongPin(attempts) => Self::authentication_failed("Wrong PIN"),
//             Error::PairingFailed => Self::authentication_failed("Pairing failed"),
//             Error::MutualAuthenticationFailed => {
//                 Self::authentication_failed("Mutual authentication failed")
//             }
//             Error::AlreadyInitialised => Self::protocol("Already initialized"),
//             Error::NoAvailablePairingSlots => Self::protocol("No available pairing slots"),
//             Error::Processor(e) => e, // Passthrough if it's already a ProcessorError

//             // For other cases, convert to string representation
//             _ => Self::other(err.to_string()),
//         }
//     }
// }
