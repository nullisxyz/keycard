use clap::Subcommand;

mod card_init;
mod credentials;
mod key_operations;
mod pairing;
mod status;

// Re-export all command handlers
pub use card_init::*;
pub use credentials::*;
pub use key_operations::*;
pub use pairing::*;
pub use status::*;

/// Define subcommands for the CLI
#[derive(Subcommand)]
pub enum Commands {
    /// List available readers
    List,

    /// Select the Keycard application and show info
    Select,

    /// Initialize a Keycard with random secrets
    Init {
        /// Optional PIN (6 digits, default is random)
        #[arg(long)]
        pin: Option<String>,

        /// Optional PUK (12 digits, default is random)
        #[arg(long)]
        puk: Option<String>,

        /// Optional pairing password (default is random)
        #[arg(long)]
        pairing_password: Option<String>,
    },

    /// Pair with a Keycard
    Pair {
        /// Pairing password
        #[arg(required = true)]
        pairing_password: String,

        /// Optional output file to save pairing info
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },

    /// Open a secure channel
    OpenSecureChannel {
        /// Path to file containing pairing data
        #[arg(long, group = "pairing")]
        file: Option<std::path::PathBuf>,

        /// Pairing key in hex (must be used with --index)
        #[arg(long, requires = "index", group = "pairing")]
        key: Option<String>,

        /// Pairing index (must be used with --key)
        #[arg(long, requires = "key")]
        index: Option<u8>,
    },

    /// Verify PIN
    VerifyPin {
        /// PIN code
        #[arg(required = true)]
        pin: String,

        /// Pairing key in hex (needed if secure channel not already open)
        #[arg(long, requires = "index", group = "pairing")]
        pairing_key: Option<String>,

        /// Pairing index (needed if secure channel not already open)
        #[arg(long, requires = "pairing_key")]
        index: Option<u8>,

        /// Path to file containing pairing data
        #[arg(long, group = "pairing")]
        file: Option<std::path::PathBuf>,
    },

    /// Generate a new key pair on the card
    GenerateKey {
        /// PIN code (needed if not already verified)
        #[arg(long)]
        pin: Option<String>,

        /// Pairing key in hex (needed if secure channel not already open)
        #[arg(long, requires = "index", group = "pairing")]
        pairing_key: Option<String>,

        /// Pairing index (needed if secure channel not already open)
        #[arg(long, requires = "pairing_key")]
        index: Option<u8>,

        /// Path to file containing pairing data
        #[arg(long, group = "pairing")]
        file: Option<std::path::PathBuf>,
    },

    /// Sign data with the current key
    Sign {
        /// Data to sign, as a hex string
        #[arg(required = true)]
        data: String,

        /// Optional key derivation path
        #[arg(long)]
        path: Option<String>,

        /// PIN code (needed if not already verified)
        #[arg(long)]
        pin: Option<String>,

        /// Pairing key in hex (needed if secure channel not already open)
        #[arg(long, requires = "index", group = "pairing")]
        pairing_key: Option<String>,

        /// Pairing index (needed if secure channel not already open)
        #[arg(long, requires = "pairing_key")]
        index: Option<u8>,

        /// Path to file containing pairing data
        #[arg(long, group = "pairing")]
        file: Option<std::path::PathBuf>,
    },

    /// Export pairing info to a file
    ExportPairing {
        /// Output file path
        #[arg(short, long, required = true)]
        output: std::path::PathBuf,
    },

    /// Change PIN, PUK, or pairing secret
    ChangeCredentials {
        /// Type of credential to change: 'pin', 'puk', or 'pairing'
        #[arg(short, long, required = true)]
        credential_type: String,

        /// New value for the credential
        #[arg(short, long, required = true)]
        new_value: String,

        /// Current PIN (required for authentication)
        #[arg(long)]
        pin: Option<String>,

        /// Pairing info for secure channel
        #[command(flatten)]
        pairing: crate::utils::PairingArgs,
    },

    /// Unblock PIN using PUK
    UnblockPin {
        /// PUK code
        #[arg(required = true)]
        puk: String,

        /// New PIN code
        #[arg(required = true)]
        new_pin: String,

        /// Pairing info for secure channel
        #[command(flatten)]
        pairing: crate::utils::PairingArgs,
    },

    /// Set a PIN-less path for signature operations
    SetPinlessPath {
        /// Derivation path (e.g. m/44'/0'/0'/0/0)
        #[arg(required = true)]
        path: String,

        /// PIN code (needed if not already verified)
        #[arg(long)]
        pin: Option<String>,

        /// Pairing info for secure channel
        #[command(flatten)]
        pairing: crate::utils::PairingArgs,
    },

    /// Remove the current key from the card
    RemoveKey {
        /// PIN code (needed if not already verified)
        #[arg(long)]
        pin: Option<String>,

        /// Pairing info for secure channel
        #[command(flatten)]
        pairing: crate::utils::PairingArgs,
    },

    /// Get detailed status information
    GetStatus,
}
