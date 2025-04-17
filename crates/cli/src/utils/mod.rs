use alloy_primitives::hex;
use clap::Args;
use nexum_keycard::PairingInfo;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

pub mod reader;
pub mod session;

/// Common arguments for pairing information
#[derive(Args, Debug, Clone)]
pub struct PairingArgs {
    /// Path to file containing pairing data
    #[arg(long, group = "pairing")]
    pub file: Option<PathBuf>,

    /// Pairing key in hex (must be used with --index)
    #[arg(long, requires = "index", group = "pairing")]
    pub key: Option<String>,

    /// Pairing index (must be used with --key)
    #[arg(long, requires = "key")]
    pub index: Option<u8>,
}

/// Save pairing information to a file
pub fn save_pairing_to_file(
    pairing_info: &PairingInfo,
    path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;

    // Format: index,key_hex
    let content = format!("{},{}", pairing_info.index, hex::encode(pairing_info.key));
    file.write_all(content.as_bytes())?;

    Ok(())
}

/// Prompt for PIN
pub fn prompt_for_pin() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::{self, Write};

    print!("Enter PIN: ");
    io::stdout().flush()?;
    let mut pin = String::new();
    io::stdin().read_line(&mut pin)?;
    Ok(pin.trim().to_string())
}
