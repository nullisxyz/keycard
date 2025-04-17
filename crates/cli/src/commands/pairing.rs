//! Pairing-related commands

use alloy_primitives::hex;
use nexum_apdu_transport_pcsc::PcscTransport;
use std::path::PathBuf;
use tracing::info;

use crate::utils::{self, session};

/// Pair with a Keycard
pub fn pair_command(
    transport: PcscTransport,
    pairing_password: &str,
    output_file: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut keycard, _) = session::initialize_keycard(transport)?;

    info!("Pairing with card using password...");
    match keycard.pair(|| pairing_password.to_string()) {
        Ok(pairing_info) => {
            println!("\u{1F511} Pairing successful!");
            println!("\nPairing Information (SAVE THIS):");
            println!("  Pairing key: {}", hex::encode(pairing_info.key));
            println!("  Pairing index: {}", pairing_info.index);
            println!(
                "\nYou can use these values with --key and --index options for future operations"
            );

            // Save to file if an output file was specified
            if let Some(path) = output_file {
                utils::save_pairing_to_file(&pairing_info, path)?;
                println!("Pairing information saved to: {}", path.display());
            }
            Ok(())
        }
        Err(e) => Err(format!("Failed to pair with Keycard: {:?}", e).into()),
    }
}

/// Open a secure channel
pub fn open_secure_channel_command(
    transport: PcscTransport,
    file: Option<&PathBuf>,
    key_hex: Option<&String>,
    index: Option<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Create secure keycard and open channel
    let _secure_keycard = session::ensure_secure_channel(keycard, file, key_hex, index)?;

    // If we got here, the secure channel is open
    println!("\u{1F512} Secure channel opened successfully!");
    Ok(())
}

/// Export pairing information to a file
pub fn export_pairing_command(
    transport: PcscTransport,
    output: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let (keycard, _) = session::initialize_keycard(transport)?;

    if let Some(pairing_info) = keycard.pairing_info() {
        utils::save_pairing_to_file(pairing_info, output)?;
        println!(
            "\u{1F4BE} Pairing information exported to: {}",
            output.display()
        );
        Ok(())
    } else {
        Err("No pairing information available. Please pair with the card first.".into())
    }
}
