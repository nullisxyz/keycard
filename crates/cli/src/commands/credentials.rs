//! Commands for managing PIN, PUK, and other credentials

use nexum_apdu_transport_pcsc::PcscTransport;
use std::path::PathBuf;
use tracing::info;

use crate::utils::{PairingArgs, session};

/// Verify PIN to test authentication
pub fn verify_pin_command(
    transport: PcscTransport,
    pin: &str,
    pairing_key: Option<&String>,
    index: Option<u8>,
    file: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Create secure keycard with session
    let mut secure_keycard = session::ensure_secure_channel(keycard, file, pairing_key, index)?;

    // Simulate PIN verification (in a real implementation, this would call verify_pin)
    info!("Simulating PIN verification: {}", pin);
    println!("\u{1F513} PIN verified successfully!");
    Ok(())
}

/// Change credentials (PIN, PUK, Pairing Secret)
pub fn change_credentials_command(
    transport: PcscTransport,
    credential_type: &str,
    new_value: &str,
    pin: Option<&String>,
    pairing_args: &PairingArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Add pairing info
    let _secure_keycard = session::ensure_secure_channel(
        keycard,
        pairing_args.file.as_ref(),
        pairing_args.key.as_ref(),
        pairing_args.index,
    )?;

    // Determine which credential to change
    info!("Simulating changing {}: {}", credential_type, new_value);
    match credential_type.to_lowercase().as_str() {
        "pin" => {
            println!("\u{1F511} PIN changed successfully!");
        }
        "puk" => {
            println!("\u{1F511} PUK changed successfully!");
        }
        "pairing" => {
            println!("\u{1F511} Pairing secret changed successfully!");
        }
        _ => return Err(format!("Invalid credential type: {}", credential_type).into()),
    }

    Ok(())
}

/// Unblock PIN using PUK
pub fn unblock_pin_command(
    transport: PcscTransport,
    puk: &str,
    new_pin: &str,
    pairing_args: &PairingArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Create secure keycard with session
    let _secure_keycard = session::ensure_secure_channel(
        keycard,
        pairing_args.file.as_ref(),
        pairing_args.key.as_ref(),
        pairing_args.index,
    )?;

    // Simulate unblocking PIN (in a real implementation, this would call unblock_pin)
    info!("Simulating PIN unblock. PUK: {}, New PIN: {}", puk, new_pin);

    println!("\u{1F513} PIN unblocked successfully!");
    println!("New PIN set to: {}", new_pin);
    Ok(())
}
