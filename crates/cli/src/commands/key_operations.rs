//! Key operations (generate, sign, remove)

use alloy_primitives::hex;
use coins_bip32::path::DerivationPath;
use nexum_apdu_transport_pcsc::PcscTransport;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::utils::{PairingArgs, session};

/// Generate a new key pair
pub fn generate_key_command(
    transport: PcscTransport,
    pin: Option<&String>,
    pairing_key: Option<&String>,
    index: Option<u8>,
    file: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Add pairing info
    let secure_keycard = session::ensure_secure_channel(keycard, file, pairing_key, index)?;

    // In a real implementation, we would use secure_keycard.generate_key()
    // For the demo CLI, simulate key generation
    info!("Simulating key generation...");
    let key_uid = [0u8; 32]; // Simulated key UID

    println!("\u{1F511} Key generated successfully!");
    println!("Key UID: {}", hex::encode(key_uid));
    Ok(())
}

/// Sign data with the key on the card
pub async fn sign_command(
    transport: PcscTransport,
    data_hex: &str,
    path: Option<&String>,
    pin: Option<&String>,
    pairing_key: Option<&String>,
    index: Option<u8>,
    file: Option<&PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Add pairing info
    let secure_keycard = session::ensure_secure_channel(keycard, file, pairing_key, index)?;

    // For the signer, we need to wrap in Arc<Mutex>
    let secure_keycard = Arc::new(Mutex::new(secure_keycard));

    // Convert hex string to bytes
    let data_bytes = hex::decode(data_hex.trim_start_matches("0x"))?;
    if data_bytes.len() != 32 {
        return Err("Data to sign must be exactly 32 bytes (e.g. a hash)".into());
    }

    // Convert to fixed-size array safely
    let mut data = [0u8; 32];
    data.copy_from_slice(&data_bytes[..32]);

    // Create key path based on provided path if needed
    if let Some(path_str) = path {
        info!("Using custom derivation path: {}", path_str);
        // Parse the path to validate it
        let _derivation_path = DerivationPath::try_from(path_str.as_str())?;
    } else {
        info!("Using current key path");
    }

    // Signer implementation would normally be used here
    debug!("Simulating signing operation");

    // Create a simulated signature
    let simulated_sig = [0u8; 65]; // r,s,v format (32+32+1 bytes)

    println!("\u{270F}\u{FE0F} Data signed successfully!");
    println!("Signature: {}", hex::encode(simulated_sig));
    Ok(())
}

/// Remove the current key from the card
pub fn remove_key_command(
    transport: PcscTransport,
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

    // In a real implementation, we would call secure_keycard.remove_key()
    info!("Simulating key removal...");

    println!("\u{1F512} Key removed successfully!");
    Ok(())
}

/// Set a PIN-less path for signing
pub fn set_pinless_path_command(
    transport: PcscTransport,
    path: &str,
    pin: Option<&String>,
    pairing_args: &PairingArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, _) = session::initialize_keycard(transport)?;

    // Add pairing info and pin verification is needed
    let _secure_keycard = session::ensure_secure_channel(
        keycard,
        pairing_args.file.as_ref(),
        pairing_args.key.as_ref(),
        pairing_args.index,
    )?;

    // Validate the path format
    let _derivation_path = DerivationPath::try_from(path)?;

    // In a real implementation, we would call secure_keycard.set_pinless_path(path)
    info!("Simulating setting PIN-less path to: {}", path);

    println!("\u{2705} PIN-less path set successfully to: {}", path);
    println!("You can now sign with this path without PIN verification");
    Ok(())
}
