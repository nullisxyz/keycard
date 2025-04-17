//! Commands for credential management operations

use nexum_apdu_transport_pcsc::PcscTransport;
use nexum_keycard::CredentialType;
use std::error::Error;
use tracing::debug;

use crate::utils;

/// Change a credential (PIN, PUK, or pairing secret)
pub fn change_credential_command(
    transport: PcscTransport,
    credential_type: &str,
    new_value: &str,
    pairing_args: &utils::PairingArgs,
) -> Result<(), Box<dyn Error>> {
    // Initialize keycard with pairing info
    let (mut keycard, _) =
        utils::session::initialize_keycard_with_pairing(transport, pairing_args)?;

    // Verify PIN if needed
    let status = keycard.get_status()?;
    if status.pin_retry_count < 3 {
        debug!("PIN verification required");
        keycard.verify_pin()?;
    }

    // Parse credential type
    let cred_type = match credential_type.to_lowercase().as_str() {
        "pin" => {
            validate_pin(new_value)?;
            CredentialType::Pin
        }
        "puk" => {
            validate_puk(new_value)?;
            CredentialType::Puk
        }
        "pairing" => {
            // validate_pairing_secret(new_value)?;
            CredentialType::PairingSecret
        }
        _ => return Err(format!("Unknown credential type: {}", credential_type).into()),
    };

    // Change the credential
    keycard.change_credential(cred_type, new_value, true)?;

    println!("Successfully changed {}", credential_type);

    Ok(())
}

/// Unblock PIN using PUK
pub fn unblock_pin_command(
    transport: PcscTransport,
    puk: &str,
    new_pin: &str,
    pairing_args: &utils::PairingArgs,
) -> Result<(), Box<dyn Error>> {
    // Validate PUK and new PIN
    validate_puk(puk)?;
    validate_pin(new_pin)?;

    // Initialize keycard with pairing info
    let (mut keycard, _) =
        utils::session::initialize_keycard_with_pairing(transport, pairing_args)?;

    // We need a secure channel for unblocking PIN
    if !keycard.is_secure_channel_open() && keycard.pairing_info().is_some() {
        debug!("Opening secure channel");
        keycard.open_secure_channel()?;
    }

    // Unblock PIN
    keycard.unblock_pin(puk, new_pin, true)?;

    println!("PIN unblocked successfully");
    println!("New PIN: {}", new_pin);

    Ok(())
}

/// Validate PIN format
fn validate_pin(pin: &str) -> Result<(), Box<dyn Error>> {
    if pin.len() != 6 || !pin.chars().all(|c| c.is_digit(10)) {
        return Err("PIN must be 6 digits".into());
    }
    Ok(())
}

/// Validate PUK format
fn validate_puk(puk: &str) -> Result<(), Box<dyn Error>> {
    if puk.len() != 12 || !puk.chars().all(|c| c.is_digit(10)) {
        return Err("PUK must be 12 digits".into());
    }
    Ok(())
}
