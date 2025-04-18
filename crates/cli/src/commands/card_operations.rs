//! Commands for basic card operations

use nexum_apdu_transport_pcsc::PcscTransport;
use nexum_keycard::Secrets;
use std::error::Error;
use std::path::PathBuf;
use tracing::{debug, info};

use crate::utils;

/// Select the Keycard application and display info
pub fn select_command(transport: PcscTransport) -> Result<(), Box<dyn Error>> {
    let mut keycard = utils::session::initialize_keycard(transport, None)?;
    let app_info = keycard.select_keycard()?;

    // Display card info
    info!("Keycard applet selected successfully.");
    println!("Card Info:");
    println!(
        "  Instance: {}",
        alloy_primitives::hex::encode(app_info.instance_uid)
    );
    println!("  Version: {}", app_info.version);
    println!("  Free slots: {}", app_info.remaining_slots);
    println!("  Capabilities: {}", app_info.capabilities);

    match app_info.key_uid {
        Some(key_uid) => println!("  Key UID: {}", alloy_primitives::hex::encode(key_uid)),
        None => println!("  Key UID: None (use GENERATE KEY)"),
    }

    match app_info.public_key {
        Some(public_key) => println!(
            "  Secure channel public Key: {}",
            alloy_primitives::hex::encode(public_key.to_sec1_bytes())
        ),
        None => println!("  Secure channel public Key: None"),
    }

    Ok(())
}

/// Initialize a new Keycard
pub fn init_command(
    transport: PcscTransport,
    pin: &Option<String>,
    puk: &Option<String>,
    pairing_password: &Option<String>,
    output_file: Option<&PathBuf>,
) -> Result<(), Box<dyn Error>> {
    // Create a keycard instance
    let mut keycard = utils::session::initialize_keycard(transport, None)?;

    // Create secrets based on provided values or generate them
    let secrets = if pin.is_some() || puk.is_some() || pairing_password.is_some() {
        let pin = pin.clone().unwrap_or_else(utils::generate_random_pin);
        let puk = puk.clone().unwrap_or_else(utils::generate_random_puk);
        let pairing_password = pairing_password
            .clone()
            .unwrap_or_else(utils::generate_random_pairing_password);

        debug!("Using provided secrets");
        Secrets::new(&pin, &puk, &pairing_password)
    } else {
        debug!("Generating random secrets");
        Secrets::generate_v3_1(3, 5, true)
    };

    // Initialize the card
    keycard.initialize(&secrets, true)?;

    println!("Keycard initialized successfully!");
    println!("Secrets (SAVE THESE!):");
    println!("  PIN: {}", secrets.pin());
    println!("  PUK: {}", secrets.puk());
    println!("  Pairing password: {}", secrets.pairing_pass());

    // Save pairing info if requested
    if let Some(path) = output_file {
        if let Some(pairing_info) = keycard.pairing_info() {
            utils::save_pairing_to_file(pairing_info, path)?;
            println!("Pairing information saved to {:?}", path);
        }
    }

    Ok(())
}

/// Pair with a card
pub fn pair_command(
    transport: PcscTransport,
    output_file: Option<&PathBuf>,
) -> Result<(), Box<dyn Error>> {
    info!("Pairing with card");

    // Create a keycard instance
    let mut keycard = utils::session::initialize_keycard(transport, None)?;

    // Perform the pairing
    let pairing_info = keycard.pair()?;

    println!("Pairing successful!");
    println!("Pairing index: {}", pairing_info.index);
    println!(
        "Pairing key: {}",
        alloy_primitives::hex::encode(pairing_info.key.as_slice())
    );

    // Save pairing info to file if requested
    if let Some(path) = output_file {
        utils::save_pairing_to_file(&pairing_info, path)?;
        println!("Pairing information saved to {:?}", path);
    }

    Ok(())
}

/// Unpair from a card
pub fn unpair_command(
    transport: PcscTransport,
    pairing_args: &utils::PairingArgs,
) -> Result<(), Box<dyn Error>> {
    // Initialize keycard with pairing info
    let mut keycard = utils::session::initialize_keycard(transport, Some(pairing_args))?;

    // We need pairing info to unpair
    if keycard.pairing_info().is_none() {
        return Err("Pairing information is required for unpair command".into());
    }

    // Unpair
    let index = keycard.pairing_info().unwrap().index;
    info!("Removing pairing with index {} from card", index);
    keycard.unpair(index, true)?;
    println!("Pairing removed successfully");

    Ok(())
}

/// Get detailed status information
pub fn get_status_command(
    transport: PcscTransport,
    pairing_args: &utils::PairingArgs,
) -> Result<(), Box<dyn Error>> {
    // Initialize keycard with pairing info
    let mut keycard = utils::session::initialize_keycard(transport, Some(pairing_args))?;

    // Display basic card info
    if let Ok(info) = keycard.select_keycard() {
        println!("Card Info:");
        println!(
            "  Instance: {}",
            alloy_primitives::hex::encode(info.instance_uid)
        );
        println!("  Version: {}", info.version);
        println!("  Free slots: {}", info.remaining_slots);
    }

    // Try to get more detailed status if we have a secure channel
    if let Ok(status) = keycard.get_status() {
        println!("\nDetailed Status:");
        println!("  PIN retry count: {}", status.pin_retry_count);
        println!("  PUK retry count: {}", status.puk_retry_count);
        println!("  Key initialized: {}", status.key_initialized);

        // Show key path if available
        if let Ok(path) = keycard.get_key_path() {
            println!("  Current key path: {:?}", path);
        } else {
            println!("  No key path set");
        }
    }

    Ok(())
}
