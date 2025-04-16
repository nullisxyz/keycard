//! Card initialization and selection commands

use nexum_apdu_transport_pcsc::PcscDeviceManager;
use nexum_apdu_transport_pcsc::PcscTransport;
use nexum_keycard::{Keycard, ParsedSelectOk, Secrets};
use tracing::{debug, info};

use crate::utils::reader;
use crate::utils::session;

/// List all available readers
pub fn list_readers(manager: &PcscDeviceManager) -> Result<(), Box<dyn std::error::Error>> {
    reader::list_readers(manager)
}

/// Select the Keycard application and display info
pub fn select_command(transport: PcscTransport) -> Result<(), Box<dyn std::error::Error>> {
    let (_, select_response) = session::initialize_keycard(transport)?;

    // Display card info
    info!("Keycard applet selected successfully.");
    println!("ud83dudd0d Card Info:");
    println!("{}", select_response);

    Ok(())
}

/// Initialize a new Keycard
pub fn init_command(
    transport: PcscTransport,
    pin: &Option<String>,
    puk: &Option<String>,
    pairing_password: &Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a keycard with the transport
    let mut keycard = Keycard::new(transport);

    // Select the card to get into proper state
    let select_response = keycard.select_keycard()?;

    // Check if card is in pre-initialized state
    match select_response {
        ParsedSelectOk::PreInitialized(_) => {
            // Create secrets based on provided values or generate them
            let secrets = if pin.is_some() || puk.is_some() || pairing_password.is_some() {
                let pin = pin.clone().unwrap_or_else(|| "123456".to_string());
                let puk = puk.clone().unwrap_or_else(|| "123456789012".to_string());
                let pairing_password = pairing_password
                    .clone()
                    .unwrap_or_else(|| "KeycardDefaultPairing".to_string());

                debug!("Using provided secrets");
                Secrets::new(&pin, &puk, &pairing_password)
            } else {
                debug!("Generating random secrets");
                Secrets::generate()
            };

            match keycard.initialize(&secrets) {
                Ok(_) => {
                    println!("ud83cudf89 Keycard initialized successfully!");
                    println!("Secrets (SAVE THESE!):");
                    println!("  PIN: {}", secrets.pin());
                    println!("  PUK: {}", secrets.puk());
                    println!("  Pairing password: {}", secrets.pairing_pass());
                    Ok(())
                }
                Err(e) => Err(format!("Failed to initialize Keycard: {:?}", e).into()),
            }
        }
        _ => {
            println!("u26a0ufe0f Card is already initialized.");
            Ok(())
        }
    }
}