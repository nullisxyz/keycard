//! Status and information commands

use alloy_primitives::hex;
use nexum_apdu_transport_pcsc::PcscTransport;
use tracing::info;

use crate::utils::session;

/// Get status information from the card
pub fn get_status_command(
    transport: PcscTransport,
) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize keycard
    let (keycard, select_info) = session::initialize_keycard(transport)?;
    
    // Display basic information from selection
    println!("\u{1F50D} Card Status Information:");
    println!("{}", select_info);
    
    // In a real implementation, we would create a secure channel and get detailed status
    // For our simplified CLI, we'll just show what we have from the select response
    info!("Showing card status information from selection response");
    match select_info {
        nexum_keycard::ParsedSelectOk::ApplicationInfo(app_info) => {
            println!("\n\u{1F4CA} Application Details:");
            println!("  Instance UID: {}", hex::encode(app_info.instance_uid));
            println!("  Version: {}.{}", app_info.version.major, app_info.version.minor);
            println!("  Remaining pairing slots: {}", app_info.remaining_slots);
            println!("  Has secure channel: {}", if app_info.public_key.is_some() {"\u{2705} Yes"} else {"\u{274C} No"});
            
            if let Some(key_uid) = app_info.key_uid {
                println!("  Key UID: {}", hex::encode(key_uid));
            } else {
                println!("  Key UID: None (no key loaded)");
            }
            
            println!("  Capabilities: {:#?}", app_info.capabilities);
        }
        _ => {
            println!("\n\u{2139}\u{FE0F} Detailed status unavailable - card may not be fully initialized");
        }
    }
    
    Ok(())
}