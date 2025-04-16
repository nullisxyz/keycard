use clap::Parser;
use nexum_apdu_transport_pcsc::{PcscConfig, PcscDeviceManager};
use tracing::info;

mod commands;
mod utils;

use commands::Commands;

#[derive(Parser)]
#[command(version, about = "Keycard CLI for managing and using Status Keycard")]
struct Cli {
    /// Optional reader name to use (will auto-detect if not specified)
    #[arg(short, long)]
    reader: Option<String>,

    /// Trace level output
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let cli = Cli::parse();

    // Setup logging based on verbosity
    setup_logging(cli.verbose);

    // Create a PC/SC device manager
    let manager = PcscDeviceManager::new()?;

    match &cli.command {
        Commands::List => {
            commands::list_readers(&manager)?;
            return Ok(());
        }
        _ => {
            // For all other commands, find appropriate reader
            let reader = match &cli.reader {
                Some(reader_name) => utils::reader::find_reader_by_name(&manager, reader_name)?,
                None => utils::reader::find_reader_with_card(&manager)?,
            };

            info!("Using reader: {}", reader.name());

            // Execute the command using the selected reader
            let config = PcscConfig::default();
            let transport = manager.open_reader_with_config(reader.name(), config)?;

            match &cli.command {
                Commands::List => unreachable!(), // Already handled above
                Commands::Select => commands::select_command(transport)?,
                Commands::Init {
                    pin,
                    puk,
                    pairing_password,
                } => commands::init_command(transport, pin, puk, pairing_password)?,
                Commands::Pair {
                    pairing_password,
                    output,
                } => commands::pair_command(transport, pairing_password, output.as_ref())?,
                Commands::OpenSecureChannel { file, key, index } => {
                    commands::open_secure_channel_command(transport, file.as_ref(), key.as_ref(), *index)?
                }
                Commands::VerifyPin {
                    pin,
                    pairing_key,
                    index,
                    file,
                } => {
                    commands::verify_pin_command(transport, pin, pairing_key.as_ref(), *index, file.as_ref())?
                }
                Commands::GenerateKey {
                    pin,
                    pairing_key,
                    index,
                    file,
                } => commands::generate_key_command(
                    transport,
                    pin.as_ref(),
                    pairing_key.as_ref(),
                    *index,
                    file.as_ref(),
                )?,
                Commands::Sign {
                    data,
                    path,
                    pin,
                    pairing_key,
                    index,
                    file,
                } => {
                    commands::sign_command(
                        transport,
                        data,
                        path.as_ref(),
                        pin.as_ref(),
                        pairing_key.as_ref(),
                        *index,
                        file.as_ref(),
                    )
                    .await?
                }
                Commands::ExportPairing { output } => commands::export_pairing_command(transport, output)?,
                Commands::ChangeCredentials {
                    credential_type,
                    new_value,
                    pin,
                    pairing,
                } => commands::change_credentials_command(
                    transport,
                    credential_type,
                    new_value,
                    pin.as_ref(),
                    pairing,
                )?,
                Commands::UnblockPin {
                    puk,
                    new_pin,
                    pairing,
                } => commands::unblock_pin_command(transport, puk, new_pin, pairing)?,
                Commands::SetPinlessPath { path, pin, pairing } => {
                    commands::set_pinless_path_command(transport, path, pin.as_ref(), pairing)?
                }
                Commands::RemoveKey { pin, pairing } => {
                    commands::remove_key_command(transport, pin.as_ref(), pairing)?
                }
                Commands::GetStatus => commands::get_status_command(transport)?,
            }
        }
    }

    Ok(())
}

fn setup_logging(verbose: bool) {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_ansi(true)
        .init();
}