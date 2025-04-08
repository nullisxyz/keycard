// use alloy_primitives::{PrimitiveSignature, hex};
// use clap::{ArgGroup, Parser, Subcommand};
// use nexum_apdu_core::CardExecutor;
// use nexum_apdu_transport_pcsc::{PcscConfig, PcscDeviceManager};
// use nexum_keycard::{
//     GenerateKeyCommand, GenerateKeyResponse, InitResponse, KEYCARD_AID, Keycard, PairingInfo,
//     Secrets, SelectSuccessResponse, SignCommand, SignResponse,
// };
// use std::io::{self, Write};
// use std::path::PathBuf;
// use tracing::{debug, error, info, warn};

// #[derive(Parser)]
// #[command(version, about = "Keycard CLI for managing and using Status Keycard")]
// struct Cli {
//     /// Optional reader name to use (will auto-detect if not specified)
//     #[arg(short, long)]
//     reader: Option<String>,

//     /// Trace level output
//     #[arg(short, long)]
//     verbose: bool,

//     #[command(subcommand)]
//     command: Commands,
// }

// #[derive(Subcommand)]
// enum Commands {
//     /// List available readers
//     List,

//     /// Select the Keycard application and show info
//     Select,

//     /// Initialize a Keycard with random secrets
//     Init {
//         /// Optional PIN (6 digits, default is random)
//         #[arg(long)]
//         pin: Option<String>,

//         /// Optional PUK (12 digits, default is random)
//         #[arg(long)]
//         puk: Option<String>,

//         /// Optional pairing password (default is random)
//         #[arg(long)]
//         pairing_password: Option<String>,
//     },

//     /// Pair with a Keycard
//     Pair {
//         /// Pairing password
//         #[arg(required = true)]
//         pairing_password: String,

//         /// Optional output file to save pairing info
//         #[arg(short, long)]
//         output: Option<PathBuf>,
//     },

//     /// Open a secure channel
//     OpenSecureChannel {
//         /// Path to file containing pairing data
//         #[arg(long, group = "pairing")]
//         file: Option<PathBuf>,

//         /// Pairing key in hex (must be used with --index)
//         #[arg(long, requires = "index", group = "pairing")]
//         key: Option<String>,

//         /// Pairing index (must be used with --key)
//         #[arg(long, requires = "key")]
//         index: Option<u8>,
//     },

//     /// Verify PIN
//     VerifyPin {
//         /// PIN code
//         #[arg(required = true)]
//         pin: String,

//         /// Pairing key in hex (needed if secure channel not already open)
//         #[arg(long, requires = "index", group = "pairing")]
//         pairing_key: Option<String>,

//         /// Pairing index (needed if secure channel not already open)
//         #[arg(long, requires = "pairing_key")]
//         index: Option<u8>,

//         /// Path to file containing pairing data
//         #[arg(long, group = "pairing")]
//         file: Option<PathBuf>,
//     },

//     /// Generate a new key pair on the card
//     GenerateKey {
//         /// PIN code (needed if not already verified)
//         #[arg(long)]
//         pin: Option<String>,

//         /// Pairing key in hex (needed if secure channel not already open)
//         #[arg(long, requires = "index", group = "pairing")]
//         pairing_key: Option<String>,

//         /// Pairing index (needed if secure channel not already open)
//         #[arg(long, requires = "pairing_key")]
//         index: Option<u8>,

//         /// Path to file containing pairing data
//         #[arg(long, group = "pairing")]
//         file: Option<PathBuf>,
//     },

//     /// Sign data with the current key
//     Sign {
//         /// Data to sign, as a hex string
//         #[arg(required = true)]
//         data: String,

//         /// Optional key derivation path
//         #[arg(long)]
//         path: Option<String>,

//         /// PIN code (needed if not already verified)
//         #[arg(long)]
//         pin: Option<String>,

//         /// Pairing key in hex (needed if secure channel not already open)
//         #[arg(long, requires = "index", group = "pairing")]
//         pairing_key: Option<String>,

//         /// Pairing index (needed if secure channel not already open)
//         #[arg(long, requires = "pairing_key")]
//         index: Option<u8>,

//         /// Path to file containing pairing data
//         #[arg(long, group = "pairing")]
//         file: Option<PathBuf>,
//     },

//     /// Export pairing info to a file
//     ExportPairing {
//         /// Output file path
//         #[arg(short, long, required = true)]
//         output: PathBuf,
//     },
// }

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // Parse command line arguments
//     let cli = Cli::parse();

//     tracing_subscriber::fmt()
//         .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
//         .with_ansi(true)
//         .init();

//     // Create a PC/SC device manager
//     let manager = PcscDeviceManager::new()?;

//     // Handle list command
//     if let Commands::List = cli.command {
//         list_readers(&manager)?;
//         return Ok(());
//     }

//     // Find appropriate reader
//     let reader = match &cli.reader {
//         Some(reader_name) => {
//             let readers = manager.list_readers()?;
//             readers
//                 .iter()
//                 .find(|r| r.name() == reader_name)
//                 .ok_or_else(|| format!("Reader '{}' not found", reader_name))?
//                 .clone()
//         }
//         None => find_reader_with_card(&manager)?,
//     };

//     info!("Using reader: {}", reader.name());

//     // Connect to the reader
//     let config = PcscConfig::default();
//     let transport = manager.open_reader_with_config(reader.name(), config)?;
//     let executor = CardExecutor::new(transport);

//     // Create Keycard instance
//     let mut keycard = Keycard::new(executor);

//     match cli.command {
//         Commands::List => {
//             // Already handled above
//             unreachable!()
//         }
//         Commands::Select => {
//             select_and_display_info(&mut keycard)?;
//         }
//         Commands::Init {
//             pin,
//             puk,
//             pairing_password,
//         } => {
//             initialize_card(&mut keycard, pin, puk, pairing_password)?;
//         }
//         Commands::Pair {
//             pairing_password,
//             output,
//         } => {
//             pair_with_card(&mut keycard, &pairing_password, output.as_ref())?;
//         }
//         Commands::OpenSecureChannel { key, index, file } => {
//             let response = select_and_display_info(&mut keycard)?;

//             // Set pairing info - either from file or from key and index
//             if let Some(file_path) = file {
//                 // Load pairing info from file
//                 let pairing_info = load_pairing_from_file(&file_path)?;
//                 keycard.set_pairing_info(pairing_info);
//             } else if let (Some(key_hex), Some(idx)) = (key, index) {
//                 // Use provided key and index
//                 let pairing_key = hex::decode(key_hex.trim_start_matches("0x"))?;
//                 let pairing_info = PairingInfo {
//                     key: pairing_key,
//                     index: idx as usize,
//                 };
//                 keycard.set_pairing_info(pairing_info);
//             }

//             open_secure_channel(&mut keycard, &response)?;
//         }
//         Commands::VerifyPin {
//             pin,
//             pairing_key,
//             index,
//             file,
//         } => {
//             let response = select_and_display_info(&mut keycard)?;

//             if !keycard.is_secure_channel_open() {
//                 // Set pairing info if needed
//                 if let Some(file_path) = file {
//                     let pairing_info = load_pairing_from_file(&file_path)?;
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else if let (Some(key_hex), Some(idx)) = (pairing_key, index) {
//                     let pairing_key = hex::decode(key_hex.trim_start_matches("0x"))?;
//                     let pairing_info = PairingInfo {
//                         key: pairing_key,
//                         index: idx as usize,
//                     };
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else {
//                     return Err(
//                         "Secure channel not open. Please provide pairing key and index, or a file."
//                             .into(),
//                     );
//                 }
//             }

//             verify_pin(&mut keycard, &pin)?;
//         }
//         Commands::GenerateKey {
//             pin,
//             pairing_key,
//             index,
//             file,
//         } => {
//             let response = select_and_display_info(&mut keycard)?;

//             // Ensure secure channel is open
//             if !keycard.is_secure_channel_open() {
//                 // Set pairing info if needed
//                 if let Some(file_path) = file {
//                     let pairing_info = load_pairing_from_file(&file_path)?;
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else if let (Some(key_hex), Some(idx)) = (pairing_key, index) {
//                     let pairing_key = hex::decode(key_hex.trim_start_matches("0x"))?;
//                     let pairing_info = PairingInfo {
//                         key: pairing_key,
//                         index: idx as usize,
//                     };
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else {
//                     return Err(
//                         "Secure channel not open. Please provide pairing key and index, or a file."
//                             .into(),
//                     );
//                 }
//             }

//             // Ensure PIN is verified
//             if !keycard.is_pin_verified() {
//                 let pin_to_use = match pin {
//                     Some(p) => p,
//                     None => prompt_for_pin()?,
//                 };
//                 verify_pin(&mut keycard, &pin_to_use)?;
//             }

//             generate_key(&mut keycard)?;
//         }
//         Commands::Sign {
//             data,
//             path,
//             pin,
//             pairing_key,
//             index,
//             file,
//         } => {
//             let response = select_and_display_info(&mut keycard)?;

//             // Ensure secure channel is open
//             if !keycard.is_secure_channel_open() {
//                 // Set pairing info if needed
//                 if let Some(file_path) = file {
//                     let pairing_info = load_pairing_from_file(&file_path)?;
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else if let (Some(key_hex), Some(idx)) = (pairing_key, index) {
//                     let pairing_key = hex::decode(key_hex.trim_start_matches("0x"))?;
//                     let pairing_info = PairingInfo {
//                         key: pairing_key,
//                         index: idx as usize,
//                     };
//                     keycard.set_pairing_info(pairing_info);
//                     open_secure_channel(&mut keycard, &response)?;
//                 } else {
//                     return Err(
//                         "Secure channel not open. Please provide pairing key and index, or a file."
//                             .into(),
//                     );
//                 }
//             }

//             // Ensure PIN is verified
//             if !keycard.is_pin_verified() {
//                 let pin_to_use = match pin {
//                     Some(p) => p,
//                     None => prompt_for_pin()?,
//                 };
//                 verify_pin(&mut keycard, &pin_to_use)?;
//             }

//             sign_data(&mut keycard, &data, path.as_deref())?;
//         }
//         Commands::ExportPairing { output } => {
//             select_and_display_info(&mut keycard)?;

//             if let Some(pairing_info) = keycard.pairing_info() {
//                 save_pairing_to_file(pairing_info, &output)?;
//                 println!("Pairing information exported to: {}", output.display());
//             } else {
//                 return Err(
//                     "No pairing information available. Please pair with the card first.".into(),
//                 );
//             }
//         }
//     }

//     Ok(())
// }

// /// List all available readers
// fn list_readers(manager: &PcscDeviceManager) -> Result<(), Box<dyn std::error::Error>> {
//     let readers = manager.list_readers()?;

//     if readers.is_empty() {
//         println!("No readers found!");
//         return Ok(());
//     }

//     println!("Available readers:");
//     for (i, reader) in readers.iter().enumerate() {
//         let status = if reader.has_card() {
//             "card present"
//         } else {
//             "no card"
//         };
//         println!("{}. {} ({})", i + 1, reader.name(), status);
//     }

//     Ok(())
// }

// /// Find a reader with a card inserted
// fn find_reader_with_card(
//     manager: &PcscDeviceManager,
// ) -> Result<nexum_apdu_transport_pcsc::PcscReader, Box<dyn std::error::Error>> {
//     let readers = manager.list_readers()?;

//     if readers.is_empty() {
//         return Err("No readers found!".into());
//     }

//     // Find a reader with a card
//     let reader = readers
//         .iter()
//         .find(|r| r.has_card())
//         .ok_or("No card found in any reader!")?;

//     Ok(reader.clone())
// }

// /// Select card application and display info
// fn select_and_display_info(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
// ) -> Result<SelectSuccessResponse, Box<dyn std::error::Error>> {
//     info!("Selecting Keycard application...");
//     let select_response = keycard.select_keycard()?;

//     // Convert to SelectSuccessResponse
//     let success_response = SelectSuccessResponse::try_from(select_response)?;
//     println!("Keycard applet selected successfully.");
//     println!("{}", success_response);

//     Ok(success_response)
// }

// /// Initialize the card with new secrets
// fn initialize_card(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
//     pin: Option<String>,
//     puk: Option<String>,
//     pairing_password: Option<String>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let select_response = select_and_display_info(keycard)?;

//     // Check if card is in pre-initialized state
//     if let SelectSuccessResponse::PreInitialized(_) = select_response {
//         // Create secrets based on provided values or generate them
//         let secrets = if pin.is_some() || puk.is_some() || pairing_password.is_some() {
//             let pin = pin.unwrap_or_else(|| "123456".to_string());
//             let puk = puk.unwrap_or_else(|| "123456789012".to_string());
//             let pairing_password =
//                 pairing_password.unwrap_or_else(|| "KeycardDefaultPairing".to_string());

//             Secrets::new(&pin, &puk, &pairing_password)
//         } else {
//             Secrets::generate()
//         };

//         // Initialize the card
//         match keycard.init(select_response, &secrets) {
//             Ok(InitResponse::Success) => {
//                 println!("🎉 Keycard initialized successfully!");
//                 println!("Secrets (SAVE THESE!):");
//                 println!("  PIN: {}", secrets.pin());
//                 println!("  PUK: {}", secrets.puk());
//                 println!("  Pairing password: {}", secrets.pairing_pass());
//                 Ok(())
//             }
//             Ok(InitResponse::AlreadyInitialized) => {
//                 println!("Keycard is already initialized.");
//                 Ok(())
//             }
//             Ok(InitResponse::InvalidData) => Err("Invalid data received from Keycard.".into()),
//             Ok(InitResponse::OtherError { sw1, sw2 }) => Err(format!(
//                 "Error during initialization: SW1={:02X}, SW2={:02X}",
//                 sw1, sw2
//             )
//             .into()),
//             Err(e) => Err(format!("Failed to initialize Keycard: {:?}", e).into()),
//         }
//     } else {
//         println!("Card is already initialized.");
//         Ok(())
//     }
// }

// /// Pair with the card using the provided pairing password
// fn pair_with_card(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
//     pairing_password: &str,
//     output_file: Option<&PathBuf>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     select_and_display_info(keycard)?;

//     match keycard.pair(pairing_password) {
//         Ok(response) => {
//             println!("🔑 Pairing successful!");
//             if let Some(pairing_info) = keycard.pairing_info() {
//                 println!("\nPairing Information (SAVE THIS):");
//                 println!("  Pairing key: {}", hex::encode(&pairing_info.key));
//                 println!("  Pairing index: {}", pairing_info.index);
//                 println!(
//                     "\nYou can use these values with --key and --index options for future operations"
//                 );

//                 // Save to file if an output file was specified
//                 if let Some(path) = output_file {
//                     save_pairing_to_file(pairing_info, path)?;
//                     println!("Pairing information saved to: {}", path.display());
//                 }
//             }
//             Ok(())
//         }
//         Err(e) => Err(format!("Failed to pair with Keycard: {:?}", e).into()),
//     }
// }

// /// Open a secure channel with the card
// fn open_secure_channel(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
//     select_response: &SelectSuccessResponse,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     if keycard.pairing_info().is_none() {
//         return Err("You need to pair with the card first.".into());
//     }

//     match keycard.open_secure_channel(select_response) {
//         Ok(_) => {
//             println!("🔒 Secure channel opened successfully!");
//             Ok(())
//         }
//         Err(e) => Err(format!("Failed to open secure channel: {:?}", e).into()),
//     }
// }

// /// Verify PIN
// fn verify_pin(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
//     pin: &str,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     match keycard.verify_pin(pin) {
//         Ok(_) => {
//             println!("✅ PIN verified successfully!");
//             Ok(())
//         }
//         Err(e) => Err(format!("PIN verification failed: {:?}", e).into()),
//     }
// }

// /// Prompt for PIN
// fn prompt_for_pin() -> Result<String, Box<dyn std::error::Error>> {
//     print!("Enter PIN: ");
//     io::stdout().flush()?;
//     let mut pin = String::new();
//     io::stdin().read_line(&mut pin)?;
//     Ok(pin.trim().to_string())
// }

// /// Generate a new key pair on the card
// fn generate_key(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     let cmd = GenerateKeyCommand::create();

//     match keycard.execute_secure::<GenerateKeyCommand, GenerateKeyResponse>(&cmd) {
//         Ok(response) => {
//             println!("🔑 Key generated successfully!");
//             println!("Public key: {:#?}", response);
//             // println!("Public key: {}", hex::encode(&response.public_key));
//             Ok(())
//         }
//         Err(e) => Err(format!("Failed to generate key: {:?}", e).into()),
//     }
// }

// /// Sign data with the current key
// fn sign_data(
//     keycard: &mut Keycard<CardExecutor<nexum_apdu_transport_pcsc::PcscTransport>>,
//     data_hex: &str,
//     path: Option<&str>,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     // Convert hex string to bytes
//     let data = hex::decode(data_hex.trim_start_matches("0x"))?;

//     let cmd = match path {
//         Some(derivation_path) => {
//             SignCommand::with_path(&data.try_into().unwrap(), derivation_path, true)?
//         }
//         None => SignCommand::with_current_key(&data.try_into().unwrap())?,
//     };

//     match keycard.execute_secure::<SignCommand, SignResponse>(&cmd) {
//         Ok(signature) => {
//             println!("✍️  Data signed successfully!");
//             println!("Signature:");
//             if let SignResponse::Success { signature } = signature {
//                 // let signature = PrimitiveSignature::from_raw(signature.as_ref()).unwrap();
//                 println!("Signature: {:#?}", signature);
//             }
//             Ok(())
//         }
//         Err(e) => Err(format!("Failed to sign data: {:?}", e).into()),
//     }
// }

// /// Save pairing information to a file
// fn save_pairing_to_file(
//     pairing_info: &PairingInfo,
//     path: &PathBuf,
// ) -> Result<(), Box<dyn std::error::Error>> {
//     use std::fs::File;
//     use std::io::Write;

//     let mut file = File::create(path)?;

//     // Format: index,key_hex
//     let content = format!("{},{}", pairing_info.index, hex::encode(&pairing_info.key));
//     file.write_all(content.as_bytes())?;

//     Ok(())
// }

// /// Load pairing information from a file
// fn load_pairing_from_file(path: &PathBuf) -> Result<PairingInfo, Box<dyn std::error::Error>> {
//     use std::fs::File;
//     use std::io::Read;

//     let mut file = File::open(path)?;
//     let mut content = String::new();
//     file.read_to_string(&mut content)?;

//     // Parse format: index,key_hex
//     let parts: Vec<&str> = content.trim().split(',').collect();
//     if parts.len() != 2 {
//         return Err(format!(
//             "Invalid pairing file format. Expected 'index,key_hex' but got: {}",
//             content
//         )
//         .into());
//     }

//     let index = parts[0].parse::<usize>()?;
//     let key = hex::decode(parts[1])?;

//     Ok(PairingInfo { key, index })
// }
