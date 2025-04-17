//! Keycard application implementation
//!
//! This module provides the main Keycard application interface,
//! which encapsulates all the functionality for interacting with a Keycard.

use nexum_apdu_core::prelude::*;
use nexum_apdu_globalplatform::commands::select::SelectCommand;

use crate::commands::*;
use crate::constants::KEYCARD_AID;
use crate::secure_channel::KeycardSecureChannelExt;
use crate::types::Signature;
use crate::{ApplicationInfo, ApplicationStatus, Error, PairingInfo, Result};

/// Type for function that provides an input string (ie. PIN)
pub type InputRequestFn = Box<dyn Fn(&str) -> String + Send + Sync>;
/// Type for function that confirms operations
pub type ConfirmationFn = Box<dyn Fn(&str) -> bool + Send + Sync>;

/// Keycard application implementation
pub struct Keycard<E: Executor> {
    /// Command executor
    executor: E,
    /// Pairing information for secure channel
    pairing_info: Option<PairingInfo>,
    /// Card public key (required for secure channel)
    card_public_key: Option<k256::PublicKey>,
    /// Application info retrieved during selection
    application_info: Option<ApplicationInfo>,
    /// Callback for requesting input
    input_request_callback: InputRequestFn,
    /// Callback for confirming critical operations
    confirmation_callback: ConfirmationFn,
}

impl<E: Executor> Keycard<E> {
    /// Create a new Keycard instance with an executor
    ///
    /// This constructor automatically selects the Keycard application and fetches its information
    pub fn new(
        executor: E,
        input_request_callback: InputRequestFn,
        confirmation_callback: ConfirmationFn,
    ) -> Result<Self> {
        let mut keycard = Self {
            executor,
            pairing_info: None,
            card_public_key: None,
            application_info: None,
            input_request_callback,
            confirmation_callback,
        };

        // Automatically select the Keycard application to fetch information
        let app_info = keycard.select_keycard()?;
        keycard.application_info = Some(app_info);

        Ok(keycard)
    }

    /// Create a new Keycard instance with an executor and pairing info
    pub fn with_pairing(
        executor: E,
        pairing_info: PairingInfo,
        card_public_key: k256::PublicKey,
        input_request_callback: InputRequestFn,
        confirmation_callback: ConfirmationFn,
    ) -> Result<Self> {
        let mut keycard = Self {
            executor,
            pairing_info: Some(pairing_info),
            card_public_key: Some(card_public_key),
            application_info: None,
            input_request_callback,
            confirmation_callback,
        };

        // Automatically select the Keycard application to fetch information
        let app_info = keycard.select_keycard()?;
        keycard.application_info = Some(app_info);

        Ok(keycard)
    }

    /// Set the callback for requesting input
    pub fn with_input_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        self.input_request_callback = Box::new(callback);
        self
    }

    /// Set the callback for confirming critical operations
    pub fn with_confirmation_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.confirmation_callback = Box::new(callback);
        self
    }

    /// Get a reference to the executor
    pub fn executor(&self) -> &E {
        &self.executor
    }

    /// Get a mutable reference to the executor
    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Set or update the pairing info for this Keycard
    pub fn set_pairing_info(&mut self, pairing_info: PairingInfo) {
        self.pairing_info = Some(pairing_info);
    }

    /// Load pairing information from external source
    ///
    /// This method allows setting up the Keycard with pairing information that was previously saved.
    /// It returns an error if the card public key is not available, which is needed for secure channel.
    pub fn load_pairing(&mut self, pairing_info: PairingInfo) -> Result<()> {
        // Check if we have card public key (needed for secure channel)
        if self.card_public_key.is_none() {
            return Err(Error::Message(
                "Card public key is required to load pairing".to_string(),
            ));
        }

        // Store the pairing info
        self.pairing_info = Some(pairing_info);

        Ok(())
    }

    /// Get the pairing info for this Keycard
    pub fn pairing_info(&self) -> Option<&PairingInfo> {
        self.pairing_info.as_ref()
    }

    /// Select the Keycard application on the device using the default AID
    pub fn select_keycard(&mut self) -> Result<ApplicationInfo> {
        // Create a select command for Keycard using the default AID
        let cmd = SelectCommand::with_aid(KEYCARD_AID.to_vec());

        // Execute the command
        let select_response = self.executor.execute(&cmd)?;

        // Parse the response
        let parsed = ParsedSelectOk::try_from(select_response)?;

        // Extract and store the information
        match parsed {
            ParsedSelectOk::ApplicationInfo(info) => {
                // Store the application info
                self.application_info = Some(info.clone());

                // Extract and store the public key if available
                if let Some(pk) = info.public_key {
                    self.card_public_key = Some(pk);
                }

                Ok(info)
            }
            ParsedSelectOk::PreInitialized(maybe_key) => {
                if let Some(key) = maybe_key {
                    self.card_public_key = Some(key);
                }
                Err(Error::Message(
                    "Card is in pre-initialized state".to_string(),
                ))
            }
        }
    }

    /// Initialize the Keycard card (factory reset)
    /// IMPORTANT: This will erase all data on the card
    pub fn initialize(&mut self, confirm: bool) -> Result<()> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(
                "Initialize the card? This will erase all data and cannot be undone.",
            ) {
                return Err(Error::UserCancelled);
            }
        }

        // Check if we have the card's public key
        match self.card_public_key {
            Some(card_pubkey) => {
                // Create the initialization command
                let cmd = InitCommand::with_card_pubkey(card_pubkey);

                // Execute the command
                self.executor.execute(&cmd)?;

                // Clear out any existing pairing info since the card has been reset
                self.pairing_info = None;

                Ok(())
            }
            None => Err(Error::InvalidData(
                "Card public key is required for initialization",
            )),
        }
    }

    /// Request input using the input request callback
    fn request_input(&self, prompt: &str) -> String {
        (&self.input_request_callback)(prompt)
    }

    /// Confirm a critical operation using the confirmation callback if available
    fn confirm_operation(&self, operation_description: &str) -> bool {
        (&self.confirmation_callback)(operation_description)
    }
}

impl<E> Keycard<E>
where
    E: Executor + SecureChannelExecutor,
    E::Transport: crate::secure_channel::KeycardSecureChannelExt,
{
    /// Check if the secure channel is open
    pub fn is_secure_channel_open(&self) -> bool {
        self.executor.has_secure_channel()
    }

    /// Open the secure channel with the card
    pub fn open_secure_channel(&mut self) -> Result<()> {
        // Check if we have pairing info
        if self.pairing_info.is_none() {
            return Err(Error::Message(
                "No pairing information available".to_string(),
            ));
        }

        // Check if we have card public key
        if self.card_public_key.is_none() {
            return Err(Error::Message("No card public key available".to_string()));
        }

        // Get underlying transport to initialize session
        let transport = self.executor.transport_mut();

        // Initialize session with pairing info and card public key
        transport.initialize_session(
            self.card_public_key.as_ref().unwrap(),
            self.pairing_info.as_ref().unwrap(),
        )?;

        // Open the secure channel
        self.executor.open_secure_channel().map_err(Error::from)
    }

    /// Pair with the card
    pub fn pair(&mut self) -> Result<PairingInfo> {
        // Get the pairing password from the user
        let password = self.request_input("Enter pairing password");

        // Get underlying transport to perform pairing
        let transport = self.executor.transport_mut();

        // Perform pairing with updated method signature
        let pairing_info = transport.pair(&password)?;

        // Store the pairing info
        self.pairing_info = Some(pairing_info.clone());

        Ok(pairing_info)
    }

    /// Establish a secure session with the card
    ///
    /// This method provides a convenient way to perform all the steps needed to establish
    /// a secure session with the card: pairing, opening secure channel, and verifying PIN.
    /// If pairing info is already available, it will use that instead of pairing again.
    pub fn establish_session(&mut self, verify_pin: bool) -> Result<()> {
        // Check if we need to pair
        if self.pairing_info.is_none() {
            // Perform pairing
            self.pair()?;
        }

        // Open secure channel
        self.open_secure_channel()?;

        // Verify PIN if requested
        if verify_pin {
            self.verify_pin()?;
        }

        Ok(())
    }

    /// Verify the PIN to gain full access
    /// This requires a secure channel with PIN verification capability
    pub fn verify_pin(&mut self) -> Result<()> {
        // Get the PIN from the user
        let pin = self.request_input("Enter your PIN");

        // Check if secure channel is open first
        if !self.is_secure_channel_open() {
            return Err(Error::Message(
                "Secure channel must be open to verify PIN".to_string(),
            ));
        }

        // Get the transport and directly call its verify_pin method
        let transport = self.executor.transport_mut();

        // Call verify_pin on the transport which will handle both
        // command execution and security level update
        transport.verify_pin(&pin)?;

        Ok(())
    }

    /// Get the status of the Keycard application
    pub fn get_status(&mut self) -> Result<ApplicationStatus> {
        // Create the get status command
        let cmd = GetStatusCommand::application();

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Extract status from response
        match response {
            GetStatusOk::ApplicationStatus { status } => Ok(status),
            _ => Err(Error::Message("Unexpected response type".to_string())),
        }
    }

    /// Get the current key path from the Keycard
    pub fn get_key_path(&mut self) -> Result<coins_bip32::path::DerivationPath> {
        // Create the get status command for key path
        let cmd = GetStatusCommand::key_path();

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Extract path from response
        match response {
            GetStatusOk::KeyPathStatus { path } => Ok(path),
            _ => Err(Error::Message("Unexpected response type".to_string())),
        }
    }

    /// Generate a new key in the card
    pub fn generate_key(&mut self, confirm: bool) -> Result<[u8; 32]> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(
                "Generate a new keypair on the card? This will overwrite any existing key.",
            ) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the command
        let cmd = GenerateKeyCommand::create();

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Return the key UID from the response
        let GenerateKeyOk::Success { key_uid } = response;
        Ok(key_uid)
    }

    /// Sign data with the current key
    pub fn sign(&mut self, data: &[u8], key_path: KeyPath, confirm: bool) -> Result<Signature> {
        // Create description for confirmation
        let path_str = match &key_path {
            KeyPath::Current => "current key".to_string(),
            KeyPath::FromMaster(Some(path)) => format!("master key with path {:?}", path),
            KeyPath::FromMaster(None) => "master key".to_string(),
            KeyPath::FromParent(path) => format!("parent key with path {:?}", path),
            KeyPath::FromCurrent(path) => format!("current key with path {:?}", path),
        };

        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(&format!("Sign data using {}?", path_str)) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the sign command - requires a 32-byte hash
        if data.len() != 32 {
            return Err(Error::InvalidData("Data to sign must be exactly 32 bytes"));
        }

        let data_array: [u8; 32] = data
            .try_into()
            .map_err(|_| Error::InvalidData("Failed to convert data to 32-byte array"))?;

        // Create sign command
        let cmd = SignCommand::with(&data_array, &key_path, Some(DeriveMode::Temporary))?;

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Return the signature from the response
        let SignOk::Success { signature } = response;
        Ok(signature)
    }

    /// Change a credential (PIN, PUK, or pairing secret)
    pub fn change_credential(
        &mut self,
        credential_type: CredentialType,
        new_value: &str,
        confirm: bool,
    ) -> Result<()> {
        // Create a description for the confirmation
        let description = match credential_type {
            CredentialType::Pin => "Change the PIN?",
            CredentialType::Puk => "Change the PUK?",
            CredentialType::PairingSecret => "Change the pairing secret?",
        };

        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(description) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the change command based on credential type
        let cmd = match credential_type {
            CredentialType::Pin => ChangePinCommand::with_pin(new_value),
            CredentialType::Puk => ChangePinCommand::with_puk(new_value),
            CredentialType::PairingSecret => {
                ChangePinCommand::with_pairing_secret(new_value.as_bytes())
            }
        };

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        // If we're changing the pairing secret, clear the pairing info
        if credential_type == CredentialType::PairingSecret {
            self.pairing_info = None;
        }

        Ok(())
    }

    /// Unblock the PIN using the PUK
    pub fn unblock_pin(&mut self, puk: &str, new_pin: &str, confirm: bool) -> Result<()> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation("Unblock the PIN? This will set a new PIN using the PUK.") {
                return Err(Error::UserCancelled);
            }
        }

        // Create the unblock PIN command
        let cmd = UnblockPinCommand::with_puk_and_new_pin(puk, new_pin);

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        Ok(())
    }

    /// Remove the current key from the card
    pub fn remove_key(&mut self, confirm: bool) -> Result<()> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self
                .confirm_operation("Remove the current key from the card? This cannot be undone.")
            {
                return Err(Error::UserCancelled);
            }
        }

        // Create the remove key command
        let cmd = RemoveKeyCommand::remove();

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        Ok(())
    }

    /// Set the pinless path for the card
    pub fn set_pinless_path(
        &mut self,
        path: Option<&coins_bip32::path::DerivationPath>,
        confirm: bool,
    ) -> Result<()> {
        // Create description for confirmation
        let description = match path {
            Some(p) => format!("Set the pinless path to {:?}?", p),
            None => "Clear the pinless path?".to_string(),
        };

        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(&description) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the command
        let cmd = match path {
            Some(p) => SetPinlessPathCommand::with_path(p),
            None => {
                // Manually handle clearing the path by sending an empty path
                let empty_path = coins_bip32::path::DerivationPath::default();
                SetPinlessPathCommand::with_path(&empty_path)
            }
        };

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        Ok(())
    }

    /// Generate a mnemonic phrase of the specified length
    pub fn generate_mnemonic(
        &mut self,
        words: u8,
    ) -> Result<coins_bip39::Mnemonic<coins_bip39::English>> {
        // Create the generate mnemonic command
        let cmd = GenerateMnemonicCommand::with_words(words)?;

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Convert to mnemonic phrase
        response.to_phrase()
    }

    /// Identify the card by signing a challenge
    pub fn ident(&mut self, challenge: Option<&[u8; 32]>) -> Result<Signature> {
        // Create the ident command
        let cmd = match challenge {
            Some(c) => IdentCommand::with_challenge(c),
            None => IdentCommand::with_random_challenge(),
        };

        // Execute the command
        let response = self.executor.execute(&cmd)?;

        // Return the signature from the response
        let IdentOk::Success { signature } = response;
        Ok(signature)
    }

    /// Load a key into the card
    pub fn load_key(
        &mut self,
        public_key: Option<k256::PublicKey>,
        private_key: k256::SecretKey,
        confirm: bool,
    ) -> Result<[u8; 32]> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(
                "Load a new key into the card? This will overwrite any existing key.",
            ) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the load key command
        let cmd = LoadKeyCommand::load_keypair(public_key, private_key)?;

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Return the key UID from the response
        let LoadKeyOk::Success { key_uid } = response;
        Ok(key_uid)
    }

    /// Load an extended key into the card
    pub fn load_extended_key(
        &mut self,
        public_key: Option<k256::PublicKey>,
        private_key: k256::SecretKey,
        chain_code: [u8; 32],
        confirm: bool,
    ) -> Result<[u8; 32]> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(
                "Load an extended key into the card? This will overwrite any existing key.",
            ) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the load key command
        let cmd = LoadKeyCommand::load_extended_keypair(public_key, private_key, chain_code)?;

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Return the key UID from the response
        let LoadKeyOk::Success { key_uid } = response;
        Ok(key_uid)
    }

    /// Load a BIP39 seed into the card
    pub fn load_seed(&mut self, seed: &[u8; 64], confirm: bool) -> Result<[u8; 32]> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(
                "Load a BIP39 seed into the card? This will overwrite any existing key.",
            ) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the load key command
        let cmd = LoadKeyCommand::load_bip39_seed(seed);

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Return the key UID from the response
        let LoadKeyOk::Success { key_uid } = response;
        Ok(key_uid)
    }

    /// Delete a key path (alias for remove_key)
    pub fn delete_key(&mut self, confirm: bool) -> Result<()> {
        self.remove_key(confirm)
    }

    /// Unpair the card from a specific pairing index
    pub fn unpair(&mut self, index: u8, confirm: bool) -> Result<()> {
        // Confirm the operation if a confirmation function is provided
        if confirm {
            if !self.confirm_operation(&format!("Unpair slot {} from the card?", index)) {
                return Err(Error::UserCancelled);
            }
        }

        // Create the unpair command
        let cmd = UnpairCommand::with_index(index);

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        // If we unpaired our own slot, clear the pairing info
        if let Some(pairing_info) = &self.pairing_info {
            if pairing_info.index == index {
                self.pairing_info = None;
            }
        }

        Ok(())
    }

    /// Store data in the card
    pub fn store_data(&mut self, record: PersistentRecord, data: &[u8]) -> Result<()> {
        // Create the store data command
        let cmd = StoreDataCommand::put(record, data);

        // Execute the command
        self.executor.execute_secure(&cmd)?;

        Ok(())
    }

    /// Get data from the card
    pub fn get_data(&mut self, record: PersistentRecord) -> Result<Vec<u8>> {
        // Create the get data command
        let cmd = GetDataCommand::get(record);

        // Execute the command
        let response = self.executor.execute_secure(&cmd)?;

        // Extract data from the response
        let GetDataOk::Success { data } = response;
        Ok(data)
    }
}

/// Credential type for changing credentials
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialType {
    /// PIN (authentication credential)
    Pin,
    /// PUK (unblocking credential)
    Puk,
    /// Pairing secret (pairing credential)
    PairingSecret,
}
