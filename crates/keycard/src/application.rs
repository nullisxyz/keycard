use std::ops::Deref;
use std::str::FromStr;

use alloy_primitives::hex::ToHexExt;
use coins_bip32::path::DerivationPath;
use k256::ecdsa::RecoveryId;
/// Keycard application implementation
///
/// This module provides the main Keycard application interface, which
/// encapsulates all the functionality for managing Keycards.
use nexum_apdu_core::prelude::*;

use nexum_apdu_core::response::Response;
use nexum_apdu_globalplatform::SelectCommand;
use tracing::debug;

use crate::commands::{
    select::ParsedSelectOk, ChangePinCommand, GenerateKeyCommand, GetStatusOk, InitCommand,
    KeyPath, SignCommand, UnblockPinCommand, VerifyPinCommand,
};
use crate::secure_channel::KeycardSCP;
use crate::{Error, Result};

use crate::types::{ApplicationInfo, PairingInfo};
use crate::{ApplicationStatus, GenerateKeyOk, InitOk, Secrets, SignOk, KEYCARD_AID};

/// Type alias for a secure channel transport
pub type SecureTransport<T> = KeycardSCP<T>;

/// Keycard card management application
#[derive(Debug)]
pub struct Keycard<T: CardTransport> {
    /// Card transport
    transport: T,
    /// Pairing information - optional to support unpaired states
    pairing_info: Option<PairingInfo>,
    /// Card public key - optional to support unpaired states
    card_public_key: Option<k256::PublicKey>,
    /// Application info from card selection
    application_info: Option<ApplicationInfo>,
}

// Base implementation for any transport
impl<T: CardTransport> Keycard<T> {
    /// Create a new Keycard instance
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            pairing_info: None,
            card_public_key: None,
            application_info: None,
        }
    }

    /// Create a new Keycard instance with existing pairing information
    pub fn with_pairing(
        transport: T,
        pairing_info: PairingInfo,
        card_public_key: k256::PublicKey,
    ) -> Self {
        Self {
            transport,
            pairing_info: Some(pairing_info),
            card_public_key: Some(card_public_key),
            application_info: None,
        }
    }

    /// Get access to the transport
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Get mutable access to the transport
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Set or update pairing information
    pub fn set_pairing_info(&mut self, pairing_info: PairingInfo) {
        self.pairing_info = Some(pairing_info);
    }

    /// Get current pairing information
    pub fn pairing_info(&self) -> Option<&PairingInfo> {
        self.pairing_info.as_ref()
    }

    /// Select Keycard
    pub fn select_keycard(&mut self) -> crate::Result<ParsedSelectOk> {
        self.select_application(KEYCARD_AID)
    }

    /// Select the application by AID
    pub fn select_application(&mut self, aid: &[u8]) -> crate::Result<ParsedSelectOk> {
        // Create SELECT command
        debug!("Selecting application: {:?}", aid);
        let cmd = SelectCommand::with_aid(aid.to_vec());

        // Send the command through the transport directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse the response manually
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse response bytes")))?;

        // Parse with SelectCommand and then convert to our custom response type
        let select_ok = SelectCommand::parse_response(response).map_err(Error::from)?;
        let app_select_response = ParsedSelectOk::try_from(select_ok)
            .map_err(|_| Error::InvalidData("Unable to parse response"))?;

        if let ParsedSelectOk::ApplicationInfo(application_info) = &app_select_response {
            self.application_info = Some(application_info.clone());
            if let Some(public_key) = application_info.public_key {
                self.card_public_key = Some(public_key);
            }
        }

        Ok(app_select_response)
    }

    /// Initialize the keycard
    pub fn initialize(&mut self, secrets: &Secrets) -> Result<InitOk> {
        // First select the card to get into proper state
        let select_response = self.select_keycard()?;

        // Initialize the card
        self.init(select_response, secrets)
    }

    /// Init the keycard (internal implementation)
    fn init(&mut self, select_response: ParsedSelectOk, secrets: &Secrets) -> Result<InitOk> {
        // Create INIT command
        match select_response {
            ParsedSelectOk::PreInitialized(pre) => {
                let card_pubkey = pre.ok_or(Error::SecureChannelNotSupported)?;

                let cmd = InitCommand::with_card_pubkey_and_secrets(card_pubkey, secrets);

                // Send the command through the transport directly
                let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

                // Parse the response
                let response = Response::from_bytes(&response_bytes)
                    .map_err(|e| Error::from(e.with_context("Failed to parse INIT response")))?;

                // Parse the initialization response
                InitCommand::parse_response(response).map_err(Error::from)
            }
            _ => Err(Error::AlreadyInitialized),
        }
    }

    /// Pair with the card
    pub fn pair<F>(&mut self, pairing_pass: F) -> crate::Result<PairingInfo>
    where
        F: FnOnce() -> String,
    {
        // Use pair method directly with our transport
        let pairing_info = KeycardSCP::<T>::pair(&mut self.transport, pairing_pass)?;

        // Store pairing info for future secure channel establishment
        self.pairing_info = Some(pairing_info.clone());

        Ok(pairing_info)
    }

    /// Create a secure Keycard that uses a KeycardSCP transport
    pub fn into_secure_channel(self) -> Result<Keycard<SecureTransport<T>>>
    where
        T: Clone,
    {
        if self.pairing_info.is_none() {
            return Err(Error::PairingRequired);
        }

        if self.card_public_key.is_none() {
            return Err(Error::InvalidData(
                "Card public key is required for secure channel",
            ));
        }

        // Get the card public key and pairing info
        let card_public_key = self.card_public_key.unwrap();
        let pairing_info = self.pairing_info.unwrap();

        // Initialize a secure channel with the transport and pairing info
        let secure_transport =
            SecureTransport::initialize(self.transport, card_public_key, pairing_info.clone())?;

        // Create the new keycard
        let mut secure_keycard = Keycard::new(secure_transport);

        // Copy over state
        secure_keycard.pairing_info = Some(pairing_info);
        secure_keycard.card_public_key = Some(card_public_key);
        secure_keycard.application_info = self.application_info;

        Ok(secure_keycard)
    }
}

/// Implementation for KeycardSCP transport
impl<T: CardTransport> Keycard<SecureTransport<T>> {
    /// Check if secure channel is open
    pub fn is_secure_channel_open(&self) -> bool {
        self.transport.is_established()
    }

    /// Open a secure channel with the card
    pub fn open_secure_channel(&mut self) -> Result<()> {
        // The secure channel should already be initialized
        // Just call the open method on the transport
        self.transport.open().map_err(Error::from)
    }

    /// Check if PIN has been verified in this session
    pub fn is_pin_verified(&self) -> bool {
        // This would need to track PIN verification state
        // For now, we assume PIN is not verified by default
        false
    }

    /// Verify PIN
    pub fn verify_pin<F>(&mut self, pin: F) -> crate::Result<()>
    where
        F: FnOnce() -> String,
    {
        // Create the command
        let pin_str = pin();
        let cmd = VerifyPinCommand::with_pin(&pin_str);

        // Send command directly through the transport
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse verify PIN response")))?;

        // Handle the response
        VerifyPinCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Get application status
    pub fn get_status(&mut self) -> crate::Result<ApplicationStatus> {
        // Use typed GetStatusCommand instead of raw transmit
        use crate::commands::get_status::GetStatusCommand;

        let cmd = GetStatusCommand::application();

        // Send command directly through the transport
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse get status response")))?;

        // Handle the response
        let result = GetStatusCommand::parse_response(response).map_err(Error::from)?;

        match result {
            GetStatusOk::ApplicationStatus { status } => Ok(status),
            // This branch should be unreachable if we requested application status,
            // but using a proper error instead of unreachable! improves robustness
            _ => Err(Error::InvalidData(
                "Unexpected response type from get status",
            )),
        }
    }

    /// Get the current key path from the card
    pub fn get_key_path(&mut self) -> crate::Result<DerivationPath> {
        use crate::commands::get_status::GetStatusCommand;

        let cmd = GetStatusCommand::key_path();

        // Send command directly through the transport
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse get key path response")))?;

        // Handle the response
        let result = GetStatusCommand::parse_response(response).map_err(Error::from)?;

        match result {
            GetStatusOk::KeyPathStatus { path } => Ok(path),
            // Return error if unexpected response type is received
            _ => Err(Error::InvalidData(
                "Unexpected response type from get key path",
            )),
        }
    }

    /// Generate a new key on the card
    pub fn generate_key(&mut self) -> crate::Result<[u8; 32]> {
        // Create the command
        let cmd = GenerateKeyCommand::create();

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse generate key response")))?;

        // Handle the response
        let result = GenerateKeyCommand::parse_response(response).map_err(Error::from)?;

        // Pattern match to extract the key_uid and ensure type safety
        match result {
            GenerateKeyOk::Success { key_uid } => Ok(key_uid),
            // This branch should be unreachable if the command succeeded, but this ensures type safety
            // and makes the code more resilient to future changes
            #[allow(unreachable_patterns)]
            _ => Err(Error::InvalidData(
                "Unexpected response type from generate key",
            )),
        }
    }

    /// Sign data with the key on the card
    pub fn sign(
        &mut self,
        data: &[u8; 32],
        path: &KeyPath,
    ) -> crate::Result<alloy_primitives::Signature> {
        // Create sign command with path and data
        let cmd = SignCommand::with(data, path, None)?;

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse sign response")))?;

        // Handle the response
        let result = SignCommand::parse_response(response).map_err(Error::from)?;

        // Extract the signature using pattern matching for type safety
        let signature = match result {
            SignOk::Success { signature } => signature,
            // This branch should be unreachable if the command succeeded, but this ensures type safety
            #[allow(unreachable_patterns)]
            _ => return Err(Error::InvalidData("Unexpected response type from sign")),
        };

        let recovery_id = RecoveryId::trial_recovery_from_prehash(
            &signature.public_key.into(),
            data,
            signature.signature.deref(),
        )?;

        let address = alloy_primitives::Address::from_public_key(&signature.public_key.into());
        let signature: alloy_primitives::Signature =
            (*signature.signature.deref(), recovery_id).into();

        println!("Recovery ID: {:?}", recovery_id);

        println!("Signing address: {:?}", address.encode_hex_with_prefix());
        println!(
            "Signature: {:?}",
            signature.as_bytes().encode_hex_with_prefix()
        );

        let recovered_address = signature.recover_address_from_prehash(data.into()).unwrap();
        println!(
            "Recovered address: {:?}",
            recovered_address.encode_hex_with_prefix()
        );
        Ok(signature)
    }

    /// Change credential (PIN, PUK, or pairing secret)
    pub fn change_credential<S>(
        &mut self,
        credential_type: CredentialType,
        new_value: S,
    ) -> crate::Result<()>
    where
        S: AsRef<str>,
    {
        match credential_type {
            CredentialType::Pin => self.change_pin(new_value.as_ref()),
            CredentialType::Puk => self.change_puk(new_value.as_ref()),
            CredentialType::PairingSecret => {
                self.change_pairing_secret(new_value.as_ref().as_bytes())
            }
        }
    }

    /// Unblock PIN using PUK
    pub fn unblock_pin<S1, S2>(&mut self, puk: S1, new_pin: S2) -> crate::Result<()>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let puk_str = puk.as_ref();
        let pin_str = new_pin.as_ref();
        let cmd = UnblockPinCommand::with_puk_and_new_pin(puk_str, pin_str);

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse unblock PIN response")))?;

        // Handle the response
        UnblockPinCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Remove the current key from the card
    pub fn remove_key(&mut self) -> crate::Result<()> {
        use crate::commands::RemoveKeyCommand;

        let cmd = RemoveKeyCommand::remove();

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse remove key response")))?;

        // Handle the response
        RemoveKeyCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Change PIN
    pub fn change_pin(&mut self, new_pin: &str) -> crate::Result<()> {
        let cmd = ChangePinCommand::with_pin(new_pin);

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse change PIN response")))?;

        // Handle the response
        ChangePinCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Change PUK
    pub fn change_puk(&mut self, new_puk: &str) -> crate::Result<()> {
        let cmd = ChangePinCommand::with_puk(new_puk);

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes)
            .map_err(|e| Error::from(e.with_context("Failed to parse change PUK response")))?;

        // Handle the response
        ChangePinCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Change pairing secret
    pub fn change_pairing_secret(&mut self, new_secret: &[u8]) -> crate::Result<()> {
        let cmd = ChangePinCommand::with_pairing_secret(new_secret);

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes).map_err(|e| {
            Error::from(e.with_context("Failed to parse change pairing secret response"))
        })?;

        // Handle the response
        ChangePinCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }

    /// Set a PIN-less path for signature operations
    pub fn set_pinless_path(&mut self, path: &str) -> crate::Result<()> {
        use crate::commands::SetPinlessPathCommand;

        // Parse the path string into a DerivationPath
        let derivation_path = DerivationPath::from_str(path)?;

        let cmd = SetPinlessPathCommand::with_path(&derivation_path);

        // Send command directly
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse response
        let response = Response::from_bytes(&response_bytes).map_err(|e| {
            Error::from(e.with_context("Failed to parse set pinless path response"))
        })?;

        // Handle the response
        SetPinlessPathCommand::parse_response(response).map_err(Error::from)?;

        Ok(())
    }
}

/// Enum for credential types that can be changed
pub enum CredentialType {
    /// PIN code
    Pin,
    /// PUK code
    Puk,
    /// Pairing secret
    PairingSecret,
}
