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
use nexum_apdu_core::error::Error as CoreError;
use nexum_apdu_core::executor::SecureChannelExecutor;
use nexum_apdu_core::executor::response_aware::ResponseAwareExecutor;
use nexum_apdu_globalplatform::SelectCommand;
use tracing::debug;

use crate::commands::{
    GenerateKeyCommand, GetStatusOk, InitCommand, KeyPath, SignCommand,
    VerifyPinCommand, ChangePinCommand, UnblockPinCommand,
};
use crate::error::{Error, Result};
use crate::secure_channel::KeycardSCP;

use crate::types::{ApplicationInfo, PairingInfo};
use crate::{
    ApplicationStatus, GenerateKeyOk, InitOk, KEYCARD_AID, ParsedSelectOk, Secrets, SignOk,
};

/// Keycard card management application
#[derive(Debug)]
pub struct Keycard<E>
where
    E: Executor + SecureChannelExecutor + ResponseAwareExecutor,
{
    /// Card executor
    executor: E,
    /// Pairing information - optional to support unpaired states
    pairing_info: Option<PairingInfo>,
    /// Card public key - optional to support unpaired states
    card_public_key: Option<k256::PublicKey>,
    /// Application info from card selection
    application_info: Option<ApplicationInfo>,
}

impl<E> Keycard<E>
where
    E: Executor + SecureChannelExecutor + ResponseAwareExecutor,
{
    /// Create a new Keycard instance
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            pairing_info: None,
            card_public_key: None,
            application_info: None,
        }
    }

    /// Create a new Keycard instance with existing pairing information
    pub fn with_pairing(
        executor: E,
        pairing_info: PairingInfo,
        card_public_key: k256::PublicKey,
    ) -> Self {
        Self {
            executor,
            pairing_info: Some(pairing_info),
            card_public_key: Some(card_public_key),
            application_info: None,
        }
    }

    /// Select Keycard
    pub fn select_keycard(&mut self) -> Result<ParsedSelectOk> {
        self.select_application(KEYCARD_AID)
    }

    /// Select the application by AID
    pub fn select_application(&mut self, aid: &[u8]) -> Result<ParsedSelectOk> {
        // Create SELECT command
        debug!("Selecting application: {:?}", aid);
        let cmd = SelectCommand::with_aid(aid.to_vec());
        
        // Execute the command
        let result = self.executor.execute(&cmd)?;

        // Convert to our custom response type
        let app_select_response = ParsedSelectOk::try_from(result)
            .map_err(|_| Error::Core(CoreError::ParseError("Unable to parse response")))?;
            
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

                Ok(self.executor.execute(&cmd)?)
            }
            _ => Err(Error::AlreadyInitialized),
        }
    }

    /// Pair with the card
    pub fn pair<F>(&mut self, pairing_pass: F) -> Result<PairingInfo>
    where
        F: FnOnce() -> String,
    {
        // Get the card transport from the executor
        let transport = self.executor.transport_mut();
        
        // Use pair method with explicit type parameters to resolve type issues
        let pairing_info = KeycardSCP::<E::Transport>::pair(transport, pairing_pass)
            .map_err(|e| Error::Core(e))?;

        // Store pairing info for future secure channel establishment
        self.pairing_info = Some(pairing_info.clone());
        
        Ok(pairing_info)
    }

    /// Get application status
    pub fn get_status(&mut self) -> Result<ApplicationStatus> {
        // Use typed GetStatusCommand instead of raw transmit
        use crate::commands::get_status::GetStatusCommand;

        let cmd = GetStatusCommand::application();
        let response = self.executor.execute(&cmd)?;

        match response {
            GetStatusOk::ApplicationStatus { status } => Ok(status),
            _ => unreachable!("Requested application status, should be unreachable"),
        }
    }

    /// Verify PIN
    pub fn verify_pin<F>(&mut self, pin: F) -> Result<()>
    where
        F: FnOnce() -> String,
    {
        // Create and execute the command
        let pin_str = pin();
        let cmd = VerifyPinCommand::with_pin(&pin_str);
        let _ = self.executor.execute(&cmd)?;

        Ok(())
    }

    /// Generate a new key on the card
    pub fn generate_key(&mut self) -> Result<[u8; 32]> {
        // Create the command
        let cmd = GenerateKeyCommand::create();

        // Execute it (security requirements handled automatically by executor)
        let response = self.executor.execute(&cmd)?;

        let GenerateKeyOk::Success { key_uid } = response;
        Ok(key_uid)
    }

    /// Sign data with the key on the card
    pub fn sign(&mut self, data: &[u8; 32], path: &KeyPath) -> Result<alloy_primitives::Signature> {
        // Create sign command with path and data
        let cmd = SignCommand::with(data, path, None)?;

        // Execute the command
        let response = self.executor.execute(&cmd)?;

        let SignOk::Success { signature } = response;

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

    /// Get the executor
    pub fn executor(&self) -> &E {
        &self.executor
    }

    /// Get mutable access to the executor
    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    /// Set or update pairing information
    pub fn set_pairing_info(&mut self, pairing_info: PairingInfo) {
        self.pairing_info = Some(pairing_info);
    }

    /// Get current pairing information
    pub fn pairing_info(&self) -> Option<&PairingInfo> {
        self.pairing_info.as_ref()
    }

    /// Change credential (PIN, PUK, or pairing secret)
    pub fn change_credential<S>(
        &mut self,
        credential_type: CredentialType,
        new_value: S,
    ) -> Result<()>
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
    pub fn unblock_pin<S1, S2>(&mut self, puk: S1, new_pin: S2) -> Result<()>
    where
        S1: AsRef<str>,
        S2: AsRef<str>,
    {
        let puk_str = puk.as_ref();
        let pin_str = new_pin.as_ref();
        let cmd = UnblockPinCommand::with_puk_and_new_pin(puk_str, pin_str);
        self.executor.execute(&cmd)?;
        Ok(())
    }

    /// Remove the current key from the card
    pub fn remove_key(&mut self) -> Result<()> {
        use crate::commands::RemoveKeyCommand;

        let cmd = RemoveKeyCommand::remove();
        self.executor.execute(&cmd)?;
        Ok(())
    }

    /// Change PIN
    pub fn change_pin(&mut self, new_pin: &str) -> Result<()> {
        let cmd = ChangePinCommand::with_pin(new_pin);
        self.executor.execute(&cmd)?;
        Ok(())
    }

    /// Change PUK
    pub fn change_puk(&mut self, new_puk: &str) -> Result<()> {
        let cmd = ChangePinCommand::with_puk(new_puk);
        self.executor.execute(&cmd)?;
        Ok(())
    }

    /// Change pairing secret
    pub fn change_pairing_secret(&mut self, new_secret: &[u8]) -> Result<()> {
        let cmd = ChangePinCommand::with_pairing_secret(new_secret);
        self.executor.execute(&cmd)?;
        Ok(())
    }

    /// Set a PIN-less path for signature operations
    pub fn set_pinless_path(&mut self, path: &str) -> Result<()> {
        use crate::commands::SetPinlessPathCommand;

        // Parse the path string into a DerivationPath
        let derivation_path = DerivationPath::from_str(path)?;

        let cmd = SetPinlessPathCommand::with_path(&derivation_path);
        self.executor.execute(&cmd)?;
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