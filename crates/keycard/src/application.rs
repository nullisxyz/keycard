/// Keycard application implementation
///
/// This module provides the main Keycard application interface, which
/// encapsulates all the functionality for managing Keycards.
use nexum_apdu_core::prelude::{
    Executor, ResponseAwareExecutor, SecureChannelExecutor, SecurityLevel,
};
use nexum_apdu_globalplatform::{SelectCommand, SelectResponse};
use tracing::{debug, warn};

use crate::commands::init::{InitCommand, InitResponse};
use crate::error::{Error, Result};
use crate::secure_channel::{KeycardScp, create_secure_channel_provider};

use crate::types::PairingInfo;
use crate::{KEYCARD_AID, Secrets, SelectSuccessResponse, VerifyPinResponse, keycard_instance_aid};

/// Keycard card management application
#[allow(missing_debug_implementations)]
pub struct Keycard<E>
where
    E: Executor + ResponseAwareExecutor + SecureChannelExecutor,
{
    /// Card executor
    executor: E,
    /// Secure channel
    secure_channel: KeycardScp,
}

impl<E> Keycard<E>
where
    E: Executor + ResponseAwareExecutor + SecureChannelExecutor,
{
    /// Create a new Keycard instance
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            secure_channel: KeycardScp::new(),
        }
    }

    /// Select Keycard
    pub fn select_keycard(&mut self) -> Result<SelectResponse> {
        self.select_application(KEYCARD_AID)
    }

    /// Select the application by AID
    pub fn select_application(&mut self, aid: &[u8]) -> Result<SelectResponse> {
        // Create SELECT command
        debug!("Selecting application: {:?}", aid);
        let cmd = SelectCommand::with_aid(aid.to_vec());
        self.executor.execute(&cmd).map_err(Into::into)
    }

    /// Init the keycard
    pub fn init(
        &mut self,
        select_response: SelectSuccessResponse,
        secrets: &Secrets,
    ) -> Result<InitResponse> {
        // Create INIT command
        if let SelectSuccessResponse::PreInitialized(pre) = select_response {
            let cmd = InitCommand::with_card_pubkey_and_secrets(
                pre.ok_or(Error::SecureChannelNotSupported)?,
                secrets,
            )?;

            return self.executor.execute(&cmd).map_err(Into::into);
        }

        Err(Error::AlreadyInitialised)
    }

    /// Pair with the card
    pub fn pair(&mut self, pairing_pass: &str) -> Result<()> {
        self.secure_channel.pair(&mut self.executor, pairing_pass)
    }

    /// Open secure channel using current pairing information
    pub fn open_secure_channel(&mut self, select_response: &SelectSuccessResponse) -> Result<()> {
        // Get the card's public key
        let card_public_key = match select_response {
            SelectSuccessResponse::ApplicationInfo(info) => info
                .public_key
                .as_ref()
                .ok_or(Error::SecureChannelNotSupported)?,
            SelectSuccessResponse::PreInitialized(maybe_key) => {
                maybe_key.as_ref().ok_or(Error::SecureChannelNotSupported)?
            }
        };

        // Get pairing info from the secure channel
        let pairing_info = self
            .secure_channel
            .pairing_info()
            .ok_or(Error::SecureChannelNotInitialized)?
            .clone();

        // Create a secure channel provider
        let provider = create_secure_channel_provider(pairing_info, *card_public_key);

        // Open the secure channel through the executor
        self.executor.open_secure_channel(&provider)?;

        Ok(())
    }

    /// Verify PIN
    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        // Create the command
        let cmd = crate::commands::pin::VerifyPinCommand::with_pin(pin);

        // Execute the command (this will go through secure channel if open)
        let response = self.executor.execute(&cmd)?;

        match response {
            crate::commands::pin::VerifyPinResponse::Success => {
                // Update secure channel state to PIN verified
                self.secure_channel
                    .set_state(SecureChannelState::PinVerified);
                debug!("PIN verified successfully");
                Ok(())
            }
            crate::commands::pin::VerifyPinResponse::WrongPin { sw2 } => {
                let remaining_attempts = sw2 & 0x0F;
                warn!("Wrong PIN. Remaining attempts: {}", remaining_attempts);
                Err(Error::WrongPin(remaining_attempts))
            }
            crate::commands::pin::VerifyPinResponse::PinBlocked => {
                warn!("PIN is blocked");
                Err(Error::PinVerificationRequired)
            }
            crate::commands::pin::VerifyPinResponse::OtherError { sw1, sw2 } => {
                warn!(
                    "Unexpected error during PIN verification: {:02X}{:02X}",
                    sw1, sw2
                );
                Err(Error::Unknown)
            }
        }
    }

    /// Execute a command securely
    pub fn execute_secure<C, R>(&mut self, command: &C) -> nexum_apdu_core::Result<R>
    where
        C: nexum_apdu_core::ApduCommand,
        R: TryFrom<nexum_apdu_core::Bytes, Error = nexum_apdu_core::Error>,
    {
        let cmd_bytes = command.to_bytes();
        let response_bytes = self.executor.transmit(&cmd_bytes).map_err(Into::into)?;

        R::try_from(response_bytes)
    }

    /// Set pairing information
    pub fn set_pairing_info(&mut self, pairing_info: PairingInfo) {
        self.secure_channel.set_pairing_info(pairing_info);
    }

    /// Get current pairing info
    pub fn pairing_info(&self) -> Option<&PairingInfo> {
        self.secure_channel.pairing_info()
    }

    /// Check if a secure channel is open
    pub fn is_secure_channel_open(&self) -> bool {
        self.secure_channel.is_open()
    }

    /// Check if PIN is verified
    pub fn is_pin_verified(&self) -> bool {
        self.secure_channel
            .security_level()
            .satisfies(&SecurityLevel::authenticated_encrypted())
    }
}
