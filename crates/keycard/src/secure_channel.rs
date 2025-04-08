use bytes::{Bytes, BytesMut};
use k256::PublicKey;
use nexum_apdu_core::prelude::SecurityLevel;
use nexum_apdu_core::processor::SecureProtocolError;
use nexum_apdu_core::processor::{CommandProcessor, error::ProcessorError, secure::SecureChannel};
use nexum_apdu_core::transport::CardTransport;
use nexum_apdu_core::{ApduCommand, ApduResponse, Command, Executor, Response};
use rand_v8::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, trace, warn};

use crate::crypto::{ApduMeta, Challenge, Cryptogram};
use crate::session::Session;
use crate::{
    Error,
    commands::mutually_authenticate::MutuallyAuthenticateCommand,
    commands::pair::PairCommand,
    crypto::{calculate_cryptogram, decrypt_data, encrypt_data, generate_pairing_token},
};
use crate::{PairOk, PairingInfo, VerifyPinCommand};

/// Represents a secure communication channel with a Keycard
#[derive(Clone)]
pub struct KeycardSCP {
    /// Session containing keys and state
    session: Session,
    /// Security level of the secure channel
    security_level: SecurityLevel,
}

impl fmt::Debug for KeycardSCP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycardSCP").finish()
    }
}

impl KeycardSCP {
    /// Create a new secure channel instance
    pub fn new(session: Session) -> Self {
        Self {
            session,
            security_level: SecurityLevel::encrypted(),
        }
    }

    /// Get the channel state
    pub const fn security_level(&self) -> &SecurityLevel {
        &self.security_level
    }

    /// Check if the secure channel is open
    pub fn is_open(&self) -> bool {
        self.security_level()
            .satisfies(&SecurityLevel::mac_protected())
    }

    /// Pair with the card using the provided pairing password
    pub fn pair<E, F>(executor: &mut E, pairing_pass: F) -> crate::Result<PairingInfo>
    where
        E: Executor,
        F: FnOnce() -> String,
    {
        debug!("Starting pairing process with pairing password");

        // Generate a random challenge
        let mut challenge = Challenge::default();
        thread_rng().fill_bytes(&mut challenge);

        // Create PAIR (first step) command
        let cmd = PairCommand::with_first_stage(&challenge);

        // Send the command
        let response = executor
            .execute(&cmd)
            .map_err(crate::Error::from)?
            .to_result()
            .map_err(nexum_apdu_core::Error::from)?;

        let (card_cryptogram, card_challenge) = match response {
            PairOk::Success { data } => {
                let card_cryptogram = Cryptogram::clone_from_slice(&data[..32]);
                let card_challenge = Challenge::clone_from_slice(&data[32..]);
                (card_cryptogram, card_challenge)
            }
        };

        // Verify the card cryptogram
        let shared_secret = generate_pairing_token(pairing_pass().as_str());
        if card_cryptogram != calculate_cryptogram(&card_challenge, &shared_secret) {
            return Err(crate::Error::SecureProtocol(SecureProtocolError::Protocol(
                "Card cryptogram verification failed",
            )));
        }

        // Calculate client cryptogram
        let client_cryptogram = calculate_cryptogram(&shared_secret, &card_challenge);

        // Create PAIR (final step) command
        let cmd = PairCommand::with_final_stage(&client_cryptogram.try_into().unwrap());

        // Send the command
        let response = executor
            .execute(&cmd)
            .map_err(crate::Error::from)?
            .to_result()
            .map_err(nexum_apdu_core::Error::from)?;

        let (index, key) = match response {
            PairOk::Success { data } => {
                let index = data[0];
                let key = {
                    let mut hasher = Sha256::new();
                    Digest::update(&mut hasher, &shared_secret);
                    Digest::update(&mut hasher, &data[1..]);
                    hasher.finalize()
                };
                (index, key)
            }
        };

        debug!("Pairing successful with index {}", index);

        Ok(PairingInfo { key, index })
    }

    pub fn verify_pin<E, F>(&mut self, executor: &mut E, pin: F) -> crate::Result<()>
    where
        E: Executor,
        F: FnOnce() -> String,
    {
        // Create the command
        let cmd = VerifyPinCommand::with_pin(pin().as_str());

        // Execute the command
        let _ = executor
            .execute(&cmd)?
            .to_result()
            .map_err(|e| Error::Pin(e))?;

        // At this point, it is guaranteed that the PIN was verified successfully.
        self.security_level = SecurityLevel::authenticated_encrypted();

        Ok(())
    }

    /// Perform mutual authentication to complete secure channel establishment
    fn mutually_authenticate(&mut self, transport: &mut dyn CardTransport) -> crate::Result<()> {
        // Generate a random challenge
        let mut challenge = Challenge::default();
        thread_rng().fill_bytes(&mut challenge);

        // Create the command
        let cmd = MutuallyAuthenticateCommand::with_challenge(&challenge);

        // Encrypt the command
        let encrypted_cmd = self.encrypt_command(cmd.to_command());

        // Send through transport
        let response_bytes = transport.transmit_raw(&encrypted_cmd.to_bytes())?;
        let response = nexum_apdu_core::Response::from_bytes(&response_bytes)?;

        if !response.is_success() || self.decrypt_response(response).is_err() {
            return Err(crate::Error::MutualAuthenticationFailed);
        }

        debug!("Mutual authentication successful");

        Ok(())
    }

    /// Encrypt APDU command data for the secure channel
    fn encrypt_command(&mut self, command: Command) -> Command {
        let payload = command.data().unwrap_or(&[]);

        // Encrypt the command data
        let mut data_to_encrypt = BytesMut::from(payload);
        let encrypted_data = encrypt_data(
            &mut data_to_encrypt,
            self.session.keys().enc(),
            &self.session.iv(),
        );

        // Prepare metadata for MAC calculation
        let mut meta = ApduMeta::default();
        meta[0] = command.class();
        meta[1] = command.instruction();
        meta[2] = command.p1();
        meta[3] = command.p2();
        meta[4] = (encrypted_data.len() + 16) as u8; // Add MAC size

        // Calculate the IV/MAC
        self.session.update_iv(&meta.into(), &encrypted_data);

        // Combine MAC and encrypted data
        let mut data = BytesMut::with_capacity(16 + encrypted_data.len());
        data.extend(self.session.iv());
        data.extend(encrypted_data);

        trace!(
            "Encrypted command: cla={:02X}, ins={:02X}, p1={:02X}, p2={:02X}, data_len={}",
            command.class(),
            command.instruction(),
            command.p1(),
            command.p2(),
            data.len()
        );

        command.with_data(data)
    }

    /// Decrypt APDU response data from the secure channel
    fn decrypt_response(&mut self, response: Response) -> Result<Vec<u8>, Error> {
        let response_data = response.payload().to_vec();

        // Need at least a MAC (16 bytes)
        if response_data.len() < 16 {
            warn!(
                "Response data too short for secure channel: {}",
                response_data.len()
            );
            return Err(Error::Response(
                nexum_apdu_core::response::error::ResponseError::BufferTooSmall,
            ));
        }

        // Split into MAC and encrypted data
        let (rmac, rdata) = response_data.split_at(16);
        let rdata = Bytes::from(rdata.to_vec());

        // Prepare metadata for MAC verification
        let mut metadata = ApduMeta::default();
        metadata[0] = response_data.len() as u8;

        // Decrypt the data
        let mut data_to_decrypt = BytesMut::from(&rdata[..]);
        let decrypted_data = decrypt_data(
            &mut data_to_decrypt,
            self.session.keys().enc(),
            self.session.iv(),
        )?;

        // Update IV for MAC verification
        self.session.update_iv(&metadata, &rdata);

        // Verify MAC
        if rmac != self.session.iv().as_slice() {
            warn!("MAC verification failed for secure channel response");
            return Err(Error::SecureProtocol(SecureProtocolError::Protocol(
                "Invalid response MAC",
            )));
        }

        trace!("Decrypted response: len={}", decrypted_data.len());

        Ok(decrypted_data.to_vec())
    }
}

impl CommandProcessor for KeycardSCP {
    fn do_process_command(
        &mut self,
        command: &Command,
        transport: &mut dyn CardTransport,
    ) -> Result<Response, ProcessorError> {
        if !self.is_open() {
            return Err(ProcessorError::session("Secure channel not established"));
        }

        trace!(command = ?command, "Processing command with Keycard secure channel");

        // Encrypt the command
        let encrypted_data = self.encrypt_command(command.clone());

        // Send the command
        let response_bytes = transport.transmit_raw(&encrypted_data.to_bytes())?;

        // Parse the response
        let response = Response::from_bytes(&response_bytes)?;

        // Decrypt the response if successful
        if response.is_success() {
            let decrypted_data = self
                .decrypt_response(response.clone())
                .map_err(|e| ProcessorError::Other(e.to_string()))?;

            // Create a new response with decrypted data
            let decrypted_response = Response::from_bytes(decrypted_data.as_ref())?;
            Ok(decrypted_response)
        } else {
            // For error responses, just return as is
            Ok(response)
        }
    }

    fn is_active(&self) -> bool {
        self.is_open()
    }
}

impl SecureChannel for KeycardSCP {
    fn is_established(&self) -> bool {
        self.is_open()
    }

    fn close(&mut self) -> nexum_apdu_core::Result<()> {
        warn!("Closure of secure channel not implemented for Keycard secure channel");
        Ok(())
    }

    fn reestablish(&mut self) -> nexum_apdu_core::Result<()> {
        warn!("Reestablish not implemented for Keycard secure channel");
        Err(ProcessorError::session(
            "Cannot reestablish Keycard secure channel - a new session must be created",
        )
        .into())
    }
}

/// Keycard secure channel provider
#[derive(Debug)]
pub struct KeycardSecureChannelProvider {
    /// Pairing information
    pairing_info: PairingInfo,
    /// Card's public key
    card_public_key: PublicKey,
}

impl KeycardSecureChannelProvider {
    /// Create a new secure channel provider
    pub const fn new(pairing_info: PairingInfo, card_public_key: PublicKey) -> Self {
        Self {
            pairing_info,
            card_public_key,
        }
    }
}

impl nexum_apdu_core::processor::secure::SecureChannelProvider for KeycardSecureChannelProvider {
    fn create_secure_channel(
        &self,
        transport: &mut dyn CardTransport,
    ) -> nexum_apdu_core::Result<Box<dyn CommandProcessor>> {
        // Create a new secure channel
        let mut secure_channel = KeycardSCP::new(
            Session::new(&self.card_public_key, &self.pairing_info, transport).map_err(|e| {
                nexum_apdu_core::Error::SecureProtocol(SecureProtocolError::Other(e.to_string()))
            })?,
        );

        secure_channel
            .mutually_authenticate(transport)
            .map_err(|e| {
                nexum_apdu_core::Error::SecureProtocol(SecureProtocolError::Other(e.to_string()))
            })?;

        Ok(Box::new(secure_channel))
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::KeycardScp;

    use super::*;
    use alloy_primitives::hex;
    use cipher::{Iv, Key};
    use nexum_apdu_core::Command;

    #[test]
    fn test_encrypt_command_and_update_iv() {
        // Set up the same keys and IV as in the Go test
        let enc_key =
            hex::decode("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
                .unwrap();
        let mac_key =
            hex::decode("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
                .unwrap();
        let iv = hex::decode("627E64358FA9BDCDAD4442BD8006E0A5").unwrap();

        // Create KeycardScp with the same state as in the Go test
        let session = Session::from_raw(
            Key::<KeycardScp>::from_slice(&enc_key),
            Key::<KeycardScp>::from_slice(&mac_key),
            Iv::<KeycardScp>::from_slice(&iv),
        );
        let mut scp = KeycardSCP::new(session);

        // Create the same command as in the Go test
        let data = hex::decode("D545A5E95963B6BCED86A6AE826D34C5E06AC64A1217EFFA1415A96674A82500")
            .unwrap();
        let command = Command::new_with_data(0x80, 0x11, 0x00, 0x00, data);

        // Encrypt the command
        let encrypted_cmd = scp.encrypt_command(command);

        // Check the result matches the Go test
        let expected_data = hex!(
            "BA796BF8FAD1FD50407B87127B94F5023EF8903AE926EAD8A204F961B8A0EDAEE7CCCFE7F7F6380CE2C6F188E598E4468B7DEDD0E807C18CCBDA71A55F3E1F9A"
        );
        assert_eq!(encrypted_cmd.data().unwrap(), expected_data.to_vec());

        // Check the IV matches the Go test
        let expected_iv = hex::decode("BA796BF8FAD1FD50407B87127B94F502").unwrap();
        assert_eq!(scp.session.iv().to_vec(), expected_iv.to_vec());
    }
}
