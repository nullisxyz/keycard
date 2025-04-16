use bytes::{Bytes, BytesMut};
use k256::PublicKey;
use nexum_apdu_core::prelude::*;
use nexum_apdu_core::error::Error;
use rand_v8::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, trace, warn};

use crate::{
    PairingInfo,
    commands::{MutuallyAuthenticateCommand, PairCommand, pin},
    crypto::{ApduMeta, Challenge},
    crypto::{calculate_cryptogram, decrypt_data, encrypt_data, generate_pairing_token},
    session::Session,
};

/// Represents a secure communication channel with a Keycard
#[derive(Clone)]
pub struct KeycardSCP<T: CardTransport> {
    /// Session containing keys and state
    session: Session,
    /// Security level of the secure channel
    security_level: SecurityLevel,
    /// The underlying transport
    transport: T,
    /// Whether the secure channel is established
    established: bool,
}

impl<T: CardTransport> fmt::Debug for KeycardSCP<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycardSCP")
            .field("security_level", &self.security_level)
            .field("established", &self.established)
            .finish()
    }
}

impl<T: CardTransport> KeycardSCP<T> {
    /// Create a new secure channel instance
    pub fn new(
        mut transport: T,
        card_public_key: PublicKey,
        pairing_info: PairingInfo,
    ) -> Result<Self, Error> {
        let session = Session::new(&card_public_key, &pairing_info, &mut transport)?;

        let mut secure_channel = Self {
            transport,
            session,
            security_level: SecurityLevel::none(),
            established: false,
        };

        // Authenticate to establish the channel
        secure_channel.authenticate()?;

        Ok(secure_channel)
    }

    /// Pair with the card using the provided pairing password
    pub fn pair<Tr, F>(transport: &mut Tr, pairing_pass: F) -> std::result::Result<PairingInfo, nexum_apdu_core::Error>
    where
        Tr: CardTransport,
        F: FnOnce() -> String,
    {
        debug!("Starting pairing process with pairing password");

        // Generate a random challenge
        let mut challenge = Challenge::default();
        thread_rng().fill_bytes(&mut challenge);

        // Create PAIR (first step) command
        let cmd = PairCommand::with_first_stage(&challenge);

        // Send the command through the transport
        let command_bytes = cmd.to_command().to_bytes();
        let response_bytes = transport.transmit_raw(&command_bytes)?;
        let response = Response::from_bytes(&response_bytes)?;
        
        if !response.is_success() {
            return Err(Error::message("PAIR command failed"));
        }
        
        // Manual parsing of the response for PairOk
        let payload = response.payload().as_ref().ok_or_else(|| Error::protocol("Missing response payload"))?;
        if payload.len() < 16 { // At least challenge (8) + cryptogram (8)
            return Err(Error::protocol("Invalid response payload length"));
        }
        
        // Extract the challenge and cryptogram from the payload
        let mut card_challenge = Challenge::default();
        card_challenge.copy_from_slice(&payload[0..8]);
        
        let mut card_cryptogram = [0u8; 8];
        card_cryptogram.copy_from_slice(&payload[8..16]);

        // Verify the card cryptogram
        let shared_secret = generate_pairing_token(&pairing_pass());
        let expected_cryptogram = calculate_cryptogram(&shared_secret, &challenge);
        let expected_cryptogram_array = <[u8; 8]>::try_from(expected_cryptogram.as_slice()).unwrap();
        if card_cryptogram != expected_cryptogram_array {
            return Err(Error::protocol("Card cryptogram verification failed"));
        }

        // Calculate client cryptogram
        let client_cryptogram = calculate_cryptogram(&shared_secret, &card_challenge);
        
        // Create PAIR (final step) command
        let cmd = PairCommand::with_final_stage(&client_cryptogram);

        // Send the command through the transport
        let command_bytes = cmd.to_command().to_bytes();
        let response_bytes = transport.transmit_raw(&command_bytes)?;
        let response = Response::from_bytes(&response_bytes)?;
        
        if !response.is_success() {
            return Err(Error::message("PAIR final stage command failed"));
        }
        
        // Manual parsing of the final response for PairOk
        let payload = response.payload().as_ref().ok_or_else(|| Error::protocol("Missing final response payload"))?;
        if payload.len() < 33 { // At least index (1) + salt (32)
            return Err(Error::protocol("Invalid final response payload length"));
        }
        
        // Extract the pairing index and salt from the payload
        let index = payload[0];
        let salt = &payload[1..33];
        
        // The salt is available directly from the typed response
        
        // Generate the key using the shared secret and salt
        let key = {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, &shared_secret);
            Digest::update(&mut hasher, salt);
            hasher.finalize()
        };
        
        debug!("Pairing successful with index {}", index);

        Ok(PairingInfo { key, index })
    }

    /// Verify PIN and upgrade security level
    pub fn verify_pin<E, F>(&mut self, executor: &mut E, pin: F) -> Result<(), Error>
    where
        E: Executor,
        F: FnOnce() -> String,
    {
        if !self.is_established() {
            return Err(Error::SecureChannelNotEstablished);
        }

        // Create the command
        let cmd = pin::VerifyPinCommand::with_pin(&pin());

        // Execute the command
        executor
            .execute(&cmd)
            .map_err(|e| Error::message(e.to_string()))?;

        // At this point, it is guaranteed that the PIN was verified successfully.
        self.security_level = SecurityLevel::full();

        Ok(())
    }

    /// Encrypt APDU command data for the secure channel
    fn protect_command(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let command = Command::from_bytes(command)?;

        // Only apply protection if the channel is established
        if !self.is_established() {
            return Ok(command.to_bytes().to_vec());
        }

        let payload = command.data().unwrap_or(&[]);

        // Encrypt the command data if encryption is enabled
        let mut data_to_encrypt = BytesMut::from(payload);
        let encrypted_bytes = encrypt_data(
            &mut data_to_encrypt,
            self.session.keys().enc(),
            self.session.iv(),
        );

        let encrypted_data = encrypted_bytes.to_vec();

        // Prepare metadata for MAC calculation
        let mut meta = ApduMeta::default();
        meta[0] = command.class();
        meta[1] = command.instruction();
        meta[2] = command.p1();
        meta[3] = command.p2();
        meta[4] = (encrypted_data.len() + 16) as u8; // Add MAC size

        // Calculate the IV/MAC
        let encrypted_bytes_copy = Bytes::copy_from_slice(&encrypted_data);
        self.session.update_iv(&meta, &encrypted_bytes_copy);

        // Combine MAC and encrypted data
        let mut data = BytesMut::with_capacity(16 + encrypted_data.len());
        data.extend_from_slice(self.session.iv().as_ref());
        data.extend_from_slice(&encrypted_data);

        trace!(
            "Encrypted command: cla={:02X}, ins={:02X}, p1={:02X}, p2={:02X}, data_len={}",
            command.class(),
            command.instruction(),
            command.p1(),
            command.p2(),
            data.len()
        );

        let protected_command = command.with_data(data);
        Ok(protected_command.to_bytes().to_vec())
    }

    /// Process APDU response data from the secure channel
    fn process_response(&mut self, response: &[u8]) -> Result<Bytes, Error> {
        // Parse the response
        let response = Response::from_bytes(response)?;

        // Only process if the channel is established and response is success
        if !self.is_established() || !response.is_success() {
            return Ok(Bytes::copy_from_slice(response.to_bytes().as_ref()));
        }

        match response.payload() {
            Some(payload) => {
                let response_data = payload.to_vec();

                // Need at least a MAC (16 bytes)
                if response_data.len() < 16 {
                    warn!(
                        "Response data too short for secure channel: {}",
                        response_data.len()
                    );
                    return Err(Error::BufferTooSmall);
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
                )
                .map_err(|e| Error::message(e.to_string()))?;

                // Update IV for MAC verification
                self.session.update_iv(&metadata, &rdata);

                // Verify MAC
                if rmac != self.session.iv().as_slice() {
                    warn!("MAC verification failed for secure channel response");
                    return Err(Error::protocol("Invalid response MAC"));
                }

                trace!("Decrypted response: len={}", decrypted_data.len());

                // Create a new response with the decrypted data and status code
                let mut response_bytes = BytesMut::from(&decrypted_data[..]);
                let status = response.status();
                response_bytes.extend_from_slice(&[status.sw1, status.sw2]);

                Ok(Bytes::from(response_bytes))
            }
            None => {
                // No data in response, just return the status
                Ok(Bytes::copy_from_slice(response.to_bytes().as_ref()))
            }
        }
    }

    /// Perform mutual authentication to establish secure channel
    fn authenticate(&mut self) -> Result<(), Error> {
        debug!("Starting mutual authentication process");

        // Generate a random challenge
        let mut challenge = Challenge::default();
        thread_rng().fill_bytes(&mut challenge);

        // Create the command
        let cmd = MutuallyAuthenticateCommand::with_challenge(&challenge);

        // Send through transport
        let response_bytes = self.transport.transmit_raw(&cmd.to_command().to_bytes())?;

        // Parse the response
        let response = Response::from_bytes(&response_bytes)?;

        if !response.is_success() {
            return Err(Error::AuthenticationFailed("Mutual authentication failed"));
        }

        debug!("Mutual authentication successful");

        // Update state
        self.established = true;
        self.security_level = SecurityLevel::enc_mac(); // Encryption and MAC, but not authenticated

        Ok(())
    }
}

impl<T: CardTransport> SecureChannel for KeycardSCP<T> {
    type UnderlyingTransport = T;

    fn transport(&self) -> &Self::UnderlyingTransport {
        &self.transport
    }

    fn transport_mut(&mut self) -> &mut Self::UnderlyingTransport {
        &mut self.transport
    }

    fn open(&mut self) -> std::result::Result<(), nexum_apdu_core::Error> {
        if self.is_established() {
            return Ok(());
        }

        // Perform mutual authentication to establish the secure channel
        self.authenticate()
    }

    fn is_established(&self) -> bool {
        self.established
    }

    fn close(&mut self) -> std::result::Result<(), nexum_apdu_core::Error> {
        debug!("Closing Keycard secure channel");
        self.established = false;
        self.security_level = SecurityLevel::none();
        Ok(())
    }

    fn security_level(&self) -> SecurityLevel {
        trace!(
            "KeycardSCP::security_level() returning {:?}",
            self.security_level
        );
        self.security_level
    }

    fn upgrade(&mut self, level: SecurityLevel) -> std::result::Result<(), nexum_apdu_core::Error> {
        trace!(
            "KeycardSCP::upgrade called with current level={:?}, requested level={:?}",
            self.security_level, level
        );

        if !self.is_established() {
            return Err(Error::SecureChannelNotEstablished);
        }

        // Check if we're already at or above the required level
        if self.security_level.satisfies(&level) {
            return Ok(());
        }

        // For Keycard SCP, we only support upgrading to authentication through PIN verification
        // which is handled separately via verify_pin method
        if level.authentication && !self.security_level.authentication {
            return Err(Error::message(
                "Authentication upgrade must be done with verify_pin".to_string(),
            ));
        }

        // We already have encryption and integrity in KeycardSCP
        Ok(())
    }
}

impl<T: CardTransport> CardTransport for KeycardSCP<T> {
    fn transmit_raw(&mut self, command: &[u8]) -> std::result::Result<Bytes, nexum_apdu_core::Error> {
        trace!(
            "KeycardSCP::transmit_raw called with security_level={:?}, established={}",
            self.security_level,
            self.is_established()
        );

        if self.is_established() {
            debug!("KeycardSCP: protecting command");
            // Apply SCP protection
            let protected = self.protect_command(command)?;

            // Send the protected command
            let response = self.transport.transmit_raw(&protected)?;

            // Process the response
            self.process_response(&response)
        } else {
            // If channel not established, pass through to underlying transport
            self.transport.transmit_raw(command)
        }
    }

    fn reset(&mut self) -> std::result::Result<(), nexum_apdu_core::Error> {
        // Close the channel if it's open
        if self.is_established() {
            self.close()?;
        }

        // Reset the underlying transport
        self.transport.reset()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeycardScp;
    use alloy_primitives::hex;
    use cipher::{Iv, Key};

    #[test]
    fn test_protect_command() {
        // Set up the same keys and IV as in the Go test
        let enc_key =
            hex::decode("FDBCB1637597CF3F8F5E8263007D4E45F64C12D44066D4576EB1443D60AEF441")
                .unwrap();
        let mac_key =
            hex::decode("2FB70219E6635EE0958AB3F7A428BA87E8CD6E6F873A5725A55F25B102D0F1F7")
                .unwrap();
        let iv = hex::decode("627E64358FA9BDCDAD4442BD8006E0A5").unwrap();

        // Create a session with the test keys and IV
        let session = Session::from_raw(
            Key::<KeycardScp>::from_slice(&enc_key),
            Key::<KeycardScp>::from_slice(&mac_key),
            Iv::<KeycardScp>::from_slice(&iv),
        );

        // Create a mock transport
        #[derive(Debug)]
        struct MockTransport;
        impl CardTransport for MockTransport {
            fn transmit_raw(&mut self, _command: &[u8]) -> Result<Bytes, Error> {
                unimplemented!()
            }
            fn reset(&mut self) -> Result<(), Error> {
                unimplemented!()
            }
        }

        // Create secure channel with the session
        let mut scp = KeycardSCP {
            session,
            security_level: SecurityLevel::enc_mac(),
            transport: MockTransport,
            established: true,
        };

        // Create the same command as in the Go test
        let data = hex::decode("D545A5E95963B6BCED86A6AE826D34C5E06AC64A1217EFFA1415A96674A82500")
            .unwrap();
        let command = Command::new_with_data(0x80, 0x11, 0x00, 0x00, data).to_bytes();

        // Protect the command
        let protected = scp.protect_command(&command).unwrap();
        let protected_cmd = Command::from_bytes(&protected).unwrap();

        // Check the result matches the expected data
        let expected_data = hex::decode(
            "BA796BF8FAD1FD50407B87127B94F5023EF8903AE926EAD8A204F961B8A0EDAEE7CCCFE7F7F6380CE2C6F188E598E4468B7DEDD0E807C18CCBDA71A55F3E1F9A"
        ).unwrap();
        assert_eq!(protected_cmd.data().unwrap(), &expected_data);

        // Check the IV matches the expected IV
        let expected_iv = hex::decode("BA796BF8FAD1FD50407B87127B94F502").unwrap();
        assert_eq!(scp.session.iv().to_vec(), expected_iv);
    }
}
