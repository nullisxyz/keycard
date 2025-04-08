use aes::cipher::{Iv, Key};
use bytes::{Bytes, BytesMut};
use k256::{PublicKey, SecretKey};
use nexum_apdu_core::prelude::SecurityLevel;
use nexum_apdu_core::processor::SecureProtocolError;
use nexum_apdu_core::processor::{CommandProcessor, error::ProcessorError, secure::SecureChannel};
use nexum_apdu_core::transport::CardTransport;
use nexum_apdu_core::{
    ApduCommand, ApduResponse, Command, Executor, Response, ResponseAwareExecutor,
    SecureChannelExecutor,
};
use rand_v8::{RngCore, thread_rng};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::{debug, trace, warn};
use zeroize::Zeroize;

use crate::PairOk;
use crate::crypto::{ApduMeta, Challenge, Cryptogram, KeycardScp};
use crate::{
    Error,
    commands::mutually_authenticate::MutuallyAuthenticateCommand,
    commands::open_secure_channel::OpenSecureChannelCommand,
    commands::pair::PairCommand,
    crypto::{
        calculate_cryptogram, calculate_mac, decrypt_data, derive_session_keys, encrypt_data,
        generate_ecdh_shared_secret, generate_pairing_token,
    },
};

/// Secure Channel Protocol (KeycardScp) keys
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct Keys {
    /// Encryption key
    enc: Key<KeycardScp>,
    /// MAC key
    mac: Key<KeycardScp>,
}

impl Keys {
    /// Create a new key set with the specified encryption and MAC keys.
    fn new(enc: Key<KeycardScp>, mac: Key<KeycardScp>) -> Self {
        Self { enc, mac }
    }

    /// Get the encryption key
    fn enc(&self) -> &Key<KeycardScp> {
        &self.enc
    }

    /// Get the MAC key
    fn mac(&self) -> &Key<KeycardScp> {
        &self.mac
    }
}

/// Represents a secure communication channel with a Keycard
#[derive(Clone)]
pub struct KeycardSCP {
    /// Current state of the secure channel
    security_level: SecurityLevel,
    /// Session keys derived from ECDH
    keys: Option<Keys>,
    /// IV
    iv: Option<Iv<KeycardScp>>,
    /// Card public key
    card_public_key: Option<PublicKey>,
    /// Host ephemeral key pair
    host_private_key: Option<SecretKey>,
    /// Pairing information
    pairing_info: Option<crate::types::PairingInfo>,
}

impl fmt::Debug for KeycardSCP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeycardScp")
            .field("level", &self.security_level)
            .field("card_public_key", &self.card_public_key)
            .field("pairing_info", &self.pairing_info)
            .finish()
    }
}

impl Default for KeycardSCP {
    fn default() -> Self {
        Self::new()
    }
}

impl KeycardSCP {
    /// Create a new secure channel instance
    pub fn new() -> Self {
        Self {
            security_level: SecurityLevel::none(),
            keys: None,
            iv: None,
            card_public_key: None,
            host_private_key: None,
            pairing_info: None,
        }
    }

    /// Initialize the secure channel with card's public key
    fn initialize(&mut self, card_public_key: PublicKey) {
        debug!("Initializing secure channel with card public key");
        self.reset();

        // Generate an ephemeral keypair for this session
        let host_private_key = SecretKey::random(&mut thread_rng());

        self.card_public_key = Some(card_public_key);
        self.host_private_key = Some(host_private_key);

        debug!("Secure channel initialization complete");
    }

    /// Reset the secure channel state
    pub fn reset(&mut self) {
        debug!("Resetting secure channel");
        self.security_level = SecurityLevel::none();
        self.keys = None;
        self.iv = None;
        self.card_public_key = None;
        self.host_private_key = None;
        // Note: We don't reset pairing_info as that persists across sessions
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

    /// Set pairing information
    pub fn set_pairing_info(&mut self, info: crate::types::PairingInfo) {
        self.pairing_info = Some(info);
    }

    /// Get current pairing information
    pub const fn pairing_info(&self) -> Option<&crate::types::PairingInfo> {
        self.pairing_info.as_ref()
    }

    /// Pair with the card using the provided pairing password
    pub fn pair<E>(&mut self, executor: &mut E, pairing_pass: &str) -> crate::Result<()>
    where
        E: Executor + ResponseAwareExecutor + SecureChannelExecutor,
    {
        debug!("Starting pairing process with pairing password");

        // Generate a random challenge
        let mut challenge = [0u8; 32];
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
        let shared_secret = generate_pairing_token(pairing_pass);
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

        // Store pairing information
        self.pairing_info = Some(crate::types::PairingInfo { key, index });

        debug!("Pairing successful with index {}", index);
        Ok(())
    }

    /// Get the host public key (derived from private key)
    fn host_public_key(&self) -> PublicKey {
        self.host_private_key.as_ref().unwrap().public_key()
    }

    /// Establish the secure channel with the card response data and pairing key
    fn establish(
        &mut self,
        card_data: &[u8; 48],
        pairing_key: &Key<KeycardScp>,
    ) -> crate::Result<()> {
        debug!("Establishing secure channel with card data");

        // We must have the private key and card public key at this point
        let host_private_key = self.host_private_key.as_ref().unwrap();
        let card_public_key = self.card_public_key.as_ref().unwrap();

        // Generate the shared secret
        let shared_secret = generate_ecdh_shared_secret(host_private_key, card_public_key);

        // Derive session keys
        let challenge = Challenge::from_slice(&card_data[..32]);
        let iv = Iv::<crate::crypto::KeycardScp>::from_slice(&card_data[32..48]);
        let (enc_key, mac_key) = derive_session_keys(shared_secret, pairing_key, challenge);

        // Store the keys and IV
        self.keys = Some(Keys::new(enc_key, mac_key));
        self.iv = Some(*iv);
        self.security_level = SecurityLevel::encrypted();

        debug!("Secure channel established successfully");
        Ok(())
    }

    /// Open secure channel with the card
    pub fn open_secure_channel(
        &mut self,
        transport: &mut dyn CardTransport,
        card_public_key: PublicKey,
    ) -> crate::Result<()> {
        // Make sure we have pairing information
        let pairing_info = self.pairing_info.as_ref().unwrap().clone();

        // Initialize the secure channel
        self.initialize(card_public_key);

        // Create OPEN SECURE CHANNEL command
        let cmd = OpenSecureChannelCommand::with_pairing_index_and_pubkey(
            pairing_info.index as u8,
            &self.host_public_key(),
        );

        // Send the command
        let response_bytes = transport.transmit_raw(&cmd.to_command().to_bytes())?;
        let response = nexum_apdu_core::Response::from_bytes(&response_bytes)?;

        // Check for errors
        if !response.is_success() {
            return Err(crate::Error::SecureProtocol(SecureProtocolError::Protocol(
                "Open secure channel failed",
            )));
        }

        let response_data = response.payload();
        if response_data.len() != 48 {
            return Err(crate::Error::Response(
                nexum_apdu_core::response::error::ResponseError::Parse(
                    "Response data length mismatch",
                ),
            ));
        }

        // Convert data to expected format
        let card_data: [u8; 48] = response_data.try_into().unwrap();

        // Establish the secure channel
        self.establish(&card_data, &pairing_info.key)?;

        // Perform mutual authentication
        self.mutually_authenticate(transport)?;

        Ok(())
    }

    /// Perform mutual authentication to complete secure channel establishment
    fn mutually_authenticate(&mut self, transport: &mut dyn CardTransport) -> crate::Result<()> {
        // Generate a random challenge
        let mut challenge = [0u8; 32];
        thread_rng().fill_bytes(&mut challenge);

        // Create the command
        let cmd = MutuallyAuthenticateCommand::with_challenge(&challenge);

        // Encrypt the command
        let encrypted_cmd = self.encrypt_command(cmd.to_command())?;

        // Send through transport
        let response_bytes = transport.transmit_raw(&encrypted_cmd)?;
        let response = nexum_apdu_core::Response::from_bytes(&response_bytes)?;

        if !response.is_success() || self.decrypt_response(response).is_err() {
            return Err(crate::Error::MutualAuthenticationFailed);
        }

        debug!("Mutual authentication successful");

        Ok(())
    }

    /// Encrypt APDU command data for the secure channel
    fn encrypt_command(&mut self, command: Command) -> crate::Result<Vec<u8>> {
        let keys = self.keys.as_ref().unwrap().clone();
        let iv = self.iv.as_ref().unwrap().clone();

        let payload = command.data().unwrap_or(&[]);

        // Encrypt the command data
        let mut data_to_encrypt = BytesMut::from(payload);
        let encrypted_data = encrypt_data(&mut data_to_encrypt, keys.enc(), &iv);

        // Prepare metadata for MAC calculation
        let mut meta = ApduMeta::default();
        meta[0] = command.class();
        meta[1] = command.instruction();
        meta[2] = command.p1();
        meta[3] = command.p2();
        meta[4] = (encrypted_data.len() + 16) as u8; // Add MAC size

        // Calculate the IV/MAC
        self.update_iv(&meta.into(), &encrypted_data);

        // Combine MAC and encrypted data
        let mut data = BytesMut::with_capacity(16 + encrypted_data.len());
        data.extend(self.iv.unwrap());
        data.extend(encrypted_data);

        trace!(
            "Encrypted command: cla={:02X}, ins={:02X}, p1={:02X}, p2={:02X}, data_len={}",
            command.class(),
            command.instruction(),
            command.p1(),
            command.p2(),
            data.len()
        );

        let command = command.with_data(data);
        Ok(command.to_bytes().to_vec())
    }

    /// Decrypt APDU response data from the secure channel
    fn decrypt_response(&mut self, response: Response) -> Result<Vec<u8>, Error> {
        // We need the keys and IV for decryption
        let keys = self.keys.as_ref().unwrap();
        let iv = self.iv.as_ref().unwrap();

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
        let decrypted_data = decrypt_data(&mut data_to_decrypt, keys.enc(), iv)?;

        // Update IV for MAC verification
        self.update_iv(&metadata, &rdata);

        // Verify MAC
        if rmac != self.iv.unwrap().as_slice() {
            warn!("MAC verification failed for secure channel response");
            return Err(Error::SecureProtocol(SecureProtocolError::Protocol(
                "Invalid response MAC",
            )));
        }

        trace!("Decrypted response: len={}", decrypted_data.len());

        Ok(decrypted_data.to_vec())
    }

    /// Update the IV
    fn update_iv(&mut self, meta: &ApduMeta, data: &Bytes) {
        let keys = self.keys.as_ref().unwrap();

        self.iv = Some(calculate_mac(meta, data, keys.mac()));
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
        let encrypted_data = self
            .encrypt_command(command.clone())
            .map_err(|e| ProcessorError::Other(e.to_string()))?;

        // Send the command
        let response_bytes = transport.transmit_raw(&encrypted_data)?;

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
        debug!("Closing Keycard secure channel");
        self.reset();
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
    pairing_info: crate::types::PairingInfo,
    /// Card's public key
    card_public_key: PublicKey,
}

impl KeycardSecureChannelProvider {
    /// Create a new secure channel provider
    pub const fn new(pairing_info: crate::types::PairingInfo, card_public_key: PublicKey) -> Self {
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
        let mut secure_channel = KeycardSCP::new();

        // Set the pairing information
        secure_channel.set_pairing_info(crate::types::PairingInfo {
            key: self.pairing_info.key.clone(),
            index: self.pairing_info.index,
        });

        // Open the secure channel
        secure_channel
            .open_secure_channel(transport, self.card_public_key)
            .map_err(|e| {
                nexum_apdu_core::Error::SecureProtocol(SecureProtocolError::Other(e.to_string()))
            });

        Ok(Box::new(secure_channel))
    }
}

/// Create a secure channel provider from pairing info and card public key
pub fn create_secure_channel_provider(
    pairing_info: crate::types::PairingInfo,
    card_public_key: PublicKey,
) -> KeycardSecureChannelProvider {
    KeycardSecureChannelProvider::new(pairing_info, card_public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::hex;
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
        let mut scp = KeycardSCP::new();
        scp.security_level = SecurityLevel::encrypted();
        scp.keys = Some(Keys::new(
            *Key::<crate::crypto::KeycardScp>::from_slice(&enc_key),
            *Key::<crate::crypto::KeycardScp>::from_slice(&mac_key),
        ));
        scp.iv = Some(*Iv::<crate::crypto::KeycardScp>::from_slice(&iv));

        // Create the same command as in the Go test
        let data = hex::decode("D545A5E95963B6BCED86A6AE826D34C5E06AC64A1217EFFA1415A96674A82500")
            .unwrap();
        let command = Command::new_with_data(0x80, 0x11, 0x00, 0x00, data);

        // Encrypt the command
        let encrypted_cmd = scp.encrypt_command(command).unwrap();

        // Check the result matches the Go test
        let expected_data = hex!(
            "BA796BF8FAD1FD50407B87127B94F5023EF8903AE926EAD8A204F961B8A0EDAEE7CCCFE7F7F6380CE2C6F188E598E4468B7DEDD0E807C18CCBDA71A55F3E1F9A"
        );
        assert_eq!(encrypted_cmd.as_ref(), expected_data.to_vec());

        // Check the IV matches the Go test
        let expected_iv = "BA796BF8FAD1FD50407B87127B94F502";
        assert_eq!(hex::encode(scp.iv.unwrap().as_slice()), expected_iv);
    }
}
