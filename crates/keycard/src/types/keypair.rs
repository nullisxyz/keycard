use std::fmt;

use iso7816_tlv::ber::{Tag, Tlv, Value};
use k256::{PublicKey, SecretKey};

// Import the tags from the constants module
use crate::tags;

use super::get_primitive_value;

/// Represents a keypair template (tag 0xA1) that can be used for both loading and exporting keys.
///
/// For EXPORT KEY command, this struct is obtained by parsing the response.
/// For LOAD KEY command, this struct can be created and serialized to send to the card.
#[derive(Clone, PartialEq, Eq)]
pub struct Keypair {
    /// ECC public key component (tag 0x80)
    pub public_key: Option<PublicKey>,

    /// ECC private key component (tag 0x81)
    pub private_key: Option<SecretKey>,

    /// Chain code for extended keys (tag 0x82)
    pub chain_code: Option<Vec<u8>>,
}

impl Keypair {
    /// Creates a new empty keypair for loading to the card
    ///
    /// This is used for the LOAD KEY command.
    pub fn new() -> Self {
        Keypair {
            public_key: None,
            private_key: None,
            chain_code: None,
        }
    }

    /// Creates a keypair with a private key for loading to the card
    ///
    /// This is primarily used for the LOAD KEY command.
    /// Note that the public key component is optional when loading a key.
    pub fn with_private_key(private_key: SecretKey) -> Self {
        let mut keypair = Self::new();
        keypair.private_key = Some(private_key);
        keypair
    }

    /// Creates a keypair with public and private keys for loading to the card
    ///
    /// This is primarily used for the LOAD KEY command.
    pub fn with_keypair(public_key: PublicKey, private_key: SecretKey) -> Self {
        let mut keypair = Self::new();
        keypair.public_key = Some(public_key);
        keypair.private_key = Some(private_key);
        keypair
    }

    /// Creates an extended keypair with public key, private key, and chain code for loading to the card
    ///
    /// This is primarily used for the LOAD KEY command with P1=0x02 (extended keypair).
    pub fn with_extended_keypair(
        public_key: PublicKey,
        private_key: SecretKey,
        chain_code: Vec<u8>,
    ) -> Self {
        let mut keypair = Self::new();
        keypair.public_key = Some(public_key);
        keypair.private_key = Some(private_key);
        keypair.chain_code = Some(chain_code);
        keypair
    }

    /// Determines if this keypair has a chain code, making it an extended keypair
    pub fn is_extended(&self) -> bool {
        self.chain_code.is_some()
    }

    /// Serialize the keypair to bytes for sending to the card
    ///
    /// This is used for the LOAD KEY command.
    pub fn to_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let tlv: Tlv = self.try_into()?;
        Ok(tlv.to_vec())
    }
}

impl TryFrom<Tlv> for Keypair {
    type Error = anyhow::Error;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        if tlv.tag() != &Tag::try_from(tags::TEMPLATE_KEYPAIR).unwrap() {
            return Err(anyhow::Error::msg("Invalid keypair template tag"));
        }

        let mut keypair = Keypair::new();

        match tlv.value() {
            Value::Primitive(_) => {
                return Err(anyhow::Error::msg(
                    "Expected constructed TLV for keypair template",
                ));
            }
            Value::Constructed(tlvs) => {
                for tlv in tlvs {
                    let tag = tlv.tag();

                    if tag == &Tag::try_from(tags::ECC_PUBLIC_KEY).unwrap() {
                        keypair.public_key = Some(PublicKey::from_sec1_bytes(
                            &get_primitive_value(tag, &tlv)?,
                        )?);
                    } else if tag == &Tag::try_from(tags::ECC_PRIVATE_KEY).unwrap() {
                        keypair.private_key =
                            Some(SecretKey::from_slice(&get_primitive_value(tag, &tlv)?)?);
                    } else if tag == &Tag::try_from(tags::CHAIN_CODE).unwrap() {
                        keypair.chain_code = Some(get_primitive_value(tag, &tlv)?);
                    }
                }
            }
        }

        Ok(keypair)
    }
}

impl TryFrom<&[u8]> for Keypair {
    type Error = anyhow::Error;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let (tlv, _) = Tlv::parse(data);
        Self::try_from(tlv.unwrap())
    }
}

impl TryInto<Tlv> for &Keypair {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Tlv, Self::Error> {
        let template_tag = Tag::try_from(tags::TEMPLATE_KEYPAIR).unwrap();
        let mut inner_tlvs = Vec::new();

        // Helper function to create TLV for each component
        let add_tlv = |tag_value: u8,
                       data: &Option<Vec<u8>>,
                       tlvs: &mut Vec<Tlv>|
         -> Result<(), anyhow::Error> {
            if let Some(data) = data {
                let tag = Tag::try_from(tag_value).unwrap();
                let tlv = Tlv::new(tag, Value::Primitive(data.clone())).unwrap();
                tlvs.push(tlv);
            }
            Ok(())
        };

        // Add TLV for each component if present
        add_tlv(
            tags::ECC_PUBLIC_KEY,
            &self.public_key.map(|f| f.to_sec1_bytes().to_vec()),
            &mut inner_tlvs,
        )?;
        add_tlv(
            tags::ECC_PRIVATE_KEY,
            &self.private_key.as_ref().map(|f| f.to_bytes().to_vec()),
            &mut inner_tlvs,
        )?;
        add_tlv(tags::CHAIN_CODE, &self.chain_code, &mut inner_tlvs)?;

        Ok(Tlv::new(template_tag, Value::Constructed(inner_tlvs)).unwrap())
    }
}

// For security, don't display private key in debug output
impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keypair")
            .field(
                "public_key",
                &self
                    .public_key
                    .as_ref()
                    .map(|pk| format!("[Public Key: {} bytes]", pk.to_sec1_bytes().len())),
            )
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "[Private Key Present]"),
            )
            .field(
                "chain_code",
                &self.chain_code.as_ref().map(|_| "[Chain Code Present]"),
            )
            .finish()
    }
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Keypair:")?;

        match &self.public_key {
            Some(pk) => writeln!(f, "  Public Key: {} bytes", pk.to_sec1_bytes().len())?,
            None => writeln!(f, "  Public Key: Not present")?,
        }

        match &self.private_key {
            Some(_) => writeln!(f, "  Private Key: Present")?,
            None => writeln!(f, "  Private Key: Not present")?,
        }

        match &self.chain_code {
            Some(_) => writeln!(f, "  Chain Code: Present (Extended keypair)")?,
            None => writeln!(f, "  Chain Code: Not present")?,
        }

        Ok(())
    }
}
