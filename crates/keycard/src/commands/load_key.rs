use bytes::Bytes;
use iso7816_tlv::TlvError;
use iso7816_tlv::ber::{Tag, Tlv, Value};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// LOAD KEY command for Keycard
    pub struct LoadKey {
        command {
            cla: CLA_GP,
            ins: 0xD0,
            required_security_level: SecurityLevel::authenticated_encrypted(),

            builders {
                /// Create a LOAD KEY command for loading an ECC secp256k1 keypair
                fn load_keypair(public_key: Option<PublicKey>, private_key: SecretKey) -> Result<Self, TlvError> {
                    let buf = Bytes::from(
                        create_keypair_template(
                            public_key,
                            private_key,
                            None
                        )?
                        .to_vec());

                    Ok(Self::new(0x01, 0x00).with_data(buf).with_le(0))
                }

                /// Create a LOAD KEY command for loading an ECC secp256k1 extended keypair
                fn load_extended_keypair(public_key: Option<PublicKey>, private_key: SecretKey, chain_code: [u8; 32]) -> Result<Self, TlvError> {
                    let buf = Bytes::from(
                        create_keypair_template(
                            public_key,
                            private_key,
                            Some(chain_code)
                        )?
                        .to_vec()
                    );

                    Ok(Self::new(0x02, 0x00).with_data(buf).with_le(0))
                }

                /// Create a LOAD KEY command for loading a BIP39 seed
                fn load_bip39_seed(seed: &[u8; 64]) -> Self {
                    Self::new(0x03, 0x00).with_data(Bytes::copy_from_slice(seed)).with_le(0)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                Success {
                    /// Key UID
                    key_uid: Vec<u8>,
                }
            }

            errors {
                /// Wrong data: format is invalid
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data: format is invalid")]
                WrongData,

                /// Incorrect P1/P2: P1 is invalid
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: P1 is invalid")]
                IncorrectP1P2,

                /// Other error
                #[sw(_, _)]
                #[error("Other error: {sw1:02X}{sw2:02X}")]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }
        }
    }
}

pub const TAG_KEYPAIR_TEMPLATE: u8 = 0xA1;
pub const TAG_ECC_PUBLIC_KEY: u8 = 0x80;
pub const TAG_ECC_PRIVATE_KEY: u8 = 0x81;
pub const TAG_CHAIN_CODE: u8 = 0x82;

pub struct PublicKeyTlvWrapper(PublicKey);

impl TryFrom<PublicKeyTlvWrapper> for Tlv {
    type Error = TlvError;

    fn try_from(wrapper: PublicKeyTlvWrapper) -> Result<Self, Self::Error> {
        Tlv::new(
            Tag::try_from(TAG_ECC_PUBLIC_KEY)?,
            Value::Primitive(wrapper.0.to_encoded_point(false).as_bytes().to_vec()),
        )
    }
}

pub struct PrivateKeyTlvWrapper(SecretKey);

impl TryFrom<PrivateKeyTlvWrapper> for Tlv {
    type Error = TlvError;

    fn try_from(wrapper: PrivateKeyTlvWrapper) -> Result<Self, Self::Error> {
        Tlv::new(
            Tag::try_from(TAG_ECC_PRIVATE_KEY)?,
            Value::Primitive(wrapper.0.to_bytes().as_slice().to_vec()),
        )
    }
}

pub struct ChainCodeTlvWrapper([u8; 32]);

impl TryFrom<ChainCodeTlvWrapper> for Tlv {
    type Error = TlvError;

    fn try_from(wrapper: ChainCodeTlvWrapper) -> Result<Self, Self::Error> {
        Tlv::new(
            Tag::try_from(TAG_CHAIN_CODE)?,
            Value::Primitive(wrapper.0.to_vec()),
        )
    }
}

fn create_keypair_template(
    public_key: Option<PublicKey>,
    private_key: SecretKey,
    chain_code: Option<[u8; 32]>,
) -> Result<Tlv, TlvError> {
    let mut tlvs: Vec<Tlv> = vec![];
    if let Some(public_key) = public_key {
        tlvs.push(PublicKeyTlvWrapper(public_key).try_into()?);
    }
    tlvs.push(PrivateKeyTlvWrapper(private_key).try_into()?);
    if let Some(chain_code) = chain_code {
        tlvs.push(ChainCodeTlvWrapper(chain_code).try_into()?);
    }

    Tlv::new(
        Tag::try_from(TAG_KEYPAIR_TEMPLATE)?,
        Value::Constructed(tlvs),
    )
}
