use derive_more::{AsRef, Deref};
use iso7816_tlv::ber::{Tag, Tlv, Value};
use k256::ecdsa;

use crate::tags;

use super::get_primitive_value;

#[derive(Debug, Clone, PartialEq, Eq, AsRef)]
pub struct Signature {
    pub public_key: k256::PublicKey,
    pub signature: EcdsaSignature,
}

impl TryFrom<Tlv> for Signature {
    type Error = anyhow::Error;

    fn try_from(tlv: Tlv) -> Result<Self, Self::Error> {
        if tlv.tag()
            != &Tag::try_from(tags::TEMPLATE_SIGNATURE)
                .map_err(|_| anyhow::Error::msg("Invalid tag"))?
        {
            return Err(anyhow::Error::msg("Invalid tag"));
        }

        let (public_key, signature) = match tlv.value() {
            Value::Primitive(_) => Err(anyhow::Error::msg("Invalid value")),
            Value::Constructed(tlvs) => {
                let public_key = PublicKey::try_from(&tlvs[0])?;
                let signature = EcdsaSignature::try_from(&tlvs[1])?;
                Ok((public_key, signature))
            }
        }?;

        Ok(Signature {
            public_key: public_key
                .as_ref()
                .ok_or(anyhow::Error::msg("Invalid public key"))?,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, AsRef, Deref)]
pub struct PublicKey(Option<k256::PublicKey>);

impl TryFrom<&Tlv> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(tlv: &Tlv) -> Result<Self, Self::Error> {
        if tlv.tag()
            != &Tag::try_from(tags::ECC_PUBLIC_KEY)
                .map_err(|_| anyhow::Error::msg("Invalid tag"))?
        {
            return Err(anyhow::Error::msg("Invalid tag"));
        }

        let public_key = {
            let value =
                get_primitive_value(&Tag::try_from(tags::ECC_PUBLIC_KEY).unwrap(), &tlv).unwrap();
            match value.len() {
                0 => None,
                65 => Some(k256::PublicKey::from_sec1_bytes(value.as_slice().into())?),
                _ => return Err(anyhow::Error::msg("Invalid public key length")),
            }
        };

        Ok(PublicKey(public_key))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, AsRef, Deref)]
pub struct EcdsaSignature(k256::ecdsa::Signature);

impl TryFrom<&Tlv> for EcdsaSignature {
    type Error = anyhow::Error;

    fn try_from(tlv: &Tlv) -> Result<Self, Self::Error> {
        if tlv.tag()
            != &Tag::try_from(tags::ECDSA_SIGNATURE)
                .map_err(|_| anyhow::Error::msg("Invalid tag"))?
        {
            return Err(anyhow::Error::msg("Invalid tag"));
        }

        let (r, s) = match tlv.value() {
            Value::Primitive(_) => Err(anyhow::Error::msg("Invalid value")),
            Value::Constructed(tlvs) => {
                let r: [u8; 32] =
                    get_primitive_value(&Tag::try_from(tags::OTHER).unwrap(), &tlvs[0])
                        .unwrap()
                        .try_into()
                        .unwrap();
                let s: [u8; 32] =
                    get_primitive_value(&Tag::try_from(tags::OTHER).unwrap(), &tlvs[1])
                        .unwrap()
                        .try_into()
                        .unwrap();
                Ok((r, s))
            }
        }?;

        Ok(EcdsaSignature(ecdsa::Signature::from_scalars(r, s)?))
    }
}
