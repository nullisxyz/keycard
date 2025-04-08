use derive_more::{Display, From, Into};
use iso7816_tlv::ber::{Tag, Tlv, Value};

use crate::tags;

/// Application version (major.minor)
#[derive(Debug, Clone, Copy, PartialEq, Display, From, Into)]
#[display("{}.{}", major, minor)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
}

impl TryFrom<&Tlv> for Version {
    type Error = anyhow::Error;

    fn try_from(tlv: &Tlv) -> Result<Self, Self::Error> {
        if tlv.tag()
            != &Tag::try_from(tags::OTHER).map_err(|_| anyhow::Error::msg("Invalid tag"))?
        {
            return Err(anyhow::Error::msg("Invalid tag"));
        }

        let (major, minor) = match tlv.value() {
            Value::Primitive(bytes) => {
                let major = bytes[0];
                let minor = bytes[1];
                (major, minor)
            }
            _ => return Err(anyhow::Error::msg("Invalid value")),
        };

        Ok(Version { major, minor })
    }
}
