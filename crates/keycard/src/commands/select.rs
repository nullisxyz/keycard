use std::fmt;

use iso7816_tlv::ber::{Tag, Tlv};
use nexum_apdu_globalplatform::commands::select::SelectOk;

use crate::constants::tags;
use crate::types::ApplicationInfo;

impl TryFrom<SelectOk> for SelectSuccessResponse {
    type Error = anyhow::Error;

    fn try_from(response: SelectOk) -> Result<Self, Self::Error> {
        match response {
            SelectOk::Success { fci } => SelectSuccessResponse::try_from(fci.as_slice()),
        }
    }
}

#[derive(Debug)]
pub enum SelectSuccessResponse {
    /// Regular response with application info
    ApplicationInfo(ApplicationInfo),
    /// Response in pre-initialized state (only public key - optional)
    PreInitialized(Option<k256::PublicKey>),
}

impl fmt::Display for SelectSuccessResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelectSuccessResponse::ApplicationInfo(info) => write!(f, "{}", info),
            SelectSuccessResponse::PreInitialized(maybe_key) => {
                writeln!(f, "Pre-initialized State:")?;
                match &maybe_key {
                    Some(key) => write!(f, "  Public Key: {:#?}", key),
                    None => write!(f, "  Public Key: None"),
                }
            }
        }
    }
}

impl TryFrom<&[u8]> for SelectSuccessResponse {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let fci = Tlv::from_bytes(value).unwrap();

        let application_info = Tag::try_from(tags::TEMPLATE_APPLICATION_INFO).unwrap();
        let ecc_public_key = Tag::try_from(tags::ECC_PUBLIC_KEY).unwrap();

        if fci.tag() == &application_info {
            Ok(SelectSuccessResponse::ApplicationInfo(
                ApplicationInfo::try_from(&fci)?,
            ))
        } else if fci.tag() == &ecc_public_key {
            Ok(SelectSuccessResponse::PreInitialized(
                *crate::types::PublicKey::try_from(&fci).unwrap(),
            ))
        } else {
            Err(anyhow::Error::msg("Unsupported tag"))
        }
    }
}
