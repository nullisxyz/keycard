mod application_info;
mod application_status;
mod capabilities;
mod keypair;
mod pairing_info;
mod signature;
mod version;

pub use application_info::ApplicationInfo;
pub use application_status::ApplicationStatus;
pub use capabilities::Capabilities;
use iso7816_tlv::ber::{Tag, Tlv, Value};
pub use keypair::*;
pub use pairing_info::PairingInfo;
pub use signature::*;
pub use version::Version;

pub(crate) fn get_primitive_value(tag: &Tag, tlv: &Tlv) -> Result<Vec<u8>, anyhow::Error> {
    if tag != tlv.tag() {
        return Err(anyhow::Error::msg("Invalid tag"));
    }
    match tlv.value() {
        Value::Primitive(bytes) => Ok(bytes.to_vec()),
        _ => Err(anyhow::Error::msg("Invalid value type")),
    }
}
