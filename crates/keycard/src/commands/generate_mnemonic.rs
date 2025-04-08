use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// GENERATE MNEMONIC command for Keycard
    pub struct GenerateMnemonic {
        command {
            cla: CLA_GP,
            ins: 0xD2,
            required_security_level: SecurityLevel::encrypted(),

            builders {
                /// Create a GENERATE MNEMONIC command with a given checksum size
                pub fn with_checksum_size(checksum_size: u8) -> Self {
                    Self::new(checksum_size, 0x00).with_le(0)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "seed")]
                Success {
                    seed: Vec<u8>
                }
            }

            errors {
                /// Incorrect P1/P2: Checksum is out of range (between 4 and 8)
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: Checksum is out of range (between 4 and 8)")]
                IncorrectChecksumSize,

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
