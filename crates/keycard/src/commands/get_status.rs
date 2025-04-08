use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// GET STATUS command for Keycard
    pub struct GetStatus {
        command {
            cla: CLA_GP,
            ins: 0xF2,
            required_security_level: SecurityLevel::mac_protected(),

            builders {
                /// Create a GET STATUS command for the application status.
                pub fn application() -> Self {
                    Self::new(0x00, 0x00).with_le(0x00)
                }

                /// Create a GET STATUS command for the key path status.
                pub fn key_path() -> Self {
                    Self::new(0x01, 0x00).with_le(0x00)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "data")]
                Success {
                    data: Vec<u8>,
                }
            }

            errors {
                /// Incorrect P1/P2: Undefined P1
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: Undefined P1")]
                IncorrectP1P2,
            }
        }
    }
}
