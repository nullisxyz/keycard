use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::{CLA_GP, PersistentRecord};

apdu_pair! {
    /// GET DATA command for Keycard
    pub struct GetData {
        command {
            cla: CLA_GP,
            ins: 0xCA,

            builders {
                /// Create a GET DATA command as a request for the specified record.
                pub fn get(record: PersistentRecord) -> Self {
                    Self::new(record as u8, 0x00).with_le(0)
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
                /// Incorrect P1/P2: The record specified is not valid
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: The record specified is not valid")]
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
