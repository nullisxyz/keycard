use bytes::Bytes;
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::{CLA_GP, PersistentRecord};

apdu_pair! {
    /// STORE DATA command for Keycard
    pub struct StoreData {
        command {
            cla: CLA_GP,
            ins: 0xE2,
            required_security_level: SecurityLevel::authenticated_mac(),

            builders {
                /// Create a STORE DATA command with the given data.
                pub fn put(record: PersistentRecord, data: &[u8]) -> Self {
                    Self::new(record as u8, 0x00).with_data(Bytes::copy_from_slice(data))
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                Success,
            }

            errors {
                /// Conditions not satisfied (e.g. secure channel + verified pin)
                #[sw(status::SW_CONDITIONS_NOT_SATISFIED)]
                #[error("Conditions not satisfied: Require secure channel and verified pin")]
                ConditionsNotSatisfied,

                /// Incorrect P1/P2: The record specified is not valid
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: The record specified is not valid")]
                IncorrectP1P2,

                /// Wrong data: Data is too long
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data: Data is too long")]
                WrongData,

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
