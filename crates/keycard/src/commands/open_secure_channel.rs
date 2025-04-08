use k256::PublicKey;
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// OPEN SECURE CHANNEL command for Keycard
    pub struct OpenSecureChannel {
        command {
            cla: CLA_GP,
            ins: 0x10,

            builders {
                /// Create an OPEN SECURE CHANNEL command with parameters
                pub fn with_pairing_index_and_pubkey(pairing_index: u8, public_key: &PublicKey) -> Self {
                    Self::new(pairing_index, 0x00).with_data(public_key.to_sec1_bytes()).with_le(0)
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
                },
            }

            errors {
                /// Incorrect P1/P2: Invalid pairing index
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: Invalid pairing index")]
                IncorrectP1P2,

                /// Wrong data: Data is not a public key
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data: Data is not a public key")]
                WrongData,

                /// MAC cannot be verified
                #[sw(status::SW_SECURITY_STATUS_NOT_SATISFIED)]
                #[error("Security status not satisfied: MAC cannot be verified")]
                SecurityStatusNotSatisfied,

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
