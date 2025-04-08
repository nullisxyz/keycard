use crate::Challenge;
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// PAIR command for Keycard
    pub struct Pair {
        command {
            cla: CLA_GP,
            ins: 0x12,

            builders {
                /// Create a PAIR for first stage with parameters
                pub fn with_first_stage(challenge: &Challenge) -> Self {
                    Self::new(0x00, 0x00).with_data(challenge.to_vec())
                }
                /// Create a PAIR for final stage with parameters
                pub fn with_final_stage(cryptogram_hash: &[u8; 32]) -> Self {
                    Self::new(0x01, 0x00).with_data(cryptogram_hash.to_vec())
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
                /// Wrong data
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data")]
                WrongData,

                /// Security status not satisfied: Client cryptogram verification fails
                #[sw(status::SW_SECURITY_STATUS_NOT_SATISFIED)]
                #[error("Security status not satisfied: Client cryptogram verification failed")]
                SecurityStatusNotSatisfied,

                /// File full: All available pairing slots are taken
                #[sw(status::SW_FILE_FULL)]
                #[error("File full: All available pairing slots are taken")]
                FileFull,

                /// Incorrect P1/P2: P1 is invalid or is 0x01 but the first phase was not completed
                #[sw(status::SW_INCORRECT_P1P2)]
                #[error("Incorrect P1/P2: P1 is invalid or is 0x01 but the first phase was not completed")]
                IncorrectP1P2,

                /// Conditions not satisfied: Secure channel is open
                #[sw(status::SW_CONDITIONS_NOT_SATISFIED)]
                #[error("Conditions not satisfied: Secure channel is open")]
                ConditionsNotSatisfied,

                /// Other error
                #[sw(_, _)]
                #[error("Other error")]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }
        }
    }
}
