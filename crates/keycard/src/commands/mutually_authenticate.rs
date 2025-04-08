use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// MUTUALLY AUTHENTICATE command for Keycard
    pub struct MutuallyAuthenticate {
        command {
            cla: CLA_GP,
            ins: 0x11,

            builders {
                /// Create a MUTUALLY AUTHENTICATE command with challenge
                pub fn with_challenge(challenge: &[u8; 32]) -> Self {
                    Self::new(0x00, 0x00).with_data(challenge.to_vec()).with_le(0)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "cryptogram")]
                Success {
                    cryptogram: Vec<u8>,
                },
            }

            errors {
                /// Previous command was not OPEN SECURE CHANNEL
                #[sw(status::SW_CONDITIONS_NOT_SATISFIED)]
                #[error("Conditions not satisfied: Previous command was not OPEN SECURE CHANNEL")]
                ConditionsNotSatisfied,

                /// Client cryptogram verification fails
                #[sw(status::SW_SECURITY_STATUS_NOT_SATISFIED)]
                #[error("Security status not satisfied: Client cryptogram verification failed")]
                SecurityStatusNotSatisfied,

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
