use nexum_apdu_macros::apdu_pair;

use nexum_apdu_globalplatform::constants::status;
use rand::RngCore;

use super::CLA_GP;

apdu_pair! {
    /// IDENT command for Keycard
    pub struct Ident {
        command {
            cla: CLA_GP,
            ins: 0x14,

            builders {
                /// Create an IDENT command with the nominated challenge
                pub fn with_challenge(challenge: &[u8; 32]) -> Self {
                    Self::new(0x00, 0x00).with_data(challenge.to_vec()).with_le(0)
                }

                /// Create an IDENT command with a random 256-bit challenge
                pub fn with_random_challenge() -> Self {
                    let mut rng = rand::rng();
                    let mut challenge = [0u8; 32];
                    rng.fill_bytes(&mut challenge.as_mut_slice());
                    Self::with_challenge(&challenge)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "data")]
                Success {
                    /// The response data
                    data: Vec<u8>,
                }
            }

            errors {
                /// Wrong data
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data")]
                WrongData,
            }
        }
    }
}
