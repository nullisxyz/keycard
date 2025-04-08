use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// GENERATE KEY command for Keycard
    pub struct GenerateKey {
        command {
            cla: CLA_GP,
            ins: 0xD4,
            required_security_level: SecurityLevel::authenticated_mac(),

            builders {
                /// Create a new GENERATE KEY command with default parameters
                pub fn create() -> Self {
                    Self::new(0x00, 0x00)
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "public_key")]
                Success {
                    public_key: Vec<u8>,
                },
            }

            errors {
                /// Security status not satisfied: Secure channel required
                #[sw(status::SW_SECURITY_STATUS_NOT_SATISFIED)]
                #[error("Security status not satisfied: Secure channel required")]
                SecurityStatusNotSatisfied,

                /// Conditions not satisfied: PIN is not validated
                #[sw(status::SW_CONDITIONS_NOT_SATISFIED)]
                #[error("Conditions not satisfied: PIN is not validated")]
                ConditionsNotSatisfied,

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
