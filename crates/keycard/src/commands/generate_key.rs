use nexum_apdu_core::response::error::ResponseError;
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::CLA_GP;

apdu_pair! {
    /// GENERATE KEY command for Keycard
    pub struct GenerateKey {
        command {
            cla: CLA_GP,
            ins: 0xD4,
            required_security_level: SecurityLevel::encrypted(),

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
                Success {
                    key_uid: [u8; 32],
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
            }

            custom_parse = |response: &nexum_apdu_core::Response| -> Result<GenerateKeyOk, GenerateKeyError> {
                use nexum_apdu_core::ApduResponse;

                match response.status() {
                    status::SW_NO_ERROR => {
                        match response.payload() {
                            Some(payload) => Ok(GenerateKeyOk::Success{
                                key_uid: payload.to_vec().try_into()
                                    .map_err(|_| ResponseError::Parse("Key UID was not 32 bytes long"))?,
                            }),
                            None => Err(ResponseError::Parse("No payload in response").into()),
                        }
                    },
                    status::SW_SECURITY_STATUS_NOT_SATISFIED => Err(GenerateKeyError::SecurityStatusNotSatisfied),
                    status::SW_CONDITIONS_NOT_SATISFIED => Err(GenerateKeyError::ConditionsNotSatisfied),
                    _ => Err(GenerateKeyError::Unknown { sw1: response.status().sw1, sw2: response.status().sw2 }),
                }
            }
        }
    }
}
