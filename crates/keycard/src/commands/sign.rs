use bytes::{Bytes, BytesMut};
use nexum_apdu_globalplatform::constants::status;
use nexum_apdu_macros::apdu_pair;

use super::{CLA_GP, DeriveMode, KeyPath, prepare_derivation_parameters};

apdu_pair! {
    /// SIGN command for Keycard
    pub struct Sign {
        command {
            cla: CLA_GP,
            ins: 0xC0,
            required_security_level: SecurityLevel::authenticated_encrypted(),

            builders {
                /// Create a SIGN command
                pub fn with(
                    data: &[u8; 32],
                    key_path: &KeyPath,
                    derive_mode: Option<DeriveMode>,
                ) -> Result<Self, crate::Error> {
                    let (p1, path_data) = prepare_derivation_parameters(key_path, derive_mode)?;

                    // Combine data and path
                    let buf = match path_data {
                        Some(path_data) => {
                            let mut buf = BytesMut::with_capacity(data.len() + path_data.len());
                            buf.extend(data);
                            buf.extend(path_data);
                            buf.freeze()
                        }
                        None => Bytes::copy_from_slice(data.as_slice()),
                    };

                    Ok(Self::new(p1, 0x00).with_data(buf).with_le(0))
                }

                /// Sign with pinless path
                pub fn with_pinless(data: &[u8; 32]) -> Self {
                    Self::new(0x03, 0x00).with_data(Bytes::copy_from_slice(data.as_slice()))
                }
            }
        }

        response {
            ok {
                /// Success response
                #[sw(status::SW_NO_ERROR)]
                #[payload(field = "signature")]
                Success {
                    signature: Vec<u8>,
                },
            }

            errors {
                /// Conditions not satisfied (e.g. secure channel + verified pin)
                #[sw(status::SW_CONDITIONS_NOT_SATISFIED)]
                #[error("Conditions not satisfied: Require secure channel and verified pin")]
                ConditionsNotSatisfied,

                /// Data is less than 32 bytes
                #[sw(status::SW_WRONG_DATA)]
                #[error("Wrong data: Incorrect length for P1")]
                WrongData,

                /// Referenced data not found
                #[sw(status::SW_REFERENCED_DATA_NOT_FOUND)]
                #[error("Referenced data not found: Pinless path not set")]
                ReferencedDataNotFound,

                /// Other error
                #[sw(_, _)]
                #[error("Other error: {sw1:02X}{sw2:02X}")]
                OtherError {
                    sw1: u8,
                    sw2: u8,
                }
            }

            // // Define custom parser
            // custom_parse = |payload: &[u8], sw: StatusWord| -> Result<Self, ResponseError> {
            //     Ok(match sw {
            //         status::SW_NO_ERROR => {
            //             SignResponse::Success{ signature: parse_signature(payload)? }
            //         },
            //         status::SW_CONDITIONS_NOT_SATISFIED => SignResponse::ConditionsNotSatisfied,
            //         status::SW_WRONG_DATA => SignResponse::WrongData,
            //         status::SW_REFERENCED_DATA_NOT_FOUND => SignResponse::ReferencedDataNotFound,
            //         _ => SignResponse::OtherError { sw1: sw.sw1, sw2: sw.sw2 },
            //     }).into()
            // }
        }
    }
}

// const TAG_SIGNATURE_TEMPLATE: u8 = 0xA0;
// const TAG_ECC_PUBLIC_KEY: u8 = 0x80;
// const TAG_ECDSA_SIGNATURE: u8 = 0x30;
// const TAG_ECDSA_SIGNATURE_RV: u8 = 0x02;

// #[derive(Debug, Clone)]
// pub struct SignatureTemplate {
//     public_key: PublicKey,
//     signature: PrimitiveSignature,
// }

// /// Parse TLV data and extract a signature
// pub fn parse_signature(data: &[u8]) -> Result<SignatureTemplate> {
//     let sign_response =
//         Tlv::from_bytes(data).map_err(|_| Error::InvalidData("Failed to parse TLV data"))?;

//     println!("Signature response: {:?}", sign_response);

//     if sign_response.tag()
//         != &Tag::try_from(TAG_SIGNATURE_TEMPLATE)
//             .map_err(|_| Error::InvalidData("Invalid tag format"))?
//     {
//         return Err(Error::InvalidData("Missing signature template tag"));
//     }

//     // Find and extract public key (optional in this context)
//     let public_key = if let Some(tlv) = sign_response.find(
//         &Tag::try_from(TAG_ECC_PUBLIC_KEY)
//             .map_err(|_| Error::InvalidData("Invalid public key tag format"))?,
//     ) {
//         if let Value::Primitive(data) = tlv.value() {
//             Some(data.to_vec())
//         } else {
//             None
//         }
//     } else {
//         None
//     }
//     .ok_or(Error::InvalidData("Missing public key"))?;
//     let public_key = PublicKey::from_sec1_bytes(&public_key).unwrap();
//     println!("Public key: {:?}", public_key);

//     // Find and extract signature components
//     println!(
//         "sign_response: {}",
//         sign_response.to_vec().encode_hex_with_prefix()
//     );

//     let signature_tlvs = iso7816_tlv::simple::Tlv::parse_all(&sign_response.to_vec());
//     println!("Signature TLVs: {:?}", signature_tlvs);

//     let signature_tlvs = sign_response.find_all(
//         &Tag::try_from(TAG_ECDSA_SIGNATURE)
//             .map_err(|_| Error::InvalidData("Invalid signature tag format"))?,
//     );
//     println!("Signature TLVs: {:?}", signature_tlvs);

//     // let signature_tlv = if let Some(tlv) = sign_response.find_all(
//     //     &Tag::try_from(TAG_ECDSA_SIGNATURE)
//     //         .map_err(|_| Error::InvalidData("Invalid signature tag format"))?,
//     // ) {
//     //     println!("Found ECDSA signature tag!!");
//     //     if let Value::Constructed(_) = tlv.value() {
//     //         tlv
//     //     } else {
//     //         return Err(Error::InvalidData("Invalid signature tag format"));
//     //     }
//     // } else {
//     //     return Err(Error::InvalidData("Missing ECDSA signature tag"));
//     // };

//     let components = sign_response.find_all(
//         &Tag::try_from(TAG_ECDSA_SIGNATURE_RV)
//             .map_err(|_| Error::InvalidData("Invalid signature RV tag format"))?,
//     );

//     println!("Found {} components", components.len());
//     println!("components: {:?}", components);

//     if components.len() != 2 {
//         return Err(Error::InvalidData(
//             "Expected exactly 2 signature components (r,s)",
//         ));
//     }

//     let r = match components[0].value() {
//         Value::Primitive(data) => data.to_vec(),
//         _ => return Err(Error::InvalidData("Invalid r component")),
//     };

//     let s = match components[1].value() {
//         Value::Primitive(data) => data.to_vec(),
//         _ => return Err(Error::InvalidData("Invalid s component")),
//     };

//     Ok(SignatureTemplate {
//         public_key,
//         signature: PrimitiveSignature::from_scalars_and_parity(
//             FixedBytes::<32>::from_slice(&r),
//             FixedBytes::<32>::from_slice(&s),
//             false,
//         ),
//     })
// }
