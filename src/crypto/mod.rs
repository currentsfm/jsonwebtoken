use hmac::digest::KeyInit;
use hmac::Mac;
use subtle::ConstantTimeEq;
use crate::algorithms::Algorithm;
use crate::decoding::{DecodingKey, DecodingKeyKind};
use crate::encoding::EncodingKey;
use crate::errors::Result;
use crate::serialization::{b64_encode};

pub(crate) mod ecdsa;
pub(crate) mod eddsa;
pub(crate) mod rsa;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;
type HmacSha384 = hmac::Hmac<sha2::Sha384>;
type HmacSha512 = hmac::Hmac<sha2::Sha512>;

/// The actual HS signing + encoding
/// Could be in its own file to match RSA/EC but it's 2 lines...
pub(crate) fn sign_hmac<Hmac: KeyInit + Mac>(key: &[u8], message: &[u8]) -> String {
    let mut mac: Hmac = KeyInit::new_from_slice(key)
        .expect("HMAC key should be valid");
    mac.update(message);
    let result = mac.finalize();
    let digest = result.into_bytes();
    b64_encode(digest)
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// If you just want to encode a JWT, use `encode` instead.
pub fn sign(message: &[u8], key: &EncodingKey, algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => Ok(sign_hmac::<HmacSha256>(key.inner(), message)),
        Algorithm::HS384 => Ok(sign_hmac::<HmacSha384>(key.inner(), message)),
        Algorithm::HS512 => Ok(sign_hmac::<HmacSha512>(key.inner(), message)),

        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::sign(ecdsa::alg_to_ec_signing(algorithm), key.inner(), message)
        }

        Algorithm::EdDSA => eddsa::sign(key.inner(), message),

        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => rsa::sign(rsa::alg_to_rsa_signing(algorithm), key.inner(), message),
    }
}


/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA/EC.
///
/// If you just want to decode a JWT, use `decode` instead.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `message` is base64(header) + "." + base64(claims)
pub fn verify(
    signature: &str,
    message: &[u8],
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the message with the key and compare if they are equal
            let signed = sign(message, &EncodingKey::from_secret(key.as_bytes()), algorithm)?;
            Ok(ConstantTimeEq::ct_eq(signature.as_bytes(), signed.as_bytes()).into())
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            ecdsa::verify_ecdsa(
                ecdsa::alg_to_ec_verification(algorithm),
                signature,
                message,
                key.as_bytes(),
            )
        },
        Algorithm::EdDSA => {
            eddsa::verify_eddsa(
                eddsa::alg_to_ec_verification(algorithm),
                signature,
                message,
                key.as_bytes(),
            )
        },
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let alg = rsa::alg_to_rsa_parameters(algorithm);
            match &key.kind {
                DecodingKeyKind::SecretOrDer(bytes) => rsa::verify_rsa_from_secret_or_der(alg, signature, message, bytes),
                DecodingKeyKind::RsaModulusExponent { n, e } => {
                    rsa::verify_from_components(alg, signature, message, (n, e))
                }
            }
        }
    }
}
