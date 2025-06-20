use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::serialization::{b64_decode, b64_encode};
use ecdsa::elliptic_curve::pkcs8::{DecodePrivateKey, DecodePublicKey};
use signature::{Signer, Verifier};

/// ECDSA verification algorithms
pub(crate) enum EcdsaVerificationAlgorithm {
    P256Sha256,
    P384Sha384,
}

/// Only used internally when validating EC, to map from our enum to the ECDSA verification algorithm.
pub(crate) fn alg_to_ec_verification(alg: Algorithm) -> EcdsaVerificationAlgorithm {
    match alg {
        Algorithm::ES256 => EcdsaVerificationAlgorithm::P256Sha256,
        Algorithm::ES384 => EcdsaVerificationAlgorithm::P384Sha384,
        _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
    }
}

/// Only used internally when signing EC, to map from our enum to the ECDSA signing algorithm.
pub(crate) fn alg_to_ec_signing(alg: Algorithm) -> EcdsaVerificationAlgorithm {
    alg_to_ec_verification(alg)
}

// macro because trait bounds on `SigningKey` are too annoying
macro_rules! parse_signing_key {
    ($curve:ident, $key:expr) => {{
        if let Ok(key) = $curve::ecdsa::SigningKey::from_pkcs8_der($key) {
            key
        } else {
            $curve::ecdsa::SigningKey::from_slice($key)
            .map_err(|_| crate::errors::ErrorKind::InvalidEcdsaKey)?
        }
    }};
    () => {};
}
// macro because trait bounds on `VerifyingKey` are too annoying
macro_rules! parse_verifying_key {
    ($curve:ident, $key:expr) => {{
        if let Ok(key) = $curve::ecdsa::VerifyingKey::from_public_key_der($key) {
            key
        } else {
            $curve::ecdsa::VerifyingKey::from_sec1_bytes($key)
            .map_err(|_| crate::errors::ErrorKind::InvalidEcdsaKey)?
        }
    }};
    () => {};
}

/// The actual ECDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(alg: EcdsaVerificationAlgorithm, key: &[u8], message: &[u8]) -> Result<String> {
    match alg {
        EcdsaVerificationAlgorithm::P256Sha256 => {
            let signing_key = parse_signing_key!(p256, key);
            let (signature, _rec_id) = signing_key.sign(message);

            Ok(b64_encode(signature.to_bytes()))
        }
        EcdsaVerificationAlgorithm::P384Sha384 => {
            let signing_key = parse_signing_key!(p384, key);
            let (signature, _rec_id) = signing_key.sign(message);

            Ok(b64_encode(signature.to_bytes()))
        }
    }
}

/// Verify ECDSA signature
pub(crate) fn verify_ecdsa(
    alg: EcdsaVerificationAlgorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    let signature = b64_decode(signature)?;
    match alg {
        EcdsaVerificationAlgorithm::P256Sha256 => {
            let signature = p256::ecdsa::Signature::from_slice(&signature)
                .map_err(|_| crate::errors::ErrorKind::InvalidSignature)?;
            
            let verifying_key = parse_verifying_key!(p256, key);
            let result = verifying_key.verify(message, &signature);
            Ok(result.is_ok())
        }
        EcdsaVerificationAlgorithm::P384Sha384 => {
            let signature = p384::ecdsa::Signature::from_slice(&signature)
                .map_err(|_| crate::errors::ErrorKind::InvalidSignature)?;

            let verifying_key = parse_verifying_key!(p384, key);
            let result = verifying_key.verify(message, &signature);
            Ok(result.is_ok())
        }
    }
}
