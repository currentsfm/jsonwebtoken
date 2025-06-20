use ed25519_dalek::{Signature, Signer, Verifier};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use crate::algorithms::Algorithm;
use crate::errors::Result;
use crate::serialization::{b64_encode, b64_decode};

pub(crate) enum EddsaVerificationAlgorithm {
    Ed25519,
}

/// Only used internally when signing or validating EdDSA, to map from our enum to the EdDSA algorithm.
pub(crate) fn alg_to_ec_verification(alg: Algorithm) -> EddsaVerificationAlgorithm {
    // To support additional key subtypes, like Ed448, we would need to match on the JWK's ("crv")
    // parameter.
    match alg {
        Algorithm::EdDSA => EddsaVerificationAlgorithm::Ed25519,
        _ => unreachable!("Tried to get EdDSA alg for a non-EdDSA algorithm"),
    }
}

fn parse_signing_key(key: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(&key) {
        return Ok(key)
    }
    let bytes = <[u8; 64]>::try_from(key).map_err(|_| crate::errors::ErrorKind::InvalidEdDSAKey)?;
    let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&bytes)
        .map_err(|_| crate::errors::ErrorKind::InvalidEdDSAKey)?;
    
    Ok(signing_key)
}

fn parse_verifying_key(key: &[u8]) -> Result<ed25519_dalek::VerifyingKey> {
    if let Ok(key) = ed25519_dalek::VerifyingKey::from_public_key_der(&key) {
        return Ok(key)
    }
    let bytes = <[u8; 32]>::try_from(key).map_err(|_| crate::errors::ErrorKind::InvalidEdDSAKey)?;
    let signing_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| crate::errors::ErrorKind::InvalidEdDSAKey)?;
    
    Ok(signing_key)
}

/// The actual EdDSA signing + encoding
/// The key needs to be in PKCS8 format
pub fn sign(key: &[u8], message: &[u8]) -> Result<String> {
    let signing_key = parse_signing_key(key)?;
    
    let signature = signing_key.sign(message);

    Ok(b64_encode(signature.to_bytes()))
}

/// Verify EdDSA signature
pub(crate) fn verify_eddsa(
    alg: EddsaVerificationAlgorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    match alg {
        EddsaVerificationAlgorithm::Ed25519 => {
            let key = parse_verifying_key(key)?;
            let signature_bytes = b64_decode(signature)?;
            let signature = Signature::from_slice(&signature_bytes).map_err(|_| crate::errors::ErrorKind::InvalidSignature)?;
            let result = key.verify(message, &signature);
            Ok(result.is_ok())
        }
    }
}
