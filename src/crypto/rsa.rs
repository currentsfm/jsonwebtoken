use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1v15, pss};
use rsa::signature::{RandomizedSigner, Verifier, SignatureEncoding};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use sha2::{Sha256, Sha384, Sha512};
use rand_core::OsRng;

use crate::algorithms::Algorithm;
use crate::errors::{Error, ErrorKind, Result};
use crate::serialization::{b64_decode, b64_encode};

/// RSA verification algorithms  
#[derive(Clone, Copy)]
pub(crate) enum RsaVerificationAlgorithm {
    Pkcs1v15Sha256,
    Pkcs1v15Sha384,
    Pkcs1v15Sha512,
    PssSha256,
    PssSha384,
    PssSha512,
}

/// Only used internally when signing with RSA, to map from our enum to the RSA signing structs.
pub(crate) fn alg_to_rsa_signing(alg: Algorithm) -> RsaVerificationAlgorithm {
    match alg {
        Algorithm::RS256 => RsaVerificationAlgorithm::Pkcs1v15Sha256,
        Algorithm::RS384 => RsaVerificationAlgorithm::Pkcs1v15Sha384,
        Algorithm::RS512 => RsaVerificationAlgorithm::Pkcs1v15Sha512,
        Algorithm::PS256 => RsaVerificationAlgorithm::PssSha256,
        Algorithm::PS384 => RsaVerificationAlgorithm::PssSha384,
        Algorithm::PS512 => RsaVerificationAlgorithm::PssSha512,
        _ => unreachable!("Tried to get RSA signature for a non-rsa algorithm"),
    }
}

/// Only used internally when validating RSA, to map from our enum to the RSA verification algorithm.
pub(crate) fn alg_to_rsa_parameters(alg: Algorithm) -> RsaVerificationAlgorithm {
    alg_to_rsa_signing(alg)
}

/// Try to parse RSA private key from either PKCS#1 or PKCS#8 format
fn parse_rsa_private_key(key: &[u8]) -> Result<RsaPrivateKey> {
    if let Ok(private_key) = RsaPrivateKey::from_pkcs8_der(key) {
        return Ok(private_key);
    }
    
    if let Ok(private_key) = RsaPrivateKey::from_pkcs1_der(key) {
        return Ok(private_key);
    }
    
    Err(Error::from(ErrorKind::InvalidRsaKey("Unable to parse RSA private key as PKCS#1 or PKCS#8".to_string())))
}

/// Try to parse RSA public key from either PKCS#1 or PKCS#8 format
fn parse_rsa_public_key(key: &[u8]) -> Result<RsaPublicKey> {
    if let Ok(public_key) = RsaPublicKey::from_public_key_der(key) {
        return Ok(public_key);
    }
    
    if let Ok(public_key) = RsaPublicKey::from_pkcs1_der(key) {
        return Ok(public_key);
    }
    
    Err(Error::from(ErrorKind::InvalidRsaKey("Unable to parse RSA public key as PKCS#1 or PKCS#8".to_string())))
}

/// The actual RSA signing + encoding
/// The key can be in PKCS#1 or PKCS#8 format
pub(crate) fn sign(
    alg: RsaVerificationAlgorithm,
    key: &[u8],
    message: &[u8],
) -> Result<String> {
    let private_key = parse_rsa_private_key(key)?;

    let signature_bytes = match alg {
        RsaVerificationAlgorithm::Pkcs1v15Sha256 => {
            let signing_key = pkcs1v15::SigningKey::<Sha256>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
        RsaVerificationAlgorithm::Pkcs1v15Sha384 => {
            let signing_key = pkcs1v15::SigningKey::<Sha384>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
        RsaVerificationAlgorithm::Pkcs1v15Sha512 => {
            let signing_key = pkcs1v15::SigningKey::<Sha512>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
        RsaVerificationAlgorithm::PssSha256 => {
            let signing_key = pss::SigningKey::<Sha256>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
        RsaVerificationAlgorithm::PssSha384 => {
            let signing_key = pss::SigningKey::<Sha384>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
        RsaVerificationAlgorithm::PssSha512 => {
            let signing_key = pss::SigningKey::<Sha512>::new(private_key);
            signing_key.sign_with_rng(&mut OsRng, message).to_bytes().to_vec()
        }
    };

    Ok(b64_encode(signature_bytes))
}

fn verify_rsa(
    alg: RsaVerificationAlgorithm,
    public_key: RsaPublicKey,
    signature_bytes: &[u8],
    message: &[u8],
) -> Result<()> {
    let result = match alg {
        RsaVerificationAlgorithm::Pkcs1v15Sha256 => {
            let verifying_key = pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
            let signature = pkcs1v15::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
        RsaVerificationAlgorithm::Pkcs1v15Sha384 => {
            let verifying_key = pkcs1v15::VerifyingKey::<Sha384>::new(public_key);
            let signature = pkcs1v15::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
        RsaVerificationAlgorithm::Pkcs1v15Sha512 => {
            let verifying_key = pkcs1v15::VerifyingKey::<Sha512>::new(public_key);
            let signature = pkcs1v15::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
        RsaVerificationAlgorithm::PssSha256 => {
            let verifying_key = pss::VerifyingKey::<Sha256>::new(public_key);
            let signature = pss::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
        RsaVerificationAlgorithm::PssSha384 => {
            let verifying_key = pss::VerifyingKey::<Sha384>::new(public_key);
            let signature = pss::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
        RsaVerificationAlgorithm::PssSha512 => {
            let verifying_key = pss::VerifyingKey::<Sha512>::new(public_key);
            let signature = pss::Signature::try_from(signature_bytes)
                .map_err(|_| ErrorKind::InvalidSignature)?;
            verifying_key.verify(message, &signature)
        }
    };

    Ok(())
}

/// Verify RSA signature using a DER-encoded public key
pub(crate) fn verify_rsa_from_secret_or_der(
    alg: RsaVerificationAlgorithm,
    signature: &str,
    message: &[u8],
    key: &[u8],
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    
    let public_key = parse_rsa_public_key(key)?;
    
    let result = verify_rsa(alg, public_key, &signature_bytes, message);
    Ok(result.is_ok())
}

/// Checks that a signature is valid based on the (n, e) RSA pubkey components
pub(crate) fn verify_from_components(
    alg: RsaVerificationAlgorithm,
    signature: &str,
    message: &[u8],
    components: (&[u8], &[u8]),
) -> Result<bool> {
    let signature_bytes = b64_decode(signature)?;
    
    // Create RSA public key from components
    let n = rsa::BigUint::from_bytes_be(components.0);
    let e = rsa::BigUint::from_bytes_be(components.1);
    
    let public_key = RsaPublicKey::new(n, e)
        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;

    let result = verify_rsa(alg, public_key, &signature_bytes, message);

    Ok(result.is_ok())
}
