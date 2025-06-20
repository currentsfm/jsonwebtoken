use jsonwebtoken::{
    decode, encode, get_current_timestamp, Algorithm, DecodingKey, EncodingKey, Validation,
};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: u64,
}

fn main() {
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key = signing_key.verifying_key();

    let private_key_der = signing_key.to_pkcs8_der().unwrap();
    let public_key_der = verifying_key.to_public_key_der().unwrap();

    let encoding_key = EncodingKey::from_ed_der(private_key_der.as_bytes());
    let decoding_key = DecodingKey::from_ed_der(public_key_der.as_bytes());

    let claims = Claims { sub: "test".to_string(), exp: get_current_timestamp() };

    let token =
        encode(&jsonwebtoken::Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

    let validation = Validation::new(Algorithm::EdDSA);
    let _token_data = decode::<Claims>(&token, &decoding_key, &validation).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Jot {
        encoding_key: EncodingKey,
        decoding_key: DecodingKey,
    }

    impl Jot {
        fn new() -> Jot {
            // Generate a new Ed25519 signing key
            let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let verifying_key = signing_key.verifying_key();

            // Convert to PKCS8 DER format for use with jsonwebtoken
            let private_key_der = signing_key.to_pkcs8_der().unwrap();
            let public_key_der = verifying_key.to_public_key_der().unwrap();

            let encoding_key = EncodingKey::from_ed_der(private_key_der.as_bytes());
            let decoding_key = DecodingKey::from_ed_der(public_key_der.as_bytes());

            Jot { encoding_key, decoding_key }
        }
    }

    #[test]
    fn test() {
        let jot = Jot::new();
        let claims = Claims { sub: "test".to_string(), exp: get_current_timestamp() };

        let token =
            encode(&jsonwebtoken::Header::new(Algorithm::EdDSA), &claims, &jot.encoding_key)
                .unwrap();

        let validation = Validation::new(Algorithm::EdDSA);
        let token_data = decode::<Claims>(&token, &jot.decoding_key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "test");
    }
}
