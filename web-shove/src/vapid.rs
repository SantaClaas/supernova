use std::sync::Arc;

///! Voluntary Application Server Identification for Web Push (VAPID) based on RFC8292.
use aes_gcm::aead::OsRng;
use p256::ecdsa::SigningKey;

#[derive(Clone)]
pub struct Vapid {
    pub subject: Arc<str>,
    pub private_key: Arc<[u8; 32]>,
    pub public_key: Arc<[u8; 65]>,
}

impl Vapid {
    pub fn generate(email: &str) -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = private_key.verifying_key();

        let private_bytes = private_key.to_bytes();
        assert_eq!(32, private_bytes.len());
        let private_bytes = private_bytes.try_into().unwrap();
        let point = public_key.to_encoded_point(false);
        let public_bytes: &[u8] = point.as_bytes();
        assert_eq!(65, public_bytes.len());
        assert_eq!(0x04, public_bytes[0]);
        let public_bytes: [u8; 65] = public_bytes.try_into().unwrap();

        Self {
            subject: format!("emailto:{}", email).into(),
            private_key: Arc::new(private_bytes),
            public_key: Arc::new(public_bytes),
        }
    }

    pub fn with_private_key(email: &str, private_key: &[u8; 32]) -> Self {
        let private_key = SigningKey::from_bytes(private_key.into()).unwrap();
        let public_key = private_key.verifying_key();
        let private_bytes = private_key.to_bytes();
        let private_bytes = private_bytes.try_into().unwrap();
        let point = public_key.to_encoded_point(false);
        let public_bytes = point.as_bytes();
        assert_eq!(65, public_bytes.len());
        assert_eq!(0x04, public_bytes[0]);
        let public_bytes: [u8; 65] = public_bytes.try_into().unwrap();

        Self {
            subject: format!("emailto:{}", email).into(),
            private_key: Arc::new(private_bytes),
            public_key: Arc::new(public_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_keys() {
        Vapid::generate("emailto:example@example.com");
    }
}
