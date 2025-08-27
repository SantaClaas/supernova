use aes_gcm::{aead::AeadMutInPlace, aes::cipher::InvalidLength, KeyInit};

use crate::{LAST_PADDING_DELIMITER, PADDING_DELIMITER};

const SALT_LENGTH: usize = 16;

// struct Test<const SIZE: usize>([u8; SIZE]);
// struct Header<const KEY_ID_SIZE: usize> {
//     salt: [u8; SALT_LENGTH],
//     record_size: u32,
//     key_id: [u8; KEY_ID_SIZE],
//     test: Test<{ 3 + KEY_ID_SIZE }>,
// }

// struct Content<const RECORD_SIZE: usize> {
//     content: [u8; RECORD_SIZE],
// }
struct EncryptionKey([u8; 16]);

struct Nonce([u8; 12]);
trait CryptographyProvider {
    type Error;
    fn aes_128_gcm_encrypt(
        &self,
        plain_text: &mut [u8],
        key: &EncryptionKey,
        nonce: &Nonce,
    ) -> Result<(), Self::Error>;
}

struct RustCryptoProvider;
enum RustCryptoProviderError {
    BadPlainTextLength,
    InvalidKeyLength(InvalidLength),
    InsufficientCapacity(aes_gcm::Error),
}

impl CryptographyProvider for RustCryptoProvider {
    type Error = RustCryptoProviderError;

    fn aes_128_gcm_encrypt(
        &self,
        original_plain_text: &mut [u8],
        EncryptionKey(key): &EncryptionKey,
        Nonce(nonce): &Nonce,
    ) -> Result<(), Self::Error> {
        //TODO this is not ergonomic
        let mut plain_text = aes_gcm::aead::heapless::Vec::<u8, 4096>::new();

        for byte in &original_plain_text[..original_plain_text.len() - 16] {
            plain_text
                .push(*byte)
                .map_err(|_| RustCryptoProviderError::BadPlainTextLength)?;
        }

        let mut cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
            .map_err(RustCryptoProviderError::InvalidKeyLength)?;

        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher
            .encrypt_in_place(nonce, Default::default(), &mut plain_text)
            .map_err(RustCryptoProviderError::InsufficientCapacity)?;

        //TODO this will panic for usecases outside of demo
        original_plain_text.copy_from_slice(plain_text.as_slice());

        Ok(())
    }
}
struct CipherText {
    content: [u8; 4096],
    length: usize,
}

struct Record {
    content: [u8; 4096],
    length: usize,
}

impl Record {
    const PADDING_LENGTH: usize = 17;
    const PADDING_DELIMITER: u8 = 0x01;
    const LAST_PADDING_DELIMITER: u8 = 0x02;

    fn new() -> Self {
        Self {
            content: [0; 4096],
            length: 0,
        }
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.content.len()
    }

    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), ()> {
        if self.length + other.len() + Self::PADDING_LENGTH > self.capacity() {
            return Err(());
        }

        for byte in other {
            self.content[self.length] = *byte;
            self.length += 1;
        }

        Ok(())
    }

    fn encrypt(
        mut self,
        provider: &impl CryptographyProvider,
        is_last: bool,
        key: &EncryptionKey,
        nonce: &Nonce,
    ) -> Result<CipherText, ()> {
        self.content[self.length] = if is_last {
            LAST_PADDING_DELIMITER
        } else {
            PADDING_DELIMITER
        };

        let new_length = self.length + Self::PADDING_LENGTH;
        let mut buffer = &mut self.content[..new_length];

        provider.aes_128_gcm_encrypt(&mut buffer, key, nonce);

        Ok(CipherText {
            content: self.content,
            length: new_length,
        })
    }
}

#[cfg(test)]
mod test {
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use ring::aead::NONCE_LEN;

    use super::*;
    #[test]
    fn can_run_rfc_8188_example() {
        // Arrange
        const PLAIN_TEXT: &[u8] = b"I am the walrus";
        const EXPECETD_CONTENT: &str =
            "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg";

        let pseudo_random_key = EncryptionKey(
            BASE64_URL_SAFE_NO_PAD
                .decode("_wniytB-ofscZDh4tbSjHw")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let nonce = Nonce(
            BASE64_URL_SAFE_NO_PAD
                .decode("Bcs8gkIRKLI8GeI8")
                .unwrap()
                .try_into()
                .unwrap(),
        );

        let provider = RustCryptoProvider;
        // Act
        let mut content = Record::new();
        content.extend_from_slice(PLAIN_TEXT).unwrap();

        let encrypted = content
            .encrypt(&provider, true, &pseudo_random_key, &nonce)
            .unwrap();
        let actual = BASE64_URL_SAFE_NO_PAD.encode(&encrypted.content);

        // Assert
        assert_eq!(EXPECETD_CONTENT, actual);
    }
}
