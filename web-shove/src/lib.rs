use std::{array::TryFromSliceError, rc::Rc};

use aes_gcm::{aead::AeadMut, KeyInit};
use rand::prelude::*;
use ring::{
    aead::BoundKey,
    agreement::{self, EphemeralPrivateKey},
    rand::SecureRandom,
};
use thiserror::Error;

const KEY_INFO: &[u8] = b"WebPush: info";
const CONTENT_ENCODING_KEY_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";

const PADDING_DELIMITER: u8 = 0x01;
const LAST_PADDING_DELIMITER: u8 = 0x02;

//TODO use ring when we know it works and figure out deterministic key generation for testing as it only generates ephemeral keys
fn create_pseudo_random_key(authentication_secret: &[u8], ecdh_secret: &[u8]) -> Rc<[u8]> {
    libcrux_hkdf::extract(
        libcrux_hkdf::Algorithm::Sha256,
        authentication_secret,
        ecdh_secret,
    )
    .into()
}

fn create_shared_ecdh_secret(
    application_server_private_key: &[u8; 32],
    user_agent_public_key: &[u8; 64],
) -> [u8; 32] {
    let application_server_private_key =
        libcrux_ecdh::P256PrivateKey::from(application_server_private_key);

    let user_agent_public_key = libcrux_ecdh::P256PublicKey::from(user_agent_public_key);

    let shared_ecdh_secret =
        libcrux_ecdh::p256_derive(&user_agent_public_key, &application_server_private_key).unwrap();

    shared_ecdh_secret.0[..32].try_into().unwrap()
}

fn create_key_info(
    application_server_public_key: &[u8; 65],
    user_agent_public_key: &[u8],
) -> Rc<[u8]> {
    //TODO this can be fixed length
    let mut key_info = Vec::new();
    key_info.extend_from_slice(KEY_INFO);
    key_info.push(0x00);
    key_info.extend_from_slice(user_agent_public_key);
    key_info.extend_from_slice(application_server_public_key);
    // key_info.push(0x01);
    key_info.into()
}

const SALT_LENGTH: usize = 16;
const RECORD_SIZE_LENGTH: usize = size_of::<u32>();
const KEY_ID_LENGTH: usize = size_of::<u8>();
mod experimental {

    /// Restrict key id to length of <=255 as defined by the specification but do it at compile time
    struct KeyId<const LENGTH: usize>([u8; LENGTH]);
    impl<const LENGTH: usize> KeyId<LENGTH> {
        pub fn new(key_id: [u8; LENGTH]) -> Self {
            const {
                assert!(
                    LENGTH <= u8::MAX as usize,
                    "Key id length is greater than 255"
                )
            };
            Self(key_id)
        }

        #[inline]
        pub const fn length() -> usize {
            LENGTH
        }
    }
    fn impossible() {
        let key = KeyId::<259>::new([0; 259]);
    }
}

fn create_content_encoding_header(
    salt: &[u8; SALT_LENGTH],
    record_size: &[u8; RECORD_SIZE_LENGTH],
    key_id: &[u8],
) -> Rc<[u8]> {
    let Ok(key_id_length) = key_id.len().try_into() else {
        todo!("Key id length has to be <= 255")
    };

    let mut buffer =
        Vec::with_capacity(SALT_LENGTH + RECORD_SIZE_LENGTH + KEY_ID_LENGTH + key_id.len());

    buffer.extend_from_slice(salt);
    buffer.extend_from_slice(record_size);
    buffer.push(key_id_length);
    buffer.extend_from_slice(key_id);

    buffer.into()
}

fn encrypt_plain_text(key: &[u8], plaintext: &[u8], nonce: &[u8]) -> Rc<[u8]> {
    // let Ok(key) = key..try_into() else {
    //     todo!("Key has to be 16 bytes")
    // };

    // let key = ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, key).unwrap();
    // ring::aead::SealingKey::new(key, nonce)

    let mut cipher = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext).unwrap().into()
}

#[cfg(test)]
mod test {
    /// Using the base64 url encoded values as the RFC uses them and they are subjectively easier to compare
    mod rfc8291 {
        use super::super::*;
        use base64::prelude::*;

        const APPLICATION_SERVER_PRIVATE_KEY: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        const APPLICATION_SERVER_PUBLIC_KEY: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                                                 Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        const USER_AGENT_PUBLIC_KEY: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
                                         aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        const AUTHENTICATION_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
        const RECORD_SIZE: [u8; 4] = 4096u32.to_be_bytes();
        const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";

        const PLAINTEXT: &str = "When I grow up, I want to be a watermelon";

        #[test]
        fn can_produce_shared_ecdh_secret() {
            // Arrange
            let expected_shared_ecdh_secret = BASE64_URL_SAFE_NO_PAD
                .decode("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")
                .unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap()[1..]
                .try_into()
                .unwrap();

            // Act

            let shared_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);

            // Assert
            assert_eq!(expected_shared_ecdh_secret, shared_secret);
        }

        #[test]
        fn can_crate_pseudo_random_key_for_combining() {
            // Arrange
            const EXPECTED_PSEUDO_RANDOM_KEY: &str = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k";

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap()[1..]
                .try_into()
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act
            let ecdh_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);

            let pseudo_random_key = libcrux_hkdf::extract(
                libcrux_hkdf::Algorithm::Sha256,
                authentication_secret,
                ecdh_secret,
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(pseudo_random_key);
            // Assert
            assert_eq!(EXPECTED_PSEUDO_RANDOM_KEY, encoded);
        }

        #[test]
        fn can_create_info_for_key_combining() {
            // Arrange
            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let expected_key_info = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVG\
                 q8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3\
                 ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew\
                 bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP";

            // V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0EwbZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP
            // V2ViUHVzaDogaW5mbwAEJXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3ylkYfpJGmQ22ggCLDv4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8
            // Act
            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(key_info);

            // Assert
            assert_eq!(expected_key_info, encoded);
        }

        #[test]
        fn can_crate_input_keying_material_for_content_encryption_key_derivation() {
            // Arrange
            let expected_input_keying_material = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";
            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();
            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );

            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(input_keying_material);
            // Assert
            assert_eq!(expected_input_keying_material, encoded);
        }

        #[test]
        fn can_create_pseudo_random_key_for_content_encryption() {
            // Arrange
            let expected_pseudo_random_key: &str = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";
            let salt = BASE64_URL_SAFE_NO_PAD.decode(SALT).unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &salt,
                &input_keying_material,
                None,
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(pseudo_random_key);

            // Assert
            assert_eq!(expected_pseudo_random_key, encoded);
        }

        #[test]
        fn can_create_info_for_content_encryption_key_derivation() {
            // Arrange
            let expected_cek_info = "Q29udGVudC1FbmNvZGluZzogYWVzMTI4Z2NtAA";
            // Act
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(CONTENT_ENCODING_KEY_INFO);
            // Assert
            assert_eq!(expected_cek_info, encoded);
        }

        #[test]
        fn can_create_content_encryption_key() {
            // Arrange
            let expected_content_encryption_key = "oIhVW04MRdy2XN9CiKLxTg";
            let salt = BASE64_URL_SAFE_NO_PAD.decode(SALT).unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &salt,
                &input_keying_material,
                None,
            );
            //TODO make fixed length
            let mut key_info = Vec::from(CONTENT_ENCODING_KEY_INFO);
            key_info.push(PADDING_DELIMITER);

            let content_encryption_key = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(16),
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(content_encryption_key);
            // Assert
            assert_eq!(expected_content_encryption_key, encoded)
        }

        #[test]
        fn can_create_info_for_content_encryption_nonce_derivation() {
            // Arrange
            let expected_nonce_info = "Q29udGVudC1FbmNvZGluZzogbm9uY2UA";
            // Act
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(NONCE_INFO);
            // Assert
            assert_eq!(expected_nonce_info, encoded);
        }

        #[test]
        fn can_create_nonce() {
            // Arrange
            let expected_nonce = "4h_95klXJ5E_qnoN";
            let salt = BASE64_URL_SAFE_NO_PAD.decode(SALT).unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &salt,
                &input_keying_material,
                None,
            );
            //TODO make fixed length
            let mut key_info = Vec::from(NONCE_INFO);
            key_info.push(PADDING_DELIMITER);

            let nonce = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(12),
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(nonce);
            // Assert
            assert_eq!(expected_nonce, encoded)
        }

        #[test]
        fn can_create_content_encoding_header() {
            // Arrange
            let expexted_content_encoding_header =
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtk\
                gcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";

            let salt = BASE64_URL_SAFE_NO_PAD
                .decode(SALT)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            // Act
            let header =
                create_content_encoding_header(&salt, &RECORD_SIZE, &application_server_public_key);
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(header);

            // Assert
            assert_eq!(expexted_content_encoding_header, encoded);
        }

        #[test]
        fn can_create_push_message_plaintext() {
            // Arrange
            let expected_push_message_plaintext =
                "V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24C";

            // Act

            let mut buffer = Vec::from(PLAINTEXT);
            buffer.push(LAST_PADDING_DELIMITER);
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(buffer);

            // Assert
            assert_eq!(expected_push_message_plaintext, encoded);
        }

        #[test]
        fn can_aes128gcm_encrypt_plaintext() {
            // Arrange
            let expected_ciphertext =
                "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";
            let salt = BASE64_URL_SAFE_NO_PAD.decode(SALT).unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &salt,
                &input_keying_material,
                None,
            );
            //TODO make fixed length
            let mut key_info = Vec::from(CONTENT_ENCODING_KEY_INFO);
            key_info.push(PADDING_DELIMITER);

            let content_encryption_key = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(16),
            );

            //TODO make fixed length
            let mut plaintext = Vec::from(PLAINTEXT);
            plaintext.push(LAST_PADDING_DELIMITER);

            //TODO make fixed length
            let mut key_info = Vec::from(NONCE_INFO);
            key_info.push(PADDING_DELIMITER);

            let nonce = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(12),
            );

            assert_eq!(12, nonce.len());
            let ciphertext = encrypt_plain_text(content_encryption_key, &plaintext, nonce);

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);

            // Assert
            assert_eq!(expected_ciphertext, encoded)
        }

        #[test]
        fn can_produce_rfc8291_section_5_result() {
            // Arrange
            let expected_result =
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
                mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
                pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

            let salt = BASE64_URL_SAFE_NO_PAD.decode(SALT).unwrap();

            let application_server_private_key: [u8; 32] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let application_server_public_key: [u8; 65] = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap()
                .try_into()
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &application_server_private_key,
                user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(PADDING_DELIMITER);

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &salt,
                &input_keying_material,
                None,
            );
            //TODO make fixed length
            let mut key_info = Vec::from(CONTENT_ENCODING_KEY_INFO);
            key_info.push(PADDING_DELIMITER);

            let content_encryption_key = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(16),
            );

            //TODO make fixed length
            let mut plaintext = Vec::from(PLAINTEXT);
            plaintext.push(LAST_PADDING_DELIMITER);

            //TODO make fixed length
            let mut key_info = Vec::from(NONCE_INFO);
            key_info.push(PADDING_DELIMITER);

            let nonce = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(12),
            );

            assert_eq!(12, nonce.len());
            let ciphertext = encrypt_plain_text(content_encryption_key, &plaintext, nonce);
            let header = create_content_encoding_header(
                &salt.try_into().unwrap(),
                &RECORD_SIZE,
                &application_server_public_key,
            );

            let mut buffer = Vec::from(header.as_ref());
            buffer.extend_from_slice(ciphertext.as_ref());
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(buffer);

            // Assert
            assert_eq!(expected_result, encoded)
        }
    }
}
