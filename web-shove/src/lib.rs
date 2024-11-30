use std::{array::TryFromSliceError, rc::Rc};

use rand::prelude::*;
use ring::{
    agreement::{self, EphemeralPrivateKey},
    rand::SecureRandom,
};
use thiserror::Error;

const KEY_INFO: &[u8] = b"WebPush: info";
const CONTENT_ENCODING_KEY_INFO: &[u8] = b"Content-Encoding: aes128gcm\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";

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
    application_server_private_key: &[u8],
    user_agent_public_key: &[u8],
) -> [u8; 32] {
    let application_server_private_key: &[u8; 32] =
        application_server_private_key.try_into().unwrap();

    let user_agent_public_key: &[u8; 64] = &user_agent_public_key[1..].try_into().unwrap();

    let application_server_private_key =
        libcrux_ecdh::P256PrivateKey::from(application_server_private_key);

    let user_agent_public_key = libcrux_ecdh::P256PublicKey::from(user_agent_public_key);

    let shared_ecdh_secret =
        libcrux_ecdh::p256_derive(&user_agent_public_key, &application_server_private_key).unwrap();

    shared_ecdh_secret.0[..32].try_into().unwrap()
}

fn create_key_info(application_server_public_key: &[u8], user_agent_public_key: &[u8]) -> Rc<[u8]> {
    //TODO this can be fixed length
    let mut key_info = Vec::new();
    key_info.extend_from_slice(KEY_INFO);
    key_info.push(0x00);
    key_info.extend_from_slice(&user_agent_public_key);
    key_info.extend_from_slice(&application_server_public_key);
    // key_info.push(0x01);
    key_info.into()
}

fn create_content_encoding_key_info() {}

// 2591738300
// 2591738300
#[cfg(test)]
mod test {
    ///! Using the base64 url encoded values as the RFC uses them and they are subjectively easier to compare
    use super::*;
    mod rfc8291 {
        use super::super::*;
        use base64::prelude::*;

        const APPLICATION_SERVER_PRIVATE_KEY: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        const APPLICATION_SERVER_PUBLIC_KEY: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                                                 Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        const USER_AGENT_PUBLIC_KEY: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
                                         aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        const AUTHENTICATION_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";

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
            let application_server_private_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
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
            let application_server_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let expected_key_info = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVG\
                 q8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3\
                 ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew\
                 bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewP";

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

            let application_server_private_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap();
            let application_server_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(0x01);

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
            let salt = BASE64_URL_SAFE_NO_PAD
                .decode("DGv6ra1nlYgDCS1FRnbzlw")
                .unwrap();

            let application_server_private_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap();
            let application_server_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act
            let ecdh_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(0x01);

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
            let salt = BASE64_URL_SAFE_NO_PAD
                .decode("DGv6ra1nlYgDCS1FRnbzlw")
                .unwrap();

            let application_server_private_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap();
            let application_server_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(0x01);

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
            key_info.push(0x01);

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
            let salt = BASE64_URL_SAFE_NO_PAD
                .decode("DGv6ra1nlYgDCS1FRnbzlw")
                .unwrap();

            let application_server_private_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PRIVATE_KEY)
                .unwrap();
            let application_server_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(APPLICATION_SERVER_PUBLIC_KEY)
                .unwrap();

            let user_agent_public_key = BASE64_URL_SAFE_NO_PAD
                .decode(USER_AGENT_PUBLIC_KEY)
                .unwrap();

            let authentication_secret = BASE64_URL_SAFE_NO_PAD
                .decode(AUTHENTICATION_SECRET)
                .unwrap();

            // Act

            let ecdh_secret =
                create_shared_ecdh_secret(&application_server_private_key, &user_agent_public_key);
            let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);

            let key_info = create_key_info(&application_server_public_key, &user_agent_public_key);
            //TODO make fixed length
            let mut key_info = Vec::from(key_info.as_ref());
            key_info.push(0x01);

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
            key_info.push(0x01);

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
    }
}
