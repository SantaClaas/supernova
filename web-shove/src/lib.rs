use std::{rc::Rc, time::Duration};

use aes_gcm::{
    aead::{heapless, AeadMutInPlace, OsRng},
    KeyInit,
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand_chacha::rand_core::RngCore;
use ring::rand::{self, SecureRandom};
use time::OffsetDateTime;
pub mod authorization_header;
mod encrypted_content_encoding;
mod experiments;
pub mod vapid;

const KEY_INFO: &[u8; 13] = b"WebPush: info";
const CONTENT_ENCODING_KEY_INFO: &[u8; 29] = b"Content-Encoding: aes128gcm\x00\x01";
/// Nonce information with padding delimiter
const NONCE_INFO: &[u8; 25] = b"Content-Encoding: nonce\x00\x01";

const PADDING_DELIMITER: u8 = 0x01;
const LAST_PADDING_DELIMITER: u8 = 0x02;
const PUBLIC_KEY_LENGTH: usize = 65;
const PRIVATE_KEY_LENGTH: usize = 32;
//TODO check if record size is fixed
const RECORD_SIZE: [u8; 4] = 4096u32.to_be_bytes();

pub struct PushMessageParameters {
    pub salt: [u8; 16],
    pub application_server_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub content: Vec<u8>,
}

pub fn create_push_message_payload(
    plaintext: &[u8],
    user_agent_public_key: &[u8; PUBLIC_KEY_LENGTH],
    authentication_secret: &[u8; 16],
) -> PushMessageParameters {
    // Temporary keys for Elliptic Curve Diffie-Hellman key exchange
    let (application_server_private_key, mut application_server_public_key) =
        libcrux_ecdh::key_gen(libcrux_ecdh::Algorithm::P256, &mut OsRng).unwrap();

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let application_server_private_key = &application_server_private_key.try_into().unwrap();
    //TODO solve this a better way instead of shifting all 64 bytes
    // Insert the 0x04 byte for the uncompressed point encoding
    application_server_public_key.insert(0, 0x04);
    let application_server_public_key = &application_server_public_key.try_into().unwrap();

    let ecdh_secret = create_shared_ecdh_secret(
        application_server_private_key,
        user_agent_public_key[1..].try_into().unwrap(),
    );

    let key_info = create_key_info(application_server_public_key, user_agent_public_key);

    // # HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
    let pseudo_random_key = create_pseudo_random_key(&authentication_secret, &ecdh_secret);
    // # HKDF-Expand(PRK_key, key_info, L_key=32)
    let input_keying_material = libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        &pseudo_random_key,
        &key_info,
        Some(32),
    );

    // # HKDF-Extract(salt, IKM)
    let pseudo_random_key = libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        &salt,
        &input_keying_material,
        None,
    );

    // # HKDF-Expand(PRK, cek_info, L_cek=16)
    let content_encryption_key: &[u8; 16] = &libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        &pseudo_random_key,
        CONTENT_ENCODING_KEY_INFO,
        Some(16),
    )
    .try_into()
    .unwrap();

    let nonce: &[u8; 12] = &libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        &pseudo_random_key,
        NONCE_INFO,
        Some(12),
    )
    .try_into()
    .unwrap();

    assert_eq!(12, nonce.len());
    //TODO add padding to payload/plaintext?
    let ciphertext = encrypt_plain_text(content_encryption_key, &plaintext, nonce);
    let header = create_content_encoding_header(
        &salt,
        // Size might be fixed to add padding to avoid side channel by checking message size?
        &RECORD_SIZE,
        &application_server_public_key,
    );

    //TODO reduce allocation
    let mut buffer = Vec::with_capacity(CONTENT_ENCODING_HEADER_LENGTH + ciphertext.len());

    buffer.extend_from_slice(header.as_ref());
    buffer.extend_from_slice(ciphertext.as_ref());

    PushMessageParameters {
        salt,
        application_server_public_key: *application_server_public_key,
        content: buffer,
    }
}

//TODO use ring when we know it works and figure out deterministic key generation for testing as it only generates ephemeral keys
fn create_pseudo_random_key(authentication_secret: &[u8; 16], ecdh_secret: &[u8; 32]) -> [u8; 32] {
    libcrux_hkdf::extract(
        libcrux_hkdf::Algorithm::Sha256,
        authentication_secret,
        ecdh_secret,
    )
    .try_into()
    .expect("Expected 32 bytes for SHA256")
}

fn create_shared_ecdh_secret(
    application_server_private_key: &[u8; PRIVATE_KEY_LENGTH],
    user_agent_public_key: &[u8; 64],
) -> [u8; 32] {
    let application_server_private_key =
        libcrux_ecdh::P256PrivateKey::from(application_server_private_key);

    let user_agent_public_key = libcrux_ecdh::P256PublicKey::from(user_agent_public_key);

    let shared_ecdh_secret =
        libcrux_ecdh::p256_derive(&user_agent_public_key, &application_server_private_key).unwrap();

    shared_ecdh_secret.0[..32].try_into().unwrap()
}

const KEY_INFO_LENGTH: usize = KEY_INFO.len() + 1 + PUBLIC_KEY_LENGTH * 2 + 1;
fn create_key_info(
    application_server_public_key: &[u8; PUBLIC_KEY_LENGTH],
    user_agent_public_key: &[u8; PUBLIC_KEY_LENGTH],
) -> [u8; KEY_INFO_LENGTH] {
    let mut key_info = [0u8; KEY_INFO_LENGTH];
    key_info[..KEY_INFO.len()].copy_from_slice(KEY_INFO);
    // This is already zeroed
    // key_info[KEY_INFO.len()] = 0x00;
    key_info[KEY_INFO.len() + 1..KEY_INFO.len() + 1 + PUBLIC_KEY_LENGTH]
        .copy_from_slice(user_agent_public_key);
    key_info[KEY_INFO.len() + 1 + PUBLIC_KEY_LENGTH..KEY_INFO.len() + 1 + PUBLIC_KEY_LENGTH * 2]
        .copy_from_slice(application_server_public_key);
    key_info[KEY_INFO.len() + 1 + PUBLIC_KEY_LENGTH * 2] = PADDING_DELIMITER;

    key_info
}

const SALT_LENGTH: usize = 16;
const RECORD_SIZE_LENGTH: usize = size_of::<u32>();
const KEY_ID_LENGTH: usize = size_of::<u8>();

const CONTENT_ENCODING_HEADER_LENGTH: usize =
    SALT_LENGTH + RECORD_SIZE_LENGTH + KEY_ID_LENGTH + PUBLIC_KEY_LENGTH;
fn create_content_encoding_header(
    salt: &[u8; SALT_LENGTH],
    record_size: &[u8; RECORD_SIZE_LENGTH],
    key_id: &[u8; PUBLIC_KEY_LENGTH],
) -> [u8; CONTENT_ENCODING_HEADER_LENGTH] {
    let mut header = [0; CONTENT_ENCODING_HEADER_LENGTH];
    header[..SALT_LENGTH].copy_from_slice(salt);
    header[SALT_LENGTH..SALT_LENGTH + RECORD_SIZE_LENGTH].copy_from_slice(record_size);

    const {
        assert!(
            PUBLIC_KEY_LENGTH <= u8::MAX as usize,
            "Public key can not be longer than 255 because the length field is only one byte long"
        );
    }
    header[SALT_LENGTH + RECORD_SIZE_LENGTH] = PUBLIC_KEY_LENGTH as u8;
    header[SALT_LENGTH + RECORD_SIZE_LENGTH + KEY_ID_LENGTH..].copy_from_slice(key_id);
    header
}

fn encrypt_plain_text(key: &[u8; 16], plaintext: &[u8], nonce: &[u8; 12]) -> Rc<[u8]> {
    //TODO no allocation like below
    // 42 plaintext length + 16 key length + 12 nonce length = 58??
    // or is it 42 + 12 + 4?
    // let mut buffer: heapless::Vec<u8, 58> = heapless::Vec::new();
    // buffer.extend_from_slice(plaintext).unwrap();
    // let mut cipher = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    // let nonce = aes_gcm::Nonce::from_slice(nonce);
    // cipher
    //     .encrypt_in_place(nonce, Default::default(), &mut buffer)
    //     .unwrap();

    // buffer.into_array().unwrap()

    // Quick and dirty attempt to fix
    let mut plaintext = Vec::from(plaintext);
    plaintext.push(LAST_PADDING_DELIMITER);
    let plaintext = &plaintext;

    let mut buffer = Vec::with_capacity(plaintext.len() + 16);
    buffer.extend_from_slice(plaintext);
    let mut cipher = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap();
    let nonce = aes_gcm::Nonce::from_slice(nonce);
    cipher
        .encrypt_in_place(nonce, Default::default(), &mut buffer)
        .unwrap();

    assert_eq!(buffer.len(), plaintext.len() + 16);

    Rc::from(buffer)
}

#[cfg(test)]
mod test {
    /// Using the base64 url encoded values as the RFC uses them, and they are subjectively easier to compare
    mod rfc_8291 {
        use super::super::*;
        use base64::prelude::*;
        use rstest::{fixture, rstest};

        const APPLICATION_SERVER_PRIVATE_KEY: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        const APPLICATION_SERVER_PUBLIC_KEY: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                                                 Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        const USER_AGENT_PUBLIC_KEY: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
                                         aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
        const AUTHENTICATION_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
        const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";

        const PLAINTEXT: &str = "When I grow up, I want to be a watermelon";

        struct Fixture {
            application_server_private_key: [u8; PRIVATE_KEY_LENGTH],
            application_server_public_key: [u8; PUBLIC_KEY_LENGTH],
            user_agent_public_key: [u8; PUBLIC_KEY_LENGTH],
            authentication_secret: [u8; 16],
            salt: [u8; 16],
        }

        #[fixture]
        fn rfc_8291_example() -> Fixture {
            Fixture {
                application_server_private_key: BASE64_URL_SAFE_NO_PAD
                    .decode(APPLICATION_SERVER_PRIVATE_KEY)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                application_server_public_key: BASE64_URL_SAFE_NO_PAD
                    .decode(APPLICATION_SERVER_PUBLIC_KEY)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                user_agent_public_key: BASE64_URL_SAFE_NO_PAD
                    .decode(USER_AGENT_PUBLIC_KEY)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                authentication_secret: BASE64_URL_SAFE_NO_PAD
                    .decode(AUTHENTICATION_SECRET)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                salt: BASE64_URL_SAFE_NO_PAD
                    .decode(SALT)
                    .unwrap()
                    .try_into()
                    .unwrap(),
            }
        }

        #[rstest]
        fn can_produce_shared_ecdh_secret(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expected_shared_ecdh_secret = BASE64_URL_SAFE_NO_PAD
                .decode("kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs")
                .unwrap();

            // Act

            let shared_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );

            // Assert
            assert_eq!(expected_shared_ecdh_secret, shared_secret);
        }

        #[rstest]
        fn can_crate_pseudo_random_key_for_combining(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            const EXPECTED_PSEUDO_RANDOM_KEY: &str = "Snr3JMxaHVDXHWJn5wdC52WjpCtd2EIEGBykDcZW32k";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                &fixture.user_agent_public_key[1..].try_into().unwrap(),
            );

            let pseudo_random_key = libcrux_hkdf::extract(
                libcrux_hkdf::Algorithm::Sha256,
                fixture.authentication_secret,
                ecdh_secret,
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(pseudo_random_key);
            // Assert
            assert_eq!(EXPECTED_PSEUDO_RANDOM_KEY, encoded);
        }

        #[rstest]
        fn can_create_info_for_key_combining(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange

            // Added the "AQ" at the end which differs from the RFC example because the key info is always used with the
            // 0x01 delimiter at the end
            let expected_key_info = "V2ViUHVzaDogaW5mbwAEJXGyvs3942BVG\
                 q8e0PTNNmwRzr5VX4m8t7GGpTM5FzFo7OLr4BhZe9MEebhuPI-OztV3\
                 ylkYfpJGmQ22ggCLDgT-M_SrDepxkU21WCP3O1SUj0Ew\
                 bZIHMtu5pZpTKGSCIA5Zent7wmC6HCJ5mFgJkuk5cwAvMBKiiujwa7t45ewPAQ";

            // Act
            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(key_info);

            // Assert
            assert_eq!(expected_key_info, encoded);
        }

        #[rstest]
        fn can_crate_input_keying_material_for_content_encryption_key_derivation(
            #[from(rfc_8291_example)] fixture: Fixture,
        ) {
            // Arrange
            let expected_input_keying_material = "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg";

            // Act

            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );

            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

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

        #[rstest]
        fn can_create_pseudo_random_key_for_content_encryption(
            #[from(rfc_8291_example)] fixture: Fixture,
        ) {
            // Arrange
            let expected_pseudo_random_key: &str = "09_eUZGrsvxChDCGRCdkLiDXrReGOEVeSCdCcPBSJSc";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &fixture.salt,
                &input_keying_material,
                None,
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(pseudo_random_key);

            // Assert
            assert_eq!(expected_pseudo_random_key, encoded);
        }

        #[rstest]
        fn can_create_content_encryption_key(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expected_content_encryption_key = "oIhVW04MRdy2XN9CiKLxTg";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &fixture.salt,
                &input_keying_material,
                None,
            );

            let content_encryption_key = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                CONTENT_ENCODING_KEY_INFO,
                Some(16),
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(content_encryption_key);
            // Assert
            assert_eq!(expected_content_encryption_key, encoded)
        }

        #[rstest]
        fn can_create_nonce(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expected_nonce = "4h_95klXJ5E_qnoN";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &fixture.salt,
                &input_keying_material,
                None,
            );

            let nonce = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                NONCE_INFO,
                Some(12),
            );

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(nonce);
            // Assert
            assert_eq!(expected_nonce, encoded)
        }

        #[rstest]
        fn can_create_content_encoding_header(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expexted_content_encoding_header =
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtk\
                gcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";

            // Act
            let header = create_content_encoding_header(
                &fixture.salt,
                &RECORD_SIZE,
                &fixture.application_server_public_key,
            );
            let encoded = BASE64_URL_SAFE_NO_PAD.encode(header);

            // Assert
            assert_eq!(expexted_content_encoding_header, encoded);
        }

        #[rstest]
        fn can_aes128gcm_encrypt_plaintext(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expected_ciphertext =
                "8pfeW0KbunFT06SuDKoJH9Ql87S1QUrdirN6GcG7sFz1y1sqLgVi1VhjVkHsUoEsbI_0LpXMuGvnzQ";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );
            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &fixture.salt,
                &input_keying_material,
                None,
            );

            let content_encryption_key = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                CONTENT_ENCODING_KEY_INFO,
                Some(16),
            )
            .try_into()
            .unwrap();

            let nonce: &[u8; 12] = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                NONCE_INFO,
                Some(12),
            )
            .try_into()
            .unwrap();

            assert_eq!(12, nonce.len());
            let ciphertext =
                encrypt_plain_text(content_encryption_key, PLAINTEXT.as_bytes(), nonce);

            let encoded = BASE64_URL_SAFE_NO_PAD.encode(ciphertext);

            // Assert
            assert_eq!(expected_ciphertext, encoded)
        }

        #[rstest]
        fn can_produce_rfc8291_section_5_result(#[from(rfc_8291_example)] fixture: Fixture) {
            // Arrange
            let expected_result =
                "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml\
                mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT\
                pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

            // Act
            let ecdh_secret = create_shared_ecdh_secret(
                &fixture.application_server_private_key,
                fixture.user_agent_public_key[1..].try_into().unwrap(),
            );
            let key_info = create_key_info(
                &fixture.application_server_public_key,
                &fixture.user_agent_public_key,
            );

            // # HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
            let pseudo_random_key =
                create_pseudo_random_key(&fixture.authentication_secret, &ecdh_secret);

            // # HKDF-Expand(PRK_key, key_info, L_key=32)
            let input_keying_material = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                &key_info,
                Some(32),
            );

            // # HKDF-Extract(salt, IKM)
            let pseudo_random_key = libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &fixture.salt,
                &input_keying_material,
                None,
            );

            // # HKDF-Expand(PRK, cek_info, L_cek=16)
            let content_encryption_key: &[u8; 16] = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                CONTENT_ENCODING_KEY_INFO,
                Some(16),
            )
            .try_into()
            .unwrap();

            let nonce: &[u8; 12] = &libcrux_hmac::hmac(
                libcrux_hmac::Algorithm::Sha256,
                &pseudo_random_key,
                NONCE_INFO,
                Some(12),
            )
            .try_into()
            .unwrap();

            assert_eq!(12, nonce.len());

            let ciphertext =
                encrypt_plain_text(content_encryption_key, PLAINTEXT.as_bytes(), nonce);
            let header = create_content_encoding_header(
                &fixture.salt,
                &RECORD_SIZE,
                &fixture.application_server_public_key,
            );

            let mut buffer = Vec::with_capacity(header.len() + ciphertext.len());
            // let mut buffer = Vec::from(header.as_ref());
            buffer.extend_from_slice(header.as_ref());
            buffer.extend_from_slice(ciphertext.as_ref());
            let actual = BASE64_URL_SAFE_NO_PAD.encode(buffer);

            // Assert
            assert_eq!(expected_result, actual)
        }
    }
}
