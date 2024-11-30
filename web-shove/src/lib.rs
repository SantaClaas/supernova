use std::{array::TryFromSliceError, rc::Rc};

use rand::prelude::*;
use ring::{
    agreement::{self, EphemeralPrivateKey},
    rand::SecureRandom,
};
use thiserror::Error;

const KEY_INFO: &[u8] = b"WebPush: info\0";
const NONCE_INFO: &[u8] = b"Content-Encoding: nonce\0";

//TODO use ring when we know it works and figure out deterministic key generation for testing as it only generates ephemeral keys
fn create_pseudo_random_key<'a>(
    application_server_private_key: &[u8],
    user_agent_public_key: &[u8],
    authentication_secret: &[u8],
) -> Rc<[u8]> {
    // let mut random = rand_chacha::ChaCha8Rng::seed_from_u64(69);
    // let random = ring::rand::SystemRandom::new();
    // EphemeralPrivateKey::generate(&agreement::ECDH_P256, &random);
    // let number: u32 = random.gen();
    // let mut buffer = [0u8; 4];
    // let number = random.fill(&mut buffer);
    // println!("My data is {:?}", buffer);
    // println!("My number is {number}");
    // EphemeralPrivateKey::generate(alg, rng)
    let application_server_key =
        libcrux_ecdh::P256PrivateKey::try_from(application_server_private_key).unwrap();

    // The first byte is a special byte that is used to identify the key type
    let user_agent_key =
        libcrux_ecdh::P256PublicKey::try_from(&user_agent_public_key[1..]).unwrap();

    let shared_key = libcrux_ecdh::p256_derive(&user_agent_key, &application_server_key).unwrap();

    // HKDF expand?
    // libcrux_hkdf::expand(libcrux_hkdf::Algorithm::Sha256, prk, info, okm_len)
    libcrux_hmac::hmac(
        libcrux_hmac::Algorithm::Sha256,
        application_server_private_key,
        authentication_secret,
        None,
    )
    .into()
    // libcrux_hkdf::hkdf(
    //     libcrux_hkdf::Algorithm::Sha256,
    //     authentication_secret,
    //     application_server_private_key,
    //     info,
    //     okm_len,
    // );
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

// 2591738300
// 2591738300
#[cfg(test)]
mod test {
    use base64::{
        prelude::{BASE64_URL_SAFE, BASE64_URL_SAFE_NO_PAD},
        Engine,
    };

    use super::*;

    const APPLICATION_SERVER_PRIVATE_KEY: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const USER_AGENT_PUBLIC_KEY: &str = "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx\
                                        aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const AUTHENTICATION_SECRET: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    #[ignore]
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
        let pseudo_random_key = create_pseudo_random_key(
            &application_server_private_key,
            &user_agent_public_key,
            &authentication_secret,
        );

        let encoded = BASE64_URL_SAFE.encode(pseudo_random_key);

        // Assert
        assert_eq!(EXPECTED_PSEUDO_RANDOM_KEY.len(), encoded.len());
        assert_eq!(EXPECTED_PSEUDO_RANDOM_KEY, encoded);
    }

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
}
