use std::time::SystemTime;

use crate::{PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use base64::prelude::*;
use http::{header, HeaderName, HeaderValue};
use josekit::{
    jws::JwsHeader,
    jwt::{self, JwtPayload},
};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use time::OffsetDateTime;

//TODO support urgency header
pub enum Subject<'a> {
    Email(&'a str),
    Https(&'a str),
}

pub struct TokenData<'a> {
    pub subject: Subject<'a>,
    pub push_service_origin: &'a str,
    pub not_before: OffsetDateTime,
    pub expires: OffsetDateTime,
    pub issued_at: OffsetDateTime,
}

impl<'a> TokenData<'a> {
    fn encode(&self) -> String {
        let formatted = format!(
            r#"{{"aud":"{audience}","exp":"{expires}","sub":"{subject}"}}"#,
            audience = self.push_service_origin,
            // not_before = self.not_before.unix_timestamp(),
            expires = self.expires.unix_timestamp(),
            // issued_at = self.issued_at.unix_timestamp(),
            subject = match self.subject {
                Subject::Email(email) => format!(r#"mailto:{}"#, email),
                Subject::Https(https) => format!(r#"{}"#, https),
            }
        );

        BASE64_URL_SAFE_NO_PAD.encode(formatted.as_bytes())
    }
}

fn create_jwt(data: TokenData, private_key: &[u8; PRIVATE_KEY_LENGTH]) -> String {
    //TODO check if subject is optional
    const JWT_INFO: &str = r#"{"typ":"JWT","alg":"ES256"}"#;
    let jwt_info = BASE64_URL_SAFE_NO_PAD.encode(JWT_INFO);
    // Can not be more than 24 hours
    // Just naively format a string
    let jwt_data = data.encode();
    let signing_material = format!("{}.{}", jwt_info, jwt_data);

    let key = SigningKey::from_slice(private_key).unwrap();

    let signature: Signature = key.sign(signing_material.as_bytes());
    //TODO why is there only to_vec and no slice
    let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.to_vec());
    let token = format!("{}.{}", signing_material, signature);

    token
}
fn create_jwt_2(
    data: TokenData,
    private_key: &[u8; PRIVATE_KEY_LENGTH],
    public_key: &[u8; PUBLIC_KEY_LENGTH],
) -> String {
    let mut header = JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm("ES256");

    let jwk = format!(
        r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","d":"{d}"}}"#,
        x = BASE64_URL_SAFE_NO_PAD.encode(&public_key[1..33]),
        y = BASE64_URL_SAFE_NO_PAD.encode(&public_key[33..65]),
        d = BASE64_URL_SAFE_NO_PAD.encode(&private_key)
    );

    println!("{jwk}");

    let jwk = josekit::jwk::Jwk::from_bytes(jwk.as_bytes()).unwrap();

    let now = SystemTime::now();
    let mut payload = JwtPayload::new();
    payload.set_audience(vec![data.push_service_origin]);
    payload.set_not_before(&now);
    payload.set_expires_at(&(now + time::Duration::minutes(30)));
    payload.set_issued_at(&now);
    payload.set_subject(match data.subject {
        Subject::Email(email) => format!(r#"mailto:{}"#, email),
        Subject::Https(https) => format!(r#"{}"#, https),
    });

    let signer = josekit::jws::ES256.signer_from_jwk(&jwk).unwrap();
    let encoded = jwt::encode_with_signer(&payload, &header, &signer).unwrap();
    encoded
}

pub fn create(
    data: TokenData,
    private_key: &[u8; PRIVATE_KEY_LENGTH],
    public_key: &[u8; PUBLIC_KEY_LENGTH],
) -> (http::header::HeaderName, http::header::HeaderValue) {
    // http::header::AUTHORIZATION
    let token = create_jwt_2(data, private_key, public_key);

    let value = HeaderValue::from_str(format!("WebPush {}", token).as_str()).unwrap();
    (header::AUTHORIZATION, value)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[ignore = "This test is ignored because it relies on randomness and is non deterministic. Needs to be fixed to only use fixed values"]
    fn can_create_authorization_header() {
        // Arrange
        const APPLICATION_SERVER_PRIVATE_KEY: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
        const APPLICATION_SERVER_PUBLIC_KEY: &str = "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIg\
                                                 Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8";
        let push_service_origin = "https://fcm.googleapis.com";
        let subject = super::Subject::Https("https://example.com");
        let private_key = BASE64_URL_SAFE_NO_PAD
            .decode(APPLICATION_SERVER_PRIVATE_KEY)
            .unwrap()
            .try_into()
            .unwrap();

        let public_key = BASE64_URL_SAFE_NO_PAD
            .decode(APPLICATION_SERVER_PUBLIC_KEY)
            .unwrap()
            .try_into()
            .unwrap();

        const EXPECTED_TOKEN :&str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL2ZjbS5nb29nbGVhcGlzLmNvbSIsIm5iZiI6IjE3MzM2MDE4MDIiLCJleHAiOiIxNzMzNjAyMTAyIiwiaWF0IjoxNzMzNjAxODAyfQ.p9vmEmkAC38-mVPjS2MaZNOfFcVJPWo0v3K8S9ivTsADP_Oq1q5DmNow773HHWwO0VnQb_Hk84oTRzzrhjOq7g";

        // Act
        let actual_token = create_jwt_2(
            TokenData {
                subject,
                push_service_origin,
                not_before: OffsetDateTime::from_unix_timestamp(1_733_601_802).unwrap(),
                expires: (OffsetDateTime::from_unix_timestamp(1_733_601_802).unwrap()
                    + time::Duration::minutes(5)),
                issued_at: OffsetDateTime::from_unix_timestamp(1_733_601_802).unwrap(),
            },
            &private_key,
            &public_key,
        );
        // Assert
        assert_eq!(EXPECTED_TOKEN, actual_token);
    }
}
