use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::{HeaderName, HeaderValue},
};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::{Method, Request, RequestBuilder};
use serde::Deserialize;
use time::OffsetDateTime;
use web_shove::PushMessageParameters;

use crate::AppState;

mod public_key {
    use std::sync::Arc;

    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::Deserialize;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<[u8; 65]>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(string)
            .map_err(serde::de::Error::custom)?;

        let decoded: [u8; 65] = decoded
            .try_into()
            .map_err(|decoded: Vec<u8>| serde::de::Error::invalid_length(decoded.len(), &"65"))?;

        Ok(Arc::new(decoded))
    }
}

mod authentication_secret {
    use std::sync::Arc;

    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use serde::Deserialize;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<[u8; 16]>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let decoded = BASE64_URL_SAFE_NO_PAD
            .decode(string)
            .map_err(serde::de::Error::custom)?;

        let decoded: [u8; 16] = decoded
            .try_into()
            .map_err(|decoded: Vec<u8>| serde::de::Error::invalid_length(decoded.len(), &"16"))?;

        Ok(Arc::new(decoded))
    }
}

#[derive(Deserialize, Clone)]
struct Keys {
    #[serde(rename = "p256dh", deserialize_with = "public_key::deserialize")]
    user_agent_public_key: Arc<[u8; 65]>,
    #[serde(
        rename = "auth",
        deserialize_with = "authentication_secret::deserialize"
    )]
    authentication_secret: Arc<[u8; 16]>,
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(super) struct Subscription {
    endpoint: url::Url,
    #[serde(with = "time::serde::timestamp::milliseconds::option")]
    expiration_time: Option<OffsetDateTime>,
    keys: Keys,
}

pub(super) async fn create_subscription(
    State(state): State<AppState>,
    Json(subscription): Json<Subscription>,
) {
    state.subscriptions.lock().await.push(subscription);
    tracing::info!("Subscription added");
}

pub(super) async fn create_push_notification(State(state): State<AppState>) {
    tracing::info!("Sending push notifications");
    let application_server_signing_key =
        BASE64_URL_SAFE_NO_PAD.encode(state.vapid.public_key.as_ref());
    //TODO figure out best random solution for secure salts
    for subscription in state.subscriptions.lock().await.iter() {
        tracing::info!("Sending push notification to {}", subscription.endpoint);

        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).expect("Failed to generate random salt");

        let PushMessageParameters {
            content,
            salt,
            application_server_public_key,
        } = web_shove::create_push_message_payload(
            b"A supernova hello!",
            subscription.keys.user_agent_public_key.as_ref(),
            subscription.keys.authentication_secret.as_ref(),
        );

        // let builder = RequestBuilder::new();
        // let mut request = Request::new(Method::POST, subscription.endpoint.clone());

        let content_length = content.len();
        //TODO might need different encoding
        let salt_encoded = BASE64_URL_SAFE_NO_PAD.encode(&salt);

        let body = reqwest::Body::from(content);
        let encoded_dh = BASE64_URL_SAFE_NO_PAD.encode(application_server_public_key.as_ref());
        let crpto_key_header_value = HeaderValue::from_str(&format!(
            "dh={};p256ecdsa={}",
            encoded_dh, application_server_signing_key
        ))
        .unwrap();

        let push_server_origin = subscription.endpoint.origin();

        let mut request = state
            .client
            .post(subscription.endpoint.clone())
            .body(body)
            .header(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )
            .header(
                reqwest::header::CONTENT_LENGTH,
                HeaderValue::from(content_length),
            )
            .header(
                reqwest::header::CONTENT_ENCODING,
                HeaderValue::from_static("aesgcm"),
            )
            .header(
                HeaderName::from_static("Encryption"),
                format!("salt={salt_encoded}"),
            )
            .header(
                HeaderName::from_static("Crypto-Key"),
                crpto_key_header_value,
            );

        // state.client.execute(request)
        // reqwest::RequestBuilder::
    }
}
