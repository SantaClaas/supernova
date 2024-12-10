use std::sync::Arc;

use axum::{
    extract::{Json, State},
    http::{self, HeaderName, HeaderValue},
};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use reqwest::{Method, Request, RequestBuilder, StatusCode};
use serde::Deserialize;
use time::OffsetDateTime;
use url::Origin;
use web_shove::{
    authorization_header::{Subject, TokenData},
    PushMessageParameters,
};

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
    #[serde(default, with = "time::serde::timestamp::milliseconds::option")]
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

pub(super) async fn create_push_notification(
    State(state): State<AppState>,
) -> axum::http::StatusCode {
    tracing::info!("Sending push notifications");
    let application_server_signing_key =
        BASE64_URL_SAFE_NO_PAD.encode(state.vapid.public_key.as_ref());

    let subscriptions = state.subscriptions.lock().await;
    let length = subscriptions.len();

    if length == 0 {
        tracing::info!("No subscriptions to send push notifications to");
        return StatusCode::NO_CONTENT;
    }

    let mut handles = Vec::with_capacity(length);
    //TODO figure out best random solution for secure salts
    for subscription in subscriptions.iter() {
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
        //TODO use headermap
        let salt_encoded = BASE64_URL_SAFE_NO_PAD.encode(&salt);

        let body = reqwest::Body::from(content);
        let encoded_dh = BASE64_URL_SAFE_NO_PAD.encode(application_server_public_key.as_ref());
        let crypto_key_header_value = HeaderValue::from_str(&format!(
            "dh={};p256ecdsa={}",
            encoded_dh, application_server_signing_key
        ))
        .unwrap();

        let origin = subscription.endpoint.origin();
        if matches!(origin, Origin::Opaque(_)) {
            return todo!("Error can not send to opaque origin");
        }
        let push_service_origin = &origin.ascii_serialization();

        let now = OffsetDateTime::now_utc();
        let expires = now + time::Duration::minutes(5);
        let authorization_header = web_shove::authorization_header::create(
            TokenData {
                subject: Subject::Email("example@example.com"),
                push_service_origin,
                not_before: now,
                expires,
                issued_at: now,
            },
            state.vapid.private_key.as_ref(),
            state.vapid.public_key.as_ref(),
        );

        let request = state
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
                HeaderName::from_static("encryption"),
                format!("salt={salt_encoded}"),
            )
            .header(
                HeaderName::from_static("crypto-key"),
                crypto_key_header_value,
            )
            .header(authorization_header.0, authorization_header.1)
            // Time to live 4 weeks default (maximum?)
            .header(
                HeaderName::from_static("ttl"),
                HeaderValue::from_static("2419200"),
            )
            .build()
            .unwrap();

        let future = state.client.execute(request);
        let handle = tokio::spawn(future);
        handles.push(handle);

        // state.client.execute(request)
        // reqwest::RequestBuilder::
    }

    let mut results = Vec::with_capacity(length);
    for handle in handles {
        let result = handle.await.unwrap();
        results.push(result);
    }

    tracing::info!("Push notifications sent");
    for result in results {
        let response = result;
        tracing::info!("Response: {:?}", response);
        if let Ok(response) = response {
            let text = response.text().await;
            tracing::info!("Response text: {:?}", text);
        }
    }

    StatusCode::CREATED
}
