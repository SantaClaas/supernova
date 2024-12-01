use std::sync::Arc;

use axum::extract::Json;
use serde::Deserialize;
use time::OffsetDateTime;

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

#[derive(Deserialize)]
struct Keys {
    #[serde(rename = "p256dh", deserialize_with = "public_key::deserialize")]
    p256PublicKey: Arc<[u8; 65]>,
    #[serde(
        rename = "auth",
        deserialize_with = "authentication_secret::deserialize"
    )]
    authentication_secret: Arc<[u8; 16]>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Subscription {
    endpoint: String,
    #[serde(with = "time::serde::timestamp::milliseconds::option")]
    expiration_time: Option<OffsetDateTime>,
    keys: Keys,
}

pub(super) async fn create_subscription(Json(subscription): Json<Subscription>) {}
