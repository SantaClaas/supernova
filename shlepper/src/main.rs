mod database;
mod error;
mod secret;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!(
                    "{}=trace,tower_http=debug,bollard=debug",
                    env!("CARGO_CRATE_NAME")
                )
                .into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    #[cfg(debug_assertions)]
    dotenvy::dotenv().expect("Expected to load .env file in development");

    let secrets = secret::setup().await.inspect_err(|error| {
        tracing::error!("Error setting up secrets {}", error);
    })?;

    let url = std::env::var("LIBSQL_URL").map_err(Error::DatabaseUrlError)?;
    let key = URL_SAFE_NO_PAD
        .decode(secrets.database_encryption_key.as_ref())
        .map_err(Error::BadDatabaseKey)?
        .into();

    let connection = database::initialize(url, secrets.lib_sql_auth_token.clone(), key).await?;

    let cookie_key: [u8; Key::LENGTH] = URL_SAFE_NO_PAD
        .decode(secrets.cookie_signing_secret.as_ref())
        .map_err(Error::CookieDecodeError)?
        .try_into()
        .map_err(|secret: Vec<u8>| Error::BadCookieKeyLength {
            expected: Key::LENGTH,
            actual: secret.len(),
        })?;

    Ok(())
}
