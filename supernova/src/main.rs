mod secrets;

mod auth;
mod index;
mod notification;

use std::net::Ipv4Addr;
use std::path::Path;

use auth::cookie::{self, Key};
use axum::routing::{get, post};
use axum::Router;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use dotenvy::dotenv;
use secrets::Secrets;
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry;
use tracing_subscriber::util::SubscriberInitExt;
use web_shove::vapid::Vapid;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) secrets: Secrets,
    pub(crate) key: cookie::Key,
    pub(crate) vapid: Vapid,
}

#[tokio::main]
async fn main() {
    registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    dotenv().ok();

    let public_path = if cfg!(debug_assertions) {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("public")
    } else {
        std::env::current_exe().unwrap_or_else(|error| {
            tracing::warn!(
                "Could not get current executable path. Will serve static files from relative \"public\" directory. Causing Error: {}",
                error
            );
            "public".into()
        })
    };

    let secrets = secrets::setup().await.unwrap();
    let key_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(secrets.vapid_private_key.as_ref())
        .unwrap();
    let key_bytes = &key_bytes.try_into().unwrap();
    //TODO email
    let vapid = Vapid::with_private_key("example@example.com", key_bytes);

    let state = AppState {
        secrets,
        key: Key::new().expect("Error accessing random"),
        vapid,
    };

    let app = Router::new()
        .route("/", get(index::get))
        .route("/signin", get(auth::get_sign_in).post(auth::create_sign_in))
        .route(
            "/notifications/subscriptions",
            post(notification::create_subscription),
        )
        .fallback_service(ServeDir::new(public_path))
        .with_state(state);

    // Run the server
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), 3000))
        .await
        .unwrap();

    tracing::debug!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
