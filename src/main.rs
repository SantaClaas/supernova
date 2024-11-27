mod secrets;

mod auth;
mod index;

use std::net::Ipv4Addr;

use axum::routing::get;
use axum::Router;
use dotenvy::dotenv;
use secrets::Secrets;
use tower_http::services::ServeDir;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) secrets: Secrets,
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

    let secrets = secrets::setup().await.unwrap();
    let state = AppState { secrets };

    let app = Router::new()
        .route("/", get(index::get))
        .route("/signin", get(auth::get_sign_in).post(auth::create_sign_in))
        .fallback_service(ServeDir::new("public"))
        .with_state(state);

    // Run the server
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), 3000))
        .await
        .unwrap();

    tracing::debug!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
