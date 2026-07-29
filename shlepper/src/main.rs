mod cookie;
mod database;
mod docker;
mod error;
mod garbage_collector;
mod public_directory;
mod secret;
mod shutdown_signal;
mod state;

use std::net::Ipv4Addr;

use axum::Router;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{error::Error, state::State};

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

    let state = State::initialize().await?;

    // Set up background workers
    let _handle = tokio::spawn(garbage_collector::start(state.clone()));

    let app = Router::new()
        .fallback_service(public_directory::serve())
        .with_state(state);

    let address = if cfg!(debug_assertions) {
        Ipv4Addr::LOCALHOST
    } else {
        Ipv4Addr::UNSPECIFIED
    };

    let listener = TcpListener::bind((address, 3001))
        .await
        .map_err(Error::TcpListener)?;

    tracing::info!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal::get())
        .await
        .map_err(Error::AxumServe)?;

    Ok(())
}
