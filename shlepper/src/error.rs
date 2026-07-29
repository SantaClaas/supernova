use std::io;

use crate::state;

#[derive(thiserror::Error, Debug)]
pub(super) enum Error {
    #[error("Error initializing state: {0}")]
    InitializeState(#[from] state::InitializeError),
    #[error("Error setting up TCP listener: {0}")]
    TcpListener(io::Error),
    #[error("Error serving axum app: {0}")]
    AxumServe(io::Error),
}
