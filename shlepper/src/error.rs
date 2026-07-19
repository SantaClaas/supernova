use crate::{database, secret};

#[derive(thiserror::Error, Debug)]
pub(super) enum Error {
    #[error("Error setting up secrets")]
    SecretError(#[from] secret::Error),
    #[error("Error setting up docker")]
    DockerError(#[from] bollard::errors::Error),
    #[error("Error decoding cookie key")]
    CookieDecodeError(base64::DecodeError),
    #[error("Bad cookie key length")]
    BadCookieKeyLength { expected: usize, actual: usize },
    #[error("Error reading database URL: {0}")]
    DatabaseUrlError(#[from] std::env::VarError),
    #[error("Bad database key encoding: {0}")]
    BadDatabaseKey(base64::DecodeError),
    #[error("Error initializing database: {0}")]
    DatabaseError(#[from] database::InitializeError),
}
