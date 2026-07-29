use std::{collections::HashMap, sync::Arc};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bollard::Docker;
use tokio::sync::Mutex;

use crate::{
    cookie::{self, Key},
    database, docker,
    secret::{self, Secrets},
};

type UpdateLocks = Arc<Mutex<HashMap<Arc<str>, Arc<Mutex<()>>>>>;

#[derive(Clone)]
pub(crate) struct State {
    pub(super) docker: Docker,
    pub(super) secrets: Secrets,
    pub(crate) cookie_key: cookie::Key,
    // Is there a better primitive to have one task exclusively running the update
    /// Lock to avoid multiple updates at the same time
    /// Does not lock the docker instance as other tasks are still permitted
    pub(super) connection: libsql::Connection,
    pub(super) update_locks: UpdateLocks,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum InitializeError {
    #[error("Error setting up secrets")]
    Secret(#[from] secret::Error),
    #[error("Bad database key encoding: {0}")]
    BadDatabaseKey(base64::DecodeError),
    #[error("Error reading database URL: {0}")]
    DatabaseUrlError(#[from] std::env::VarError),
    #[error("Error decoding cookie key")]
    CookieDecodeError(base64::DecodeError),
    #[error("Bad cookie key length")]
    BadCookieKeyLength { expected: usize, actual: usize },
    #[error("Error setting up docker")]
    DockerError(#[from] bollard::errors::Error),
    #[error("Error initializing database: {0}")]
    DatabaseError(#[from] database::InitializeError),
}

impl State {
    pub(super) async fn initialize() -> Result<Self, InitializeError> {
        let secrets = secret::setup().await.inspect_err(|error| {
            tracing::error!("Error setting up secrets {}", error);
        })?;

        let key = URL_SAFE_NO_PAD
            .decode(secrets.database_encryption_key.as_ref())
            .map_err(InitializeError::BadDatabaseKey)?
            .into();

        let url = std::env::var("LIBSQL_URL").map_err(InitializeError::DatabaseUrlError)?;
        let connection = database::initialize(url, secrets.lib_sql_auth_token.clone(), key).await?;

        let cookie_key: [u8; Key::LENGTH] = URL_SAFE_NO_PAD
            .decode(secrets.cookie_signing_secret.as_ref())
            .map_err(InitializeError::CookieDecodeError)?
            .try_into()
            .map_err(|secret: Vec<u8>| InitializeError::BadCookieKeyLength {
                expected: Key::LENGTH,
                actual: secret.len(),
            })?;

        let cookie_key = cookie::Key::from(cookie_key);

        let docker = docker::set_up()?;

        Ok(Self {
            docker,
            secrets,
            cookie_key,
            connection,
            update_locks: Arc::default(),
        })
    }
}
