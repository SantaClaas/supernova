use std::{
    collections::HashMap,
    env::{self},
    rc::Rc,
    sync::Arc,
};

use bitwarden::{Client, auth::login::AccessTokenLoginRequest, secrets_manager::secrets::SecretsGetRequest};
use bitwarden_core::auth::login::LoginError;
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub(super) enum ErrorType {
    #[error("Error loading secret id from environment variables: {0}")]
    VarError(#[from] env::VarError),
    #[error("Error parsing user secret id: {0}")]
    ParseError(#[from] uuid::Error),
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Secret {
    UserSecret,
    CookieSigningSecret,
    LibSqlAuthToken,
    DatabaseEncryptionKey,
}

impl Secret {
    const fn get_variable(&self) -> &'static str {
        match self {
            Secret::UserSecret => "USER_SECRET_ID",
            Secret::CookieSigningSecret => "COOKIE_SIGNING_SECRET_ID",
            Secret::LibSqlAuthToken => "LIBSQL_AUTH_TOKEN_ID",
            Secret::DatabaseEncryptionKey => "DATABASE_ENCRYPTION_KEY_ID",
        }
    }
}

#[derive(Error, Debug)]
#[error("Error loading secret id {variable}: {source}")]
pub(super) struct LoadSecretIdError {
    variable: Rc<str>,
    #[source]
    source: ErrorType,
}

#[derive(Error, Debug)]
pub(super) enum Error {
    #[error("Failed to load token from environment variables: {0}")]
    LoadTokenError(#[source] env::VarError),
    #[error("Error getting secrets from Bitwarden Secrets Manager: {0}")]
    BwsError(#[from] bitwarden::error::Error),
    #[error("Error logging in to Bitwarden: {0}")]
    LoginError(#[from] LoginError),
    #[error("Error authenticating with Bitwarden")]
    BwsAuthenticationFailed,
    #[error("Error loading secret id from environment variables: {0}")]
    LoadSecretIdError(#[from] LoadSecretIdError),
    #[error("Secret not provided by Bitwarden: {0:?}")]
    SecretNotProvided(Secret),
}

#[derive(Clone)]
pub(crate) struct Secrets {
    pub(crate) user_secret: Arc<str>,
    pub(crate) cookie_signing_secret: Arc<str>,
    pub(crate) lib_sql_auth_token: String,
    pub(crate) database_encryption_key: Arc<str>,
}

fn load_secret_ids() -> Result<HashMap<Uuid, Secret>, LoadSecretIdError> {
    const SECRETS: &[Secret] = &[
        Secret::UserSecret,
        Secret::CookieSigningSecret,
        Secret::LibSqlAuthToken,
        Secret::DatabaseEncryptionKey,
    ];

    let mut secret_ids = HashMap::with_capacity(SECRETS.len());

    for secret in SECRETS {
        let value = env::var(secret.get_variable()).map_err(|error| LoadSecretIdError {
            variable: secret.get_variable().into(),
            source: ErrorType::VarError(error),
        })?;

        let id: Uuid = value.parse().map_err(|error| LoadSecretIdError {
            variable: secret.get_variable().into(),
            source: ErrorType::ParseError(error),
        })?;

        secret_ids.insert(id, *secret);
    }

    Ok(secret_ids)
}

pub(super) async fn setup() -> Result<Secrets, Error> {
    let client = Client::new(None);

    let request = AccessTokenLoginRequest {
        access_token: env::var("BWS_TOKEN").map_err(Error::LoadTokenError)?,
        state_file: None,
    };

    let response = client.auth().login_access_token(&request).await?;

    if !response.authenticated {
        return Err(Error::BwsAuthenticationFailed);
    }

    let ids_by_variable = load_secret_ids()?;
    let request = SecretsGetRequest {
        ids: ids_by_variable.keys().copied().collect(),
    };

    let responses = client.secrets().get_by_ids(request).await?;
    let mut user_secret = None;
    let mut cookie_signing_secret = None;
    let mut lib_sql_auth_token = None;
    let mut database_encryption_key = None;
    for secret in responses.data {
        let Some(variable) = ids_by_variable.get(&secret.id) else {
            tracing::warn!(
                "Received secret with id {} that was not requested",
                secret.id
            );
            continue;
        };

        match variable {
            Secret::UserSecret => user_secret = Some(secret.value),
            Secret::CookieSigningSecret => cookie_signing_secret = Some(secret.value),
            Secret::LibSqlAuthToken => lib_sql_auth_token = Some(secret.value),
            Secret::DatabaseEncryptionKey => database_encryption_key = Some(secret.value),
        }
    }

    let user_secret = user_secret
        .ok_or_else(|| Error::SecretNotProvided(Secret::UserSecret))?
        .into();

    let cookie_signing_secret = cookie_signing_secret
        .ok_or_else(|| Error::SecretNotProvided(Secret::CookieSigningSecret))?
        .into();

    let lib_sql_auth_token =
        lib_sql_auth_token.ok_or_else(|| Error::SecretNotProvided(Secret::LibSqlAuthToken))?;

    let database_encryption_key = database_encryption_key
        .ok_or_else(|| Error::SecretNotProvided(Secret::DatabaseEncryptionKey))?
        .into();

    Ok(Secrets {
        user_secret,
        cookie_signing_secret,
        lib_sql_auth_token,
        database_encryption_key,
    })
}
