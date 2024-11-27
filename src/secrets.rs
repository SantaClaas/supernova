use std::{env, sync::Arc};

use bitwarden::{
    auth::login::AccessTokenLoginRequest,
    secrets_manager::{
        secrets::{SecretGetRequest, SecretsGetRequest},
        ClientSecretsExt,
    },
    Client,
};
use thiserror::Error;

#[derive(Error, Debug)]
pub(super) enum Error {
    #[error("Failed to load token from environment variables: {0}")]
    LoadTokenError(#[source] env::VarError),
    #[error("Error getting secrets from Bitwarden Secrets Manager")]
    BwsError(#[from] bitwarden::Error),
    #[error("Error authenticating with Bitwarden")]
    BwsAuthenticationFailed,
    #[error("Error loading user secret id")]
    LoadUserSecretIdError(#[source] env::VarError),
    #[error("Error parsing user secret id")]
    ParseIdError(#[from] uuid::Error),
}

#[derive(Clone)]
pub(crate) struct Secrets {
    pub(crate) user_secret: Arc<str>,
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

    let request = SecretGetRequest {
        id: env::var("USER_SECRET_ID")
            .map_err(Error::LoadUserSecretIdError)?
            .parse()?,
    };
    let response = client.secrets().get(&request).await?;

    Ok(Secrets {
        user_secret: response.value.into(),
    })
}
