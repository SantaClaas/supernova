use std::rc::Rc;

use askama::Template;
use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use reqwest::StatusCode;

use crate::{auth::AuthenticatedUser, AppState};

#[derive(Template)]
#[template(path = "index.html")]
pub(super) struct IndexTemplate {
    /// Base64 url safe encoded public key for the application server from the VAPID keys
    application_server_public_key: Rc<str>,
}

pub(super) async fn get<'a>(
    State(state): State<AppState>,
    user: Option<AuthenticatedUser>,
) -> impl IntoResponse {
    tracing::debug!("User is authenticated? {}", user.is_some());
    let public_key = BASE64_URL_SAFE_NO_PAD.encode(state.vapid.public_key.as_ref());
    let template = IndexTemplate {
        application_server_public_key: public_key.into(),
    };

    match template.render() {
        Ok(render) => Html(render).into_response(),
        Err(error) => {
            tracing::error!("Error rendering index: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}
