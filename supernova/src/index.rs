use std::rc::Rc;

use askama_axum::Template;
use axum::extract::State;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};

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
) -> IndexTemplate {
    tracing::debug!("User is authenticated? {}", user.is_some());
    let public_key = BASE64_URL_SAFE_NO_PAD.encode(state.vapid.public_key.as_ref());
    IndexTemplate {
        application_server_public_key: public_key.into(),
    }
}
