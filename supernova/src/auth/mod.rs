mod authenticated_user;
pub(crate) mod cookie;

use askama::Template;
pub(super) use authenticated_user::AuthenticatedUser;

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use axum_extra::extract::{
    cookie::{Key, SameSite},
    PrivateCookieJar,
};
use serde::Deserialize;
use thiserror::Error;

use crate::AppState;

#[derive(Template)]
#[template(path = "sign_in.html")]
pub(super) struct SignInTemplate;

pub(super) async fn get_sign_in() -> impl IntoResponse {
    match SignInTemplate.render() {
        Ok(render) => Html(render).into_response(),
        Err(error) => {
            tracing::error!("Error rendering sign in template: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Deserialize)]
pub(super) struct SignInRequest {
    secret: Arc<str>,
}

#[derive(Error, Debug)]
pub(super) enum CreateSignInError {
    #[error("Bad secret")]
    BadSecret,
    #[error("Error building cookie {0}")]
    BuildCookieError(#[from] postcard::Error),
}

impl IntoResponse for CreateSignInError {
    fn into_response(self) -> Response {
        match self {
            CreateSignInError::BadSecret => StatusCode::FORBIDDEN.into_response(),
            CreateSignInError::BuildCookieError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

pub(super) async fn create_sign_in(
    State(AppState { secrets, .. }): State<AppState>,
    jar: PrivateCookieJar<Key>,
    Form(request): Form<SignInRequest>,
) -> Result<Response, CreateSignInError> {
    if request.secret != secrets.user_secret {
        return Err(CreateSignInError::BadSecret);
    }

    // Set session cookie
    // The cookie does not need to be encrypted as it doesn't contain any sensitive information
    let cookie = cookie::Session::build()?
        .path("/")
        .secure(true)
        // Tell browsers to not allow JavaScript to access the cookie. Prevents some XSS attacks
        // (JS can still indirectly find out if user is authenticated by trying to access authenticated endpoints)
        .http_only(true)
        // Prevents CRSF attack
        .same_site(SameSite::Strict);

    Ok((jar.add(cookie), Redirect::to("/")).into_response())
}
