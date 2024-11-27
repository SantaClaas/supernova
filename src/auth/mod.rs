use std::sync::Arc;

use askama_axum::{IntoResponse, Template};
use axum::{extract::State, http::StatusCode, response::Redirect, Form};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use nanoid::nanoid;
use serde::Deserialize;

use crate::AppState;

#[derive(Template)]
#[template(path = "sign_in.html")]
pub(super) struct SignInTemplate;

pub(super) async fn get_sign_in() -> SignInTemplate {
    SignInTemplate
}

#[derive(Deserialize)]
pub(super) struct SignInRequest {
    secret: Arc<str>,
}

const SESSION_LIFETIME: time::Duration = time::Duration::days(30);

pub(super) async fn create_sign_in(
    State(AppState { secrets }): State<AppState>,
    jar: CookieJar,
    Form(request): Form<SignInRequest>,
) -> impl IntoResponse {
    if request.secret != secrets.user_secret {
        return StatusCode::FORBIDDEN.into_response();
    }

    let session_id = nanoid!();
    let expires_at = time::OffsetDateTime::now_utc() + SESSION_LIFETIME;
    // Set session cookie
    // The cookie does not need to be encrypted as it doesn't contain any sensitive information
    let cookie = Cookie::build(("session", session_id))
        .path("/")
        .secure(true)
        // Tell browsers to not allow JavaScript to access the cookie. Prevents some XSS attacks
        // (JS can still indirectly find out if user is authenticated by trying to access authenticated endpoints)
        .http_only(true)
        // Prevents CRSF attack
        .same_site(SameSite::Strict)
        .expires(expires_at);

    (jar.add(cookie), Redirect::to("/")).into_response()
}
