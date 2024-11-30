use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::{cookie::Key, PrivateCookieJar};
use thiserror::Error;
use time::OffsetDateTime;

use crate::AppState;

use super::cookie;

pub(crate) struct AuthenticatedUser;

#[derive(Error, Debug)]
pub(crate) enum Error {
    #[error("No cookie")]
    NoCookie,
    #[error(transparent)]
    BadCookie(#[from] cookie::Error),
    #[error("Expired cookie")]
    ExpiredCookie,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        match self {
            Error::NoCookie | Error::BadCookie(_) | Error::ExpiredCookie => {
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let key = Key::from_ref(&app_state);
        // Infallible 🙂
        let Ok(headers) = HeaderMap::from_request_parts(parts, state).await;
        let jar = PrivateCookieJar::from_headers(&headers, key);

        let cookie = jar.get(cookie::NAME).ok_or(Error::NoCookie)?;

        // This can be set by users.
        // So additional validation is required when not expired.
        // The worst case here is the user sets it lower and is signed out earlier but that is their fault.
        // But they should not be allowed to set it higher and stay signed in.
        let is_expired = cookie
            .expires_datetime()
            .is_some_and(|datetime| OffsetDateTime::now_utc() > datetime);

        if is_expired {
            return Err(Error::ExpiredCookie);
        }

        let value = cookie::Session::try_from(cookie)?;
        if value.is_expired() {
            return Err(Error::ExpiredCookie);
        }

        Ok(AuthenticatedUser)
    }
}
