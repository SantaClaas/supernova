use askama_axum::Template;

use crate::auth::AuthenticatedUser;

#[derive(Template)]
#[template(path = "index.html")]
pub(super) struct IndexTemplate;

pub(super) async fn get(user: Option<AuthenticatedUser>) -> IndexTemplate {
    tracing::debug!("User is authenticated? {}", user.is_some());
    IndexTemplate
}
