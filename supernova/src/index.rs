use axum::response::{Html, IntoResponse};

const TEMPLATE: &str = include_str!("index.html");

pub(super) async fn get<'a>() -> impl IntoResponse {
    Html(TEMPLATE)
}
