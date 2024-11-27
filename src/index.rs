use askama_axum::Template;

#[derive(Template)]
#[template(path = "index.html")]
pub(super) struct IndexTemplate;

pub(super) async fn get() -> IndexTemplate {
    IndexTemplate
}
