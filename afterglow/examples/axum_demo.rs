//! Streaming HTML demo. Run with:
//!
//! ```sh
//! cargo run --example axum_demo
//! curl --no-buffer localhost:3210/
//! ```
//!
//! The shell arrives immediately with spinners; the widget `<template>`
//! chunks trickle in over the next ~2.5 seconds.

use std::net::Ipv4Addr;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::time::sleep;

use afterglow::{Node, html, render_stream};

async fn weather() -> Result<Node, &'static str> {
    sleep(Duration::from_millis(800)).await;
    Ok(html! { <p>"21 °C, clear skies"</p> })
}

async fn news() -> Result<Node, &'static str> {
    sleep(Duration::from_millis(2500)).await;
    Ok(html! {
        <ul>
            <li>"Streaming HTML lands in afterglow"</li>
            <li>"Shell rendered " {2500} "ms before this item"</li>
        </ul>
    })
}

async fn stock_ticker() -> Result<Node, &'static str> {
    sleep(Duration::from_millis(1500)).await;
    // Widgets can fail without taking down the response: this renders as an
    // error slot inside its placeholder.
    Err("stock service unavailable")
}

async fn index() -> Response {
    let page = html! {
        <html>
            <head><title>"afterglow demo"</title></head>
            <body>
                <h1>"Dashboard"</h1>
                <section>
                    <h2>"Weather"</h2>
                    @{weather()} else { <p>"checking the sky…"</p> }
                </section>
                <section>
                    <h2>"News"</h2>
                    @{news()} else { <p>"fetching headlines…"</p> }
                </section>
                <section>
                    <h2>"Stocks"</h2>
                    @{stock_ticker()}
                </section>
            </body>
        </html>
    };

    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Body::from_stream(render_stream(page)),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    let app = Router::new().route("/", get(index));
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 3210))
        .await
        .unwrap();

    println!(
        "listening on http://{} — try: curl --no-buffer localhost:3210/",
        listener.local_addr().unwrap()
    );
    axum::serve(listener, app).await.unwrap();
}
