//! Streaming HTML demo. Run with:
//!
//! ```sh
//! cargo run --example axum_demo
//! curl --no-buffer localhost:3210/
//! ```
//!
//! The shell arrives immediately with spinners; the widget `<template>`
//! chunks trickle in over the next ~2.5 seconds. The "Live price" section
//! uses `@*{...}` (a stream hole) instead of `@{...}` (a future hole): it
//! patches the same slot five times as new ticks arrive, rather than
//! resolving once. The "Status" section uses an async *attribute*
//! (`class=@{...}`): watch its whole `<div>` get replaced once the
//! attribute resolves — including the still-pending nested detail hole
//! inside it, which keeps the *same* marker id across that replacement and
//! resolves normally afterward.

use std::net::Ipv4Addr;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::Stream;
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

/// A stream hole: unlike the futures above, which fill their slot once, this
/// patches the same `<template for="N">` slot repeatedly as ticks arrive —
/// the wire-format mechanism the declarative partial updates format calls
/// out for live-updating regions. Held open for ~2s total.
fn live_price() -> impl Stream<Item = Node> {
    async_stream::stream! {
        let mut price = 100.0_f32;
        for _ in 0..5 {
            sleep(Duration::from_millis(400)).await;
            price += (price * 0.01).max(0.5);
            yield html! { <span>"$" {format!("{price:.2}")}</span> };
        }
    }
}

async fn status_class() -> &'static str {
    sleep(Duration::from_millis(600)).await;
    "status-ok"
}

/// Resolves *after* `status_class` (1.8s vs. 0.6s), on purpose: it shows the
/// swap triggered by the async attribute reusing this hole's marker id
/// rather than re-running or losing it — its own patch lands normally,
/// afterward, targeting the marker that survived the swap.
async fn status_detail() -> Node {
    sleep(Duration::from_millis(1800)).await;
    html! { "All systems operational" }
}

// Fully static — evaluated at compile time; the crate name and version are
// spliced in via `concat!`, so the whole footer is one `&'static str` in the
// binary.
const FOOTER: Node = html! {
    <footer>
        "Created with " const { env!("CARGO_PKG_NAME") } " v" const { env!("CARGO_PKG_VERSION") }
    </footer>
};

async fn index() -> Response {
    let page = html! {
        <html>
            <head>
              <title>"afterglow demo"</title>
              <script src="https://unpkg.com/template-for-polyfill"></script>
            </head>
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
                <section>
                    <h2>"Live price"</h2>
                    @*{live_price()} else { <span>"waiting for first tick…"</span> }
                </section>
                <section>
                    <h2>"Status"</h2>
                    <div class=@{status_class()} else "status-pending">
                        "Detail: " @{status_detail()}
                    </div>
                </section>
                {FOOTER}
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
