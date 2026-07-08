//! Suspense-style streaming HTML rendering.
//!
//! Render trees where some subtrees are futures ([`Node::Pending`]). The
//! renderer emits a "shell" immediately with placeholder markers for the
//! pending subtrees, then streams filled-in content as each future resolves,
//! using the wire format from Chrome's declarative partial updates feature:
//! `<?marker id="N">` / `<?start id="N">fallback<?end>` placeholders, filled
//! later by `<template for="N">...</template>` blocks.
//!
//! This is a one-shot streaming model, not a reactive or resumable one: write
//! the parts you have now, backfill the rest as they arrive.
//!
//! # Cancellation
//!
//! Widget futures are driven inside the returned stream and are dropped when
//! the stream is dropped (for example when the client disconnects and the
//! server drops the response body). To keep that free cancellation, do **not**
//! `tokio::spawn` widget futures and hand their `JoinHandle`s to the tree —
//! spawned tasks detach from drop-based cancellation and keep running after
//! the response is gone.

// Allows macro-generated `::afterglow::...` paths to resolve inside this
// crate's own tests and examples.
extern crate self as afterglow;

mod escape;
mod node;
mod render;
mod shell;
mod stream;

pub use afterglow_macros::html;
pub use node::{Node, Render};
pub use render::render_to_string;
pub use stream::{render_stream, render_stream_ordered};
