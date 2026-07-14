//! Suspense-style streaming HTML rendering.
//!
//! Render trees where some subtrees are futures ([`Node::Pending`]) or
//! sequences of values arriving over time ([`Node::Stream`]). The renderer
//! emits a "shell" immediately with placeholder markers for those holes,
//! then streams filled-in content as it becomes available, using the wire
//! format from Chrome's declarative partial updates feature:
//! `<?marker name="N">` / `<?start name="N">fallback<?end>` placeholders,
//! filled later by `<template for="N">...</template>` blocks. A `Pending`
//! hole is patched once; a `Stream` hole is patched once per value — per the
//! wire format, repeated patches at the same marker express a live-updating
//! region.
//!
//! There is no client-side state and no re-rendering: each patch is applied
//! declaratively as it arrives, and a `Stream` hole is a live region only in
//! the sense that its slot keeps being patched — nothing is diffed or
//! reconciled.
//!
//! # Cancellation
//!
//! Widget futures and stream sources are driven inside the returned stream
//! and are dropped when the stream is dropped (for example when the client
//! disconnects and the server drops the response body). To keep that free
//! cancellation, do **not** `tokio::spawn` them and hand their `JoinHandle`s
//! to the tree — spawned tasks detach from drop-based cancellation and keep
//! running after the response is gone.

// Allows macro-generated `::afterglow::...` paths to resolve inside this
// crate's own tests and examples.
extern crate self as afterglow;

mod escape;
mod node;
mod render;
mod shell;
mod stream;

pub use afterglow_macros::html;
pub use node::{IntoNodeStream, Node, NodeStream, Render};
pub use render::render_to_string;
pub use stream::{render_stream, render_stream_ordered};
