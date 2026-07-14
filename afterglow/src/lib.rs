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
//!
//! # Async attributes
//!
//! Attribute values can be async too ([`Node::element_with_pending_attributes`],
//! or `attr=@{future}` in `html!`), but the mechanism is different from a
//! content hole, because the wire format has **no attribute-level patch** —
//! the only way to change an attribute declaratively is to replace the
//! element that carries it. So instead of a hole *inside* the markup, an
//! element with a pending attribute renders its fallback attributes
//! immediately and, once the attribute future resolves, the **entire
//! element — open tag, attributes, and all descendants — is replaced in one
//! `<template>` patch.**
//!
//! This has a real, unavoidable cost, exactly once per element, at the
//! moment its attribute(s) resolve:
//!
//! - **The whole subtree is torn down and a new DOM node inserted.** Any
//!   browser-side state tied to it — focus, scroll position, in-progress
//!   form input, CSS transition/animation state, listeners attached by
//!   other client-side code — is lost. This is inherent to the wire format
//!   having no attribute-only patch; nothing in this crate can avoid it, so
//!   scope `attr=@{...}` to small elements — a large subtree behind an
//!   async attribute means a large, jarring remount.
//!
//! What it does *not* cost, because the replacement is built from the
//! element's *current* state rather than re-run from scratch:
//!
//! - **Nested `@{...}`/`@*{...}` holes are never re-run or duplicated.** A
//!   child hole that already resolved by the time the attribute resolves is
//!   inlined directly into the replacement; one that's still pending
//!   reconstructs its own marker under the *same* id, so its still-running
//!   future or stream keeps a valid target after the swap and its future
//!   patches keep landing correctly — no wasted computation, no patch
//!   addressed to a marker that no longer exists.
//! - **A nested `@*{...}` stream hole's history before the swap is
//!   collapsed to its latest value.** If several values arrived before the
//!   attribute resolved, only the most recent is inlined into the
//!   replacement — not the full sequence. The stream itself is untouched
//!   and keeps patching normally afterward.

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
