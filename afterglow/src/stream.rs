use std::collections::BTreeMap;
use std::io;

use async_stream::stream;
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, Stream, StreamExt};

use crate::node::{Node, Render};
use crate::shell::{Shell, SlotId, render_shell};

/// A slot's future tagged with its id so we know which placeholder to fill.
type TaggedFuture = BoxFuture<'static, (SlotId, Node)>;

fn tag(id: SlotId, future: BoxFuture<'static, Node>) -> TaggedFuture {
    Box::pin(async move { (id, future.await) })
}

fn template_chunk(id: SlotId, html: &str) -> Bytes {
    Bytes::from(format!("<template for=\"{id}\">{html}</template>"))
}

/// Renders `root` as a byte stream: the shell (with placeholder markers for
/// pending subtrees) is yielded first, then each resolved subtree is yielded
/// as a `<template for="N">...</template>` chunk **in completion order** —
/// whichever future resolves first is streamed first.
///
/// Resolved subtrees may themselves contain pending nodes; those are
/// registered as new slots and filled by later chunks, to any nesting depth.
///
/// Dropping the stream (e.g. because the client disconnected) drops all
/// still-pending widget futures — cancellation is free as long as widget
/// futures are not `tokio::spawn`ed (see the crate docs).
///
/// The stream never yields `Err`; the item type is `io::Result<Bytes>` so it
/// can feed `axum::body::Body::from_stream` directly.
pub fn render_stream(root: impl Render) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let root = root.into_node();
    stream! {
        let mut next_id: SlotId = 0;
        let shell = render_shell(root, &mut next_id);
        let mut pending: FuturesUnordered<TaggedFuture> = shell
            .slots
            .into_iter()
            .map(|(id, future)| tag(id, future))
            .collect();

        yield Ok(Bytes::from(shell.html));

        while let Some((id, node)) = pending.next().await {
            let Shell { html, slots } = render_shell(node, &mut next_id);
            for (new_id, future) in slots {
                pending.push(tag(new_id, future));
            }
            yield Ok(template_chunk(id, &html));
        }
    }
}

/// Like [`render_stream`], but fills slots **in registration order** (slot 0
/// first, then 1, ...) regardless of which future resolves first. Futures
/// still run concurrently; completed chunks are buffered until it is their
/// turn. Useful for deterministic snapshot testing.
///
/// Slots registered by resolved subtrees always get higher ids than the slot
/// that produced them, so waiting for ids in ascending order cannot deadlock.
pub fn render_stream_ordered(
    root: impl Render,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let root = root.into_node();
    stream! {
        let mut next_id: SlotId = 0;
        let shell = render_shell(root, &mut next_id);
        let mut pending: FuturesUnordered<TaggedFuture> = shell
            .slots
            .into_iter()
            .map(|(id, future)| tag(id, future))
            .collect();

        yield Ok(Bytes::from(shell.html));

        let mut buffered: BTreeMap<SlotId, String> = BTreeMap::new();
        let mut emit_next: SlotId = 0;
        while let Some((id, node)) = pending.next().await {
            let Shell { html, slots } = render_shell(node, &mut next_id);
            for (new_id, future) in slots {
                pending.push(tag(new_id, future));
            }
            buffered.insert(id, html);

            while let Some(html) = buffered.remove(&emit_next) {
                yield Ok(template_chunk(emit_next, &html));
                emit_next += 1;
            }
        }
    }
}
