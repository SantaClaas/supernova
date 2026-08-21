use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

use async_stream::stream;
use bytes::Bytes;
use futures::stream::{BoxStream, SelectAll, Stream, StreamExt};

use crate::node::{Node, Render};
use crate::shell::{HtmlBuf, Shell, SlotId, SlotSource, render_shell};

/// Cache cells registered by `PendingAttributes` elements, keyed by the id
/// of the hole whose resolved HTML they should receive. Seeded from the
/// initial shell and extended after every subsequent resolution (a newly
/// resolved subtree can itself contain a new `PendingAttributes` element).
/// Written to — in addition to the normal `<template>` patch — whenever a
/// tracked slot resolves, so a later element-attribute swap can inline
/// whatever is currently known instead of re-running or duplicating work.
type LiveCache = HashMap<SlotId, Arc<Mutex<Option<String>>>>;

fn record_resolution(live_cache: &LiveCache, id: SlotId, html: &str) {
    if let Some(state) = live_cache.get(&id) {
        *state.lock().expect("cache mutex is never held across a panic") = Some(html.to_owned());
    }
}

/// A slot event tagged with the slot's id: a value to patch into the slot,
/// or the end of the slot's source (used by the ordered driver's gate).
enum SlotEvent {
    Value(SlotId, Node),
    End(SlotId),
}

type TaggedStream = BoxStream<'static, SlotEvent>;

fn tag(id: SlotId, source: SlotSource) -> TaggedStream {
    let values: BoxStream<'static, Node> = match source {
        SlotSource::Future(future) => Box::pin(futures::stream::once(future)),
        SlotSource::Stream(stream) => stream,
    };
    Box::pin(
        values
            .map(move |node| SlotEvent::Value(id, node))
            .chain(futures::stream::once(async move { SlotEvent::End(id) })),
    )
}

fn template_chunk(id: SlotId, html: &str) -> Bytes {
    Bytes::from(format!("<template for=\"{id}\">{html}</template>"))
}

/// Renders `root` as a byte stream: the shell (with placeholder markers for
/// pending subtrees) is yielded first, then resolved content is yielded as
/// `<template for="N">...</template>` chunks **in completion order** —
/// whichever slot produces a value first is streamed first.
///
/// Future slots ([`Node::Pending`]) produce exactly one chunk; stream slots
/// ([`Node::Stream`]) produce one chunk per value, in value order — per the
/// declarative partial updates format, repeated patches at the same marker
/// express a live-updating region. Values may themselves contain new pending
/// or stream holes; those are registered as new slots and filled by later
/// chunks, to any nesting depth.
///
/// The stream terminates once every future has resolved and every stream
/// source has ended — an infinite source means a never-ending response.
/// Sources are only polled when the response stream is polled, so a fast
/// producer is throttled by the client rather than buffered.
///
/// Dropping the stream (e.g. because the client disconnected) drops all
/// still-pending widget futures and stream sources — cancellation is free as
/// long as they are not `tokio::spawn`ed (see the crate docs).
///
/// The stream never yields `Err`; the item type is `io::Result<Bytes>` so it
/// can feed `axum::body::Body::from_stream` directly.
pub fn render_stream(root: impl Render) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let root = root.into_node();
    stream! {
        let mut next_id: SlotId = 0;
        let Shell { html, slots, cache_registrations } = render_shell(root, &mut next_id);
        let mut live_cache: LiveCache = cache_registrations.into_iter().collect();
        let mut pending: SelectAll<TaggedStream> = futures::stream::select_all(
            slots.into_iter().map(|(id, source)| tag(id, source)),
        );

        yield Ok(html.into_bytes());

        while let Some(event) = pending.next().await {
            let SlotEvent::Value(id, node) = event else {
                continue;
            };
            let Shell { html, slots, cache_registrations } = render_shell(node, &mut next_id);
            live_cache.extend(cache_registrations);
            for (new_id, source) in slots {
                pending.push(tag(new_id, source));
            }
            record_resolution(&live_cache, id, html.as_str());
            yield Ok(template_chunk(id, html.as_str()));
        }
    }
}

/// Like [`render_stream`], but slots unblock **in registration order**: slot
/// N's first chunk is emitted before anything from slot N+1. A slot unblocks
/// once it produces its first value (or its source ends without one — the
/// fallback then simply remains); afterwards its further values pass through
/// in arrival order. Sources still run concurrently; early chunks are
/// buffered until it is their slot's turn. Useful for deterministic snapshot
/// testing.
///
/// Slots registered by resolved content always get higher ids than the slot
/// that produced them, so waiting for ids in ascending order cannot deadlock.
pub fn render_stream_ordered(
    root: impl Render,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    let root = root.into_node();
    stream! {
        let mut next_id: SlotId = 0;
        let Shell { html, slots, cache_registrations } = render_shell(root, &mut next_id);
        let mut live_cache: LiveCache = cache_registrations.into_iter().collect();
        let mut pending: SelectAll<TaggedStream> = futures::stream::select_all(
            slots.into_iter().map(|(id, source)| tag(id, source)),
        );

        yield Ok(html.into_bytes());

        // The gate: `emit_next` is the lowest still-blocked slot. Chunks for
        // blocked slots are buffered; ends without a value are remembered so
        // an empty source cannot jam the gate.
        let mut buffered: BTreeMap<SlotId, Vec<HtmlBuf>> = BTreeMap::new();
        let mut ended: BTreeSet<SlotId> = BTreeSet::new();
        let mut emit_next: SlotId = 0;

        while let Some(event) = pending.next().await {
            match event {
                SlotEvent::Value(id, node) => {
                    let Shell { html, slots, cache_registrations } = render_shell(node, &mut next_id);
                    live_cache.extend(cache_registrations);
                    for (new_id, source) in slots {
                        pending.push(tag(new_id, source));
                    }
                    record_resolution(&live_cache, id, html.as_str());
                    if id < emit_next {
                        yield Ok(template_chunk(id, html.as_str()));
                    } else {
                        buffered.entry(id).or_default().push(html);
                    }
                }
                SlotEvent::End(id) => {
                    if id >= emit_next {
                        ended.insert(id);
                    }
                }
            }

            // Advance the gate as far as possible.
            loop {
                if let Some(chunks) = buffered.remove(&emit_next) {
                    ended.remove(&emit_next);
                    for html in chunks {
                        yield Ok(template_chunk(emit_next, html.as_str()));
                    }
                    emit_next += 1;
                } else if ended.remove(&emit_next) {
                    emit_next += 1;
                } else {
                    break;
                }
            }
        }
    }
}
