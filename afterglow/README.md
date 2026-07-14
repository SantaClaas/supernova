# afterglow

Suspense-style streaming HTML rendering for Rust servers. Render trees where
some subtrees are futures: the renderer emits a **shell** immediately with
placeholder markers for the pending parts, then streams filled-in content as
each future resolves. The wire format is the one from Chrome's
[declarative partial updates](https://developer.chrome.com/blog/declarative-partial-updates)
feature: `<?marker name="N">` / `<?start name="N">fallback<?end>` placeholders,
filled later by `<template for="N">...</template>` blocks.

This is a one-shot streaming model — no client-side state, no re-renders.
Write the parts you have now, backfill the rest as they arrive.

## Example

```rust
use afterglow::{html, render_stream};

async fn weather() -> Result<Node, &'static str> { /* slow fetch */ }

let page = html! {
    <section>
        <h2>"Weather"</h2>
        @{weather()} else { <p>"checking the sky…"</p> }
    </section>
};

// impl Stream<Item = io::Result<Bytes>> — feed it straight into
// axum::body::Body::from_stream with content-type text/html; charset=utf-8.
let body = render_stream(page);
```

- `@{future}` renders a bare `<?marker name="N">` placeholder; add
  `else { markup }` for fallback content between `<?start name="N">` and
  `<?end>`.
- Async widgets return `Result<impl Render, E: Display>`; an `Err` renders as
  `<span class="afterglow-error">…</span>` in the slot instead of killing the
  stream.
- `render_stream` fills slots in **completion order**;
  `render_stream_ordered` fills in **registration order** (deterministic, for
  snapshot tests). Resolved subtrees may contain further `@{...}` widgets —
  nesting is unbounded.
- Cancellation is free: dropping the stream (client disconnect) drops all
  pending widget futures. For that to work, **never `tokio::spawn` widget
  futures** — let the render stream drive them.
- **Compile-time prerendering**: `html!` escapes and folds all static markup
  at macro expansion time into `&'static str` segments stored in the binary;
  the only per-request work is the dynamic holes (`{expr}`, `@{...}`, and
  elements with `attr={expr}` values). A fully static template expands to a
  single borrowed segment — it is const-constructible
  (`const FOOTER: Node = html! { <footer>"© 2026"</footer> };`) and its shell
  is streamed via `Bytes::from_static` without copying.
- **Const interpolation**: `const { expr }` splices compile-time strings into
  the static fold via `concat!`, e.g.
  `const { env!("CARGO_PKG_NAME") }` — verbatim (no escaping), literals and
  built-in literal macros only, and the template stays const-constructible.
- **Streamed (live-updating) holes**: `@*{source}` where `source` implements
  `IntoNodeStream` — any `Stream` whose items implement `Render`. Renders the
  same placeholder as `@{...}` (with the same optional `else { fallback }`),
  but instead of resolving once, each value from the source is streamed as
  its own `<template for="N">` patch — per the declarative partial updates
  format, repeated patches at the same marker are how a client expresses a
  live-updating region. The response stays open until every future has
  resolved *and* every stream has ended, so an infinite source means a
  held-open, forever-streaming response. `IntoNodeStream` is the crate's
  single intake point for "many values over time" — kept separate from
  `futures::Stream` so that `std::async_iter::AsyncIterator` / `async gen`
  blocks can plug in without changing `Node`, the driver, or the wire format,
  once they stabilize.

## Streaming demo

```sh
cargo run --example axum_demo
```

then, in another terminal:

```sh
curl --no-buffer localhost:3210/
```

`--no-buffer` makes curl print each chunk as it arrives. You will see the
shell immediately:

```html
<html><head><title>afterglow demo</title></head><body><h1>Dashboard</h1>
<section><h2>Weather</h2><?start name="0"><p>checking the sky…</p><?end></section>
<section><h2>News</h2><?start name="1"><p>fetching headlines…</p><?end></section>
<section><h2>Stocks</h2><?marker name="2"></section></body></html>
```

followed by the widget fills as their (artificial) delays elapse, in
completion order. Slot 3, the "Live price" section, patches five times as new
ticks arrive instead of resolving once:

```html
<template for="3"><span>$101.00</span></template>                <!-- t+0.4s -->
<template for="0"><p>21 °C, clear skies</p></template>            <!-- t+0.8s -->
<template for="3"><span>$102.01</span></template>                 <!-- t+0.8s -->
<template for="3"><span>$103.03</span></template>                 <!-- t+1.2s -->
<template for="2"><span class="afterglow-error">stock service unavailable</span></template>  <!-- t+1.5s -->
<template for="3"><span>$104.06</span></template>                 <!-- t+1.6s -->
<template for="3"><span>$105.10</span></template>                 <!-- t+2.0s -->
<template for="1"><ul><li>Streaming HTML lands in afterglow</li>…</ul></template>  <!-- t+2.5s -->
```
