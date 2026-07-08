# afterglow

Suspense-style streaming HTML rendering for Rust servers. Render trees where
some subtrees are futures: the renderer emits a **shell** immediately with
placeholder markers for the pending parts, then streams filled-in content as
each future resolves. The wire format is the one from Chrome's
[declarative partial updates](https://developer.chrome.com/blog/declarative-partial-updates)
feature: `<?marker id="N">` / `<?start id="N">fallback<?end>` placeholders,
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

- `@{future}` renders a bare `<?marker id="N">` placeholder; add
  `else { markup }` for fallback content between `<?start id="N">` and
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
<section><h2>Weather</h2><?start id="0"><p>checking the sky…</p><?end></section>
<section><h2>News</h2><?start id="1"><p>fetching headlines…</p><?end></section>
<section><h2>Stocks</h2><?marker id="2"></section></body></html>
```

followed by the widget fills as their (artificial) delays elapse, in
completion order:

```html
<template for="0"><p>21 °C, clear skies</p></template>          <!-- t+0.8s -->
<template for="2"><span class="afterglow-error">stock service unavailable</span></template>  <!-- t+1.5s -->
<template for="1"><ul><li>Streaming HTML lands in afterglow</li>…</ul></template>  <!-- t+2.5s -->
```
