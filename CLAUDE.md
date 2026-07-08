# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

Cargo workspace (`afterglow`, `afterglow-macros`, `supernova`, `supernovi`, `web-shove`) plus a standalone frontend in `app/` that is **not** part of the workspace.

- **`afterglow/`** + **`afterglow-macros/`** — Suspense-style streaming HTML templating: trees with `Node::Pending` futures render as a shell with `<?marker>`/`<?start>…<?end>` placeholders, backfilled by streamed `<template for="N">` chunks (Chrome declarative partial updates wire format). `render_stream` fills in completion order, `render_stream_ordered` in registration order. The `html!{}` proc macro (in `afterglow-macros`) supports `@{future} else { fallback }` for async widgets. Widget futures are driven by the response stream itself — never `tokio::spawn` them, or drop-based cancellation breaks. See `afterglow/README.md` and `cargo run --example axum_demo`.
- **`web-shove/`** — Library crate implementing Web Push from scratch: RFC 8291 message encryption (ECDH P-256 key exchange, HKDF key derivation, AES-128-GCM, `aes128gcm` content-coding header) in `src/lib.rs`, VAPID key handling in `src/vapid.rs`, and the VAPID JWT `Authorization` header in `src/authorization_header.rs`. Also has a small binary (`src/main.rs`) that generates and prints a new base64url-encoded VAPID private key. Tests use `rstest` fixtures and assert against the RFC 8291 Appendix A test vectors.
- **`supernova/`** — Axum web server (binds `127.0.0.1:3000`). Routes: `GET /` (server-rendered page from `templates/`), `POST /signin`, `POST /notifications/subscriptions`, `POST /notifications/push`. Static files served from `supernova/public/` (includes the service worker and push-subscription JS). Depends on `web-shove` for push payload encryption. Push subscriptions are held in-memory (`Arc<Mutex<Vec<Subscription>>>` in `AppState`) — nothing is persisted yet.
- **`supernovi/`** — Minimal scratch binary that only tests Bitwarden Secrets Manager login.
- **`app/`** — SolidJS + Vite + Tailwind CSS v4 frontend (pnpm), currently a prototype calendar/time-grid UI in `src/App.tsx`. Its dev server proxies `/api` to the Rust server at `http://127.0.0.1:3000`.

## Secrets & startup

The server loads secrets from **Bitwarden Secrets Manager** at startup (`supernova/src/secrets.rs`). It needs a `.env` file (gitignored, loaded via `dotenvy` in debug builds only) with:

- `BWS_TOKEN` — Bitwarden Secrets Manager access token
- `USER_SECRET_ID`, `VAPID_PRIVATE_KEY_ID` — UUIDs of the secrets to fetch

Note: `secrets::setup()` currently ends in `todo!()` after fetching, so the server panics at startup until that is finished.

Auth model: single-user. `POST /signin` compares a form secret against the Bitwarden-stored user secret and sets an encrypted private session cookie (`axum-extra` `PrivateCookieJar`); the cookie key is regenerated on every server start.

## Commands

### Rust (run from repo root)

```bash
cargo check                          # type-check workspace
cargo clippy --all-targets           # lint
cargo test                           # all tests (most live in web-shove)
cargo test -p web-shove can_create_nonce   # single test by name
cargo run -p supernova               # run the server
```

`bacon` is configured (`bacon.toml`) for watch-mode development: `bacon dev` runs the supernova server with kill-then-restart on change; `bacon test` and `bacon clippy-all` (bound to `c`) are also set up.

### Frontend (`app/`, uses pnpm)

```bash
pnpm dev            # dev server at http://localhost:5173, proxies /api to :3000
pnpm build          # tsc -b && vite build
pnpm format         # oxfmt (format:check to verify)
```

The frontend has no test runner or linter configured; `tsc -b` (via `pnpm build`) is the type check.

### Server-rendered CSS (`supernova/`)

The `supernova` crate has its own `package.json`: `pnpm start` runs the Tailwind CLI to compile `app.css` into `public/app.css` for the server-rendered templates.
