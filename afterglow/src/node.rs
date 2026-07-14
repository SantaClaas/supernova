use std::borrow::Cow;
use std::fmt::Display;

use futures::future::BoxFuture;
use futures::stream::{BoxStream, Stream, StreamExt};

/// An attribute name paired with its value. `None` renders as a bare
/// (boolean) attribute, e.g. `disabled`.
pub type Attribute = (Cow<'static, str>, Option<String>);

/// A tree of HTML content where subtrees may still be pending futures.
pub enum Node {
    /// Pre-escaped HTML written to the output verbatim. All `Html` content is
    /// assumed trusted / already escaped (the `html!` macro only produces
    /// escaped content; use [`Node::raw`] deliberately). The `html!` macro
    /// folds all static markup into `Cow::Borrowed` segments that live in the
    /// binary and are streamed without copying.
    Html(Cow<'static, str>),
    /// Text content, escaped when rendered.
    Text(Cow<'static, str>),
    /// An element with attributes and children. Void elements (`br`, `img`,
    /// ...) render without a closing tag and their children are ignored.
    Element {
        tag: Cow<'static, str>,
        attributes: Vec<Attribute>,
        children: Vec<Node>,
    },
    /// A sequence of nodes with no wrapper element.
    Fragment(Vec<Node>),
    /// A subtree that is not available yet. The shell renders the `fallback`
    /// (or a bare marker if there is none) and the resolved node is streamed
    /// later. The resolved node may itself contain further `Pending` nodes.
    Pending {
        future: BoxFuture<'static, Node>,
        fallback: Option<Box<Node>>,
    },
    /// A subtree whose content arrives as a sequence of values over time.
    /// Renders the same placeholder as [`Node::Pending`]; each value from the
    /// source is streamed as its own `<template for="N">` patch. Per the
    /// declarative partial updates format, successive patches at a bare
    /// marker insert before it — how patches apply is client-side behavior.
    /// Values may themselves contain further pending or stream holes.
    Stream {
        stream: NodeStream,
        fallback: Option<Box<Node>>,
    },
}

/// Opaque handle to a sequence of nodes arriving over time — the payload of
/// a [`Node::Stream`] hole. Construct one via [`IntoNodeStream`].
pub struct NodeStream {
    pub(crate) inner: BoxStream<'static, Node>,
}

/// Conversion into a [`NodeStream`] — the [`Render`] counterpart for "many
/// values over time". This trait is the single intake point for stream
/// holes, keeping the rest of the crate (driver, wire format, macro)
/// independent of any particular streaming trait.
///
/// Implemented for every [`futures::Stream`] whose items implement
/// [`Render`]. When `std::async_iter::AsyncIterator` / `async gen` blocks
/// stabilize they integrate here: if `futures::Stream` converges with
/// `AsyncIterator` (the stated long-term direction) the existing blanket
/// impl covers them with no changes; otherwise a `from_async_iter` adapter
/// will be added (`poll_next` maps 1:1). A second blanket impl is not
/// possible under today's coherence rules, which is why this trait is public
/// — you can bridge your own source types by implementing it directly.
pub trait IntoNodeStream {
    fn into_node_stream(self) -> NodeStream;
}

impl<S, T> IntoNodeStream for S
where
    S: Stream<Item = T> + Send + 'static,
    T: Render + 'static,
{
    fn into_node_stream(self) -> NodeStream {
        NodeStream {
            inner: Box::pin(self.map(Render::into_node)),
        }
    }
}

impl Node {
    /// Creates a raw, pre-escaped HTML node. The content is written verbatim;
    /// the caller is responsible for it being safe.
    pub fn raw(html: impl Into<Cow<'static, str>>) -> Node {
        Node::Html(html.into())
    }

    /// Creates a text node; the content is escaped when rendered.
    pub fn text(text: impl Into<Cow<'static, str>>) -> Node {
        Node::Text(text.into())
    }

    /// Creates an element node.
    pub fn element(
        tag: impl Into<Cow<'static, str>>,
        attributes: Vec<Attribute>,
        children: Vec<Node>,
    ) -> Node {
        Node::Element {
            tag: tag.into(),
            attributes,
            children,
        }
    }

    /// Creates a fragment node from anything renderable.
    pub fn fragment(children: Vec<Node>) -> Node {
        Node::Fragment(children)
    }

    /// Creates a pending node without fallback content; the shell renders a
    /// bare `<?marker name="N">` in its place.
    ///
    /// The future is driven by the render stream itself and dropped with it —
    /// do not `tokio::spawn` it (see the crate docs on cancellation).
    pub fn pending<F, T>(future: F) -> Node
    where
        F: Future<Output = T> + Send + 'static,
        T: Render,
    {
        Node::Pending {
            future: Box::pin(async move { future.await.into_node() }),
            fallback: None,
        }
    }

    /// Creates a pending node with fallback content; the shell renders
    /// `<?start name="N">fallback<?end>` in its place. The fallback may
    /// itself contain further pending nodes.
    pub fn pending_with_fallback<F, T>(future: F, fallback: Node) -> Node
    where
        F: Future<Output = T> + Send + 'static,
        T: Render,
    {
        Node::Pending {
            future: Box::pin(async move { future.await.into_node() }),
            fallback: Some(Box::new(fallback)),
        }
    }

    /// Creates a stream hole without fallback content; the shell renders a
    /// bare `<?marker name="N">` and each value from the source is streamed
    /// as its own `<template for="N">` patch.
    ///
    /// Like widget futures, the source is driven by the render stream and
    /// dropped with it — do not `tokio::spawn` producers feeding it (see the
    /// crate docs on cancellation). The response stream terminates only once
    /// every source has ended, so an infinite source means a held-open
    /// response.
    pub fn stream(source: impl IntoNodeStream) -> Node {
        Node::Stream {
            stream: source.into_node_stream(),
            fallback: None,
        }
    }

    /// Creates a stream hole with fallback content; the shell renders
    /// `<?start name="N">fallback<?end>`. If the source ends without ever
    /// yielding a value, no patch is emitted and the fallback remains.
    pub fn stream_with_fallback(source: impl IntoNodeStream, fallback: Node) -> Node {
        Node::Stream {
            stream: source.into_node_stream(),
            fallback: Some(Box::new(fallback)),
        }
    }
}

/// Conversion into a [`Node`]. This is what interpolated values in the `html!`
/// macro and async widget results go through.
pub trait Render {
    fn into_node(self) -> Node;
}

impl Render for Node {
    fn into_node(self) -> Node {
        self
    }
}

impl Render for String {
    fn into_node(self) -> Node {
        Node::Text(Cow::Owned(self))
    }
}

impl Render for &str {
    fn into_node(self) -> Node {
        Node::Text(Cow::Owned(self.to_owned()))
    }
}

impl Render for Cow<'_, str> {
    fn into_node(self) -> Node {
        Node::Text(Cow::Owned(self.into_owned()))
    }
}

impl Render for char {
    fn into_node(self) -> Node {
        Node::Text(Cow::Owned(self.to_string()))
    }
}

impl Render for () {
    fn into_node(self) -> Node {
        Node::Fragment(Vec::new())
    }
}

macro_rules! impl_render_via_display {
    ($($type:ty),+ $(,)?) => {
        $(
            impl Render for $type {
                fn into_node(self) -> Node {
                    Node::Text(Cow::Owned(self.to_string()))
                }
            }
        )+
    };
}

impl_render_via_display!(
    bool, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize, f32, f64
);

impl<T: Render> Render for Vec<T> {
    fn into_node(self) -> Node {
        Node::Fragment(self.into_iter().map(Render::into_node).collect())
    }
}

/// Collects synchronously available values into a fragment. This is the
/// bridge for plain iterators (and future sync `gen` blocks, which produce
/// `Iterator`s): all values are rendered up front. For values arriving over
/// time, use [`Node::stream`].
impl<T: Render> FromIterator<T> for Node {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Node {
        Node::Fragment(iter.into_iter().map(Render::into_node).collect())
    }
}

impl<T: Render> Render for Option<T> {
    fn into_node(self) -> Node {
        match self {
            Some(value) => value.into_node(),
            None => Node::Fragment(Vec::new()),
        }
    }
}

/// Async widgets return `Result<impl Render, E>`; an `Err` renders as an
/// error slot instead of panicking the stream, so one failed widget cannot
/// take down the whole response.
impl<T: Render, E: Display> Render for Result<T, E> {
    fn into_node(self) -> Node {
        match self {
            Ok(value) => value.into_node(),
            Err(error) => Node::element(
                "span",
                vec![(Cow::Borrowed("class"), Some("afterglow-error".to_owned()))],
                vec![Node::text(error.to_string())],
            ),
        }
    }
}
