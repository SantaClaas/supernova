use std::borrow::Cow;

use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::BoxStream;

use crate::escape::escape_text;
use crate::node::Node;
use crate::render::{is_void_element, write_close_tag, write_open_tag};

pub(crate) type SlotId = u64;

/// What fills a slot: a future resolving to one node, or a stream of nodes
/// each patched into the slot as it arrives.
pub(crate) enum SlotSource {
    Future(BoxFuture<'static, Node>),
    Stream(BoxStream<'static, Node>),
}

/// Accumulates shell HTML while preserving zero-copy for the fully static
/// case: the `html!` macro folds static templates into a single
/// `Node::Html(Cow::Borrowed(...))` segment living in the binary, and a shell
/// consisting of only that segment is sent via [`Bytes::from_static`] without
/// ever being copied. Anything else falls back to one owned buffer.
pub(crate) enum HtmlBuf {
    Empty,
    Static(&'static str),
    Owned(String),
}

impl HtmlBuf {
    fn push_cow(&mut self, content: Cow<'static, str>) {
        if content.is_empty() {
            return;
        }
        match (&mut *self, content) {
            (HtmlBuf::Empty, Cow::Borrowed(content)) => *self = HtmlBuf::Static(content),
            (HtmlBuf::Empty, Cow::Owned(content)) => *self = HtmlBuf::Owned(content),
            (_, content) => self.owned_mut().push_str(&content),
        }
    }

    fn owned_mut(&mut self) -> &mut String {
        match self {
            HtmlBuf::Owned(_) => {}
            HtmlBuf::Empty => *self = HtmlBuf::Owned(String::new()),
            HtmlBuf::Static(existing) => *self = HtmlBuf::Owned((*existing).to_owned()),
        }
        let HtmlBuf::Owned(owned) = self else {
            unreachable!("converted to Owned above");
        };
        owned
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            HtmlBuf::Empty => "",
            HtmlBuf::Static(content) => content,
            HtmlBuf::Owned(content) => content,
        }
    }

    pub(crate) fn into_bytes(self) -> Bytes {
        match self {
            HtmlBuf::Empty => Bytes::new(),
            HtmlBuf::Static(content) => Bytes::from_static(content.as_bytes()),
            HtmlBuf::Owned(content) => Bytes::from(content),
        }
    }
}

/// The synchronous part of a render pass: everything already resolved is in
/// `html` (with placeholder markers where `Pending` nodes were), and the
/// extracted futures wait in `slots` to be driven by the stream.
pub(crate) struct Shell {
    pub(crate) html: HtmlBuf,
    pub(crate) slots: Vec<(SlotId, SlotSource)>,
}

/// Renders a tree without awaiting anything. Each `Pending` or `Stream` node
/// gets a unique id from `next_id` and renders as `<?marker name="N">` (no
/// fallback) or `<?start name="N">fallback<?end>`; its source is pulled out
/// into the returned queue. Fallbacks are walked too, so a pending node
/// nested inside another pending node's fallback is registered as its own
/// slot.
pub(crate) fn render_shell(node: Node, next_id: &mut SlotId) -> Shell {
    let mut shell = Shell {
        html: HtmlBuf::Empty,
        slots: Vec::new(),
    };
    write_shell(node, next_id, &mut shell);
    shell
}

fn write_shell(node: Node, next_id: &mut SlotId, shell: &mut Shell) {
    match node {
        Node::Html(html) => shell.html.push_cow(html),
        Node::Text(text) => escape_text(&text, shell.html.owned_mut()),
        Node::Element {
            tag,
            attributes,
            children,
        } => {
            write_open_tag(&tag, &attributes, shell.html.owned_mut());
            if !is_void_element(&tag) {
                for child in children {
                    write_shell(child, next_id, shell);
                }
                write_close_tag(&tag, shell.html.owned_mut());
            }
        }
        Node::Fragment(children) => {
            for child in children {
                write_shell(child, next_id, shell);
            }
        }
        Node::Pending { future, fallback } => {
            write_slot(SlotSource::Future(future), fallback, next_id, shell);
        }
        Node::Stream { stream, fallback } => {
            write_slot(SlotSource::Stream(stream.inner), fallback, next_id, shell);
        }
    }
}

fn write_slot(
    source: SlotSource,
    fallback: Option<Box<Node>>,
    next_id: &mut SlotId,
    shell: &mut Shell,
) {
    let id = *next_id;
    *next_id += 1;
    shell.slots.push((id, source));
    match fallback {
        None => {
            shell
                .html
                .owned_mut()
                .push_str(&format!("<?marker name=\"{id}\">"));
        }
        Some(fallback) => {
            shell
                .html
                .owned_mut()
                .push_str(&format!("<?start name=\"{id}\">"));
            write_shell(*fallback, next_id, shell);
            shell.html.owned_mut().push_str("<?end>");
        }
    }
}

#[cfg(test)]
mod test {
    use futures::FutureExt;
    use futures::future::ready;

    use super::*;

    #[test]
    fn single_pending_node_renders_marker_and_queues_future() {
        let tree = Node::element(
            "div",
            vec![],
            vec![Node::pending(ready(Node::text("late")))],
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!("<div><?marker name=\"0\"></div>", shell.html.as_str());
        assert_eq!(1, shell.slots.len());
        assert_eq!(0, shell.slots[0].0);
        assert_eq!(1, next_id);
    }

    #[test]
    fn queued_future_resolves_to_the_wrapped_node() {
        let tree = Node::pending(ready(Node::text("late & escaped")));

        let mut next_id = 0;
        let mut shell = render_shell(tree, &mut next_id);

        let (_, source) = shell.slots.pop().unwrap();
        let SlotSource::Future(future) = source else {
            panic!("pending node should register a future slot");
        };
        let resolved = future
            .now_or_never()
            .expect("ready future should resolve immediately");
        assert_eq!("late &amp; escaped", crate::render_to_string(resolved));
    }

    #[test]
    fn stream_node_renders_marker_and_queues_stream_source() {
        let tree = Node::stream(futures::stream::iter([Node::text("a"), Node::text("b")]));

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!("<?marker name=\"0\">", shell.html.as_str());
        assert!(matches!(
            shell.slots.as_slice(),
            [(0, SlotSource::Stream(_))]
        ));
    }

    #[test]
    fn sibling_pending_nodes_get_distinct_ids() {
        let tree = Node::element(
            "div",
            vec![],
            vec![
                Node::pending(ready(Node::text("a"))),
                Node::text("between"),
                Node::pending(ready(Node::text("b"))),
                Node::pending(ready(Node::text("c"))),
            ],
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!(
            "<div><?marker name=\"0\">between<?marker name=\"1\"><?marker name=\"2\"></div>",
            shell.html.as_str()
        );
        let ids: Vec<_> = shell.slots.iter().map(|(id, _)| *id).collect();
        assert_eq!(vec![0, 1, 2], ids);
    }

    #[test]
    fn fallback_renders_between_start_and_end_markers() {
        let tree = Node::pending_with_fallback(
            ready(Node::text("content")),
            Node::element("span", vec![], vec![Node::text("loading…")]),
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!(
            "<?start name=\"0\"><span>loading…</span><?end>",
            shell.html.as_str()
        );
        assert_eq!(1, shell.slots.len());
    }

    #[test]
    fn pending_nested_inside_fallback_registers_its_own_slot() {
        let tree = Node::pending_with_fallback(
            ready(Node::text("outer content")),
            Node::element(
                "div",
                vec![],
                vec![
                    Node::text("outer fallback with "),
                    Node::pending(ready(Node::text("inner content"))),
                ],
            ),
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!(
            "<?start name=\"0\"><div>outer fallback with <?marker name=\"1\"></div><?end>",
            shell.html.as_str()
        );
        let ids: Vec<_> = shell.slots.iter().map(|(id, _)| *id).collect();
        assert_eq!(vec![0, 1], ids);
    }

    #[test]
    fn tree_without_pending_nodes_produces_empty_queue() {
        let tree = Node::element("p", vec![], vec![Node::text("done")]);

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!("<p>done</p>", shell.html.as_str());
        assert!(shell.slots.is_empty());
        assert_eq!(0, next_id);
    }

    #[test]
    fn fully_static_shell_reuses_the_bytes_baked_into_the_binary() {
        static HTML: &str = "<p>prerendered</p>";

        let mut next_id = 0;
        let shell = render_shell(Node::raw(HTML), &mut next_id);
        let bytes = shell.html.into_bytes();

        assert_eq!(HTML.as_bytes(), bytes.as_ref());
        // Zero-copy: the Bytes point directly at the static data.
        assert_eq!(HTML.as_ptr(), bytes.as_ptr());
    }
}
