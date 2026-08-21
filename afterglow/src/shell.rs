use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::BoxStream;

use crate::escape::escape_text;
use crate::node::{Attribute, Node};
use crate::render::{is_void_element, write_close_tag, write_open_tag};

pub(crate) type SlotId = u64;

/// What fills a slot: a future resolving to one node, or a stream of nodes
/// each patched into the slot as it arrives.
pub(crate) enum SlotSource {
    Future(BoxFuture<'static, Node>),
    Stream(BoxStream<'static, Node>),
}

/// A fragment of an element's children as known at the moment they were
/// first shell-walked: literal HTML, or a hole whose resolution state is
/// shared with the normal per-slot driver loop via `state`. Used only for
/// the children of a [`Node::PendingAttributes`] element — everywhere else,
/// `write_shell` takes the plain (non-tracked) path.
///
/// When that element's attributes resolve, [`serialize_skeleton`] rebuilds
/// the element from this: a `Hole` already resolved (`state` holding
/// `Some(html)`) is inlined verbatim; one still unresolved reconstructs its
/// own marker using the *same* `id`, so its still-running future or stream —
/// untouched, never re-run or duplicated — keeps targeting a valid location
/// after the swap.
#[derive(Clone)]
enum SkeletonPart {
    Literal(String),
    Hole {
        id: SlotId,
        fallback: Option<Skeleton>,
        state: Arc<Mutex<Option<String>>>,
    },
}

type Skeleton = Vec<SkeletonPart>;

fn push_literal(skeleton: &mut Skeleton, text: &str) {
    if text.is_empty() {
        return;
    }
    if let Some(SkeletonPart::Literal(existing)) = skeleton.last_mut() {
        existing.push_str(text);
    } else {
        skeleton.push(SkeletonPart::Literal(text.to_owned()));
    }
}

fn write_literal_both(text: &str, shell: &mut Shell, skeleton: &mut Skeleton) {
    shell.html.owned_mut().push_str(text);
    push_literal(skeleton, text);
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
    /// Cache cells registered by any `PendingAttributes` element encountered
    /// during this walk, keyed by the id of the hole whose resolved HTML
    /// they should receive. The driver merges these into a crate-wide table
    /// and writes into them whenever the corresponding slot resolves — see
    /// `stream.rs`.
    pub(crate) cache_registrations: Vec<(SlotId, Arc<Mutex<Option<String>>>)>,
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
        cache_registrations: Vec::new(),
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
        Node::PendingAttributes {
            tag,
            fallback_attributes,
            attributes,
            children,
        } => {
            // Discard the returned skeleton: nothing above us needs to
            // represent this element as a hole (that's only needed when
            // nested inside another PendingAttributes' children — see
            // write_shell_with_skeleton below).
            let _ = write_pending_attributes(
                tag,
                fallback_attributes,
                attributes,
                children,
                next_id,
                shell,
            );
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

/// Shell-walks a `PendingAttributes` element: writes its immediate
/// `<?start name="id">`-wrapped fallback rendering into `shell.html` (open
/// tag with `fallback_attributes`, children walked via
/// `write_shell_with_skeleton` so their holes are cache-tracked, close tag),
/// registers its resolution future into `shell.slots`, and returns both the
/// assigned id and a skeleton reconstructing its fallback markup. Callers
/// that need to represent this element as a hole inside an *outer* skeleton
/// (i.e. it's nested inside another `PendingAttributes`' children) use both;
/// the top-level, non-nested caller discards them.
fn write_pending_attributes(
    tag: Cow<'static, str>,
    fallback_attributes: Vec<Attribute>,
    attributes: BoxFuture<'static, Vec<Attribute>>,
    children: Vec<Node>,
    next_id: &mut SlotId,
    shell: &mut Shell,
) -> (SlotId, Skeleton) {
    let id = *next_id;
    *next_id += 1;

    shell
        .html
        .owned_mut()
        .push_str(&format!("<?start name=\"{id}\">"));

    // `open`/`close` use `fallback_attributes` and belong only in the
    // *fallback* reconstruction below — the element's own eventual future
    // writes its own open/close tag with the resolved attributes, so
    // `children_skeleton` (used by that future) must hold children only.
    let mut open = String::new();
    write_open_tag(&tag, &fallback_attributes, &mut open);
    shell.html.owned_mut().push_str(&open);

    let mut children_skeleton: Skeleton = Vec::new();
    let mut close = String::new();
    if !is_void_element(&tag) {
        for child in children {
            write_shell_with_skeleton(child, next_id, shell, &mut children_skeleton);
        }
        write_close_tag(&tag, &mut close);
        shell.html.owned_mut().push_str(&close);
    }

    shell.html.owned_mut().push_str("<?end>");

    // The eventual replacement: await the attributes, then serialize using
    // whatever is currently known in the skeleton's hole states — anything
    // not yet resolved reconstructs its own marker with the same id, so its
    // still-running future or stream keeps a valid target after the swap.
    let skeleton_for_swap = children_skeleton.clone();
    let tag_for_future = tag.clone();
    let future: BoxFuture<'static, Node> = Box::pin(async move {
        let resolved_attributes = attributes.await;
        Node::Html(Cow::Owned(serialize_skeleton(
            &tag_for_future,
            &resolved_attributes,
            &skeleton_for_swap,
        )))
    });
    shell.slots.push((id, SlotSource::Future(future)));

    // Returned to a caller that needs to represent this element as a hole in
    // an *ancestor's* skeleton: the full fallback markup (open tag with
    // fallback_attributes + children + close tag), used only if this
    // element hasn't resolved by the time that ancestor freezes.
    let mut fallback_skeleton: Skeleton = Vec::new();
    push_literal(&mut fallback_skeleton, &open);
    fallback_skeleton.extend(children_skeleton);
    push_literal(&mut fallback_skeleton, &close);

    (id, fallback_skeleton)
}

/// Like `write_shell`, but also builds a parallel [`Skeleton`] of `node` as
/// it's walked, so an enclosing `PendingAttributes` element can later
/// reconstruct this content from current state rather than re-walking the
/// (by-then partially consumed) original tree. Used only for the children of
/// a `PendingAttributes` element — everywhere else `write_shell` is the fast
/// path and stays untouched.
fn write_shell_with_skeleton(
    node: Node,
    next_id: &mut SlotId,
    shell: &mut Shell,
    skeleton: &mut Skeleton,
) {
    match node {
        Node::Html(html) => write_literal_both(&html, shell, skeleton),
        Node::Text(text) => {
            let mut escaped = String::new();
            escape_text(&text, &mut escaped);
            write_literal_both(&escaped, shell, skeleton);
        }
        Node::Element {
            tag,
            attributes,
            children,
        } => {
            let mut open = String::new();
            write_open_tag(&tag, &attributes, &mut open);
            write_literal_both(&open, shell, skeleton);

            if !is_void_element(&tag) {
                for child in children {
                    write_shell_with_skeleton(child, next_id, shell, skeleton);
                }
                let mut close = String::new();
                write_close_tag(&tag, &mut close);
                write_literal_both(&close, shell, skeleton);
            }
        }
        Node::Fragment(children) => {
            for child in children {
                write_shell_with_skeleton(child, next_id, shell, skeleton);
            }
        }
        Node::Pending { future, fallback } => {
            write_slot_with_skeleton(SlotSource::Future(future), fallback, next_id, shell, skeleton);
        }
        Node::Stream { stream, fallback } => {
            write_slot_with_skeleton(
                SlotSource::Stream(stream.inner),
                fallback,
                next_id,
                shell,
                skeleton,
            );
        }
        Node::PendingAttributes {
            tag,
            fallback_attributes,
            attributes,
            children,
        } => {
            let (id, fallback_skeleton) = write_pending_attributes(
                tag,
                fallback_attributes,
                attributes,
                children,
                next_id,
                shell,
            );
            let state = Arc::new(Mutex::new(None));
            shell.cache_registrations.push((id, Arc::clone(&state)));
            skeleton.push(SkeletonPart::Hole {
                id,
                fallback: Some(fallback_skeleton),
                state,
            });
        }
    }
}

fn write_slot_with_skeleton(
    source: SlotSource,
    fallback: Option<Box<Node>>,
    next_id: &mut SlotId,
    shell: &mut Shell,
    skeleton: &mut Skeleton,
) {
    let id = *next_id;
    *next_id += 1;
    shell.slots.push((id, source));

    let state = Arc::new(Mutex::new(None));
    shell.cache_registrations.push((id, Arc::clone(&state)));

    match fallback {
        None => {
            shell
                .html
                .owned_mut()
                .push_str(&format!("<?marker name=\"{id}\">"));
            skeleton.push(SkeletonPart::Hole {
                id,
                fallback: None,
                state,
            });
        }
        Some(fallback) => {
            shell
                .html
                .owned_mut()
                .push_str(&format!("<?start name=\"{id}\">"));
            let mut fallback_skeleton: Skeleton = Vec::new();
            write_shell_with_skeleton(*fallback, next_id, shell, &mut fallback_skeleton);
            shell.html.owned_mut().push_str("<?end>");
            skeleton.push(SkeletonPart::Hole {
                id,
                fallback: Some(fallback_skeleton),
                state,
            });
        }
    }
}

/// Rebuilds a `PendingAttributes` element's replacement markup from its
/// resolved attributes and the current state of its children's skeleton —
/// see [`SkeletonPart`].
fn serialize_skeleton(tag: &str, attributes: &[Attribute], skeleton: &Skeleton) -> String {
    let mut out = String::new();
    write_open_tag(tag, attributes, &mut out);
    if !is_void_element(tag) {
        write_skeleton_parts(skeleton, &mut out);
        write_close_tag(tag, &mut out);
    }
    out
}

fn write_skeleton_parts(skeleton: &Skeleton, out: &mut String) {
    for part in skeleton {
        match part {
            SkeletonPart::Literal(text) => out.push_str(text),
            SkeletonPart::Hole { id, fallback, state } => {
                let resolved = state.lock().expect("cache mutex is never held across a panic");
                match &*resolved {
                    Some(html) => out.push_str(html),
                    None => match fallback {
                        None => out.push_str(&format!("<?marker name=\"{id}\">")),
                        Some(fallback_skeleton) => {
                            out.push_str(&format!("<?start name=\"{id}\">"));
                            write_skeleton_parts(fallback_skeleton, out);
                            out.push_str("<?end>");
                        }
                    },
                }
            }
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

    fn attr(name: &'static str, value: &str) -> (std::borrow::Cow<'static, str>, Option<String>) {
        (name.into(), Some(value.to_owned()))
    }

    #[test]
    fn pending_attributes_wraps_whole_element_and_queues_one_future() {
        let tree = Node::element_with_pending_attributes(
            "div",
            ready(vec![attr("class", "resolved")]),
            vec![attr("class", "loading")],
            vec![Node::text("content")],
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!(
            "<?start name=\"0\"><div class=\"loading\">content</div><?end>",
            shell.html.as_str()
        );
        assert_eq!(1, shell.slots.len());
        assert_eq!(0, shell.slots[0].0);
        assert!(matches!(shell.slots[0].1, SlotSource::Future(_)));
        // No nested holes in this tree, so no cache cells are registered.
        assert!(shell.cache_registrations.is_empty());
        assert_eq!(1, next_id);
    }

    #[test]
    fn pending_attributes_future_resolves_to_the_full_replacement_element() {
        let tree = Node::element_with_pending_attributes(
            "div",
            ready(vec![attr("class", "resolved")]),
            vec![attr("class", "loading")],
            vec![Node::text("content")],
        );

        let mut next_id = 0;
        let mut shell = render_shell(tree, &mut next_id);
        let (_, source) = shell.slots.pop().unwrap();
        let SlotSource::Future(future) = source else {
            panic!("pending-attributes node should register a future slot");
        };
        let resolved = future
            .now_or_never()
            .expect("ready future should resolve immediately");

        assert_eq!(
            "<div class=\"resolved\">content</div>",
            crate::render_to_string(resolved)
        );
    }

    #[test]
    fn nested_hole_inside_pending_attributes_registers_a_cache_cell() {
        let tree = Node::element_with_pending_attributes(
            "div",
            ready(vec![attr("class", "resolved")]),
            vec![attr("class", "loading")],
            vec![
                Node::text("child: "),
                Node::pending(ready(Node::text("inner"))),
            ],
        );

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!(
            "<?start name=\"0\"><div class=\"loading\">child: <?marker name=\"1\"></div><?end>",
            shell.html.as_str()
        );
        // Two slots: the outer attribute future (id 0) and the nested
        // pending child (id 1) — the child's slot is pushed first since its
        // walk completes before the outer's own future is built, but the
        // driver (a SelectAll) doesn't care about push order.
        let mut ids: Vec<_> = shell.slots.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        assert_eq!(vec![0, 1], ids);
        // The nested hole's cache cell is registered, starting empty.
        assert_eq!(1, shell.cache_registrations.len());
        let (cache_id, state) = &shell.cache_registrations[0];
        assert_eq!(1, *cache_id);
        assert!(state.lock().unwrap().is_none());
    }

    #[test]
    fn nested_pending_attributes_registers_its_own_cache_cell_too() {
        let inner = Node::element_with_pending_attributes(
            "span",
            ready(vec![attr("data-inner", "resolved")]),
            vec![attr("data-inner", "loading")],
            vec![Node::text("inner")],
        );
        let outer = Node::element_with_pending_attributes(
            "div",
            ready(vec![attr("data-outer", "resolved")]),
            vec![attr("data-outer", "loading")],
            vec![inner],
        );

        let mut next_id = 0;
        let shell = render_shell(outer, &mut next_id);

        assert_eq!(
            "<?start name=\"0\"><div data-outer=\"loading\">\
             <?start name=\"1\"><span data-inner=\"loading\">inner</span><?end>\
             </div><?end>",
            shell.html.as_str()
        );
        let mut slot_ids: Vec<_> = shell.slots.iter().map(|(id, _)| *id).collect();
        slot_ids.sort_unstable();
        assert_eq!(vec![0, 1], slot_ids);
        // The nested PendingAttributes element (id 1) gets its own cache
        // cell too, so an ancestor's swap can inline it once resolved.
        let cache_ids: Vec<_> = shell
            .cache_registrations
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(vec![1], cache_ids);
    }
}
