use futures::future::BoxFuture;

use crate::escape::escape_text;
use crate::node::Node;
use crate::render::{is_void_element, write_close_tag, write_open_tag};

pub(crate) type SlotId = u64;

/// The synchronous part of a render pass: everything already resolved is in
/// `html` (with placeholder markers where `Pending` nodes were), and the
/// extracted futures wait in `slots` to be driven by the stream.
pub(crate) struct Shell {
    pub(crate) html: String,
    pub(crate) slots: Vec<(SlotId, BoxFuture<'static, Node>)>,
}

/// Renders a tree without awaiting anything. Each `Pending` node gets a
/// unique id from `next_id` and renders as `<?marker id="N">` (no fallback)
/// or `<?start id="N">fallback<?end>`; its future is pulled out into the
/// returned queue. Fallbacks are walked too, so a pending node nested inside
/// another pending node's fallback is registered as its own slot.
pub(crate) fn render_shell(node: Node, next_id: &mut SlotId) -> Shell {
    let mut shell = Shell {
        html: String::new(),
        slots: Vec::new(),
    };
    write_shell(node, next_id, &mut shell);
    shell
}

fn write_shell(node: Node, next_id: &mut SlotId, shell: &mut Shell) {
    match node {
        Node::Html(html) => shell.html.push_str(&html),
        Node::Text(text) => escape_text(&text, &mut shell.html),
        Node::Element {
            tag,
            attributes,
            children,
        } => {
            write_open_tag(&tag, &attributes, &mut shell.html);
            if !is_void_element(&tag) {
                for child in children {
                    write_shell(child, next_id, shell);
                }
                write_close_tag(&tag, &mut shell.html);
            }
        }
        Node::Fragment(children) => {
            for child in children {
                write_shell(child, next_id, shell);
            }
        }
        Node::Pending { future, fallback } => {
            let id = *next_id;
            *next_id += 1;
            shell.slots.push((id, future));
            match fallback {
                None => {
                    shell.html.push_str(&format!("<?marker id=\"{id}\">"));
                }
                Some(fallback) => {
                    shell.html.push_str(&format!("<?start id=\"{id}\">"));
                    write_shell(*fallback, next_id, shell);
                    shell.html.push_str("<?end>");
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

        assert_eq!("<div><?marker id=\"0\"></div>", shell.html);
        assert_eq!(1, shell.slots.len());
        assert_eq!(0, shell.slots[0].0);
        assert_eq!(1, next_id);
    }

    #[test]
    fn queued_future_resolves_to_the_wrapped_node() {
        let tree = Node::pending(ready(Node::text("late & escaped")));

        let mut next_id = 0;
        let mut shell = render_shell(tree, &mut next_id);

        let (_, future) = shell.slots.pop().unwrap();
        let resolved = future
            .now_or_never()
            .expect("ready future should resolve immediately");
        assert_eq!("late &amp; escaped", crate::render_to_string(resolved));
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
            "<div><?marker id=\"0\">between<?marker id=\"1\"><?marker id=\"2\"></div>",
            shell.html
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
            "<?start id=\"0\"><span>loading…</span><?end>",
            shell.html
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
            "<?start id=\"0\"><div>outer fallback with <?marker id=\"1\"></div><?end>",
            shell.html
        );
        let ids: Vec<_> = shell.slots.iter().map(|(id, _)| *id).collect();
        assert_eq!(vec![0, 1], ids);
    }

    #[test]
    fn tree_without_pending_nodes_produces_empty_queue() {
        let tree = Node::element("p", vec![], vec![Node::text("done")]);

        let mut next_id = 0;
        let shell = render_shell(tree, &mut next_id);

        assert_eq!("<p>done</p>", shell.html);
        assert!(shell.slots.is_empty());
        assert_eq!(0, next_id);
    }
}
