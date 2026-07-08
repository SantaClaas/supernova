use crate::escape::{escape_attribute, escape_text};
use crate::node::{Attribute, Node, Render};

/// Elements that never have a closing tag; their children are ignored.
const VOID_ELEMENTS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

pub(crate) fn is_void_element(tag: &str) -> bool {
    VOID_ELEMENTS.contains(&tag)
}

pub(crate) fn write_open_tag(tag: &str, attributes: &[Attribute], out: &mut String) {
    out.push('<');
    out.push_str(tag);
    for (name, value) in attributes {
        out.push(' ');
        out.push_str(name);
        if let Some(value) = value {
            out.push_str("=\"");
            escape_attribute(value, out);
            out.push('"');
        }
    }
    out.push('>');
}

pub(crate) fn write_close_tag(tag: &str, out: &mut String) {
    out.push_str("</");
    out.push_str(tag);
    out.push('>');
}

/// Renders a fully resolved tree to a string.
///
/// # Panics
///
/// Panics if the tree contains a [`Node::Pending`] node — those need the
/// streaming renderer (`render_stream`).
pub fn render_to_string(root: impl Render) -> String {
    let mut out = String::new();
    write_resolved(root.into_node(), &mut out);
    out
}

fn write_resolved(node: Node, out: &mut String) {
    match node {
        Node::Html(html) => out.push_str(&html),
        Node::Text(text) => escape_text(&text, out),
        Node::Element {
            tag,
            attributes,
            children,
        } => {
            write_open_tag(&tag, &attributes, out);
            if !is_void_element(&tag) {
                for child in children {
                    write_resolved(child, out);
                }
                write_close_tag(&tag, out);
            }
        }
        Node::Fragment(children) => {
            for child in children {
                write_resolved(child, out);
            }
        }
        Node::Pending { .. } => {
            panic!("render_to_string cannot render Node::Pending; use render_stream instead")
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use super::*;

    fn attr(name: &'static str, value: &str) -> Attribute {
        (Cow::Borrowed(name), Some(value.to_owned()))
    }

    #[test]
    fn renders_nested_elements() {
        let tree = Node::element(
            "div",
            vec![attr("class", "outer")],
            vec![
                Node::element(
                    "ul",
                    vec![],
                    vec![
                        Node::element("li", vec![], vec![Node::text("one")]),
                        Node::element("li", vec![], vec![Node::text("two")]),
                    ],
                ),
                Node::text("tail"),
            ],
        );

        assert_eq!(
            "<div class=\"outer\"><ul><li>one</li><li>two</li></ul>tail</div>",
            render_to_string(tree)
        );
    }

    #[test]
    fn escapes_text_content() {
        let tree = Node::element(
            "p",
            vec![],
            vec![Node::text("<script>alert(1)</script> & more")],
        );

        assert_eq!(
            "<p>&lt;script&gt;alert(1)&lt;/script&gt; &amp; more</p>",
            render_to_string(tree)
        );
    }

    #[test]
    fn escapes_attribute_values() {
        let tree = Node::element("input", vec![attr("value", "\"quoted\" & <tagged>")], vec![]);

        assert_eq!(
            "<input value=\"&quot;quoted&quot; &amp; &lt;tagged&gt;\">",
            render_to_string(tree)
        );
    }

    #[test]
    fn renders_boolean_attributes_bare() {
        let tree = Node::element(
            "input",
            vec![attr("type", "checkbox"), (Cow::Borrowed("checked"), None)],
            vec![],
        );

        assert_eq!("<input type=\"checkbox\" checked>", render_to_string(tree));
    }

    #[test]
    fn renders_empty_children() {
        assert_eq!(
            "<div></div>",
            render_to_string(Node::element("div", vec![], vec![]))
        );
        assert_eq!("", render_to_string(Node::Fragment(Vec::new())));
    }

    #[test]
    fn void_elements_have_no_closing_tag() {
        let tree = Node::element(
            "div",
            vec![],
            vec![Node::element("br", vec![], vec![]), Node::text("after")],
        );

        assert_eq!("<div><br>after</div>", render_to_string(tree));
    }

    #[test]
    fn raw_html_is_written_verbatim() {
        let tree = Node::fragment(vec![Node::raw("<b>bold</b>"), Node::text("<i>")]);

        assert_eq!("<b>bold</b>&lt;i&gt;", render_to_string(tree));
    }

    #[test]
    fn render_trait_converts_common_types() {
        assert_eq!("42", render_to_string(42));
        assert_eq!("a&amp;b", render_to_string("a&b"));
        assert_eq!("", render_to_string(Option::<&str>::None));
        assert_eq!(
            "onetwo",
            render_to_string(vec![Node::text("one"), Node::text("two")])
        );
    }

    #[test]
    fn err_result_renders_error_slot() {
        let result: Result<&str, &str> = Err("db timeout & <panic>");

        assert_eq!(
            "<span class=\"afterglow-error\">db timeout &amp; &lt;panic&gt;</span>",
            render_to_string(result)
        );
    }

    #[test]
    #[should_panic(expected = "cannot render Node::Pending")]
    fn pending_nodes_panic_in_sync_render() {
        render_to_string(Node::pending(futures::future::ready(Node::text("late"))));
    }
}
