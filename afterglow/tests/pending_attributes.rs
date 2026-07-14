//! Async attribute values: `Node::element_with_pending_attributes` /
//! `html! { attr=@{...} }`. There is no attribute-level patch in the wire
//! format, so once the attribute(s) resolve, the *whole element* is
//! replaced. These tests verify that replacement never re-runs or
//! duplicates a nested hole's work, regardless of whether that hole
//! resolves before or after the attribute — the two failure modes a naive
//! "rebuild the element from scratch" implementation would hit (content
//! silently discarded, or an orphaned patch targeting a removed marker).

use std::borrow::Cow;
use std::io;
use std::time::Duration;

use afterglow::{Node, html, render_stream};
use bytes::Bytes;
use futures::stream::{Stream, StreamExt};
use tokio::time::sleep;

async fn collect_chunks(stream: impl Stream<Item = io::Result<Bytes>>) -> Vec<String> {
    stream
        .map(|chunk| String::from_utf8(chunk.unwrap().to_vec()).unwrap())
        .collect()
        .await
}

fn attr(name: &'static str, value: &str) -> (Cow<'static, str>, Option<String>) {
    (name.into(), Some(value.to_owned()))
}

#[tokio::test(start_paused = true)]
async fn attribute_resolves_with_no_nested_holes() {
    let panel = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(10)).await;
            vec![attr("class", "theme-dark"), attr("id", "panel")]
        },
        vec![attr("class", "theme-loading"), attr("id", "panel")],
        vec![Node::text("Ready")],
    );

    let chunks = collect_chunks(render_stream(Node::element("main", vec![], vec![panel]))).await;

    assert_eq!(
        vec![
            "<main><?start name=\"0\"><div class=\"theme-loading\" id=\"panel\">Ready</div><?end></main>",
            "<template for=\"0\"><div class=\"theme-dark\" id=\"panel\">Ready</div></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_pending_child_resolving_before_the_attribute_is_inlined_not_re_marked() {
    let panel = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(30)).await;
            vec![attr("class", "theme-dark")]
        },
        vec![attr("class", "theme-loading")],
        vec![
            Node::text("child: "),
            Node::pending(async move {
                sleep(Duration::from_millis(10)).await;
                Node::text("resolved-child")
            }),
        ],
    );

    let chunks = collect_chunks(render_stream(panel)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div class=\"theme-loading\">child: <?marker name=\"1\"></div><?end>",
            "<template for=\"1\">resolved-child</template>",
            // The swap inlines the already-resolved child directly — no
            // marker for it in the new markup, and no second patch for it.
            "<template for=\"0\"><div class=\"theme-dark\">child: resolved-child</div></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_pending_child_resolving_after_the_attribute_reuses_its_marker_id() {
    let panel = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(10)).await;
            vec![attr("class", "theme-dark")]
        },
        vec![attr("class", "theme-loading")],
        vec![
            Node::text("child: "),
            Node::pending(async move {
                sleep(Duration::from_millis(30)).await;
                Node::text("resolved-child")
            }),
        ],
    );

    let chunks = collect_chunks(render_stream(panel)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div class=\"theme-loading\">child: <?marker name=\"1\"></div><?end>",
            // The swap reuses marker id 1 — the child's own future is
            // untouched, still running, and its later patch still lands.
            "<template for=\"0\"><div class=\"theme-dark\">child: <?marker name=\"1\"></div></template>",
            "<template for=\"1\">resolved-child</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_stream_hole_swap_uses_only_the_latest_value() {
    let ticks = async_stream::stream! {
        for i in 1..=3u32 {
            sleep(Duration::from_millis(10)).await;
            yield Node::text(format!("tick {i}"));
        }
    };

    let panel = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(25)).await; // after ticks 1, 2; before 3
            vec![attr("class", "theme-dark")]
        },
        vec![attr("class", "theme-loading")],
        vec![Node::stream_with_fallback(ticks, Node::text("waiting…"))],
    );

    let chunks = collect_chunks(render_stream(panel)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div class=\"theme-loading\"><?start name=\"1\">waiting…<?end></div><?end>",
            "<template for=\"1\">tick 1</template>",
            "<template for=\"1\">tick 2</template>",
            // The swap inlines only the latest value (tick 2), not the
            // accumulated history — documented as a deliberate limitation.
            "<template for=\"0\"><div class=\"theme-dark\">tick 2</div></template>",
            // The stream itself is untouched and keeps patching afterward.
            "<template for=\"1\">tick 3</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_pending_attributes_resolving_before_the_outer_is_inlined() {
    let inner = Node::element_with_pending_attributes(
        "span",
        async move {
            sleep(Duration::from_millis(10)).await;
            vec![attr("data-inner", "resolved")]
        },
        vec![attr("data-inner", "loading")],
        vec![Node::text("inner")],
    );
    let outer = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(30)).await;
            vec![attr("data-outer", "resolved")]
        },
        vec![attr("data-outer", "loading")],
        vec![inner],
    );

    let chunks = collect_chunks(render_stream(outer)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div data-outer=\"loading\">\
             <?start name=\"1\"><span data-inner=\"loading\">inner</span><?end>\
             </div><?end>",
            "<template for=\"1\"><span data-inner=\"resolved\">inner</span></template>",
            "<template for=\"0\"><div data-outer=\"resolved\"><span data-inner=\"resolved\">inner</span></div></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_pending_attributes_resolving_after_the_outer_reuses_its_marker_id() {
    let inner = Node::element_with_pending_attributes(
        "span",
        async move {
            sleep(Duration::from_millis(30)).await;
            vec![attr("data-inner", "resolved")]
        },
        vec![attr("data-inner", "loading")],
        vec![Node::text("inner")],
    );
    let outer = Node::element_with_pending_attributes(
        "div",
        async move {
            sleep(Duration::from_millis(10)).await;
            vec![attr("data-outer", "resolved")]
        },
        vec![attr("data-outer", "loading")],
        vec![inner],
    );

    let chunks = collect_chunks(render_stream(outer)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div data-outer=\"loading\">\
             <?start name=\"1\"><span data-inner=\"loading\">inner</span><?end>\
             </div><?end>",
            "<template for=\"0\"><div data-outer=\"resolved\">\
             <?start name=\"1\"><span data-inner=\"loading\">inner</span><?end>\
             </div></template>",
            "<template for=\"1\"><span data-inner=\"resolved\">inner</span></template>",
        ],
        chunks
    );
}

async fn theme_class() -> &'static str {
    sleep(Duration::from_millis(10)).await;
    "theme-dark"
}

#[tokio::test(start_paused = true)]
async fn macro_pending_attribute_with_no_fallback_omits_it_until_resolved() {
    let page = html! { <div class=@{theme_class()} id="panel">"Ready"</div> };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div id=\"panel\">Ready</div><?end>",
            "<template for=\"0\"><div class=\"theme-dark\" id=\"panel\">Ready</div></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn macro_pending_attribute_with_string_fallback() {
    let page = html! {
        <div class=@{theme_class()} else "theme-loading" id="panel">"Ready"</div>
    };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div class=\"theme-loading\" id=\"panel\">Ready</div><?end>",
            "<template for=\"0\"><div class=\"theme-dark\" id=\"panel\">Ready</div></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn macro_pending_attribute_composes_with_a_nested_content_hole() {
    async fn child() -> Node {
        sleep(Duration::from_millis(30)).await;
        Node::text("resolved-child")
    }

    let page = html! {
        <div class=@{theme_class()} else "theme-loading">
            "child: " @{child()}
        </div>
    };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><div class=\"theme-loading\">child: <?marker name=\"1\"></div><?end>",
            "<template for=\"0\"><div class=\"theme-dark\">child: <?marker name=\"1\"></div></template>",
            "<template for=\"1\">resolved-child</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn macro_output_matches_hand_built_tree() {
    let by_macro = html! {
        <div class=@{theme_class()} else "theme-loading" id="fixed">"x"</div>
    };
    let by_hand = Node::element_with_pending_attributes(
        "div",
        async move {
            let class = theme_class().await;
            vec![
                ("class".into(), Some(class.to_string())),
                ("id".into(), Some("fixed".to_owned())),
            ]
        },
        vec![
            attr("class", "theme-loading"),
            attr("id", "fixed"),
        ],
        vec![Node::text("x")],
    );

    let macro_chunks = collect_chunks(render_stream(by_macro)).await;
    let hand_chunks = collect_chunks(render_stream(by_hand)).await;

    assert_eq!(hand_chunks, macro_chunks);
}
