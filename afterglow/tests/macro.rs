//! Verifies `html!` expansion produces trees matching what the earlier
//! phases' tests built by hand, by comparing rendered output.

use std::borrow::Cow;
use std::io;
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{Stream, StreamExt};
use tokio::time::sleep;

use afterglow::{Node, Render, html, render_stream, render_to_string};

async fn collect_chunks(stream: impl Stream<Item = io::Result<Bytes>>) -> Vec<String> {
    stream
        .map(|chunk| String::from_utf8(chunk.unwrap().to_vec()).unwrap())
        .collect()
        .await
}

#[test]
fn elements_attributes_and_text_match_hand_built_tree() {
    let by_macro = html! {
        <div class="outer" data-count="3">
            <ul>
                <li>"one"</li>
                <li>"two"</li>
            </ul>
            "tail"
            <br/>
        </div>
    };

    let by_hand = Node::element(
        "div",
        vec![
            ("class".into(), Some("outer".to_owned())),
            ("data-count".into(), Some("3".to_owned())),
        ],
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
            Node::element("br", vec![], vec![]),
        ],
    );

    assert_eq!(render_to_string(by_hand), render_to_string(by_macro));
}

#[test]
fn interpolated_expressions_are_escaped() {
    let name = "Ada <script>";
    let count = 2 + 2;

    let tree = html! {
        <p title={format!("{name}!")}>{name} " has " {count} " items"</p>
    };

    assert_eq!(
        "<p title=\"Ada &lt;script&gt;!\">Ada &lt;script&gt; has 4 items</p>",
        render_to_string(tree)
    );
}

#[test]
fn boolean_attributes_render_bare() {
    let tree = html! { <input type="checkbox" checked/> };

    assert_eq!("<input type=\"checkbox\" checked>", render_to_string(tree));
}

#[test]
fn empty_macro_renders_nothing() {
    assert_eq!("", render_to_string(html! {}));
}

#[test]
fn multiple_top_level_nodes_render_in_sequence() {
    let tree = html! {
        <dt>"term"</dt>
        <dd>"definition"</dd>
    };

    assert_eq!("<dt>term</dt><dd>definition</dd>", render_to_string(tree));
}

#[test]
fn fully_static_template_folds_to_a_single_prerendered_node() {
    let tree = html! {
        <div class="a & b">
            <p>"x < y"</p>
            <br/>
        </div>
    };

    // The macro escaped and concatenated everything at expansion time; the
    // whole template is one borrowed segment living in the binary.
    let Node::Html(Cow::Borrowed(html)) = tree else {
        panic!("fully static templates should fold to one borrowed Html node");
    };
    assert_eq!("<div class=\"a &amp; b\"><p>x &lt; y</p><br></div>", html);
}

const FOOTER: Node = html! { <footer>"© 2026 — a < b"</footer> };

#[test]
fn fully_static_template_is_const_constructible() {
    assert_eq!(
        "<footer>© 2026 — a &lt; b</footer>",
        render_to_string(FOOTER)
    );
}

const BUILT_WITH: Node = html! {
    <footer>"Built with " const { env!("CARGO_PKG_NAME") } " v" const { env!("CARGO_PKG_VERSION") }</footer>
};

#[test]
fn const_interpolation_folds_into_a_single_const_constructible_segment() {
    // Still one borrowed segment: the `const { env!(...) }` pieces were
    // spliced in through `concat!` at compile time.
    let Node::Html(Cow::Borrowed(html)) = BUILT_WITH else {
        panic!("const-interpolated static template should fold to one borrowed Html node");
    };
    assert_eq!(
        concat!(
            "<footer>Built with ",
            env!("CARGO_PKG_NAME"),
            " v",
            env!("CARGO_PKG_VERSION"),
            "</footer>",
        ),
        html
    );
}

#[test]
fn const_interpolation_mixes_with_dynamic_holes() {
    let user = "Ada";
    let tree = html! {
        <p>"hi " {user} ", this is " const { env!("CARGO_PKG_NAME") }</p>
    };

    assert_eq!("<p>hi Ada, this is afterglow</p>", render_to_string(tree));
}

struct Article {
    title: String,
}

impl Render for Article {
    fn into_node(self) -> Node {
        html! { <article><h2>{self.title}</h2></article> }
    }
}

async fn load_article() -> Result<Article, std::convert::Infallible> {
    sleep(Duration::from_millis(10)).await;
    Ok(Article {
        title: "Streaming HTML".to_owned(),
    })
}

async fn load_score() -> u32 {
    sleep(Duration::from_millis(20)).await;
    9001
}

#[tokio::test(start_paused = true)]
async fn async_widgets_stream_through_the_phase_3_driver() {
    let page = html! {
        <main>
            @{load_article()} else { <p class="spinner">"loading article…"</p> }
            <aside>"score: " @{load_score()}</aside>
        </main>
    };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<main><?start name=\"0\"><p class=\"spinner\">loading article…</p><?end>\
             <aside>score: <?marker name=\"1\"></aside></main>",
            "<template for=\"0\"><article><h2>Streaming HTML</h2></article></template>",
            "<template for=\"1\">9001</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn failing_widget_written_with_macro_renders_error_slot() {
    async fn broken() -> Result<Node, &'static str> {
        sleep(Duration::from_millis(5)).await;
        Err("upstream unavailable")
    }

    let page = html! { <div>@{broken()}</div> };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"></div>",
            "<template for=\"0\"><span class=\"afterglow-error\">upstream unavailable</span></template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn pending_widget_inside_fallback_matches_hand_built_tree() {
    let by_macro = html! {
        @{load_score()} else { <span>"waiting for " @{load_score()}</span> }
    };

    let chunks = collect_chunks(render_stream(by_macro)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\"><span>waiting for <?marker name=\"1\"></span><?end>",
            "<template for=\"0\">9001</template>",
            "<template for=\"1\">9001</template>",
        ],
        chunks
    );
}

fn scores() -> impl futures::Stream<Item = u32> {
    async_stream::stream! {
        for score in [10u32, 20, 30] {
            sleep(Duration::from_millis(10)).await;
            yield score;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn stream_hole_written_with_macro_patches_repeatedly() {
    let page = html! { <div>@*{scores()}</div> };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"></div>",
            "<template for=\"0\">10</template>",
            "<template for=\"0\">20</template>",
            "<template for=\"0\">30</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn stream_hole_with_fallback_matches_hand_built_tree() {
    let by_macro = html! {
        @*{scores()} else { <p class="spinner">"waiting for scores…"</p> }
    };
    let by_hand = Node::stream_with_fallback(
        scores(),
        Node::element(
            "p",
            vec![("class".into(), Some("spinner".to_owned()))],
            vec![Node::text("waiting for scores…")],
        ),
    );

    let macro_chunks = collect_chunks(render_stream(by_macro)).await;
    let hand_chunks = collect_chunks(render_stream(by_hand)).await;

    assert_eq!(hand_chunks, macro_chunks);
}

async fn final_score() -> u32 {
    // Resolves after all of scores()'s 10/20/30ms ticks, with no tie, so
    // completion order between the two holes is unambiguous.
    sleep(Duration::from_millis(35)).await;
    9001
}

#[tokio::test(start_paused = true)]
async fn stream_and_pending_holes_compose_in_one_template() {
    let page = html! {
        <main>
            <aside>"live: " @*{scores()}</aside>
            @{final_score()} else { <p>"loading final score…"</p> }
        </main>
    };

    let chunks = collect_chunks(render_stream(page)).await;

    assert_eq!(
        vec![
            "<main><aside>live: <?marker name=\"0\"></aside>\
             <?start name=\"1\"><p>loading final score…</p><?end></main>",
            "<template for=\"0\">10</template>",
            "<template for=\"0\">20</template>",
            "<template for=\"0\">30</template>",
            "<template for=\"1\">9001</template>",
        ],
        chunks
    );
}
