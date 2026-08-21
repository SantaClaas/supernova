use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use futures::stream::{Stream, StreamExt};
use tokio::time::sleep;

use afterglow::{Node, render_stream, render_stream_ordered};

async fn delayed(milliseconds: u64, text: &'static str) -> Node {
    sleep(Duration::from_millis(milliseconds)).await;
    Node::text(text)
}

/// A tree with three pending slots resolving after different delays:
/// slot 0 → 30ms, slot 1 → 10ms, slot 2 → 20ms.
fn three_slot_tree() -> Node {
    Node::element(
        "div",
        vec![],
        vec![
            Node::pending(delayed(30, "slowest")),
            Node::pending(delayed(10, "fastest")),
            Node::pending(delayed(20, "middle")),
        ],
    )
}

async fn collect_chunks(stream: impl Stream<Item = io::Result<Bytes>>) -> Vec<String> {
    stream
        .map(|chunk| String::from_utf8(chunk.unwrap().to_vec()).unwrap())
        .collect()
        .await
}

#[tokio::test(start_paused = true)]
async fn render_stream_fills_slots_in_completion_order() {
    let chunks = collect_chunks(render_stream(three_slot_tree())).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"><?marker name=\"1\"><?marker name=\"2\"></div>",
            "<template for=\"1\">fastest</template>",
            "<template for=\"2\">middle</template>",
            "<template for=\"0\">slowest</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn render_stream_ordered_fills_slots_in_registration_order() {
    let chunks = collect_chunks(render_stream_ordered(three_slot_tree())).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"><?marker name=\"1\"><?marker name=\"2\"></div>",
            "<template for=\"0\">slowest</template>",
            "<template for=\"1\">fastest</template>",
            "<template for=\"2\">middle</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn nested_pending_nodes_are_registered_and_filled() {
    // The outer slot resolves to a subtree that itself contains a pending
    // node — the driver must register it as a new slot and fill it later.
    let tree = Node::pending_with_fallback(
        async {
            sleep(Duration::from_millis(10)).await;
            Node::element(
                "section",
                vec![],
                vec![
                    Node::text("outer resolved, inner "),
                    Node::pending(delayed(10, "inner resolved")),
                ],
            )
        },
        Node::text("loading outer…"),
    );

    let chunks = collect_chunks(render_stream(tree)).await;

    assert_eq!(
        vec![
            "<?start name=\"0\">loading outer…<?end>",
            "<template for=\"0\"><section>outer resolved, inner <?marker name=\"1\"></section></template>",
            "<template for=\"1\">inner resolved</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn failed_widget_renders_error_slot_without_killing_the_stream() {
    let tree = Node::element(
        "div",
        vec![],
        vec![
            Node::pending(async {
                sleep(Duration::from_millis(10)).await;
                Result::<Node, &str>::Err("widget exploded")
            }),
            Node::pending(delayed(20, "still fine")),
        ],
    );

    let chunks = collect_chunks(render_stream(tree)).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"><?marker name=\"1\"></div>",
            "<template for=\"0\"><span class=\"afterglow-error\">widget exploded</span></template>",
            "<template for=\"1\">still fine</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn stream_slot_patches_repeatedly_and_ends_the_response() {
    let ticker = async_stream::stream! {
        for i in 1..=3u32 {
            sleep(Duration::from_millis(10)).await;
            yield Node::text(format!("tick {i}"));
        }
    };
    let tree = Node::element(
        "div",
        vec![],
        vec![Node::stream_with_fallback(ticker, Node::text("waiting…"))],
    );

    let chunks = collect_chunks(render_stream(tree)).await;

    assert_eq!(
        vec![
            "<div><?start name=\"0\">waiting…<?end></div>",
            "<template for=\"0\">tick 1</template>",
            "<template for=\"0\">tick 2</template>",
            "<template for=\"0\">tick 3</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn stream_and_future_slots_interleave_in_completion_order() {
    let updates = async_stream::stream! {
        sleep(Duration::from_millis(10)).await;
        yield Node::text("first update");
        sleep(Duration::from_millis(20)).await; // t = 30ms
        yield Node::text("second update");
    };
    let tree = Node::element(
        "div",
        vec![],
        vec![
            Node::stream(updates),
            Node::pending(delayed(20, "widget")),
        ],
    );

    let chunks = collect_chunks(render_stream(tree)).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"><?marker name=\"1\"></div>",
            "<template for=\"0\">first update</template>",
            "<template for=\"1\">widget</template>",
            "<template for=\"0\">second update</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn pending_widget_inside_stream_value_registers_a_new_slot() {
    let feed = async_stream::stream! {
        sleep(Duration::from_millis(10)).await;
        yield Node::element(
            "article",
            vec![],
            vec![
                Node::text("item with "),
                Node::pending(delayed(10, "details")),
            ],
        );
    };

    let chunks = collect_chunks(render_stream(Node::stream(feed))).await;

    assert_eq!(
        vec![
            "<?marker name=\"0\">",
            "<template for=\"0\"><article>item with <?marker name=\"1\"></article></template>",
            "<template for=\"1\">details</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn empty_stream_leaves_the_fallback_and_terminates() {
    let tree = Node::stream_with_fallback(
        futures::stream::empty::<Node>(),
        Node::text("nothing yet"),
    );

    let chunks = collect_chunks(render_stream(tree)).await;

    assert_eq!(vec!["<?start name=\"0\">nothing yet<?end>"], chunks);
}

#[tokio::test(start_paused = true)]
async fn stream_of_results_renders_error_slots_per_value() {
    let flaky = async_stream::stream! {
        sleep(Duration::from_millis(10)).await;
        yield Result::<&str, &str>::Ok("good value");
        sleep(Duration::from_millis(10)).await;
        yield Err("bad value");
        sleep(Duration::from_millis(10)).await;
        yield Ok("recovered");
    };

    let chunks = collect_chunks(render_stream(Node::stream(flaky))).await;

    assert_eq!(
        vec![
            "<?marker name=\"0\">",
            "<template for=\"0\">good value</template>",
            "<template for=\"0\"><span class=\"afterglow-error\">bad value</span></template>",
            "<template for=\"0\">recovered</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn ordered_stream_gates_on_first_value_then_flows() {
    // Completion order would be: slot 1 (10ms), slot 1 (20ms), slot 0 (30ms),
    // slot 1 (40ms). The gate holds slot 1's early values until slot 0 has
    // emitted, then lets later values flow immediately.
    let updates = async_stream::stream! {
        sleep(Duration::from_millis(10)).await;
        yield Node::text("one");
        sleep(Duration::from_millis(10)).await;
        yield Node::text("two");
        sleep(Duration::from_millis(20)).await; // t = 40ms
        yield Node::text("three");
    };
    let tree = Node::element(
        "div",
        vec![],
        vec![
            Node::pending(delayed(30, "late widget")),
            Node::stream(updates),
        ],
    );

    let chunks = collect_chunks(render_stream_ordered(tree)).await;

    assert_eq!(
        vec![
            "<div><?marker name=\"0\"><?marker name=\"1\"></div>",
            "<template for=\"0\">late widget</template>",
            "<template for=\"1\">one</template>",
            "<template for=\"1\">two</template>",
            "<template for=\"1\">three</template>",
        ],
        chunks
    );
}

#[tokio::test(start_paused = true)]
async fn ordered_gate_is_not_jammed_by_an_empty_stream() {
    let tree = Node::element(
        "div",
        vec![],
        vec![
            Node::stream_with_fallback(futures::stream::empty::<Node>(), Node::text("quiet")),
            Node::pending(delayed(10, "loud")),
        ],
    );

    let chunks = collect_chunks(render_stream_ordered(tree)).await;

    assert_eq!(
        vec![
            "<div><?start name=\"0\">quiet<?end><?marker name=\"1\"></div>",
            "<template for=\"1\">loud</template>",
        ],
        chunks
    );
}

#[tokio::test]
async fn dropping_the_stream_cancels_a_pending_stream_source() {
    let dropped = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));

    let guard = DropGuard {
        dropped: Arc::clone(&dropped),
        completed: Arc::clone(&completed),
    };
    let source = async_stream::stream! {
        let guard = guard;
        futures::future::pending::<()>().await;
        guard.completed.store(true, Ordering::SeqCst);
        yield Node::text("unreachable");
    };

    let mut stream = Box::pin(render_stream(Node::stream(source)));
    let shell = stream.next().await.expect("shell chunk").unwrap();
    assert_eq!(Bytes::from("<?marker name=\"0\">"), shell);
    assert!(!dropped.load(Ordering::SeqCst));

    drop(stream);

    assert!(
        dropped.load(Ordering::SeqCst),
        "stream source must be dropped with the response stream"
    );
    assert!(
        !completed.load(Ordering::SeqCst),
        "stream source must have been cancelled, not run to completion"
    );
}

/// Records on drop whether the future it lives in ever completed.
struct DropGuard {
    dropped: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
}

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn dropping_the_stream_cancels_pending_widget_futures() {
    let dropped = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));

    let guard = DropGuard {
        dropped: Arc::clone(&dropped),
        completed: Arc::clone(&completed),
    };
    let tree = Node::pending(async move {
        futures::future::pending::<()>().await;
        guard.completed.store(true, Ordering::SeqCst);
        Node::text("unreachable")
    });

    let mut stream = Box::pin(render_stream(tree));
    let shell = stream.next().await.expect("shell chunk").unwrap();
    assert_eq!(Bytes::from("<?marker name=\"0\">"), shell);
    // The widget future is now owned by the stream and still pending.
    assert!(!dropped.load(Ordering::SeqCst));

    drop(stream);

    assert!(
        dropped.load(Ordering::SeqCst),
        "widget future must be dropped with the stream"
    );
    assert!(
        !completed.load(Ordering::SeqCst),
        "widget future must have been cancelled, not run to completion"
    );
}
