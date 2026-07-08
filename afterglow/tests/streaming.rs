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
            "<div><?marker id=\"0\"><?marker id=\"1\"><?marker id=\"2\"></div>",
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
            "<div><?marker id=\"0\"><?marker id=\"1\"><?marker id=\"2\"></div>",
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
            "<?start id=\"0\">loading outer…<?end>",
            "<template for=\"0\"><section>outer resolved, inner <?marker id=\"1\"></section></template>",
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
            "<div><?marker id=\"0\"><?marker id=\"1\"></div>",
            "<template for=\"0\"><span class=\"afterglow-error\">widget exploded</span></template>",
            "<template for=\"1\">still fine</template>",
        ],
        chunks
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
    assert_eq!(Bytes::from("<?marker id=\"0\">"), shell);
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
