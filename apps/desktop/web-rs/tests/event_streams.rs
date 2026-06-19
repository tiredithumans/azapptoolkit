//! Proves the streamed-event plumbing end to end: subscribe through the real
//! `bindings::events` helpers (which go through the mocked
//! `__TAURI_INTERNALS__` `listen`/`transformCallback` path), then `emit_event`
//! and assert the payload arrives on the stream. This is what backs the four
//! progress panels (audit / bulk / site-sweep / mailbox-probe).
#![cfg(target_arch = "wasm32")]

use futures::StreamExt;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::bindings::events;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn bulk_progress_stream_delivers_emitted_events() {
    ts::reset();
    let mut stream = events::bulk_progress()
        .await
        .expect("subscribe to bulk-progress");

    ts::emit_event("bulk-progress", &fixtures::bulk_progress(3, 10));

    let item = stream.next().await.expect("one progress event");
    assert_eq!(item.done, 3);
    assert_eq!(item.total, 10);
    assert!(!item.cancelled);
}

#[wasm_bindgen_test]
async fn site_sweep_stream_delivers_emitted_events() {
    ts::reset();
    let mut stream = events::site_sweep_progress()
        .await
        .expect("subscribe to site-sweep-progress");

    ts::emit_event("site-sweep-progress", &fixtures::site_sweep_progress(5, 20));

    let item = stream.next().await.expect("one progress event");
    assert_eq!(item.done, 5);
    assert_eq!(item.total, 20);
}
