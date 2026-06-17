//! Subscribes a `progress` signal to a streamed backend event for the calling
//! component's lifetime, then aborts the listener task on unmount so it neither
//! leaks nor races a remount's task. The four long-running panels (security
//! audit, bulk actions, SharePoint site sweep, mailbox probe) all drive their
//! progress bar this way; they differ only in which `events::*_progress` stream
//! they subscribe to.

use futures::StreamExt;
use leptos::prelude::*;

use crate::bindings::events::JsErrString;

/// Drives `progress` from the stream returned by `subscribe` until the stream
/// ends or the component unmounts. `subscribe` is typically an
/// `events::*_progress` async fn passed by path.
pub fn use_progress_stream<P, Fut, S>(
    progress: RwSignal<Option<P>>,
    subscribe: impl FnOnce() -> Fut + 'static,
) where
    P: Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<S, JsErrString>> + 'static,
    S: futures::Stream<Item = P> + Unpin + 'static,
{
    let (task, abort) = futures::future::abortable(async move {
        if let Ok(mut stream) = subscribe().await {
            while let Some(p) = stream.next().await {
                progress.set(Some(p));
            }
        }
    });
    on_cleanup(move || abort.abort());
    leptos::task::spawn_local(async move {
        let _ = task.await;
    });
}
