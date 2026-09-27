//! The sign-in link, offered in the app when the system browser won't open.

use leptos::prelude::*;
use thaw::Body1;

use crate::bindings::events;
use crate::components::ui::{Callout, CopyBlock};
use crate::hooks::use_progress_stream::use_progress_stream;

/// Shows the `/authorize` link while an interactive sign-in, consent, step-up
/// or re-auth flow waits on a browser the backend couldn't launch (no default
/// handler, a confined `xdg-open`, a policy blocking the handler), and hides it
/// once that flow ends. Without it the operator waited out the five-minute
/// redirect timeout with nothing to act on.
///
/// Mounted once in `Root`, above every screen, for the process lifetime — so
/// the listener subscribes exactly once and covers the sign-in card and the
/// authed shell alike. The link is single-use and redeemable only through this
/// process's loopback listener; it is shown, never logged.
#[component]
pub fn BrowserFallbackNotice() -> impl IntoView {
    // Outer `None`: no event yet; inner: the latest `Some(url)` / `None`.
    let link = RwSignal::new(None::<Option<String>>);
    use_progress_stream(link, events::auth_browser_fallback);
    move || {
        link.get().flatten().map(|url| {
            view! {
                <Callout tone="warn" role="alert" class="browser-fallback">
                    <Body1>
                        "Couldn't open your browser to sign in. Copy this link into a browser on this computer to continue — it works only while this window is waiting."
                    </Body1>
                    <CopyBlock label="Sign-in link" value=url />
                </Callout>
            }
        })
    }
}
