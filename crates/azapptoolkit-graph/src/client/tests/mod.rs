//! Wiremock tests for the Graph client, split per domain module (the impl files under
//! `client/`). Shared fixtures in `common`; pure-function unit tests (e.g. `site_lookup_path`)
//! live beside their subject.

mod common;

mod applications;
mod batch;
mod credentials;
mod directory;
mod grants;
mod policies;
mod serialization;
mod service_principals;
mod sharepoint;
mod transport;
