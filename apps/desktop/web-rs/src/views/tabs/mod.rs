//! Detail-pane tabs. Mirrors `apps/desktop/web/src/views/tabs/`.

pub mod activity_tab;
pub mod app_tab;
pub mod authentication_tab;
pub mod conditional_access_tab;
pub mod credentials_tab;
pub mod enterprise_tab;
pub mod expose_api_tab;
pub mod federated_scenarios;
pub mod federated_tab;
pub mod overview_tab;
pub mod owners_tab;
pub mod permissions_tab;
pub mod usage_panel;

pub use app_tab::AppTab;
pub use enterprise_tab::EnterpriseTab;
