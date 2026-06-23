//! Shared visual primitives used across views. Each component is small
//! (a few lines of Leptos + a class on a styled root). The CSS lives in
//! `styles.css` under the "UI primitives" section.

#![allow(unused_imports, dead_code)]

mod badge;
mod card;
mod copyable_id;
mod data_table;
mod detail_load_error;
mod empty_state;
mod icon_button;
mod search_input;
mod section_header;
mod skeleton;
mod tab_bar;

pub use badge::Badge;
pub use card::Card;
pub use copyable_id::CopyableId;
pub use data_table::DataTable;
pub use detail_load_error::DetailLoadError;
pub use empty_state::EmptyState;
pub use icon_button::IconButton;
pub use search_input::SearchInput;
pub use section_header::SectionHeader;
pub use skeleton::{DetailSkeleton, Skeleton, SkeletonList};
pub use tab_bar::{TabBar, TabBarItem};
