//! Provenance tracking for scanned content.
//!
//! This module re-exports types from [`kingfisher_core::origin`].

pub use kingfisher_core::origin::{
    get_repo_url, CommitOrigin, ExtendedOrigin, FileOrigin, GitRepoOrigin, Origin, OriginSet,
};
