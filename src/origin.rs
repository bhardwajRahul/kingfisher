//! Provenance tracking for scanned content.
//!
//! This module re-exports types from [`kingfisher_core::origin`].

pub use kingfisher_core::origin::{
    CommitOrigin, ExtendedOrigin, FileOrigin, GitRepoOrigin, Origin, OriginSet, get_repo_url,
};
