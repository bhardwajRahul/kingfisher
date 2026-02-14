//! Shared utilities for Git hosting platform integrations.
//!
//! This module provides the `ExcludeMatcher` struct and related helpers
//! used across all platform integration modules (GitHub, GitLab, Azure,
//! Bitbucket, Gitea).

use std::collections::HashSet;

use globset::{Glob, GlobSet, GlobSetBuilder};
use tracing::warn;

// -------------------------------------------------------------------------------------------------
// ExcludeMatcher
// -------------------------------------------------------------------------------------------------

/// Matches repository names against exact strings and glob patterns.
///
/// Used by all platform integrations to filter out excluded repositories.
pub struct ExcludeMatcher {
    exact: HashSet<String>,
    globs: Option<GlobSet>,
}

impl ExcludeMatcher {
    /// Returns `true` if no exclusion patterns are configured.
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.globs.is_none()
    }

    /// Returns `true` if the given name matches any exclusion pattern.
    pub fn matches(&self, name: &str) -> bool {
        if self.exact.contains(name) {
            return true;
        }
        if let Some(globs) = &self.globs {
            return globs.is_match(name);
        }
        false
    }
}

/// Returns `true` if the pattern contains glob metacharacters.
pub fn looks_like_glob(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[')
}

/// Builds an `ExcludeMatcher` from a list of exclusion patterns.
///
/// The `parse_fn` transforms each raw pattern string into a normalized
/// repository name (e.g., `"owner/repo"` or `"group/project"`). It returns
/// `None` if the pattern is invalid.
///
/// The `platform_name` is used in warning messages (e.g., `"GitHub"`,
/// `"GitLab"`).
pub fn build_exclude_matcher(
    exclude_repos: &[String],
    parse_fn: impl Fn(&str) -> Option<String>,
    platform_name: &str,
) -> ExcludeMatcher {
    let mut exact = HashSet::new();
    let mut glob_builder = GlobSetBuilder::new();
    let mut has_glob = false;

    for raw in exclude_repos {
        match parse_fn(raw) {
            Some(name) => {
                if looks_like_glob(&name) {
                    match Glob::new(&name) {
                        Ok(glob) => {
                            glob_builder.add(glob);
                            has_glob = true;
                        }
                        Err(err) => {
                            warn!(
                                "Ignoring invalid {platform_name} exclusion pattern '{raw}': {err}"
                            );
                            exact.insert(name);
                        }
                    }
                } else {
                    exact.insert(name);
                }
            }
            None => {
                warn!("Ignoring invalid {platform_name} exclusion '{raw}'");
            }
        }
    }

    let globs = if has_glob {
        match glob_builder.build() {
            Ok(set) => Some(set),
            Err(err) => {
                warn!("Failed to build {platform_name} exclusion patterns: {err}");
                None
            }
        }
    } else {
        None
    };

    ExcludeMatcher { exact, globs }
}

/// Checks whether a repository URL should be excluded.
///
/// The `extract_name` function extracts a normalized repository identifier
/// from the URL (e.g., `"owner/repo"` from `"https://github.com/owner/repo.git"`).
pub fn should_exclude_repo(
    repo_url: &str,
    excludes: &ExcludeMatcher,
    extract_name: impl Fn(&str) -> Option<String>,
) -> bool {
    if excludes.is_empty() {
        return false;
    }
    if let Some(name) = extract_name(repo_url) {
        return excludes.matches(&name);
    }
    false
}
