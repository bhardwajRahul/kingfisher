use std::{sync::Arc, time::Instant};

use anyhow::{anyhow, bail, Result};
use regex::bytes::Regex;
use tracing::{debug, debug_span, error};
use vectorscan_rs::{BlockDatabase, Flag, Pattern};

use crate::rule::{Rule, RULE_COMMENTS_PATTERN};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeSitterFallbackPolicy {
    KeepRawWhenUnavailable,
    SuppressWhenUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDetectionProfileKind {
    SelfIdentifying,
    ContextDependent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatchProfile {
    pub kind: RuleDetectionProfileKind,
    pub fallback_policy: TreeSitterFallbackPolicy,
    pub reason_codes: Vec<&'static str>,
}

pub struct RulesDatabase {
    // pub(crate) rules: Vec<Rule,>,
    pub(crate) rules: Vec<Arc<Rule>>,
    pub(crate) anchored_regexes: Vec<Regex>,
    pub(crate) rule_match_profiles: Vec<RuleMatchProfile>,
    pub(crate) vsdb: BlockDatabase,
}

pub fn format_regex_pattern(pattern: &str) -> String {
    // Remove comments and whitespace while preserving the regex pattern
    let no_comment_pattern = RULE_COMMENTS_PATTERN.replace_all(pattern, "");
    // flattens multi-line regex into a single line
    no_comment_pattern
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join("")
}

impl RulesDatabase {
    fn classify_rule_profile(rule: &Rule) -> RuleMatchProfile {
        Self::classify_rule_match_profile(rule)
    }

    fn build_rule_profiles(rules: &[Arc<Rule>]) -> Vec<RuleMatchProfile> {
        rules.iter().map(|r| Self::classify_rule_profile(r.as_ref())).collect()
    }

    pub fn get_regex_by_rule_id(&self, rule_id: &str) -> Option<&Regex> {
        self.rules
            .iter()
            .position(|r| r.syntax().id == rule_id)
            .and_then(|index| self.anchored_regexes.get(index))
    }
    pub fn classify_rule_match_profile(rule: &Rule) -> RuleMatchProfile {
        let flattened = format_regex_pattern(&rule.syntax().pattern);
        let normalized = flattened.to_lowercase();

        let mut reason_codes: Vec<&'static str> = Vec::new();

        let has_self_identifying_prefix = [
            "ccipat_",
            "xoxb-",
            "xoxa-",
            "xoxp-",
            "xapp-",
            "ghp_",
            "github_pat_",
            "sk_live_",
            "sk_test_",
            "ltai",
            "akia",
        ]
        .iter()
        .any(|m| normalized.contains(m));
        if has_self_identifying_prefix {
            reason_codes.push("self_identifying_prefix");
            return RuleMatchProfile {
                kind: RuleDetectionProfileKind::SelfIdentifying,
                fallback_policy: TreeSitterFallbackPolicy::KeepRawWhenUnavailable,
                reason_codes,
            };
        }

        let has_context_keywords =
            ["secret", "token", "key", "password", "private", "access", "client", "auth"]
                .iter()
                .any(|m| normalized.contains(m));
        if has_context_keywords {
            reason_codes.push("context_keywords");
        }

        let has_distance_operator = normalized.contains("(?:.|[\\n\\r]){0,");
        if has_distance_operator {
            reason_codes.push("distance_operator");
        }

        let has_depends_on = !rule.syntax().depends_on_rule.is_empty();
        if has_depends_on {
            reason_codes.push("depends_on_rule");
        }

        let max_quantifier = max_quantifier_min_value(&normalized);
        let looks_generic_token = has_generic_token_class(&normalized) && max_quantifier >= 24;
        if looks_generic_token {
            reason_codes.push("generic_token_shape");
        }

        let mut score = 0usize;
        if has_context_keywords {
            score += 1;
        }
        if has_distance_operator {
            score += 1;
        }
        if looks_generic_token {
            score += 2;
        }
        if has_depends_on {
            score += 1;
        }

        let is_context_dependent = score >= 3;
        if !is_context_dependent {
            return RuleMatchProfile {
                kind: RuleDetectionProfileKind::SelfIdentifying,
                fallback_policy: TreeSitterFallbackPolicy::KeepRawWhenUnavailable,
                reason_codes,
            };
        }

        let fallback_policy = if has_depends_on {
            reason_codes.push("depends_on_keep_when_unavailable");
            TreeSitterFallbackPolicy::KeepRawWhenUnavailable
        } else if looks_generic_token && has_distance_operator {
            reason_codes.push("strict_fallback_suppress_when_unavailable");
            TreeSitterFallbackPolicy::SuppressWhenUnavailable
        } else {
            reason_codes.push("fallback_keep_when_unavailable");
            TreeSitterFallbackPolicy::KeepRawWhenUnavailable
        };

        RuleMatchProfile {
            kind: RuleDetectionProfileKind::ContextDependent,
            fallback_policy,
            reason_codes,
        }
    }

    pub fn get_rule_by_finding_fingerprint(&self, finding_fingerprint: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.finding_sha1_fingerprint() == finding_fingerprint).cloned()
    }

    pub fn get_rule_by_text_id(&self, text_id: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.id() == text_id).cloned()
    }

    pub fn get_rule_by_name(&self, name: &str) -> Option<Arc<Rule>> {
        self.rules.iter().find(|r| r.name() == name).cloned()
    }

    pub fn from_rules(rules: Vec<Rule>) -> Result<Self> {
        let rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let _span = debug_span!("RulesDatabase::from_rules").entered();
        if rules.is_empty() {
            bail!("No rules to compile");
        }
        let patterns: Vec<Pattern> = rules
            .iter()
            .enumerate()
            .map(|(id, rule)| {
                Pattern::new(
                    rule.syntax().pattern.clone().into_bytes(),
                    Flag::default(),
                    Some(id.try_into().unwrap()),
                )
            })
            .collect();
        let t1 = Instant::now();
        match BlockDatabase::new(patterns) {
            Ok(vsdb) => {
                let d1 = t1.elapsed().as_secs_f64();
                let (anchored_regexes, d2) = Self::compile_regexes(&rules)?;
                let rule_match_profiles = Self::build_rule_profiles(&rules);
                debug!("Compiled {} rules: vectorscan {}s; regex {}s", rules.len(), d1, d2);
                Ok(RulesDatabase { rules, vsdb, anchored_regexes, rule_match_profiles })
            }
            Err(e) => {
                error!(
                    "Failed to create BlockDatabase: {}. Attempting to compile rules individually.",
                    e
                );
                Self::compile_rules_individually(rules)
                    .map_err(|err| anyhow!("Failed to compile rules: {}\n{}", e, err))
            }
        }
    }

    fn compile_rules_individually(rules: Vec<Arc<Rule>>) -> Result<Self> {
        // NOTE: This function only used when attempting to determine which rule failed
        // to compile
        let mut compiled_rules = Vec::new();
        let mut compiled_patterns = Vec::new();
        let mut compiled_regexes = Vec::new();
        let mut error_messages = Vec::new();
        for (id, rule) in rules.into_iter().enumerate() {
            let pattern = Pattern::new(
                rule.syntax().pattern.clone().into_bytes(),
                Flag::default(),
                Some(id.try_into().unwrap()),
            );
            match BlockDatabase::new(vec![pattern]) {
                Ok(_) => {
                    // Recreate the pattern for the final compilation
                    let final_pattern = Pattern::new(
                        rule.syntax().pattern.clone().into_bytes(),
                        Flag::default(),
                        Some(id.try_into().unwrap()),
                    );
                    compiled_patterns.push(final_pattern);
                    match rule.syntax().as_regex() {
                        Ok(regex) => {
                            compiled_regexes.push(regex);
                            compiled_rules.push(rule);
                        }
                        Err(e) => {
                            error_messages.push(format!(
                                "Failed to compile Regex for rule '{}' (ID: {}): {}",
                                rule.name(),
                                rule.id(),
                                e
                            ));
                        }
                    }
                }
                Err(e) => {
                    error_messages.push(format!(
                        "Failed to compile vectorscan pattern for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        if !error_messages.is_empty() {
            error!(
                "Errors occurred while compiling rules individually:\n{}",
                error_messages.join("\n")
            );
            bail!("Failed to compile the following rules:\n{}", error_messages.join("\n"));
        }
        let vsdb = BlockDatabase::new(compiled_patterns)?;
        let rule_match_profiles = Self::build_rule_profiles(&compiled_rules);
        Ok(RulesDatabase {
            rules: compiled_rules,
            vsdb,
            anchored_regexes: compiled_regexes,
            rule_match_profiles,
        })
    }

    fn compile_regexes(rules: &[Arc<Rule>]) -> Result<(Vec<Regex>, f64)> {
        // fn compile_regexes(rules: &[Rule],) -> Result<(Vec<Regex,>, f64,),> {
        let t2 = Instant::now();
        let mut anchored_regexes = Vec::with_capacity(rules.len());
        for rule in rules {
            match rule.syntax().as_regex() {
                Ok(regex) => anchored_regexes.push(regex),
                Err(e) => {
                    error!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    );
                    return Err(anyhow!(
                        "Failed to compile Regex for rule '{}' (ID: {}): {}",
                        rule.name(),
                        rule.id(),
                        e
                    ));
                }
            }
        }
        let d2 = t2.elapsed().as_secs_f64();
        Ok((anchored_regexes, d2))
    }

    #[inline]
    pub fn num_rules(&self) -> usize {
        self.rules.len()
    }

    #[inline]
    pub fn get_rule(&self, index: usize) -> Option<Arc<Rule>> {
        self.rules.get(index).cloned()
    }

    pub fn rules(&self) -> &[Arc<Rule>] {
        &self.rules
    }

    /// Returns a reference to the Vectorscan database.
    #[inline]
    pub fn vectorscan_db(&self) -> &BlockDatabase {
        &self.vsdb
    }

    /// Returns a slice of the anchored regexes.
    #[inline]
    pub fn anchored_regexes(&self) -> &[Regex] {
        &self.anchored_regexes
    }

    #[inline]
    pub fn rule_match_profiles(&self) -> &[RuleMatchProfile] {
        &self.rule_match_profiles
    }
}

fn has_generic_token_class(normalized_pattern: &str) -> bool {
    [
        "[a-za-z0-9]{",
        "[a-z0-9]{",
        "[a-f0-9]{",
        "[a-z0-9_-]{",
        "[a-za-z0-9_-]{",
        "[a-za-z0-9+/]{",
        "[a-za-z0-9+/=]{",
    ]
    .iter()
    .any(|needle| normalized_pattern.contains(needle))
}

fn max_quantifier_min_value(normalized_pattern: &str) -> usize {
    let mut max_seen = 0usize;
    let bytes = normalized_pattern.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut val = 0usize;
        let mut saw_digit = false;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            saw_digit = true;
            val = val.saturating_mul(10).saturating_add((bytes[j] - b'0') as usize);
            j += 1;
        }
        if saw_digit && val > max_seen {
            max_seen = val;
        }
        i = j.saturating_add(1);
    }
    max_seen
}

#[cfg(test)]
mod test_vectorscan {
    use pretty_assertions::assert_eq;

    use super::*;
    #[test]
    pub fn test_vectorscan_sanity() -> Result<()> {
        use vectorscan_rs::{BlockDatabase, BlockScanner, Pattern, Scan};
        let input = b"some test data for vectorscan";
        let pattern = Pattern::new(b"test".to_vec(), Flag::CASELESS | Flag::SOM_LEFTMOST, None);
        let db: BlockDatabase = BlockDatabase::new(vec![pattern])?;
        let mut scanner = BlockScanner::new(&db)?;
        let mut matches: Vec<(u64, u64)> = vec![];
        scanner.scan(input, |id: u32, from: u64, to: u64, _flags: u32| {
            println!("found pattern #{} @ [{}, {})", id, from, to);
            matches.push((from, to));
            Scan::Continue
        })?;
        assert_eq!(matches, vec![(5, 9)]);
        Ok(())
    }
}
#[cfg(test)]
mod test_regex_cleaning {
    use super::*;
    #[test]
    fn test_format_regex_pattern() {
        let input = r#"(?x)
            (?i)
            (?:
              \\b
              (?:AWS|AMAZON|AMZN|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)
              (?:\\.|[\\n\\r]){0,32}?  (?# THIS IS A COMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENTCOMMENT)
              (?:SECRET|PRIVATE|ACCESS|KEY|TOKEN) # THIS IS A COMMENT THAT SHOULD NOT BE USED BUT MIGHT BE
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            |
              \\b
              (?:SECRET|PRIVATE|ACCESS)
              (?:\\.|[\\n\\r]){0,16}?
              (?:KEY|TOKEN)
              (?:\\.|[\\n\\r]){0,32}?
              \\b
              (
                [A-Za-z0-9/+=]{40}
              )
              \\b
            )"#;
        let data = format_regex_pattern(input);
        println!("{}", data);
    }
}

#[cfg(test)]
mod test_rule_match_profiles {
    use super::*;
    use crate::rule::{Confidence, RuleSyntax, Validation};

    fn mk_rule(id: &str, pattern: &str) -> Rule {
        Rule::new(RuleSyntax {
            id: id.to_string(),
            name: id.to_string(),
            pattern: pattern.to_string(),
            confidence: Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![],
            pattern_requirements: None,
            tls_mode: None,
        })
    }

    #[test]
    fn classifies_self_identifying_prefix_rule() {
        let rule =
            mk_rule("kingfisher.circleci.1", r"(?x)\b(CCIPAT_[A-Za-z0-9]{22}_[a-z0-9]{40})\b");
        let profile = RulesDatabase::classify_rule_profile(&rule);
        assert_eq!(profile.kind, RuleDetectionProfileKind::SelfIdentifying);
        assert_eq!(profile.fallback_policy, TreeSitterFallbackPolicy::KeepRawWhenUnavailable);
        assert!(profile.reason_codes.contains(&"self_identifying_prefix"));
    }

    #[test]
    fn classifies_context_dependent_generic_rule() {
        let rule = mk_rule(
            "kingfisher.auth0.2",
            r"(?xi)\bauth0(?:.|[\n\r]){0,16}?(?:secret|token)(?:.|[\n\r]){0,64}?\b([a-z0-9_-]{64,})\b",
        );
        let profile = RulesDatabase::classify_rule_profile(&rule);
        assert_eq!(profile.kind, RuleDetectionProfileKind::ContextDependent);
        assert_eq!(profile.fallback_policy, TreeSitterFallbackPolicy::SuppressWhenUnavailable);
        assert!(profile.reason_codes.contains(&"generic_token_shape"));
    }

    #[test]
    fn context_like_rule_is_parser_gated() {
        let rule = mk_rule(
            "kingfisher.example.1",
            r"(?xi)\bexample(?:.|[\n\r]){0,16}?(?:secret|token)(?:.|[\n\r]){0,64}?\b([a-z0-9_-]{64,})\b",
        );
        let profile = RulesDatabase::classify_rule_profile(&rule);
        assert_eq!(profile.kind, RuleDetectionProfileKind::ContextDependent);
    }

    #[test]
    fn depends_on_rules_keep_raw_when_parser_unavailable() {
        use crate::rule::DependsOnRule;

        let rule = Rule::new(RuleSyntax {
            id: "kingfisher.algolia.1".to_string(),
            name: "algolia".to_string(),
            pattern: r"(?xi)algolia(?:.|[\n\r]){0,32}?([a-z0-9]{32})".to_string(),
            confidence: Confidence::Medium,
            min_entropy: 0.0,
            visible: true,
            examples: vec![],
            negative_examples: vec![],
            references: vec![],
            validation: None::<Validation>,
            revocation: None,
            depends_on_rule: vec![Some(DependsOnRule {
                rule_id: "kingfisher.algolia.2".to_string(),
                variable: "APPID".to_string(),
            })],
            pattern_requirements: None,
            tls_mode: None,
        });

        let profile = RulesDatabase::classify_rule_profile(&rule);
        assert_eq!(profile.kind, RuleDetectionProfileKind::ContextDependent);
        assert_eq!(profile.fallback_policy, TreeSitterFallbackPolicy::KeepRawWhenUnavailable);
        assert!(profile.reason_codes.contains(&"depends_on_keep_when_unavailable"));
    }
}
