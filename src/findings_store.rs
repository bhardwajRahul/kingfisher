use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};

use anyhow::Result;
use bloomfilter::Bloom;
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use xxhash_rust::xxh3::xxh3_64;

use crate::{
    access_map::AccessMapResult,
    blob::{BlobId, BlobMetadata},
    finding_data,
    git_url::GitUrl,
    location::OffsetSpan,
    matcher::Match,
    origin::{Origin, OriginSet},
    rules::rule::Rule,
    util::intern,
};

// share with Arc so every blob/origin is materialised once
pub type FindingsStoreMessage = (Arc<OriginSet>, Arc<BlobMetadata>, Match);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct MatchIdInt(i64);
impl FromStr for MatchIdInt {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<i64>().map(MatchIdInt)
    }
}

fn origin_fp(os: &OriginSet) -> u64 {
    let mut h = FxHasher::default();
    // OriginSet is iterable – hash each contained Origin
    for o in os.iter() {
        o.hash(&mut h);
    }
    h.finish()
}

pub struct FindingsStore {
    rules: Vec<Arc<Rule>>,
    matches: Vec<Arc<FindingsStoreMessage>>,
    index_map: FxHashMap<(BlobId, OffsetSpan), usize>,
    dedup_index_map: FxHashMap<u64, usize>,
    blobs: FxHashSet<BlobId>,
    clone_dir: PathBuf,
    seen_bloom: Bloom<u64>,
    bloom_items: usize,
    dependent_rule_ids: FxHashSet<String>,
    blob_meta: FxHashMap<BlobId, Arc<BlobMetadata>>,
    origin_meta: FxHashMap<u64, Arc<OriginSet>>,
    docker_images: FxHashMap<PathBuf, String>,
    slack_links: FxHashMap<PathBuf, String>,
    teams_links: FxHashMap<PathBuf, String>,
    confluence_links: FxHashMap<PathBuf, String>,
    s3_buckets: FxHashMap<PathBuf, String>,
    repo_links: FxHashMap<PathBuf, String>,
    access_map_results: Vec<AccessMapResult>,
}

impl FindingsStore {
    pub fn new(clone_dir: PathBuf) -> Self {
        let expected_items = 10_000_000; // tune to your largest scan
        let fp_rate = 0.001; // 0.1 % false-positive rate
        let seen_bloom = Bloom::new_for_fp_rate(expected_items, fp_rate)
            .expect("Bloom filter size params are valid");
        Self {
            rules: Vec::new(),
            matches: Vec::new(),
            blobs: FxHashSet::default(),
            index_map: FxHashMap::default(),
            dedup_index_map: FxHashMap::default(),
            blob_meta: FxHashMap::default(),
            origin_meta: FxHashMap::default(),
            clone_dir,
            seen_bloom,
            bloom_items: 0,
            dependent_rule_ids: FxHashSet::default(),
            docker_images: FxHashMap::default(),
            slack_links: FxHashMap::default(),
            teams_links: FxHashMap::default(),
            confluence_links: FxHashMap::default(),
            s3_buckets: FxHashMap::default(),
            repo_links: FxHashMap::default(),
            access_map_results: Vec::new(),
        }
    }

    pub fn update_matches_in_place(&mut self, updated_matches: Vec<Arc<FindingsStoreMessage>>) {
        for updated_match in updated_matches {
            let (_, _, updated) = &*updated_match;
            // Construct the same key used in record()
            let key = (updated.blob_id, updated.location.offset_span);
            // If we have an existing match, update it in-place
            if let Some(&idx) = self.index_map.get(&key) {
                // Get the Arc in self.matches at position idx
                let arc_in_store = &mut self.matches[idx];
                // Arc::make_mut lets us mutate the inner tuple as long as this Arc is not shared
                let (_, _, existing) = Arc::make_mut(arc_in_store);
                existing.validation_success = updated.validation_success;
                existing.validation_response_status = updated.validation_response_status;
                existing.validation_response_body = updated.validation_response_body.clone();
            }
        }
    }

    /// Replaces all stored matches with the new deduplicated matches.
    /// It also rebuilds the index map and the blobs set accordingly.
    pub fn replace_matches(&mut self, new_matches: Vec<Arc<FindingsStoreMessage>>) {
        self.matches = new_matches;
        self.index_map.clear();
        self.dedup_index_map.clear();
        self.blobs.clear();
        for (i, message) in self.matches.iter().enumerate() {
            let blob_id = message.1.id;
            let offset_span = message.2.location.offset_span;
            self.index_map.insert((blob_id, offset_span), i);
            let dedup_key = self.dedup_key(message.0.as_ref(), message.1.as_ref(), &message.2);
            self.dedup_index_map.insert(dedup_key, i);
            self.blobs.insert(blob_id);
        }
    }

    pub fn get_rules(&self) -> Result<Vec<Arc<Rule>>> {
        Ok(self.rules.clone())
    }

    pub fn get_matches(&self) -> &[Arc<FindingsStoreMessage>] {
        &self.matches
    }

    pub fn get_matches_mut(&mut self) -> &mut Vec<Arc<FindingsStoreMessage>> {
        &mut self.matches
    }

    pub fn set_access_map_results(&mut self, results: Vec<AccessMapResult>) {
        self.access_map_results = results;
    }

    pub fn access_map_results(&self) -> &[AccessMapResult] {
        &self.access_map_results
    }

    pub fn record_rules(&mut self, rules: &[Arc<Rule>]) {
        // Clear existing data and extend in place
        self.rules.clear();
        self.rules.extend_from_slice(rules);
        self.dependent_rule_ids.clear();
        for rule in rules {
            for dependency in rule.syntax().depends_on_rule.iter().flatten() {
                self.dependent_rule_ids.insert(dependency.rule_id.to_uppercase());
            }
        }
        if !self.matches.is_empty() {
            self.rebuild_dedup_index_map();
        }
    }

    fn primary_snippet<'a>(m: &'a Match) -> &'a str {
        m.groups
            .captures
            .iter()
            .find(|c| c.name.is_none() && c.match_number == 0)
            .map(|c| c.raw_value())
            .or_else(|| {
                m.groups
                    .captures
                    .iter()
                    .find(|c| matches!(c.name.as_deref(), Some("TOKEN")))
                    .map(|c| c.raw_value())
            })
            .or_else(|| m.groups.captures.get(0).map(|c| c.raw_value()))
            .unwrap_or("")
    }

    fn dedup_key(&self, origin: &OriginSet, blob_md: &BlobMetadata, m: &Match) -> u64 {
        let origin_kind = match origin.first() {
            Origin::GitRepo(_) => "git",
            Origin::File(_) => "file",
            Origin::Extended(_) => "ext",
        };
        let rule_id = m.rule.id().to_uppercase();
        let snippet = Self::primary_snippet(m);
        let key_string = if self.dependent_rule_ids.contains(&rule_id) {
            format!("{}|{}|{}|{}", rule_id, origin_kind, snippet, blob_md.id.hex())
        } else {
            format!("{}|{}|{}", rule_id, origin_kind, snippet)
        };
        xxh3_64(key_string.as_bytes())
    }

    fn normalize_path_for_order(path: &str) -> String {
        path.replace('\\', "/")
    }

    fn origin_order_key(origin: &Origin) -> (u8, String, String) {
        match origin {
            Origin::GitRepo(repo) => {
                let repo_path = Self::normalize_path_for_order(&repo.repo_path.to_string_lossy());
                let blob_path = repo
                    .first_commit
                    .as_ref()
                    .map(|commit| Self::normalize_path_for_order(&commit.blob_path))
                    .unwrap_or_default();
                let commit_id = repo
                    .first_commit
                    .as_ref()
                    .map(|commit| commit.commit_metadata.commit_id.to_string())
                    .unwrap_or_default();
                (0, format!("{repo_path}/{blob_path}"), commit_id)
            }
            Origin::File(file) => {
                (1, Self::normalize_path_for_order(&file.path.to_string_lossy()), String::new())
            }
            Origin::Extended(ext) => (
                2,
                ext.path()
                    .map(|path| Self::normalize_path_for_order(&path.to_string_lossy()))
                    .unwrap_or_else(|| Self::normalize_path_for_order(&ext.0.to_string())),
                String::new(),
            ),
        }
    }

    fn canonical_entry_key(
        origin: &OriginSet,
        blob_md: &BlobMetadata,
        m: &Match,
    ) -> ((u8, String, String), usize, usize, String) {
        let primary_origin = origin
            .iter()
            .min_by_key(|origin| Self::origin_order_key(origin))
            .map(Self::origin_order_key)
            .unwrap_or((u8::MAX, String::new(), String::new()));
        (primary_origin, m.location.offset_span.start, m.location.offset_span.end, blob_md.id.hex())
    }

    fn merge_origin_sets(existing: &OriginSet, incoming: &OriginSet) -> OriginSet {
        let mut origins = Vec::new();
        let mut push_unique = |origin: &Origin| {
            if !origins.iter().any(|existing| existing == origin) {
                origins.push(origin.clone());
            }
        };

        for origin in existing.iter().chain(incoming.iter()) {
            push_unique(origin);
        }

        origins.sort_by_key(Self::origin_order_key);
        OriginSet::try_from_iter(origins).expect("merged origin set is non-empty")
    }

    fn merge_duplicate(
        &mut self,
        idx: usize,
        incoming_origin: Arc<OriginSet>,
        incoming_blob: Arc<BlobMetadata>,
        incoming_match: Match,
    ) {
        let incoming_index_key = (incoming_blob.id, incoming_match.location.offset_span);
        let (prefer_incoming, merged_origin) = {
            let (existing_origin, existing_blob, existing_match) = &*self.matches[idx];
            let existing_key = Self::canonical_entry_key(
                existing_origin.as_ref(),
                existing_blob.as_ref(),
                existing_match,
            );
            let incoming_key = Self::canonical_entry_key(
                incoming_origin.as_ref(),
                incoming_blob.as_ref(),
                &incoming_match,
            );
            (
                incoming_key.cmp(&existing_key) == Ordering::Less,
                Self::merge_origin_sets(existing_origin.as_ref(), incoming_origin.as_ref()),
            )
        };

        let merged_origin_arc = {
            let merged_origin_arc = Arc::new(merged_origin);
            let fp = origin_fp(merged_origin_arc.as_ref());
            self.origin_meta.entry(fp).or_insert_with(|| merged_origin_arc.clone()).clone()
        };

        self.index_map.insert(incoming_index_key, idx);

        let stored = &mut self.matches[idx];
        let (stored_origin, stored_blob, stored_match) = Arc::make_mut(stored);
        *stored_origin = merged_origin_arc;
        if prefer_incoming {
            let blob_arc = self
                .blob_meta
                .entry(incoming_blob.id)
                .or_insert_with(|| incoming_blob.clone())
                .clone();
            *stored_blob = blob_arc;
            *stored_match = incoming_match;
        }
    }

    fn rebuild_dedup_index_map(&mut self) {
        self.dedup_index_map.clear();
        for (idx, message) in self.matches.iter().enumerate() {
            let key = self.dedup_key(message.0.as_ref(), message.1.as_ref(), &message.2);
            self.dedup_index_map.insert(key, idx);
        }
    }

    /// Insert a batch of findings.  
    /// Returns the number of *new blobs* discovered in this batch.
    ///
    /// * `dedup == true` -- Bloom-filter gate is applied.
    /// * Side-tables (`blob_meta`, `origin_meta`) guarantee only one Arc per distinct
    ///   `BlobMetadata` / `OriginSet`, so no more huge copies.
    pub fn record(&mut self, batch: Vec<FindingsStoreMessage>, dedup: bool) -> usize {
        let mut added = 0;

        for (origin, blob_md, m) in batch {
            /*───────────────────────────────────────────────────────────────┐
            │ 1. Optional duplicate filter (unchanged)                      │
            └───────────────────────────────────────────────────────────────*/
            if dedup {
                let dedup_key = self.dedup_key(origin.as_ref(), blob_md.as_ref(), &m);
                if self.seen_bloom.check(&dedup_key) {
                    if let Some(&idx) = self.dedup_index_map.get(&dedup_key) {
                        if self.blobs.insert(blob_md.id) {
                            added += 1;
                        }
                        self.merge_duplicate(idx, origin, blob_md, m);
                        continue;
                    }
                }
                self.seen_bloom.set(&dedup_key);
                self.bloom_items += 1;
            }

            /*───────────────────────────────────────────────────────────────┐
            │ 2.  Intern / pool the heavy structs                           │
            └───────────────────────────────────────────────────────────────*/
            // one Arc<BlobMetadata> per BlobId
            let blob_arc =
                self.blob_meta.entry(blob_md.id).or_insert_with(|| blob_md.clone()).clone();

            // one Arc<OriginSet> per (hashed) OriginSet
            let fp = origin_fp(&origin); // helper: u64 hash of OriginSet
            let origin_arc = self.origin_meta.entry(fp).or_insert_with(|| origin.clone()).clone();

            /*───────────────────────────────────────────────────────────────┐
            │ 3.  Core bookkeeping                                          │
            └───────────────────────────────────────────────────────────────*/
            if self.blobs.insert(blob_arc.id) {
                added += 1; // first time we see this blob
            }

            let msg = Arc::new((origin_arc, blob_arc, m));
            self.matches.push(msg);

            let idx = self.matches.len() - 1;
            let blob_id = self.matches[idx].1.id;
            let offset_span = self.matches[idx].2.location.offset_span;
            self.index_map.insert((blob_id, offset_span), idx);
            if dedup {
                let dedup_key = self.dedup_key(
                    self.matches[idx].0.as_ref(),
                    self.matches[idx].1.as_ref(),
                    &self.matches[idx].2,
                );
                self.dedup_index_map.insert(dedup_key, idx);
            }
        }

        /* ─────────────────────────────────────────────────────────────────── */
        // Periodically rebuild Bloom filter to bound the FP rate
        if dedup && self.bloom_items > 5_000_000 {
            self.seen_bloom = Bloom::new_for_fp_rate(5_000_000, 0.001).unwrap();
            self.bloom_items = 0;
        }

        added
    }

    // pub fn record(&mut self, batch: Vec<FindingsStoreMessage>, dedup: bool) -> usize {
    //     let mut added = 0;

    //     for message in batch {
    //         if dedup {
    //             let snippet = message
    //                 .2
    //                 .groups
    //                 .captures
    //                 .get(1)
    //                 .or_else(|| message.2.groups.captures.get(0))
    //                 .map_or("", |c| c.value.as_ref());

    //             let origin_kind = match message.0.first() {
    //                 Origin::GitRepo(_) => "git",
    //                 Origin::File(_) => "file",
    //                 Origin::Extended(_) => "ext",
    //             };

    //             // 64-bit key (turbo, cheap, good dispersion)
    //             let key = xxh3_64(
    //                 format!(
    //                     "{}|{}|{}",
    //                     message.2.rule_text_id.to_uppercase(),
    //                     origin_kind,
    //                     snippet
    //                 )
    //                 .as_bytes(),
    //             );

    //             // Bloom gate: 1. check, 2. insert (if new)
    //             if self.seen_bloom.check(&key) {
    //                 continue; // very likely a duplicate
    //             }
    //             self.seen_bloom.set(&key);
    //             self.bloom_items += 1;
    //         }

    //         // ── existing blob / index bookkeeping ───────────
    //         if self.blobs.insert(message.1.id) {
    //             added += 1;
    //         }
    //         self.matches.push(Arc::new(message));
    //         let idx = self.matches.len() - 1;
    //         let blob_id = self.matches[idx].1.id;
    //         let offset_span = self.matches[idx].2.location.offset_span;
    //         self.index_map.insert((blob_id, offset_span), idx);
    //     }

    //     // Optional : re-create filter after N inserts to bound FP rate
    //     if dedup && self.bloom_items > 5_000_000 {
    //         self.seen_bloom = Bloom::new_for_fp_rate(5_000_000, 0.001).unwrap();
    //         self.bloom_items = 0;
    //     }

    //     added
    // }

    pub fn get_num_matches(&self) -> usize {
        // only count visible matches
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = msg.as_ref();
                match_item.visible
            })
            .count()
    }

    pub fn get_summary(&self) -> FxHashMap<&'static str, usize> {
        self.matches.iter().fold(FxHashMap::default(), |mut acc, msg| {
            let (_, _, m) = &**msg;
            *acc.entry(intern(m.rule.name())).or_insert(0) += 1;
            acc
        })
    }

    pub fn clone_destination(&self, repo_url: &GitUrl) -> PathBuf {
        let repo_identifier = repo_url.to_string().replace(['/', ':'], "_");
        self.clone_dir.join(repo_identifier)
    }

    /// Return the directory used to store cloned repositories and other
    /// temporary artifacts.
    pub fn clone_root(&self) -> PathBuf {
        self.clone_dir.clone()
    }

    pub fn register_docker_image(&mut self, dir: PathBuf, image: String) {
        self.docker_images.insert(dir, image);
    }

    pub fn docker_images(&self) -> &FxHashMap<PathBuf, String> {
        &self.docker_images
    }

    pub fn register_slack_message(&mut self, path: PathBuf, permalink: String) {
        self.slack_links.insert(path, permalink);
    }

    pub fn slack_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.slack_links
    }

    pub fn register_teams_message(&mut self, path: PathBuf, url: String) {
        self.teams_links.insert(path, url);
    }

    pub fn teams_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.teams_links
    }

    pub fn register_confluence_page(&mut self, path: PathBuf, link: String) {
        self.confluence_links.insert(path, link);
    }

    pub fn confluence_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.confluence_links
    }

    pub fn register_repo_link(&mut self, path: PathBuf, link: String) {
        self.repo_links.insert(path, link);
    }

    pub fn repo_links(&self) -> &FxHashMap<PathBuf, String> {
        &self.repo_links
    }

    pub fn register_s3_bucket(&mut self, dir: PathBuf, bucket: String) {
        self.s3_buckets.insert(dir, bucket);
    }

    pub fn s3_buckets(&self) -> &FxHashMap<PathBuf, String> {
        &self.s3_buckets
    }

    pub fn merge_from(&mut self, other: &FindingsStore, dedup: bool) {
        for (dir, link) in other.repo_links() {
            self.repo_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, bucket) in other.s3_buckets() {
            self.s3_buckets.entry(dir.clone()).or_insert_with(|| bucket.clone());
        }

        for (dir, image) in other.docker_images() {
            self.docker_images.entry(dir.clone()).or_insert_with(|| image.clone());
        }

        for (dir, link) in other.slack_links() {
            self.slack_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, link) in other.teams_links() {
            self.teams_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        for (dir, link) in other.confluence_links() {
            self.confluence_links.entry(dir.clone()).or_insert_with(|| link.clone());
        }

        let batch: Vec<_> = other
            .get_matches()
            .iter()
            .map(|msg| {
                let (origin, blob_md, m) = msg.as_ref();
                (origin.clone(), blob_md.clone(), m.clone())
            })
            .collect();

        self.record(batch, dedup);
    }

    pub fn get_finding_data_iter(
        &self,
    ) -> impl Iterator<Item = finding_data::FindingMetadata> + '_ {
        self.matches.iter().map(|msg| {
            let (_, _, match_item) = &**msg;
            finding_data::FindingMetadata {
                rule_name: match_item.rule.name().to_string(),
                num_matches: 1,
                comment: None,
                visible: match_item.visible,
                finding_id: match_item.finding_id(),
                rule_finding_fingerprint: match_item.rule.finding_sha1_fingerprint().to_string(),
                rule_text_id: match_item.rule.id().to_string(),
            }
        })
    }

    pub fn get_finding_metadata(
        &self,
        metadata: &finding_data::FindingMetadata,
        _max_matches: Option<usize>,
    ) -> Result<Vec<finding_data::FindingDataEntry>> {
        self.matches
            .iter()
            .filter(|msg| {
                let (_, _, match_item) = msg.as_ref();
                match_item.rule.name() == metadata.rule_name
            })
            .map(|msg| {
                let (origin, blob_metadata, match_item) = &**msg;
                Ok(finding_data::FindingDataEntry {
                    origin: (**origin).clone(),
                    blob_metadata: (**blob_metadata).clone(),
                    match_val: match_item.clone(),
                    match_id: MatchIdInt::from_str(&match_item.finding_id())?,
                    match_comment: None,
                    visible: match_item.visible,
                    match_confidence: match_item.rule.confidence(),
                    validation_response_body: match_item.validation_response_body.clone(),
                    validation_response_status: match_item.validation_response_status,
                    validation_success: match_item.validation_success,
                })
            })
            .collect()
    }

    /// Return an iterator that yields `chunk_size` matches at a time.
    /// Clones the `Arc` wrappers only – zero extra allocation for Match bodies.
    pub fn cursor(
        &self,
        chunk_size: usize,
    ) -> impl Iterator<Item = Vec<std::sync::Arc<FindingsStoreMessage>>> + '_ {
        self.matches.chunks(chunk_size).map(|slice| slice.to_vec()) // keep Arc pointers
    }
}
