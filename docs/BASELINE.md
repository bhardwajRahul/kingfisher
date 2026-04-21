# Build a Baseline / Detect Only New Secrets

[← Back to README](../README.md)

There are situations where a repository already contains checked‑in secrets, but you want to ensure no **new** secrets are introduced. A baseline file lets you document the known findings so future scans only report anything that is not already in that list.

The easiest way to create a baseline is to run a normal scan with the `--manage-baseline` flag (typically at a low confidence level to capture all potential matches):

```bash
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml
```

This generates a YAML file named `baseline-file.yml` in the current directory. The file tracks each finding under an `ExactFindings` section:

```yaml
ExactFindings:
  matches:
  - filepath: ruby_vulnerable.rb/
    fingerprint: '389162583612032034'
    linenum: 52
    lastupdated: Mon, 14 Jul 2025 10:17:56 -0700
  - filepath: ruby_vulnerable.rb/
    fingerprint: '14862156687550263216'
    linenum: 53
    lastupdated: Mon, 14 Jul 2025 10:17:56 -0700
  - filepath: ruby_vulnerable.rb/
    fingerprint: '16736108862611731189'
    linenum: 40
    lastupdated: Mon, 14 Jul 2025 10:17:56 -0700
```

`fingerprint` reuses Kingfisher's 64-bit *finding fingerprint* algorithm with offsets set to zero. It hashes the secret value together with the normalized filepath, so moving a secret around does not create a new entry.

Fingerprints in the baseline are written as decimal `u64` values — identical to the fingerprint shown in scan output (JSON, JSONL, pretty, SARIF), so you can copy a fingerprint directly from a report into this file. For backward compatibility the baseline also accepts the legacy 16-character zero-padded hex form (e.g. `056876f00ffd0622`) and explicit `0x`-prefixed hex, so baselines produced by older releases continue to work unchanged.

Running another scan with `--manage-baseline` rewrites the file so it only contains findings that still exist in the repository. Use the same YAML file with the `--baseline-file` option on future scans to hide all recorded findings:

```bash
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yaml
```

If you intentionally add a new secret that should be ignored later, rerun the scan with both `--manage-baseline` and `--baseline-file` to refresh the baseline. New matches are appended and entries for secrets that no longer appear (for example, because files were removed or excluded) are pruned:

```bash
kingfisher scan /path/to/code \
  --manage-baseline \
  --baseline-file /path/to/baseline-file.yml
```

If you want to know which files are being skipped, enable verbose debugging (-v) when scanning, which will report any files being skipped by the baseline file (or via `--exclude`):

```bash
kingfisher scan /path/to/project -v
```