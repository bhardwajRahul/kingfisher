#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.9"
# dependencies = ["PyYAML>=6.0"]
# ///

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ModuleNotFoundError as exc:
    raise SystemExit(
        "PyYAML isn't installed.\n"
        "Run the script with `uv run …` or add PyYAML to the dependency list."
    ) from exc


DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "crates/kingfisher-rules/data/rules"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Count total rules and detector rules. "
            "Detector rules are rules that do not "
            "declare depends_on_rule."
        )
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help="Directory containing rule YAML files (default: %(default)s)",
    )
    parser.add_argument(
        "--list-validators",
        action="store_true",
        help="Print the names of detectors with and without a validator",
    )
    return parser.parse_args()


def iter_rule_files(rules_dir: Path) -> list[Path]:
    return sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])


def iter_rule_entries(path: Path) -> list[dict]:
    entries: list[dict] = []
    with path.open(encoding="utf-8") as handle:
        for document in yaml.safe_load_all(handle):
            if not isinstance(document, dict):
                continue
            rules = document.get("rules", [])
            if isinstance(rules, list):
                entries.extend(
                    rule for rule in rules if isinstance(rule, dict)
                )
    return entries


def main() -> int:
    args = parse_args()
    rules_dir = args.rules_dir.resolve()

    if not rules_dir.exists():
        print(f"error: directory does not exist: {rules_dir}", file=sys.stderr)
        return 2

    rule_files = iter_rule_files(rules_dir)
    if not rule_files:
        print(f"No YAML rule files found in {rules_dir}")
        return 1

    total_rules = 0
    dependent_rules = 0
    with_validator: list[str] = []
    without_validator: list[str] = []

    for path in rule_files:
        try:
            rules = iter_rule_entries(path)
        except yaml.YAMLError as exc:
            print(f"error: failed to parse {path}: {exc}", file=sys.stderr)
            return 1

        total_rules += len(rules)
        dependent_rules += sum(
            1 for rule in rules if rule.get("depends_on_rule")
        )
        if any(rule.get("validation") for rule in rules):
            with_validator.append(path.stem)
        else:
            without_validator.append(path.stem)

    detector_rules = total_rules - dependent_rules

    print(f"Rules directory: {rules_dir}")
    print(f"Detectors: {len(rule_files)}")
    print(f"Detectors with validator: {len(with_validator)}")
    print(f"Detectors without validator: {len(without_validator)}")
    print(f"Total rules: {total_rules}")
    print(f"Dependent rules: {dependent_rules}")
    print(f"Non-dependent rules: {detector_rules}")

    if args.list_validators:
        print(f"\nWith validator ({len(with_validator)}):")
        for name in with_validator:
            print(f"  {name}")
        print(f"\nWithout validator ({len(without_validator)}):")
        for name in without_validator:
            print(f"  {name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
