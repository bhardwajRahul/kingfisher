#!/usr/bin/env python3
"""
Reads all YAML rule definition files from crates/kingfisher-rules/data/rules/
and generates a searchable markdown page listing all built-in rules.
"""

import os
import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RULES_DIR = REPO_ROOT / "crates" / "kingfisher-rules" / "data" / "rules"
OUTPUT = REPO_ROOT / "docs-site" / "docs" / "rules" / "builtin-rules.md"


def load_rules():
    """Load all rules from YAML files."""
    all_rules = []

    for yml_file in sorted(RULES_DIR.glob("*.yml")):
        provider = yml_file.stem.replace("_", " ").replace("-", " ").title()
        try:
            with open(yml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception as e:
            print(f"  WARNING: Failed to parse {yml_file.name}: {e}")
            continue

        if not data:
            continue

        # Rules can be a list at top level or under a 'rules' key
        rules = data if isinstance(data, list) else data.get("rules", [data])

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            # Skip invisible rules
            if rule.get("visible") is False:
                continue

            name = rule.get("name", "Unknown")
            rule_id = rule.get("id", "")
            confidence = rule.get("confidence", "unknown")
            has_validation = "validation" in rule
            has_revocation = "revocation" in rule

            all_rules.append({
                "provider": provider,
                "name": name,
                "id": rule_id,
                "confidence": confidence,
                "validates": has_validation,
                "revokes": has_revocation,
            })

    return all_rules


def generate_markdown(rules):
    """Generate the markdown page content."""
    total = len(rules)
    validated = sum(1 for r in rules if r["validates"])
    revocable = sum(1 for r in rules if r["revokes"])
    providers = len(set(r["provider"] for r in rules))

    lines = [
        '---',
        'title: "Built-in Rules List"',
        f'description: "Complete list of all {total}+ built-in secret detection rules in Kingfisher. Searchable and filterable by provider, confidence level, and validation support."',
        '---',
        '',
        '# Built-in Rules',
        '',
        f'Kingfisher ships with **{total} detection rules** across **{providers} providers**.',
        f'Of these, **{validated}** include live validation and **{revocable}** support direct revocation.',
        '',
        '!!! tip "Search"',
        '    Use the search box below to filter rules by provider name, rule ID, or confidence level.',
        '',
        '<input type="text" class="rules-search" placeholder="Search rules... (e.g. github, aws, anthropic)" />',
        '<div class="rules-count"></div>',
        '',
        '<table class="rules-table">',
        '<thead>',
        '<tr>',
        '<th>Provider</th>',
        '<th>Rule Name</th>',
        '<th>Rule ID</th>',
        '<th>Confidence</th>',
        '<th>Validates</th>',
        '<th>Revokes</th>',
        '</tr>',
        '</thead>',
        '<tbody>',
    ]

    for rule in sorted(rules, key=lambda r: (r["provider"].lower(), r["id"])):
        validates = "Yes" if rule["validates"] else ""
        revokes = "Yes" if rule["revokes"] else ""
        confidence = rule["confidence"].capitalize()
        lines.append(f'<tr>')
        lines.append(f'<td>{rule["provider"]}</td>')
        lines.append(f'<td>{rule["name"]}</td>')
        lines.append(f'<td><code>{rule["id"]}</code></td>')
        lines.append(f'<td>{confidence}</td>')
        lines.append(f'<td>{validates}</td>')
        lines.append(f'<td>{revokes}</td>')
        lines.append(f'</tr>')

    lines.extend([
        '</tbody>',
        '</table>',
    ])

    return "\n".join(lines) + "\n"


def main():
    print("Generating built-in rules page...")
    rules = load_rules()
    print(f"  Found {len(rules)} rules")

    content = generate_markdown(rules)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  Written to {OUTPUT.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
