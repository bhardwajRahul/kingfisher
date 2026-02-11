#!/usr/bin/env python3
"""Check URLs under YAML `references` sections for activity."""

from __future__ import annotations

import argparse
import concurrent.futures
import pathlib
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
REFERENCES_RE = re.compile(r"^(\s*)references:\s*$")


@dataclass(frozen=True)
class ReferenceUrl:
    path: pathlib.Path
    line: int
    url: str


@dataclass(frozen=True)
class UrlResult:
    ref: ReferenceUrl
    active: bool
    detail: str


def extract_reference_urls(path: pathlib.Path) -> list[ReferenceUrl]:
    lines = path.read_text(encoding="utf-8").splitlines()
    refs: list[ReferenceUrl] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        match = REFERENCES_RE.match(line)
        if not match:
            i += 1
            continue

        base_indent = len(match.group(1))
        i += 1
        while i < len(lines):
            current = lines[i]
            stripped = current.strip()
            indent = len(current) - len(current.lstrip(" "))

            if stripped and indent <= base_indent:
                break

            if stripped:
                for url in URL_RE.findall(current):
                    refs.append(ReferenceUrl(path=path, line=i + 1, url=url.rstrip(",.)]")))

            i += 1

    return refs


def check_url(url: str, timeout: float) -> tuple[bool, str]:
    headers = {"User-Agent": "kingfisher-reference-checker/1.0"}
    request = urllib.request.Request(url, headers=headers, method="HEAD")
    head_detail = ""
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            return (200 <= status < 400), f"HTTP {status} (HEAD)"
    except urllib.error.HTTPError as exc:
        # Many docs hosts block HEAD. Retry with GET.
        if exc.code in {401, 403, 405, 429}:
            return True, f"HTTP {exc.code} (HEAD)"
        head_detail = f"HTTP {exc.code} (HEAD)"
    except Exception as exc:  # noqa: BLE001
        # Retry with GET for transient/protocol issues.
        head_detail = f"{type(exc).__name__}: {exc} (HEAD)"

    get_request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(get_request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            return (200 <= status < 400), f"HTTP {status} (GET)"
    except urllib.error.HTTPError as exc:
        if exc.code in {401, 403, 429}:
            return True, f"HTTP {exc.code} (GET)"
        if head_detail:
            return False, f"{head_detail}; HTTP {exc.code} (GET)"
        return False, f"HTTP {exc.code} (GET)"
    except Exception as exc:  # noqa: BLE001
        if head_detail:
            return False, f"{head_detail}; {type(exc).__name__}: {exc} (GET)"
        return False, f"{type(exc).__name__}: {exc} (GET)"


def check_reference(ref: ReferenceUrl, timeout: float) -> UrlResult:
    active, detail = check_url(ref.url, timeout=timeout)
    return UrlResult(ref=ref, active=active, detail=detail)


def gather_references(base_dir: pathlib.Path) -> list[ReferenceUrl]:
    refs: list[ReferenceUrl] = []
    for path in sorted(base_dir.glob("*.yml")):
        refs.extend(extract_reference_urls(path))
    return refs


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check all URLs in YAML references sections."
    )
    parser.add_argument(
        "--rules-dir",
        type=pathlib.Path,
        default=pathlib.Path("../../crates/kingfisher-rules/data/rules"),
        help="Directory with YAML rule files (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="HTTP request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Maximum concurrent URL checks (default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rules_dir = args.rules_dir.resolve()
    if not rules_dir.exists():
        print(f"error: directory does not exist: {rules_dir}", file=sys.stderr)
        return 2

    refs = gather_references(rules_dir)
    if not refs:
        print("No URLs found in references sections.")
        return 0

    print(f"Found {len(refs)} reference URLs in {rules_dir}")
    results: list[UrlResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(check_reference, ref, args.timeout) for ref in refs]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    inactive = [result for result in results if not result.active]
    inactive.sort(key=lambda item: (str(item.ref.path), item.ref.line, item.ref.url))

    print(f"Active: {len(results) - len(inactive)}")
    print(f"Inactive: {len(inactive)}")

    for result in inactive:
        rel = result.ref.path.relative_to(pathlib.Path.cwd())
        print(f"INACTIVE {rel}:{result.ref.line} {result.ref.url} [{result.detail}]")

    return 1 if inactive else 0


if __name__ == "__main__":
    raise SystemExit(main())
