#!/usr/bin/env python3
"""Redact audit evidence and create/verify reproducible audit seals."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = 2
DEFAULT_EXCLUSIONS = ("audit/", "atlas/")
TOKEN_PATTERNS = (
    re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(\b(?:api[_-]?key|password|passwd|secret|token)\b\s*[:=]\s*[\"']?)"
    r"([^\s\"']{8,})([\"']?)"
)


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _replacement(secret: str) -> str:
    return f"[REDACTED:sha256:{_fingerprint(secret)}]"


def redact_text(text: str) -> str:
    """Replace common secret values with stable, non-reversible fingerprints."""
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda match: _replacement(match.group(0)), text)

    def redact_assignment(match: re.Match[str]) -> str:
        value = match.group(2)
        if value.startswith("[REDACTED:"):
            return match.group(0)
        return f"{match.group(1)}{_replacement(value)}{match.group(3)}"

    return ASSIGNMENT_PATTERN.sub(redact_assignment, text)


def _run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _is_excluded(path: str, exclusions: Iterable[str]) -> bool:
    normalized = path.replace("\\", "/").lstrip("./")
    return any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in exclusions)


def _tracked_files(repo: Path, exclusions: Iterable[str]) -> list[str]:
    paths = _run_git(repo, "ls-files", "--", ".").splitlines()
    return sorted(path for path in paths if path and not _is_excluded(path, exclusions))


def _untracked_files(repo: Path, exclusions: Iterable[str]) -> list[str]:
    output = _run_git(repo, "ls-files", "--others", "--exclude-standard", "--", ".")
    return sorted(path for path in output.splitlines() if path and not _is_excluded(path, exclusions))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def create_seal(
    repo: Path | str,
    seal_path: Path | str,
    exclusions: Iterable[str] = DEFAULT_EXCLUSIONS,
) -> dict[str, object]:
    """Seal every tracked file in the audit scope, excluding generated outputs."""
    repo = Path(repo).resolve()
    seal_path = Path(seal_path).resolve()
    exclusions = tuple(exclusions)
    untracked = _untracked_files(repo, exclusions)
    if untracked:
        raise ValueError("untracked audited files must be reviewed first: " + ", ".join(untracked))

    artifacts = {path: _sha256(repo / path) for path in _tracked_files(repo, exclusions)}
    manifest = json.dumps(artifacts, sort_keys=True, separators=(",", ":")).encode("utf-8")
    seal: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_commit": _run_git(repo, "rev-parse", "HEAD"),
        "source_manifest_sha256": f"sha256:{hashlib.sha256(manifest).hexdigest()}",
        "scope": ".",
        "exclusions": list(exclusions),
        "artifacts": artifacts,
        "invalidation": "Run scripts/audit_guard.py verify-seal; any reported difference invalidates the opinion.",
    }
    seal_path.parent.mkdir(parents=True, exist_ok=True)
    seal_path.write_text(json.dumps(seal, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return seal


def verify_seal(repo: Path | str, seal_path: Path | str) -> list[str]:
    """Return all source-surface differences from a seal; an empty list is valid."""
    repo = Path(repo).resolve()
    seal_path = Path(seal_path).resolve()
    try:
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"invalid seal: {error}"]
    if seal.get("schema_version") != SCHEMA_VERSION:
        return [f"unsupported schema_version: {seal.get('schema_version')}"]

    exclusions = tuple(seal.get("exclusions", DEFAULT_EXCLUSIONS))
    expected = seal.get("artifacts")
    if not isinstance(expected, dict):
        return ["invalid seal: artifacts must be an object"]

    errors: list[str] = []
    current_paths = set(_tracked_files(repo, exclusions)) | set(_untracked_files(repo, exclusions))
    expected_paths = set(expected)
    for path in sorted(expected_paths - current_paths):
        errors.append(f"missing: {path}")
    for path in sorted(current_paths - expected_paths):
        errors.append(f"unexpected: {path}")
    for path in sorted(expected_paths & current_paths):
        candidate = repo / path
        if not candidate.is_file():
            errors.append(f"missing: {path}")
        elif _sha256(candidate) != expected[path]:
            errors.append(f"hash mismatch: {path}")
    return errors


def _contains_raw_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in TOKEN_PATTERNS)


def validate_bundle(sample_root: Path | str) -> list[str]:
    """Validate that an example audit bundle is public, reproducible, and sealed."""
    root = Path(sample_root).resolve()
    audit = root / "audit"
    required = (
        audit / "audit-report.md",
        audit / "audit-workpaper.md",
        audit / "unverified-ledger.md",
        audit / "seal.json",
        audit / "evidence" / "uat-log.txt",
        audit / "evidence" / "reverse-test.log",
        audit / "evidence" / "codex-initial-prompt.txt",
        audit / "evidence" / "codex-initial-output.txt",
        audit / "evidence" / "codex-revalidation-prompt.txt",
        audit / "evidence" / "codex-revalidation-output.txt",
    )
    errors = [f"missing required evidence: {path.relative_to(root)}" for path in required if not path.is_file()]
    for path in audit.rglob("*") if audit.exists() else ():
        if path.is_file() and path.suffix.lower() in {".md", ".txt", ".json", ".log"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            if _contains_raw_secret(text):
                errors.append(f"raw secret-like value: {path.relative_to(root)}")
            if "監査実施環境のセッション記録に保存" in text:
                errors.append(f"non-public evidence reference: {path.relative_to(root)}")
    if (audit / "seal.json").is_file():
        errors.extend(verify_seal(root, audit / "seal.json"))
    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    redact = subparsers.add_parser("redact", help="redact stdin or a file")
    redact.add_argument("path", nargs="?", type=Path)
    create = subparsers.add_parser("create-seal", help="create a v2 source seal")
    create.add_argument("repo", type=Path)
    create.add_argument("seal", type=Path)
    verify = subparsers.add_parser("verify-seal", help="verify a v2 source seal")
    verify.add_argument("repo", type=Path)
    verify.add_argument("seal", type=Path)
    bundle = subparsers.add_parser("validate-bundle", help="validate an example audit bundle")
    bundle.add_argument("root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "redact":
        raw = args.path.read_text(encoding="utf-8") if args.path else sys.stdin.read()
        sys.stdout.write(redact_text(raw))
        return 0
    if args.command == "create-seal":
        try:
            create_seal(args.repo, args.seal)
        except (OSError, subprocess.CalledProcessError, ValueError) as error:
            print(f"seal creation failed: {error}", file=sys.stderr)
            return 1
        return 0
    errors = (
        verify_seal(args.repo, args.seal)
        if args.command == "verify-seal"
        else validate_bundle(args.root)
    )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
