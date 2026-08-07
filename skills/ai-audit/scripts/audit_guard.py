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
DEFAULT_EXCLUSIONS: tuple[str, ...] = ()
TOKEN_PATTERNS = (
    re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?=[A-Za-z0-9_-]{32,}\b)(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{32,}\b"),
)
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)([\"']?\b(?:api[_-]?key|access[_-]?token|auth(?:orization)?|client[_-]?secret|"
    r"credential|jwt|password|passwd|pin|private[_-]?key|recovery[_-]?code|secret|token)\b[\"']?\s*[:=]\s*)"
    r"(?:(['\"])(.*?)\2|([^\s,}\]]+))"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _replacement(secret: str, include_fingerprint: bool = True) -> str:
    if not include_fingerprint:
        return "[REDACTED]"
    return f"[REDACTED:sha256:{_fingerprint(secret)}]"


def redact_text(text: str) -> str:
    """Mask common secrets; fingerprint only unassigned high-entropy tokens."""
    text = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = BEARER_PATTERN.sub(
        lambda match: _replacement(match.group(0), include_fingerprint=False), text
    )

    def redact_assignment(match: re.Match[str]) -> str:
        quote = match.group(2) or ""
        value = match.group(3) if match.group(2) else match.group(4)
        if value.startswith("[REDACTED:"):
            return match.group(0)
        return f"{match.group(1)}{quote}{_replacement(value, include_fingerprint=False)}{quote}"

    text = ASSIGNMENT_PATTERN.sub(redact_assignment, text)
    for pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda match: _replacement(match.group(0)), text)
    return text


def _run_git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    )
    return completed.stdout.strip()


def _is_excluded(path: str, exclusions: Iterable[str]) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    for exclusion in exclusions:
        prefix = exclusion.replace("\\", "/")
        while prefix.startswith("./"):
            prefix = prefix[2:]
        if normalized == prefix.rstrip("/"):
            return True
        if prefix.endswith("/") and normalized.startswith(prefix):
            return True
    return False


def _tracked_files(repo: Path, exclusions: Iterable[str]) -> list[str]:
    paths = _run_git(repo, "ls-files", "--", ".").splitlines()
    return sorted(path for path in paths if path and not _is_excluded(path, exclusions))


def _untracked_files(repo: Path, exclusions: Iterable[str]) -> list[str]:
    output = _run_git(repo, "ls-files", "--others", "--exclude-standard", "--", ".")
    return sorted(path for path in output.splitlines() if path and not _is_excluded(path, exclusions))


def _modified_files(repo: Path, exclusions: Iterable[str]) -> list[str]:
    output = _run_git(repo, "diff", "--name-only", "HEAD", "--", ".")
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
    exclusions = list(exclusions)
    try:
        seal_relative = seal_path.relative_to(repo).as_posix()
    except ValueError:
        seal_relative = None
    if seal_relative and not _is_excluded(seal_relative, exclusions):
        exclusions.append(seal_relative)
    exclusions = tuple(exclusions)
    modified = _modified_files(repo, exclusions)
    if modified:
        raise ValueError("modified audited files must be committed first: " + ", ".join(modified))
    untracked = _untracked_files(repo, exclusions)
    if untracked:
        raise ValueError("untracked audited files must be reviewed first: " + ", ".join(untracked))

    artifacts: dict[str, str] = {}
    for path in _tracked_files(repo, exclusions):
        candidate = repo / path
        if candidate.is_symlink():
            raise ValueError(f"tracked symlink is not sealable: {path}")
        if not candidate.is_file():
            raise ValueError(f"tracked non-file entry is not sealable: {path}")
        artifacts[path] = _sha256(candidate)
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
    manifest = json.dumps(expected, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_digest = f"sha256:{hashlib.sha256(manifest).hexdigest()}"
    if seal.get("source_manifest_sha256") != manifest_digest:
        errors.append("manifest digest mismatch")
    current_paths = set(_tracked_files(repo, exclusions)) | set(_untracked_files(repo, exclusions))
    expected_paths = set(expected)
    for path in sorted(expected_paths - current_paths):
        errors.append(f"missing: {path}")
    for path in sorted(current_paths - expected_paths):
        errors.append(f"unexpected: {path}")
    for path in sorted(expected_paths & current_paths):
        candidate = repo / path
        if candidate.is_symlink():
            errors.append(f"unsupported tracked symlink: {path}")
        elif not candidate.is_file():
            errors.append(f"missing: {path}")
        elif _sha256(candidate) != expected[path]:
            errors.append(f"hash mismatch: {path}")
    return errors


def _contains_raw_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in TOKEN_PATTERNS)


def scan_artifacts(artifact_root: Path | str) -> list[str]:
    """Fail closed when a publication tree cannot be fully text-scanned."""
    root = Path(artifact_root).resolve()
    if not root.is_dir():
        return [f"artifact directory is missing: {root}"]
    errors: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        raw = path.read_bytes()
        if len(raw) > 10 * 1024 * 1024:
            errors.append(f"artifact exceeds scan limit: {relative}")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"binary artifact requires separate inspection: {relative}")
            continue
        if _contains_raw_secret(text) or redact_text(text) != text:
            errors.append(f"raw secret-like value: {relative}")
        if any(marker in text for marker in ("監査実施環境のセッション記録に保存", "/Users/", "/private/tmp/")):
            errors.append(f"non-public evidence reference: {relative}")
    return errors


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
    errors.extend(scan_artifacts(audit))
    for path in audit.rglob("*") if audit.exists() else ():
        if path.is_file() and path.suffix.lower() in {".md", ".txt", ".log"}:
            text = path.read_text(encoding="utf-8")
            if re.search(
                r"\{[^{}\n]+\}|\b(?:TODO|TBD|FIXME)\b", text
            ):
                errors.append(f"unresolved placeholder: {path.relative_to(root)}")
    workpaper = audit / "audit-workpaper.md"
    if workpaper.is_file():
        workpaper_text = workpaper.read_text(encoding="utf-8")
        for reference in sorted(set(re.findall(r"`(evidence/[^`]+)`", workpaper_text))):
            if not (audit / reference).is_file():
                errors.append(f"broken evidence reference: {reference}")
    if (audit / "seal.json").is_file():
        errors.extend(verify_seal(root, audit / "seal.json"))
    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    redact = subparsers.add_parser("redact", help="redact stdin or a file")
    redact.add_argument("path", nargs="?", type=Path)
    redact.add_argument("--output", type=Path, help="write redacted output to this file")
    redact.add_argument(
        "--delete-source",
        action="store_true",
        help="delete the raw input only after --output is written successfully",
    )
    create = subparsers.add_parser("create-seal", help="create a v2 source seal")
    create.add_argument("repo", type=Path)
    create.add_argument("seal", type=Path)
    create.add_argument("--exclude", action="append", default=[], help="explicit output path/prefix")
    verify = subparsers.add_parser("verify-seal", help="verify a v2 source seal")
    verify.add_argument("repo", type=Path)
    verify.add_argument("seal", type=Path)
    bundle = subparsers.add_parser("validate-bundle", help="validate an example audit bundle")
    bundle.add_argument("root", type=Path)
    scan = subparsers.add_parser("scan-artifacts", help="scan every publication artifact")
    scan.add_argument("root", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "redact":
        if args.delete_source and (args.path is None or args.output is None):
            print("--delete-source requires both an input path and --output", file=sys.stderr)
            return 2
        if args.path is not None and args.output is not None and args.path.resolve() == args.output.resolve():
            print("input path and --output must be different", file=sys.stderr)
            return 2
        raw = args.path.read_text(encoding="utf-8") if args.path else sys.stdin.read()
        redacted = redact_text(raw)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(redacted, encoding="utf-8")
            if args.delete_source:
                args.path.unlink()
        else:
            sys.stdout.write(redacted)
        return 0
    if args.command == "create-seal":
        try:
            create_seal(args.repo, args.seal, exclusions=args.exclude)
        except (OSError, subprocess.CalledProcessError, ValueError) as error:
            print(f"seal creation failed: {error}", file=sys.stderr)
            return 1
        return 0
    if args.command == "verify-seal":
        errors = verify_seal(args.repo, args.seal)
    elif args.command == "scan-artifacts":
        errors = scan_artifacts(args.root)
    else:
        errors = validate_bundle(args.root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
