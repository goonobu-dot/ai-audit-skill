#!/usr/bin/env python3
"""Machine-enforced entry gates for AI-assisted development (P0).

Two deterministic gates that STOP leaks before they become irreversible, without
limiting what the primary agent (Claude) can build locally:

  build-prompt-bundle  Prepare code to hand to an EXTERNAL LLM (Codex/Grok) with
                       secrets and PII masked. Default `redact` mode keeps full
                       context (so the external reviewer stays capable) but masks
                       secrets/PII; `allowlist` mode sends only permitted paths.
                       Fail-closed: if a raw secret survives redaction, no bundle
                       is produced.

  gate-commit          A pre-commit gate: scan STAGED changes and block the commit
                       (non-zero exit) when a real secret is about to be committed.
                       PII is warned, not blocked, to avoid false-positive friction.

Design constitution (from the 2026-08 3-AI council): AI is analysis assistance;
the STOP decision is a deterministic gate. Never claim exhaustiveness. When a
dedicated scanner (gitleaks) is unavailable, fall back to patterns AND say so.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# Reuse the audited redaction engine from the bundled audit_guard so the two
# tools never drift on what counts as a secret.
_GUARD_PATH = Path(__file__).resolve().parent / "audit_guard.py"
_spec = importlib.util.spec_from_file_location("_audit_guard_for_gate", _GUARD_PATH)
if _spec is None or _spec.loader is None:  # pragma: no cover - defensive
    raise RuntimeError(f"cannot load audit_guard: {_GUARD_PATH}")
_guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_guard)

redact_text = _guard.redact_text
_contains_raw_secret = _guard._contains_raw_secret


# --- PII patterns (conservative, pattern-only; Presidio is a future upgrade) ---
# Kept deliberately narrow to avoid false-positive paralysis. Email is masked in
# bundles (over-masking is harmless there) but only WARNED at commit time.
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
JP_PHONE_PATTERN = re.compile(r"\b0\d{1,4}-\d{1,4}-\d{4}\b")
CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b")
# Example/placeholder domains that must NOT count as PII (docs, tests, fixtures).
_SAFE_EMAIL_DOMAINS = ("example.com", "example.org", "example.invalid", "example.net")

DEFAULT_EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".turbo",
    "audit", "atlas", "critical-review",
}
DEFAULT_EXCLUDE_SUFFIXES = {".pyc", ".pyo", ".so", ".dylib", ".o", ".a"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_safe_email(value: str) -> bool:
    return any(value.lower().endswith("@" + d) or value.lower().endswith("." + d)
               for d in _SAFE_EMAIL_DOMAINS)


def redact_pii(text: str) -> tuple[str, int]:
    """Mask conservative PII patterns; return (text, masked_count)."""
    count = 0

    def mask_email(match: re.Match[str]) -> str:
        nonlocal count
        if _is_safe_email(match.group(0)):
            return match.group(0)
        count += 1
        return "[REDACTED-EMAIL]"

    text = EMAIL_PATTERN.sub(mask_email, text)

    def mask(rx_repl: str):
        def _sub(match: re.Match[str]) -> str:
            nonlocal count
            count += 1
            del match
            return rx_repl
        return _sub

    text = JP_PHONE_PATTERN.sub(mask("[REDACTED-PHONE]"), text)
    text = CREDIT_CARD_PATTERN.sub(mask("[REDACTED-CARD]"), text)
    return text, count


def _contains_pii(text: str) -> bool:
    for m in EMAIL_PATTERN.finditer(text):
        if not _is_safe_email(m.group(0)):
            return True
    return bool(JP_PHONE_PATTERN.search(text) or CREDIT_CARD_PATTERN.search(text))


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _iter_candidate_files(repo: Path, allow: set[str] | None):
    for path in sorted(repo.rglob("*")):
        rel = path.relative_to(repo)
        parts = set(rel.parts)
        if parts & DEFAULT_EXCLUDE_DIRS:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix in DEFAULT_EXCLUDE_SUFFIXES:
            continue
        rel_posix = rel.as_posix()
        if allow is not None and rel_posix not in allow:
            continue
        yield rel_posix, path


def build_prompt_bundle(
    repo: Path | str,
    out_dir: Path | str,
    mode: str = "redact",
    allow_manifest: Path | str | None = None,
) -> tuple[int, list[str]]:
    """Produce a leak-safe copy for an external LLM. Returns (exit_code, messages)."""
    repo = Path(repo).resolve()
    out_dir = Path(out_dir).resolve()
    messages: list[str] = []
    if not repo.is_dir():
        return 2, [f"source repo is not a directory: {repo}"]
    if mode not in {"redact", "allowlist"}:
        return 2, [f"unknown mode: {mode}"]

    allow: set[str] | None = None
    if mode == "allowlist":
        if allow_manifest is None:
            return 2, ["allowlist mode requires --allow <manifest>"]
        manifest_path = Path(allow_manifest)
        if not manifest_path.is_file():
            return 2, [f"allow manifest not found: {manifest_path}"]
        allow = {
            line.strip() for line in manifest_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        }

    # out_dir must not sit inside the source repo (avoid recursively bundling it).
    try:
        out_dir.relative_to(repo)
        return 2, ["--output must be outside the source repo"]
    except ValueError:
        pass

    ledger_files: list[dict] = []
    excluded_binaries: list[str] = []
    residual_secret_files: list[str] = []
    total_pii_masks = 0

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    os.chmod(out_dir, 0o700)

    for rel_posix, path in _iter_candidate_files(repo, allow):
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            excluded_binaries.append(f"{rel_posix} (exceeds {MAX_FILE_BYTES} bytes)")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            excluded_binaries.append(f"{rel_posix} (binary/non-utf8)")
            continue
        before_secret = _contains_raw_secret(text) or redact_text(text) != text
        redacted = redact_text(text)
        redacted, pii_masks = redact_pii(redacted)
        # Fail-closed check: a raw secret must not survive redaction.
        if _contains_raw_secret(redacted):
            residual_secret_files.append(rel_posix)
        dest = out_dir / rel_posix
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(redacted, encoding="utf-8")
        os.chmod(dest, 0o600)
        ledger_files.append({
            "path": rel_posix,
            "sha256_redacted": _sha256_bytes(redacted.encode("utf-8")),
            "bytes": len(redacted.encode("utf-8")),
            "had_secret_before_redaction": bool(before_secret),
            "pii_masks": pii_masks,
        })
        total_pii_masks += pii_masks

    if residual_secret_files:
        shutil.rmtree(out_dir)
        return 1, [
            "FAIL-CLOSED: a raw secret survived redaction; no bundle produced.",
            "files: " + ", ".join(residual_secret_files),
            "Remove the secret from the source (do not send it to any external AI).",
        ]

    ledger = {
        "schema_version": 1,
        "kind": "external-llm-transmission-ledger",
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_repo": str(repo),
        "note": (
            "Pattern-based redaction only (secrets via audit_guard, PII conservative). "
            "Not exhaustive: dedicated PII (Presidio) is a future upgrade. Review before sending."
        ),
        "files_included": len(ledger_files),
        "pii_masks_total": total_pii_masks,
        "excluded_binaries": excluded_binaries,
        "files": ledger_files,
    }
    (out_dir / "transmission-ledger.json").write_text(
        json.dumps(ledger, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(out_dir / "transmission-ledger.json", 0o600)

    messages.append(f"bundle ready: {out_dir}")
    messages.append(f"included {len(ledger_files)} file(s), masked {total_pii_masks} PII span(s), mode={mode}")
    if excluded_binaries:
        messages.append(f"excluded (not sent): {len(excluded_binaries)} binary/oversize file(s)")
    messages.append("ledger: transmission-ledger.json (what will be sent). Review before handing to an external AI.")
    return 0, messages


def _gitleaks_available() -> bool:
    return shutil.which("gitleaks") is not None


def _staged_added_lines(repo: Path) -> list[tuple[str, str]]:
    """Return (file, added_line) pairs from the staged diff."""
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--unified=0", "--no-color"],
            cwd=repo, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return []
    pairs: list[tuple[str, str]] = []
    current = "?"
    for line in out.splitlines():
        if line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            pairs.append((current, line[1:]))
    return pairs


def gate_commit(repo: Path | str) -> tuple[int, list[str]]:
    """Block a commit about to introduce a real secret. Returns (exit, msgs).

    Defense in depth: gitleaks (when installed) AND the bundled pattern engine are
    BOTH run, and the commit is blocked if EITHER flags a secret. The two catch
    different things (3-AI review 2026-08: a hyphenated ``sk-live-`` token was
    missed by gitleaks but caught by the patterns), so their union is safer than
    trusting one alone.
    """
    repo = Path(repo).resolve()
    messages: list[str] = []
    blocked = False
    has_gitleaks = _gitleaks_available()

    if has_gitleaks:
        proc = subprocess.run(
            ["gitleaks", "protect", "--staged", "--no-banner", "--redact"],
            cwd=repo, capture_output=True, text=True,
        )
        if proc.returncode != 0:
            blocked = True
            messages.append("BLOCKED (gitleaks): a secret is in the staged changes.")
            tail = (proc.stdout or proc.stderr or "").strip().splitlines()[-6:]
            messages.extend(tail)
        else:
            messages.append("gitleaks: clean.")
    else:
        messages.append("NOTE: gitleaks not installed — running pattern detection only (brew install gitleaks for authoritative scanning).")

    added = _staged_added_lines(repo)
    pattern_hits: list[str] = []
    for fname, line in added:
        if _contains_raw_secret(line) or redact_text(line) != line:
            pattern_hits.append(f"{fname}: {redact_text(line).strip()[:100]}")
    if pattern_hits:
        blocked = True
        messages.append("BLOCKED (patterns): a secret-like value is in the staged changes.")
        messages.extend(pattern_hits[:8])

    if blocked:
        messages.append("Remove the secret from the source and re-stage. Do not bypass with --no-verify.")
        return 1, messages

    # PII is warned, never blocked (pattern PII is false-positive prone).
    pii_hits = {fname for fname, line in added if _contains_pii(line)}
    if pii_hits:
        messages.append(f"WARNING (not blocking): possible PII in staged changes: {', '.join(sorted(pii_hits)[:6])}")
    messages.append("gate-commit: no secret detected (not exhaustive).")
    return 0, messages


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    bundle = sub.add_parser("build-prompt-bundle", help="prepare a leak-safe copy for an external LLM")
    bundle.add_argument("repo", type=Path)
    bundle.add_argument("--output", type=Path, required=True, help="bundle output dir (must be outside repo)")
    bundle.add_argument("--mode", choices=["redact", "allowlist"], default="redact")
    bundle.add_argument("--allow", type=Path, help="allowlist manifest (allowlist mode)")

    commit = sub.add_parser("gate-commit", help="block a commit that introduces a secret")
    commit.add_argument("repo", type=Path, nargs="?", default=Path("."))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "build-prompt-bundle":
        code, messages = build_prompt_bundle(args.repo, args.output, args.mode, args.allow)
    else:
        code, messages = gate_commit(args.repo)
    stream = sys.stderr if code != 0 else sys.stdout
    for m in messages:
        print(m, file=stream)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
