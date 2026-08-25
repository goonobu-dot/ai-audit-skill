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


BUNDLE_MARKER = ".ai-audit-bundle"


def build_prompt_bundle(
    repo: Path | str,
    out_dir: Path | str,
    mode: str = "redact",
    allow_manifest: Path | str | None = None,
    destination: str | None = None,
    model: str | None = None,
    force: bool = False,
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

    # C4 fix (3-AI review 2026-08, Codex): NEVER recursively delete an arbitrary
    # existing directory. Only overwrite a directory this tool itself created
    # (identified by BUNDLE_MARKER), and only with --force. Refuse home/root,
    # symlinks, non-directories, and any non-empty directory we did not create.
    if out_dir == Path.home() or out_dir == Path(out_dir.anchor):
        return 2, ["--output must not be your home directory or the filesystem root"]
    if out_dir.is_symlink():
        return 2, [f"--output must not be a symlink: {out_dir}"]
    if out_dir.exists():
        if not out_dir.is_dir():
            return 2, [f"--output exists and is not a directory: {out_dir}"]
        has_contents = any(out_dir.iterdir())
        is_prior_bundle = (out_dir / BUNDLE_MARKER).is_file()
        if has_contents and not is_prior_bundle:
            return 2, [
                f"--output already exists and is not an ai-audit bundle: {out_dir}",
                "Refusing to delete it. Choose a new path; this tool creates the directory itself.",
            ]
        if has_contents and not force:
            return 2, [
                f"--output is a previous ai-audit bundle: {out_dir}",
                "Pass --force to overwrite it.",
            ]
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    os.chmod(out_dir, 0o700)
    (out_dir / BUNDLE_MARKER).write_text("ai-audit external-llm bundle\n", encoding="utf-8")
    os.chmod(out_dir / BUNDLE_MARKER, 0o600)

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
        # external=True: leave NO SHA fingerprint in a bundle that leaves the boundary.
        redacted = redact_text(text, external=True)
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
        "schema_version": 2,
        "kind": "external-llm-transmission-ledger",
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        # Accountability without leakage: record who/what this is going to, but never
        # the terminal's absolute source path (3-AI review 2026-08: Codex/Grok).
        "source_repo_name": repo.name,
        "destination": destination or "unspecified",
        "model": model or "unspecified",
        "note": (
            "Pattern-based redaction only (known secret patterns via audit_guard, "
            "conservative PII). NOT exhaustive: unknown-format secrets, names, "
            "addresses, and business-confidential text can survive. A human MUST "
            "review this bundle before sending, and confirm the code itself is not "
            "confidential. Dedicated PII (Presidio) is a future upgrade."
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
    if not destination or not model:
        messages.append("NOTE: --destination/--model not given; recorded as 'unspecified' in the ledger.")
    messages.append(
        "Redaction masks KNOWN secret/PII patterns only — it is NOT exhaustive. "
        "A human must review transmission-ledger.json (and the files) before sending, "
        "and confirm the code itself is not confidential."
    )
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


def gate_commit(repo: Path | str, strict: bool = False) -> tuple[int, list[str]]:
    """Block a commit about to introduce a real secret. Returns (exit, msgs).

    Defense in depth: gitleaks (when installed) AND the bundled pattern engine are
    BOTH run, and the commit is blocked if EITHER flags a secret. The two catch
    different things (3-AI review 2026-08: a hyphenated ``sk-live-`` token was
    missed by gitleaks but caught by the patterns), so their union is safer than
    trusting one alone.

    Honesty (3-AI review 2026-08, Grok): when gitleaks is absent the pattern engine
    alone is NOT authoritative. The clean result is reported as NOT-TESTED, and in
    ``strict`` mode (for CI) returns exit 3 rather than a reassuring exit 0.
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
    if not has_gitleaks:
        messages.append(
            "NOT-TESTED by an authoritative scanner: pattern detection found nothing, "
            "but this is not a clean bill of health (install gitleaks)."
        )
        if strict:
            return 3, messages
        return 0, messages
    messages.append("gate-commit: no secret detected by gitleaks + patterns (not exhaustive).")
    return 0, messages


# --- P1: dependency SCA (osv-scanner) and SBOM (syft), machine-connected ---
# These are read-only analyses of DEPENDENCIES; they never limit what the agent
# can build. When the tool is absent we return a distinct "not-tested" code and
# never claim "clean" (fail-closed on honesty, per the 3-AI council).

# Exit codes for scan-deps / gen-sbom:
#   0 = tool ran, no blocking finding
#   1 = tool ran, blocking finding (Critical/High vuln)
#   3 = tool not installed -> NOT-TESTED (caller must not treat as clean)

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "NONE": 0, "": 0}

# --- CVSS v3.x base-score parsing (deterministic; fixes the "CVSS 9.8 read as
# UNKNOWN and passed" fail-open found by Codex in the 3-AI review 2026-08) ---
_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _cvss3_roundup(value: float) -> float:
    """Official CVSS v3.1 roundup (to one decimal)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int(int_input / 10000) + 1) / 10.0


def _cvss3_base_from_vector(vector: str) -> float | None:
    """Compute a CVSS v3.0/3.1 base score from its vector string, or None."""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, _, val = part.partition(":")
            metrics[key.strip().upper()] = val.strip().upper()
    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if not all(k in metrics for k in required):
        return None
    try:
        scope_changed = metrics["S"] == "C"
        av = _CVSS3_WEIGHTS["AV"][metrics["AV"]]
        ac = _CVSS3_WEIGHTS["AC"][metrics["AC"]]
        pr = _CVSS3_WEIGHTS["PR_C" if scope_changed else "PR_U"][metrics["PR"]]
        ui = _CVSS3_WEIGHTS["UI"][metrics["UI"]]
        conf = _CVSS3_WEIGHTS["CIA"][metrics["C"]]
        integ = _CVSS3_WEIGHTS["CIA"][metrics["I"]]
        avail = _CVSS3_WEIGHTS["CIA"][metrics["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _cvss3_roundup(min(1.08 * (impact + exploitability), 10))
    return _cvss3_roundup(min(impact + exploitability, 10))


def _bucket_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _osv_severity(vuln: dict) -> str:
    """Severity label from an OSV vulnerability object.

    Parses CVSS vectors and numeric scores; falls back to database_specific.
    Returns "" (unknown) only when nothing parses — and unknown-but-present
    findings are treated as blocking by the caller (fail-closed).
    """
    best_score = -1.0
    for entry in vuln.get("severity", []) or []:
        raw = str(entry.get("score", "")).strip()
        if not raw:
            continue
        if "CVSS:" in raw.upper() or "/AV:" in raw.upper():
            score = _cvss3_base_from_vector(raw)
        else:
            try:
                score = float(raw)
            except ValueError:
                score = None
        if score is not None and score > best_score:
            best_score = score
    if best_score >= 0:
        return _bucket_from_score(best_score)
    db = (vuln.get("database_specific") or {}).get("severity", "")
    if isinstance(db, str) and db.upper() in SEVERITY_ORDER:
        return db.upper()
    return ""


def parse_osv_results(report: dict) -> list[dict]:
    """Flatten osv-scanner JSON into a list of {package, id, severity, source}."""
    findings: list[dict] = []
    for result in report.get("results", []) or []:
        source = (result.get("source") or {}).get("path", "?")
        for pkg in result.get("packages", []) or []:
            name = (pkg.get("package") or {}).get("name", "?")
            version = (pkg.get("package") or {}).get("version", "?")
            for vuln in pkg.get("vulnerabilities", []) or []:
                findings.append({
                    "package": f"{name}@{version}",
                    "id": vuln.get("id", "?"),
                    "severity": _osv_severity(vuln),
                    "source": source,
                })
    return findings


def _has_blocking(findings: list[dict]) -> bool:
    return any(SEVERITY_ORDER.get(f.get("severity", ""), 0) >= 3 for f in findings)


def scan_deps(repo: Path | str, results_path: Path | str | None = None) -> tuple[int, list[str]]:
    """Grade dependency vulnerabilities. Returns (exit, msgs).

    With ``results_path`` an existing osv-scanner JSON is graded (so CI can run
    osv-scanner in a container and feed the report here). Otherwise the local
    osv-scanner binary is invoked; if it is absent we return code 3 = NOT-TESTED
    and never claim clean.
    """
    if results_path is not None:
        try:
            raw = Path(results_path).read_text(encoding="utf-8")
            report = json.loads(raw) if raw.strip() else {}
        except (OSError, json.JSONDecodeError) as error:
            return 3, [f"NOT-TESTED: could not read osv results: {error}"]
        # C5 fix (3-AI review 2026-08, Codex): an empty file / missing "results"
        # key means the scanner did NOT actually run. Never read that as clean.
        if not isinstance(report, dict) or "results" not in report:
            return 3, [
                "NOT-TESTED: osv results are empty or missing the 'results' key "
                "(the scanner did not run). Do NOT treat this as clean.",
            ]
    else:
        repo = Path(repo).resolve()
        if shutil.which("osv-scanner") is None:
            return 3, [
                "NOT-TESTED: osv-scanner is not installed; dependency vulnerabilities were NOT checked.",
                "Do not treat this as clean. Install it: brew install osv-scanner (Apache-2.0, offline DB supported).",
            ]
        proc = subprocess.run(
            ["osv-scanner", "scan", "--format", "json", "-r", str(repo)],
            capture_output=True, text=True,
        )
        # osv-scanner exit codes: 0 = no vuln, 1 = vuln found, 128 = no packages
        # found (nothing to scan), anything else = scanner error.
        if proc.returncode == 128:
            return 0, [
                "osv-scanner: no dependency manifests found; nothing to scan "
                "(this is NOT a clearance for vendored/copied-in code)."
            ]
        if proc.returncode not in (0, 1):
            return 3, [
                f"NOT-TESTED: osv-scanner failed (exit {proc.returncode}); not a clean result.",
                (proc.stderr or "").strip()[:300],
            ]
        # returncode 0/1 proves the scanner actually ran; parse its report.
        try:
            report = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            return 3, ["NOT-TESTED: could not parse osv-scanner output.", (proc.stderr or "").strip()[:300]]
    findings = parse_osv_results(report)
    if not findings:
        return 0, ["osv-scanner: no known-vulnerable dependencies found (not exhaustive)."]
    lines = [f"{f['severity'] or 'UNKNOWN'}  {f['package']}  {f['id']}  ({f['source']})" for f in findings]
    # Fail-closed: any finding whose severity could not be determined is blocking.
    unknown = [f for f in findings if not f.get("severity")]
    if _has_blocking(findings) or unknown:
        reason = "Critical/High" if _has_blocking(findings) else "unknown-severity (treated as blocking)"
        return 1, [f"BLOCKING: {reason} dependency vulnerabilities found.", *lines[:20]]
    return 0, ["dependency vulnerabilities found (below High; review):", *lines[:20]]


def gen_sbom(repo: Path | str, output: Path | str) -> tuple[int, list[str]]:
    """Generate a CycloneDX SBOM with syft. Returns (exit, msgs)."""
    repo = Path(repo).resolve()
    output = Path(output).resolve()
    if shutil.which("syft") is None:
        return 3, [
            "NOT-TESTED: syft is not installed; no SBOM was generated.",
            "Install it: brew install syft (Apache-2.0, offline for local filesystems).",
        ]
    output.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["syft", f"dir:{repo}", "-o", "cyclonedx-json", "-q"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return 3, ["NOT-TESTED: syft failed.", (proc.stderr or "").strip()[:300]]
    output.write_text(proc.stdout, encoding="utf-8")
    os.chmod(output, 0o600)
    try:
        doc = json.loads(proc.stdout or "{}")
        n = len(doc.get("components", []) or [])
    except json.JSONDecodeError:
        n = 0
    return 0, [f"SBOM written: {output}", f"components catalogued: {n} (CycloneDX-JSON)"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    bundle = sub.add_parser("build-prompt-bundle", help="prepare a leak-safe copy for an external LLM")
    bundle.add_argument("repo", type=Path)
    bundle.add_argument("--output", type=Path, required=True, help="bundle output dir (must be a new/empty path outside repo)")
    bundle.add_argument("--mode", choices=["redact", "allowlist"], default="redact")
    bundle.add_argument("--allow", type=Path, help="allowlist manifest (allowlist mode)")
    bundle.add_argument("--destination", help="who the bundle is sent to (recorded in the ledger)")
    bundle.add_argument("--model", help="external model the bundle is sent to (recorded in the ledger)")
    bundle.add_argument("--force", action="store_true", help="overwrite a previous ai-audit bundle at --output")

    commit = sub.add_parser("gate-commit", help="block a commit that introduces a secret")
    commit.add_argument("repo", type=Path, nargs="?", default=Path("."))
    commit.add_argument("--strict", action="store_true", help="exit 3 (NOT-TESTED) when gitleaks is absent (for CI)")

    sca = sub.add_parser("scan-deps", help="scan dependencies for known vulnerabilities (osv-scanner)")
    sca.add_argument("repo", type=Path, nargs="?", default=Path("."))
    sca.add_argument("--results", type=Path, help="grade an existing osv-scanner JSON instead of invoking the binary")

    sbom = sub.add_parser("gen-sbom", help="generate a CycloneDX SBOM (syft)")
    sbom.add_argument("repo", type=Path, nargs="?", default=Path("."))
    sbom.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "build-prompt-bundle":
        code, messages = build_prompt_bundle(
            args.repo, args.output, args.mode, args.allow,
            destination=args.destination, model=args.model, force=args.force,
        )
    elif args.command == "scan-deps":
        code, messages = scan_deps(args.repo, args.results)
    elif args.command == "gen-sbom":
        code, messages = gen_sbom(args.repo, args.output)
    else:
        code, messages = gate_commit(args.repo, strict=args.strict)
    stream = sys.stderr if code != 0 else sys.stdout
    for m in messages:
        print(m, file=stream)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
