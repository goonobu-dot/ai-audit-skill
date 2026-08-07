#!/usr/bin/env python3
"""Redact audit evidence and create/verify reproducible audit seals."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable


SCHEMA_VERSION = 2
QUALITY_PROFILE_SCHEMA_VERSION = 1
QUALITY_PROFILE_VERSION = "1.2.0"
DEFAULT_EXCLUSIONS: tuple[str, ...] = ()
CORE_STANDARDS = {
    "AI-AUDIT": "1.2.0",
    "ISO-IEC-25010": "2023",
    "ISO-IEC-IEEE-29119-2": "2021",
    "ISO-IEC-IEEE-29119-3": "2021",
    "NIST-SP-800-218": "1.1",
}
REQUIRED_STANDARD_URIS = {
    "AI-AUDIT": "https://github.com/goonobu-dot/ai-audit-skill/",
    "ISO-IEC-25010": "https://www.iso.org/standard/78176.html",
    "ISO-IEC-IEEE-29119-2": "https://www.iso.org/standard/79428.html",
    "ISO-IEC-IEEE-29119-3": "https://www.iso.org/standard/79429.html",
    "NIST-SP-800-218": "https://csrc.nist.gov/pubs/sp/800/218/final",
    "OWASP-MASVS": "https://mas.owasp.org/MASVS/",
    "APPLE-APP-REVIEW": "https://developer.apple.com/app-store/review/guidelines/",
    "APPLE-PRIVACY-MANIFEST": "https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
    "APPLE-PLATFORM-SECURITY": "https://developer.apple.com/security/",
    "OWASP-ASVS": "https://owasp.org/www-project-application-security-verification-standard/",
    "NIST-SP-800-218A": "https://csrc.nist.gov/pubs/sp/800/218/a/final",
}
AUDIT_CONTROL_IDS = {
    *(f"AA-1.{number}" for number in range(1, 7)),
    *(f"AA-2.{number}" for number in range(1, 6)),
    *(f"AA-3.{number}" for number in range(1, 6)),
    *(f"AA-4.{number}" for number in range(1, 6)),
    *(f"AA-5.{number}" for number in range(1, 7)),
    *(f"AA-6.{number}" for number in range(1, 5)),
    *(f"AA-7.{number}" for number in range(1, 6)),
    *(f"AA-8.{number}" for number in range(1, 9)),
    *(f"AA-9.{number}" for number in range(1, 10)),
}
AUDIT_CRITICAL_IDS = {
    "AA-1.1", "AA-1.2", "AA-1.3", "AA-1.6", "AA-2.2", "AA-2.3",
    "AA-3.2", "AA-3.3", "AA-4.1", "AA-4.2", "AA-5.5",
}
MASVS_CONTROL_IDS = {
    "MASVS-STORAGE-1", "MASVS-STORAGE-2",
    "MASVS-CRYPTO-1", "MASVS-CRYPTO-2",
    "MASVS-AUTH-1", "MASVS-AUTH-2", "MASVS-AUTH-3",
    "MASVS-NETWORK-1", "MASVS-NETWORK-2",
    "MASVS-PLATFORM-1", "MASVS-PLATFORM-2", "MASVS-PLATFORM-3",
    "MASVS-CODE-1", "MASVS-CODE-2", "MASVS-CODE-3", "MASVS-CODE-4",
    "MASVS-RESILIENCE-1", "MASVS-RESILIENCE-2", "MASVS-RESILIENCE-3",
    "MASVS-RESILIENCE-4", "MASVS-PRIVACY-1", "MASVS-PRIVACY-2",
    "MASVS-PRIVACY-3", "MASVS-PRIVACY-4",
}
ISO_25010_CHARACTERISTICS = {
    "functional-suitability", "performance-efficiency", "compatibility",
    "interaction-capability", "reliability", "security", "maintainability",
    "flexibility", "safety",
}
NIST_SSDF_TASK_IDS = {
    "PO.1.1", "PO.1.2", "PO.1.3", "PO.2.1", "PO.2.2", "PO.2.3",
    "PO.3.1", "PO.3.2", "PO.3.3", "PO.4.1", "PO.4.2", "PO.5.1", "PO.5.2",
    "PS.1.1", "PS.2.1", "PS.3.1", "PS.3.2",
    "PW.1.1", "PW.1.2", "PW.1.3", "PW.2.1", "PW.3.1", "PW.3.2",
    "PW.4.1", "PW.4.2", "PW.4.3", "PW.4.4", "PW.4.5", "PW.5.1",
    "PW.5.2", "PW.6.1", "PW.6.2", "PW.7.1", "PW.7.2", "PW.8.1",
    "PW.8.2", "PW.9.1", "PW.9.2", "RV.1.1", "RV.1.2", "RV.1.3",
    "RV.2.1", "RV.2.2", "RV.3.1", "RV.3.2", "RV.3.3", "RV.3.4",
}
IOS_SOURCE_REQUIREMENTS = {
    "APPLE-APP-REVIEW": {"APP-REVIEW-PRIVACY", "APP-REVIEW-SECURITY"},
    "APPLE-PRIVACY-MANIFEST": {
        "PRIVACYINFO-XCPRIVACY", "REQUIRED-REASON-API", "THIRD-PARTY-SDK-MANIFEST"
    },
    "APPLE-PLATFORM-SECURITY": {
        "ENTITLEMENTS", "CODE-SIGNING", "DATA-PROTECTION", "ATS-KEYCHAIN"
    },
}
MOBILE_STANDARDS = {"OWASP-MASVS": "2.1.0"}
IOS_STANDARDS = {
    "APPLE-APP-REVIEW": "current",
    "APPLE-PRIVACY-MANIFEST": "current",
    "APPLE-PLATFORM-SECURITY": "current",
}
WEB_STANDARDS = {"OWASP-ASVS": "5.0.0"}
AI_STANDARDS = {"NIST-SP-800-218A": "2024"}
TARGET_TYPES = {
    "ios",
    "android",
    "web",
    "api",
    "backend",
    "desktop",
    "cli",
    "ai-enabled",
    "ot",
    "safety-related",
    "regulated",
}
MATRIX_COLUMNS = (
    "requirement_id",
    "source_id",
    "source_version",
    "source_requirement",
    "applicability",
    "applicability_approver",
    "mandatory",
    "severity",
    "test_method",
    "expected_result",
    "actual_result",
    "evidence_id",
    "evidence",
    "evidence_sha256",
    "result",
    "limitation",
    "owner",
    "hazard_id",
    "design_item_id",
    "test_id",
    "deviation_id",
    "residual_risk_id",
    "stage_approval_id",
)
CLAIM_LEVELS = {"referenced", "mapped", "verified"}
APPLICABILITY_VALUES = {"applicable", "not-applicable", "undetermined"}
RESULT_VALUES = {"pass", "conditional", "fail", "not-tested", "not-applicable"}
SEVERITY_VALUES = {"critical", "important", "minor"}
IDENTIFIER_PATTERN = re.compile(r"^[A-Z][A-Z0-9_.-]{2,80}$")
SOURCE_REQUIREMENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/() -]{0,119}$")
SECTOR_GATE_EVIDENCE_FIELDS = (
    "hazard_traceability_evidence",
    "configuration_baseline_evidence",
    "verification_plan_evidence",
    "independent_review_evidence",
    "stage_approval_evidence",
)
TOKEN_PATTERNS = (
    re.compile(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?=[A-Za-z0-9_-]{32,}\b)(?=[A-Za-z0-9_-]*[a-z])(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[0-9])[A-Za-z0-9_-]{32,}\b"),
)
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
ASSIGNMENT_PATTERN = re.compile(
    r"(?i)([\"']?\b(?:api[_-]?key|access[_-]?token|auth(?:orization)?|client[_-]?secret|"
    r"credential|jwt|password|passwd|pin|private[_-]?key|recovery[_-]?code|secret|token)\b[\"']?\s*[:=]\s*)"
    r'(?:"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|([^\s,}\]]+))'
)
YAML_SECRET_BLOCK_HEADER = re.compile(
    r"^(?P<indent>[ \t]*)(?P<prefix>[\"']?(?:api[_-]?key|access[_-]?token|auth(?:orization)?|"
    r"client[_-]?secret|credential|jwt|password|passwd|pin|private[_-]?key|"
    r"recovery[_-]?code|secret|token)[\"']?[ \t]*:)[ \t]*[|>][-+0-9]*[ \t]*(?:#.*)?$",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
SSH_SIGNATURE_PATTERN = re.compile(
    r"-----BEGIN SSH SIGNATURE-----\r?\n"
    r"[A-Za-z0-9+/=\r\n]+"
    r"-----END SSH SIGNATURE-----\r?\n?\Z"
)


def _fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _replacement(secret: str, include_fingerprint: bool = True) -> str:
    if not include_fingerprint:
        return "[REDACTED]"
    return f"[REDACTED:sha256:{_fingerprint(secret)}]"


def redact_text(text: str) -> str:
    """Mask common secrets; fingerprint only unassigned high-entropy tokens."""
    lines = text.splitlines(keepends=True)
    redacted_lines: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = YAML_SECRET_BLOCK_HEADER.fullmatch(line.rstrip("\r\n"))
        if match is None:
            redacted_lines.append(line)
            index += 1
            continue
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        redacted_lines.append(f"{match.group('indent')}{match.group('prefix')} [REDACTED]{newline}")
        parent_indent = len(match.group("indent").expandtabs(8))
        index += 1
        while index < len(lines):
            candidate = lines[index]
            stripped = candidate.lstrip(" \t")
            if not stripped.strip():
                index += 1
                continue
            child_indent = len(candidate[: len(candidate) - len(stripped)].expandtabs(8))
            if child_indent <= parent_indent:
                break
            index += 1
    text = "".join(redacted_lines)
    text = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", text)
    text = BEARER_PATTERN.sub(
        lambda match: _replacement(match.group(0), include_fingerprint=False), text
    )

    def redact_assignment(match: re.Match[str]) -> str:
        if match.group(2) is not None:
            quote, value = '"', match.group(2)
        elif match.group(3) is not None:
            quote, value = "'", match.group(3)
        else:
            quote, value = "", match.group(4)
        if value.startswith("[REDACTED"):
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
        "invalidation": "Run scripts/audit_guard.py verify-seal; any reported difference invalidates the technical conclusion.",
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
        if path.suffix == ".sig" and SSH_SIGNATURE_PATTERN.fullmatch(text):
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
        audit / "quality-profile.json",
        audit / "requirements-matrix.csv",
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
    profile_path = audit / "quality-profile.json"
    matrix_path = audit / "requirements-matrix.csv"
    if profile_path.is_file() and matrix_path.is_file():
        errors.extend(validate_quality_package(profile_path, matrix_path, audit))
    report_path = audit / "audit-report.md"
    if profile_path.is_file() and report_path.is_file():
        errors.extend(validate_report_consistency(profile_path, report_path))
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


def derive_technical_conclusion(rows: Iterable[dict[str, str]]) -> str:
    """Return a deterministic conclusion without turning missing work into a pass."""
    rows = list(rows)
    excluded = [row for row in rows if row.get("applicability") == "not-applicable"]
    applicable = [row for row in rows if row.get("applicability") != "not-applicable"]
    if not applicable:
        return "not-acceptable"
    for row in applicable:
        result = row.get("result")
        severity = row.get("severity")
        mandatory = row.get("mandatory") == "true"
        if severity == "critical" and result != "pass":
            return "not-acceptable"
        if mandatory and result == "fail":
            return "not-acceptable"
    if any(
        row.get("applicability") == "undetermined"
        or row.get("result") in {"conditional", "fail", "not-tested"}
        for row in applicable
    ):
        return "conditional"
    if any(
        row.get("mandatory") == "true" or row.get("severity") == "critical"
        for row in excluded
    ):
        return "conditional"
    return "acceptable-within-scope"


def _load_profile(path: Path) -> tuple[dict[str, object] | None, list[str]]:
    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, [f"invalid quality profile: {error}"]
    if not isinstance(profile, dict):
        return None, ["invalid quality profile: root must be an object"]
    return profile, []


def _validate_source_entry(entry: object, label: str) -> list[str]:
    if not isinstance(entry, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    for field in (
        "source_id", "version", "role", "claim_level", "coverage_scope",
        "official_uri", "retrieved_at",
    ):
        if not isinstance(entry.get(field), str) or not entry[field].strip():
            errors.append(f"{label}.{field} is required")
    claim_level = entry.get("claim_level")
    if claim_level not in CLAIM_LEVELS:
        errors.append(f"{label}.claim_level must be one of {sorted(CLAIM_LEVELS)}")
    source_id = entry.get("source_id")
    if isinstance(source_id, str) and not IDENTIFIER_PATTERN.fullmatch(source_id):
        errors.append(f"{label}.source_id has invalid format")
    uri = entry.get("official_uri")
    if isinstance(uri, str) and not uri.startswith("https://"):
        errors.append(f"{label}.official_uri must use https")
    expected_uri = REQUIRED_STANDARD_URIS.get(source_id) if isinstance(source_id, str) else None
    if expected_uri is not None and uri != expected_uri:
        errors.append(f"{label}.official_uri must match the canonical URI for {source_id}")
    retrieved_at = entry.get("retrieved_at")
    if isinstance(retrieved_at, str):
        try:
            date.fromisoformat(retrieved_at)
        except ValueError:
            errors.append(f"{label}.retrieved_at must be a valid YYYY-MM-DD date")
    return errors


def _required_standards(target_types: set[str]) -> dict[str, str]:
    required = dict(CORE_STANDARDS)
    if target_types & {"ios", "android"}:
        required.update(MOBILE_STANDARDS)
    if "ios" in target_types:
        required.update(IOS_STANDARDS)
    if target_types & {"web", "api"}:
        required.update(WEB_STANDARDS)
    if "ai-enabled" in target_types:
        required.update(AI_STANDARDS)
    return required


def _canonical_requirement_policy(source_id: str, requirement: str) -> tuple[str, str] | None:
    if source_id == "AI-AUDIT" and requirement in AUDIT_CONTROL_IDS:
        return "true", "critical" if requirement in AUDIT_CRITICAL_IDS else "important"
    if source_id == "ISO-IEC-25010" and requirement in ISO_25010_CHARACTERISTICS:
        return ("false", "critical") if requirement == "safety" else ("true", "important")
    if source_id == "NIST-SP-800-218" and requirement in NIST_SSDF_TASK_IDS:
        return "true", "important"
    if source_id == "OWASP-MASVS" and requirement in MASVS_CONTROL_IDS:
        return "true", "important"
    if requirement in IOS_SOURCE_REQUIREMENTS.get(source_id, set()):
        return "true", "important"
    return None


def _read_matrix(path: Path, audit_root: Path) -> tuple[list[dict[str, str]], list[str]]:
    try:
        handle = path.open("r", encoding="utf-8", newline="")
    except OSError as error:
        return [], [f"invalid requirements matrix: {error}"]
    errors: list[str] = []
    rows: list[dict[str, str]] = []
    try:
        with handle:
            reader = csv.DictReader(handle)
            headers = tuple(reader.fieldnames or ())
            missing = [column for column in MATRIX_COLUMNS if column not in headers]
            extra = [column for column in headers if column not in MATRIX_COLUMNS]
            if missing or extra:
                if missing:
                    errors.append("requirements matrix missing columns: " + ", ".join(missing))
                if extra:
                    errors.append("requirements matrix unexpected columns: " + ", ".join(extra))
                return [], errors
            for number, raw_row in enumerate(reader, start=2):
                if None in raw_row:
                    errors.append(f"requirements matrix malformed row {number}: extra cells")
                row: dict[str, str] = {}
                for key in MATRIX_COLUMNS:
                    value = raw_row.get(key)
                    if value is not None and not isinstance(value, str):
                        errors.append(f"requirements matrix malformed row {number}: invalid cell")
                        value = ""
                    row[key] = (value or "").strip()
                rows.append(row)
    except (UnicodeError, csv.Error) as error:
        return [], [f"invalid requirements matrix: {error}"]

    if not rows:
        errors.append("requirements matrix has no requirement rows")
    seen: set[str] = set()
    seen_source_requirements: dict[tuple[str, str, str], str] = {}
    evidence_by_path: dict[str, str] = {}
    evidence_by_id: dict[str, str] = {}
    evidence_by_hash: dict[str, str] = {}
    audit_root = audit_root.resolve()
    for number, row in enumerate(rows, start=2):
        row_label = f"requirements matrix row {number}"
        for column, value in row.items():
            if value.lstrip().startswith(("=", "+", "-", "@")):
                errors.append(f"{row_label} contains spreadsheet formula in {column}")
        requirement_id = row["requirement_id"]
        if not IDENTIFIER_PATTERN.fullmatch(requirement_id):
            errors.append(f"{row_label} has invalid requirement_id")
        if requirement_id in seen:
            errors.append(f"duplicate requirement_id: {requirement_id}")
        seen.add(requirement_id)
        if not IDENTIFIER_PATTERN.fullmatch(row["source_id"]):
            errors.append(f"{row_label} has invalid source_id")
        if not row["source_version"] or not row["source_requirement"]:
            errors.append(f"{row_label} requires source version and requirement")
        elif not SOURCE_REQUIREMENT_PATTERN.fullmatch(row["source_requirement"]):
            errors.append(f"{row_label} has invalid source_requirement")
        source_requirement_key = (
            row["source_id"], row["source_version"], row["source_requirement"]
        )
        previous_requirement_id = seen_source_requirements.get(source_requirement_key)
        if previous_requirement_id is not None:
            errors.append(
                f"{row_label} duplicate source_requirement already mapped by "
                f"{previous_requirement_id}: {row['source_id']} "
                f"{row['source_version']} {row['source_requirement']}"
            )
        else:
            seen_source_requirements[source_requirement_key] = requirement_id
        if row["applicability"] not in APPLICABILITY_VALUES:
            errors.append(f"{row_label} has invalid applicability")
        if row["mandatory"] not in {"true", "false"}:
            errors.append(f"{row_label} mandatory must be true or false")
        if row["severity"] not in SEVERITY_VALUES:
            errors.append(f"{row_label} has invalid severity")
        policy = _canonical_requirement_policy(row["source_id"], row["source_requirement"])
        if policy is not None and (row["mandatory"], row["severity"]) != policy:
            errors.append(
                f"{row_label} changes canonical mandatory/severity policy for "
                f"{row['source_id']} {row['source_requirement']}"
            )
        if row["result"] not in RESULT_VALUES:
            errors.append(f"{row_label} has invalid result")
        if not row["test_method"] or not row["owner"]:
            errors.append(f"{row_label} requires test_method and owner")
        if row["applicability"] == "applicable" and row["result"] == "not-applicable":
            errors.append(f"{row_label} applicable requirement cannot be not-applicable")
        if row["applicability"] == "not-applicable" and row["result"] != "not-applicable":
            errors.append(f"{row_label} non-applicable requirement must use not-applicable result")
        if row["applicability"] == "not-applicable":
            approver = row["applicability_approver"]
            if not approver:
                errors.append(f"{row_label} non-applicable requirement requires an approver")
            if row["mandatory"] == "true" or row["severity"] == "critical":
                if approver == row["owner"]:
                    errors.append(
                        f"{row_label} mandatory/critical non-applicable approval must be independent of owner"
                    )
        if row["applicability"] == "undetermined" and row["result"] != "not-tested":
            errors.append(f"{row_label} undetermined requirement must use not-tested result")
        if row["result"] in {"conditional", "fail", "not-tested", "not-applicable"} and not row[
            "limitation"
        ]:
            errors.append(f"{row_label} requires a limitation or rationale")
        references = list(filter(None, (item.strip() for item in row["evidence"].split(";"))))
        evidence_ids = list(filter(None, (item.strip() for item in row["evidence_id"].split(";"))))
        evidence_hashes = list(
            filter(None, (item.strip() for item in row["evidence_sha256"].split(";")))
        )
        if len(references) != len(set(references)):
            errors.append(f"{row_label} has duplicate evidence reference")
        if len(evidence_ids) != len(set(evidence_ids)):
            errors.append(f"{row_label} has duplicate evidence_id")
        if len(evidence_hashes) != len(set(evidence_hashes)):
            errors.append(f"{row_label} has duplicate evidence_sha256")
        if row["result"] in {"pass", "conditional", "fail"}:
            for field in ("expected_result", "actual_result", "evidence_id", "evidence", "evidence_sha256"):
                if not row[field]:
                    errors.append(f"{row_label} result {row['result']} requires {field}")
            if len(references) != len(evidence_ids) or len(references) != len(evidence_hashes):
                errors.append(f"{row_label} evidence paths, IDs, and hashes must have equal counts")
        for evidence_id in evidence_ids:
            if not IDENTIFIER_PATTERN.fullmatch(evidence_id):
                errors.append(f"{row_label} has invalid evidence_id: {evidence_id}")
        for index, reference in enumerate(references):
            relative = Path(reference.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                errors.append(f"{row_label} has unsafe evidence path: {reference}")
                continue
            candidate = audit_root / relative
            try:
                candidate.resolve().relative_to(audit_root)
            except ValueError:
                errors.append(f"{row_label} has unsafe evidence path: {reference}")
                continue
            current = audit_root
            unsafe_link = False
            for part in relative.parts:
                current = current / part
                if current.is_symlink():
                    unsafe_link = True
                    break
            if unsafe_link:
                errors.append(f"{row_label} evidence path contains symlink: {reference}")
            elif not candidate.is_file():
                errors.append(f"{row_label} missing evidence: {reference}")
            elif candidate.stat().st_size == 0:
                errors.append(f"{row_label} evidence is empty: {reference}")
            elif index < len(evidence_hashes):
                expected_hash = evidence_hashes[index]
                if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_hash):
                    errors.append(f"{row_label} has invalid evidence_sha256: {expected_hash}")
                elif _sha256(candidate) != expected_hash:
                    errors.append(f"{row_label} evidence hash mismatch: {reference}")
                if index < len(evidence_ids):
                    evidence_id = evidence_ids[index]
                    normalized_reference = relative.as_posix()
                    previous_path_requirement = evidence_by_path.get(normalized_reference)
                    if previous_path_requirement is not None and previous_path_requirement != requirement_id:
                        errors.append(
                            f"{row_label} evidence path reused across requirement rows: {reference}"
                        )
                    evidence_by_path[normalized_reference] = requirement_id
                    previous_id_requirement = evidence_by_id.get(evidence_id)
                    if previous_id_requirement is not None and previous_id_requirement != requirement_id:
                        errors.append(
                            f"{row_label} evidence_id reused across requirement rows: {evidence_id}"
                        )
                    evidence_by_id[evidence_id] = requirement_id
                    previous_hash_requirement = evidence_by_hash.get(expected_hash)
                    if previous_hash_requirement is not None and previous_hash_requirement != requirement_id:
                        errors.append(
                            f"{row_label} evidence hash reused across requirement rows: {expected_hash}"
                        )
                    evidence_by_hash[expected_hash] = requirement_id
    return rows, errors


def _validate_sector_gate(
    gate: object,
    audit_root: Path,
    declared_conclusion: object,
) -> list[str]:
    if not isinstance(gate, dict):
        return ["safety/OT/regulated targets require a sector_gate object"]
    errors: list[str] = []
    status = gate.get("status")
    if status not in {"blocked", "complete"}:
        return ["sector_gate.status must be blocked or complete"]
    if status == "blocked":
        reasons = gate.get("blocking_reasons")
        if not isinstance(reasons, list) or not reasons or not all(
            isinstance(reason, str) and reason.strip() for reason in reasons
        ):
            errors.append("blocked sector_gate requires non-empty blocking_reasons")
        if declared_conclusion != "not-acceptable":
            errors.append("blocked sector_gate requires technical_conclusion=not-acceptable")
        return errors

    audit_root = audit_root.resolve()
    references_seen: list[str] = []
    evidence_hashes = gate.get("evidence_sha256")
    if not isinstance(evidence_hashes, dict):
        evidence_hashes = {}
        errors.append("complete sector_gate requires evidence_sha256 object")
    for field in SECTOR_GATE_EVIDENCE_FIELDS:
        reference = gate.get(field)
        if not isinstance(reference, str) or not reference.strip():
            errors.append(f"complete sector_gate requires {field}")
            continue
        relative = Path(reference.replace("\\", "/"))
        references_seen.append(relative.as_posix())
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"sector_gate has unsafe evidence path in {field}: {reference}")
            continue
        candidate = audit_root / relative
        try:
            candidate.resolve().relative_to(audit_root)
        except ValueError:
            errors.append(f"sector_gate has unsafe evidence path in {field}: {reference}")
            continue
        current = audit_root
        unsafe_link = False
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                unsafe_link = True
                break
        if unsafe_link:
            errors.append(f"sector_gate evidence path contains symlink in {field}: {reference}")
        elif not candidate.is_file():
            errors.append(f"sector_gate missing evidence in {field}: {reference}")
        elif candidate.stat().st_size == 0:
            errors.append(f"sector_gate evidence is empty in {field}: {reference}")
        else:
            expected_hash = evidence_hashes.get(field)
            if not isinstance(expected_hash, str) or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", expected_hash
            ):
                errors.append(f"sector_gate requires valid evidence_sha256 for {field}")
            elif _sha256(candidate) != expected_hash:
                errors.append(f"sector_gate evidence hash mismatch in {field}: {reference}")
    approver = gate.get("responsible_approver")
    if not isinstance(approver, str) or not approver.strip():
        errors.append("complete sector_gate requires responsible_approver")
    if len(set(references_seen)) != len(references_seen):
        errors.append("complete sector_gate requires distinct evidence files for each lifecycle gate")
    for field in ("supplier_organization", "independent_reviewer", "reviewer_organization"):
        value = gate.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"complete sector_gate requires {field}")
    supplier = gate.get("supplier_organization")
    reviewer_org = gate.get("reviewer_organization")
    if isinstance(supplier, str) and isinstance(reviewer_org, str) and supplier == reviewer_org:
        errors.append("sector_gate reviewer_organization must differ from supplier_organization")
    return errors


def _validate_report_release_gate(gate: object, audit_root: Path) -> list[str]:
    """Require an explicit human semantic-review state before external release."""
    if not isinstance(gate, dict):
        return ["quality profile requires a report_release_gate object"]
    errors: list[str] = []
    status = gate.get("status")
    if status not in {"draft", "approved"}:
        errors.append("report_release_gate.status must be draft or approved")
    if gate.get("semantic_review_required") is not True:
        errors.append("report_release_gate.semantic_review_required must be true")
    if status != "approved":
        return errors

    for field in (
        "reviewer_identity", "reviewer_name", "reviewer_role", "reviewer_organization",
        "approved_at", "approval_record", "approval_record_sha256",
        "approval_signature", "report_sha256",
    ):
        if not isinstance(gate.get(field), str) or not gate[field].strip():
            errors.append(f"approved report_release_gate requires {field}")
    approved_at = gate.get("approved_at")
    if isinstance(approved_at, str):
        try:
            datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append("report_release_gate.approved_at must be an ISO-8601 timestamp")
    for field in ("approval_record_sha256", "report_sha256"):
        value = gate.get(field)
        if isinstance(value, str) and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            errors.append(f"report_release_gate.{field} must be a SHA-256 digest")
    root = audit_root.resolve()
    for field in ("approval_record", "approval_signature"):
        reference = gate.get(field)
        if not isinstance(reference, str) or not reference.strip():
            continue
        relative = Path(reference.replace("\\", "/"))
        candidate = root / relative
        if relative.is_absolute() or ".." in relative.parts:
            errors.append(f"report_release_gate has unsafe {field} path")
            continue
        try:
            candidate.resolve().relative_to(root)
        except ValueError:
            errors.append(f"report_release_gate {field} escapes audit root")
            continue
        current = root
        if any((current := current / part).is_symlink() for part in relative.parts):
            errors.append(f"report_release_gate {field} path contains symlink")
        elif not candidate.is_file() or candidate.stat().st_size == 0:
            errors.append(f"report_release_gate {field} is missing or empty")
        elif field == "approval_record":
            expected_hash = gate.get("approval_record_sha256")
            if isinstance(expected_hash, str) and re.fullmatch(
                r"sha256:[0-9a-f]{64}", expected_hash
            ) and _sha256(candidate) != expected_hash:
                errors.append("report_release_gate approval_record hash mismatch")
    return errors


def validate_external_release(
    profile_path: Path | str,
    matrix_path: Path | str,
    report_path: Path | str,
    audit_root: Path | str,
    target_root: Path | str,
    seal_path: Path | str,
    allowed_signers_path: Path | str,
) -> list[str]:
    """Verify the complete package and a detached customer-trusted release signature."""
    profile_path = Path(profile_path)
    report_path = Path(report_path)
    matrix_path = Path(matrix_path)
    audit_root = Path(audit_root).resolve()
    target_root = Path(target_root)
    seal_path = Path(seal_path)
    allowed_signers_path = Path(allowed_signers_path)
    canonical_release_paths = {
        "quality profile": (profile_path, audit_root / "quality-profile.json"),
        "requirements matrix": (matrix_path, audit_root / "requirements-matrix.csv"),
        "audit report": (report_path, audit_root / "audit-report.md"),
        "source seal": (seal_path, audit_root / "seal.json"),
    }
    path_errors: list[str] = []
    for label, (actual_path, canonical_path) in canonical_release_paths.items():
        if actual_path.resolve() != canonical_path.resolve() or actual_path.is_symlink():
            path_errors.append(
                f"external release {label} must use the canonical non-symlink path inside audit_root"
            )
    if path_errors:
        return path_errors
    errors = validate_quality_package(profile_path, matrix_path, audit_root)
    errors.extend(validate_report_consistency(profile_path, report_path))
    errors.extend(scan_artifacts(audit_root))
    errors.extend(verify_seal(target_root, seal_path))
    profile, profile_errors = _load_profile(profile_path)
    errors.extend(profile_errors)
    if profile is None:
        return errors
    gate = profile.get("report_release_gate")
    if not isinstance(gate, dict) or gate.get("status") != "approved":
        errors.append("external release requires report_release_gate.status=approved")
        return errors
    try:
        allowed_signers_path.resolve().relative_to(audit_root)
    except ValueError:
        pass
    else:
        errors.append("allowed signers must be customer-controlled and outside the audit bundle")
    if not allowed_signers_path.is_file() or allowed_signers_path.is_symlink():
        errors.append("customer-controlled allowed signers file is missing or unsafe")
    record_reference = gate.get("approval_record")
    signature_reference = gate.get("approval_signature")
    if not isinstance(record_reference, str) or not isinstance(signature_reference, str):
        return errors
    record_path = audit_root / Path(record_reference.replace("\\", "/"))
    signature_path = audit_root / Path(signature_reference.replace("\\", "/"))
    if not record_path.is_file() or not signature_path.is_file():
        return errors
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        errors.append(f"invalid signed approval record: {error}")
        return errors
    if not isinstance(record, dict):
        errors.append("signed approval record root must be an object")
        return errors
    for required_name in ("audit-workpaper.md", "unverified-ledger.md"):
        if not (audit_root / required_name).is_file():
            errors.append(f"external release is missing required artifact: {required_name}")
    manifest_exclusions: set[str] = {
        Path(record_reference.replace("\\", "/")).as_posix(),
        Path(signature_reference.replace("\\", "/")).as_posix(),
    }
    try:
        manifest_exclusions.add(profile_path.resolve().relative_to(audit_root).as_posix())
    except ValueError:
        errors.append("quality profile must be inside the audit bundle for external release")
    artifact_manifest: dict[str, str] = {}
    for candidate in sorted(audit_root.rglob("*")):
        if candidate.is_symlink():
            errors.append(
                "external release audit bundle contains symlink: "
                f"{candidate.relative_to(audit_root).as_posix()}"
            )
            continue
        if not candidate.is_file():
            continue
        relative_name = candidate.relative_to(audit_root).as_posix()
        if relative_name not in manifest_exclusions:
            artifact_manifest[relative_name] = _sha256(candidate)
    artifact_manifest_bytes = json.dumps(
        artifact_manifest, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    unsigned_profile = dict(profile)
    unsigned_profile.pop("report_release_gate", None)
    profile_payload = json.dumps(
        unsigned_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    expected_record = {
        "schema_version": 1,
        "decision": "external-release-approved",
        "system_name": profile.get("system_name"),
        "quality_profile_version": profile.get("quality_profile_version"),
        "technical_conclusion": profile.get("technical_conclusion"),
        "audit_artifact_manifest_sha256": (
            f"sha256:{hashlib.sha256(artifact_manifest_bytes).hexdigest()}"
        ),
        "profile_payload_sha256": f"sha256:{hashlib.sha256(profile_payload).hexdigest()}",
        "requirements_matrix_sha256": _sha256(matrix_path) if matrix_path.is_file() else None,
        "report_sha256": gate.get("report_sha256"),
        "source_seal_sha256": _sha256(seal_path) if seal_path.is_file() else None,
        "reviewer_identity": gate.get("reviewer_identity"),
        "reviewer_name": gate.get("reviewer_name"),
        "reviewer_role": gate.get("reviewer_role"),
        "reviewer_organization": gate.get("reviewer_organization"),
        "approved_at": gate.get("approved_at"),
    }
    if record != expected_record:
        errors.append("signed approval record does not exactly match the release profile")
    identity = gate.get("reviewer_identity")
    if not isinstance(identity, str) or not identity.strip() or errors:
        return errors
    try:
        completed = subprocess.run(
            [
                "ssh-keygen", "-Y", "verify", "-f", str(allowed_signers_path),
                "-I", identity, "-n", "ai-audit-release", "-s", str(signature_path),
            ],
            input=record_path.read_bytes(),
            capture_output=True,
            check=False,
        )
    except OSError as error:
        errors.append(f"release signature verification unavailable: {error}")
        return errors
    if completed.returncode != 0:
        errors.append("release signature verification failed")
    return errors


def validate_quality_package(
    profile_path: Path | str,
    matrix_path: Path | str,
    audit_root: Path | str,
) -> list[str]:
    """Validate a machine-readable profile, coverage claims, evidence, and conclusion."""
    profile_path = Path(profile_path)
    matrix_path = Path(matrix_path)
    audit_root = Path(audit_root)
    profile, errors = _load_profile(profile_path)
    rows, matrix_errors = _read_matrix(matrix_path, audit_root)
    errors.extend(matrix_errors)
    if profile is None:
        return errors

    if profile.get("schema_version") != QUALITY_PROFILE_SCHEMA_VERSION:
        errors.append(f"quality profile schema_version must be {QUALITY_PROFILE_SCHEMA_VERSION}")
    if profile.get("quality_profile_version") != QUALITY_PROFILE_VERSION:
        errors.append(f"quality_profile_version must be {QUALITY_PROFILE_VERSION}")
    if not isinstance(profile.get("system_name"), str) or not profile["system_name"].strip():
        errors.append("quality profile system_name is required")
    target_values = profile.get("target_types")
    if not isinstance(target_values, list) or not target_values:
        errors.append("quality profile target_types must be a non-empty array")
        target_types: set[str] = set()
    else:
        target_types = {value for value in target_values if isinstance(value, str)}
        unknown_targets = target_types - TARGET_TYPES
        if len(target_types) != len(target_values) or unknown_targets:
            errors.append("quality profile has invalid target_types")
    if profile.get("assurance_model") != "limited-scope-technical-verification":
        errors.append("assurance_model must be limited-scope-technical-verification")
    if profile.get("certification_claimed") is not False:
        errors.append("certification_claimed must be false for an ai-audit package")
    if profile.get("third_party_audit_claimed") is not False:
        errors.append("third_party_audit_claimed must be false for an ai-audit package")
    errors.extend(_validate_report_release_gate(profile.get("report_release_gate"), audit_root))

    standards = profile.get("standards")
    if not isinstance(standards, list):
        standards = []
        errors.append("quality profile standards must be an array")
    source_entries: dict[tuple[str, str], dict[str, object]] = {}
    source_ids: dict[str, set[str]] = {}
    for index, entry in enumerate(standards):
        errors.extend(_validate_source_entry(entry, f"standards[{index}]"))
        if not isinstance(entry, dict):
            continue
        source_id = entry.get("source_id")
        version = entry.get("version")
        if isinstance(source_id, str) and isinstance(version, str):
            key = (source_id, version)
            if key in source_entries:
                errors.append(f"duplicate standard entry: {source_id} {version}")
            source_entries[key] = entry
            source_ids.setdefault(source_id, set()).add(version)

    for source_id, required_version in _required_standards(target_types).items():
        versions = source_ids.get(source_id, set())
        if not versions:
            errors.append(f"required standard missing: {source_id} {required_version}")
        elif required_version not in versions:
            errors.append(
                f"required standard version mismatch: {source_id} requires {required_version}"
            )

    overlays = profile.get("sector_overlays")
    if not isinstance(overlays, list):
        overlays = []
        errors.append("sector_overlays must be an array")
    for index, entry in enumerate(overlays):
        errors.extend(_validate_source_entry(entry, f"sector_overlays[{index}]"))
        if not isinstance(entry, dict):
            continue
        source_id = entry.get("source_id")
        version = entry.get("version")
        if isinstance(source_id, str) and isinstance(version, str):
            key = (source_id, version)
            if key in source_entries:
                errors.append(f"duplicate source entry: {source_id} {version}")
            source_entries[key] = entry
    if target_types & {"safety-related", "ot", "regulated"}:
        if not overlays:
            errors.append("safety/OT/regulated targets require sector_overlays")
        if profile.get("specialist_review_required") is not True:
            errors.append("safety/OT/regulated targets require specialist_review_required=true")
        errors.extend(
            _validate_sector_gate(
                profile.get("sector_gate"), audit_root, profile.get("technical_conclusion")
            )
        )
    elif profile.get("specialist_review_required") not in {True, False}:
        errors.append("specialist_review_required must be boolean")

    rows_by_source: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in rows:
        key = (row["source_id"], row["source_version"])
        rows_by_source.setdefault(key, []).append(row)
        if key not in source_entries:
            errors.append(f"requirement row uses undeclared source: {key[0]} {key[1]}")

    required_mapped_sources = {"AI-AUDIT", "ISO-IEC-25010", "NIST-SP-800-218"}
    if target_types & {"ios", "android"}:
        required_mapped_sources.update(MOBILE_STANDARDS)
    if "ios" in target_types:
        required_mapped_sources.update(IOS_STANDARDS)
    if target_types & {"web", "api"}:
        required_mapped_sources.add("OWASP-ASVS")
    if "ai-enabled" in target_types:
        required_mapped_sources.add("NIST-SP-800-218A")
    for source_id in sorted(required_mapped_sources):
        entries = [entry for (candidate, _), entry in source_entries.items() if candidate == source_id]
        if entries and any(entry.get("claim_level") == "referenced" for entry in entries):
            errors.append(f"required source must be mapped or verified: {source_id}")

    expected_inventories: dict[tuple[str, str], set[str]] = {
        ("AI-AUDIT", "1.2.0"): AUDIT_CONTROL_IDS,
        ("ISO-IEC-25010", "2023"): ISO_25010_CHARACTERISTICS,
        ("NIST-SP-800-218", "1.1"): NIST_SSDF_TASK_IDS,
    }
    if target_types & {"ios", "android"}:
        expected_inventories[("OWASP-MASVS", "2.1.0")] = MASVS_CONTROL_IDS
    if "ios" in target_types:
        for source_id, requirements in IOS_SOURCE_REQUIREMENTS.items():
            expected_inventories[(source_id, "current")] = requirements
    for key, expected_requirements in expected_inventories.items():
        actual_requirements = {
            row["source_requirement"] for row in rows_by_source.get(key, [])
        }
        missing_requirements = expected_requirements - actual_requirements
        unexpected_requirements = actual_requirements - expected_requirements
        if missing_requirements:
            errors.append(
                f"requirement inventory incomplete for {key[0]} {key[1]}: missing "
                + ", ".join(sorted(missing_requirements))
            )
        if unexpected_requirements:
            errors.append(
                f"requirement inventory has unknown IDs for {key[0]} {key[1]}: "
                + ", ".join(sorted(unexpected_requirements))
            )

    if target_types & {"safety-related", "ot", "regulated"}:
        overlay_keys = {
            (entry.get("source_id"), entry.get("version"))
            for entry in overlays
            if isinstance(entry, dict)
        }
        for key in overlay_keys:
            entry = source_entries.get(key)
            if entry is not None and entry.get("claim_level") == "referenced":
                errors.append(f"safety sector overlay must be mapped or verified: {key[0]} {key[1]}")
            catalog = entry.get("requirement_catalog") if entry is not None else None
            if not isinstance(catalog, list) or not catalog or not all(
                isinstance(value, str) and SOURCE_REQUIREMENT_PATTERN.fullmatch(value)
                for value in catalog
            ):
                errors.append(f"safety sector overlay requires a requirement_catalog: {key[0]} {key[1]}")
                expected_overlay_requirements: set[str] = set()
            else:
                expected_overlay_requirements = set(catalog)
                if len(expected_overlay_requirements) != len(catalog):
                    errors.append(f"safety sector overlay has duplicate requirement_catalog IDs: {key[0]} {key[1]}")
            if entry is not None:
                for field in ("catalog_approver", "catalog_evidence", "catalog_evidence_sha256"):
                    if not isinstance(entry.get(field), str) or not entry[field].strip():
                        errors.append(f"safety sector overlay requires {field}: {key[0]} {key[1]}")
                catalog_reference = entry.get("catalog_evidence")
                catalog_hash = entry.get("catalog_evidence_sha256")
                if isinstance(catalog_reference, str) and catalog_reference.strip():
                    relative = Path(catalog_reference.replace("\\", "/"))
                    candidate = audit_root.resolve() / relative
                    if relative.is_absolute() or ".." in relative.parts:
                        errors.append(f"safety sector overlay has unsafe catalog evidence path: {catalog_reference}")
                        continue
                    else:
                        try:
                            candidate.resolve().relative_to(audit_root.resolve())
                        except ValueError:
                            errors.append(
                                "safety sector overlay catalog evidence escapes audit root: "
                                f"{catalog_reference}"
                            )
                            continue
                    if not candidate.is_file() or candidate.stat().st_size == 0:
                        errors.append(f"safety sector overlay catalog evidence is missing or empty: {catalog_reference}")
                    elif not isinstance(catalog_hash, str) or not re.fullmatch(
                        r"sha256:[0-9a-f]{64}", catalog_hash
                    ):
                        errors.append(f"safety sector overlay has invalid catalog_evidence_sha256: {key[0]} {key[1]}")
                    elif _sha256(candidate) != catalog_hash:
                        errors.append(f"safety sector overlay catalog evidence hash mismatch: {catalog_reference}")
            actual_overlay_requirements = {
                row["source_requirement"] for row in rows_by_source.get(key, [])
            }
            if expected_overlay_requirements and actual_overlay_requirements != expected_overlay_requirements:
                errors.append(f"safety sector overlay matrix does not match requirement_catalog: {key[0]} {key[1]}")
            for row in rows_by_source.get(key, []):
                for field in (
                    "hazard_id", "design_item_id", "test_id", "evidence_id",
                    "deviation_id", "residual_risk_id", "stage_approval_id",
                ):
                    if not row[field]:
                        errors.append(
                            f"safety requirement {row['requirement_id']} requires {field}"
                        )
    for key, entry in source_entries.items():
        claim_level = entry.get("claim_level")
        matching = rows_by_source.get(key, [])
        if claim_level in {"mapped", "verified"} and not matching:
            errors.append(f"{claim_level} standard has no requirement rows: {key[0]} {key[1]}")
        if claim_level == "verified" and any(
            row["applicability"] == "undetermined"
            or (row["applicability"] == "applicable" and row["result"] == "not-tested")
            for row in matching
        ):
            errors.append(f"verified standard contains untested requirements: {key[0]} {key[1]}")
        if claim_level == "verified" and key not in expected_inventories:
            errors.append(
                f"verified claim is unsupported without a canonical inventory: {key[0]} {key[1]}"
            )

    conclusion = derive_technical_conclusion(rows)
    if target_types & {"safety-related", "ot", "regulated"}:
        sector_gate = profile.get("sector_gate")
        if isinstance(sector_gate, dict) and sector_gate.get("status") == "blocked":
            conclusion = "not-acceptable"
        elif conclusion == "acceptable-within-scope":
            conclusion = "conditional"
    if profile.get("technical_conclusion") != conclusion:
        errors.append(
            "technical_conclusion mismatch: "
            f"declared {profile.get('technical_conclusion')}, calculated {conclusion}"
        )
    return errors


def validate_report_consistency(
    profile_path: Path | str,
    report_path: Path | str,
) -> list[str]:
    """Reject stronger report claims than the machine-readable profile permits."""
    profile_path = Path(profile_path)
    profile, errors = _load_profile(profile_path)
    try:
        report = Path(report_path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return errors + [f"invalid audit report: {error}"]
    if profile is None:
        return errors
    errors.extend(
        _validate_report_release_gate(profile.get("report_release_gate"), profile_path.parent)
    )
    conclusion_matches = re.findall(
        r"^\*\*技術評価結論:(acceptable-within-scope|conditional|not-acceptable)\*\*$",
        report,
        flags=re.MULTILINE,
    )
    if conclusion_matches != [profile.get("technical_conclusion")]:
        errors.append("audit report technical conclusion does not exactly match quality profile")
    release_gate = profile.get("report_release_gate")
    draft_marker = "**外部提出:不可（人間による意味レビュー未承認）**"
    approved_marker = "**外部提出:承認済み**"
    if report.count(draft_marker) + report.count(approved_marker) != 1:
        errors.append("audit report must contain exactly one external release marker")
    if isinstance(release_gate, dict) and release_gate.get("status") == "draft":
        if draft_marker not in report:
            errors.append("draft audit report must state that human semantic review is unapproved")
    elif isinstance(release_gate, dict) and release_gate.get("status") == "approved":
        if approved_marker not in report:
            errors.append("approved audit report must include the external release marker")
        expected_report_hash = release_gate.get("report_sha256")
        if isinstance(expected_report_hash, str) and _sha256(Path(report_path)) != expected_report_hash:
            errors.append("approved audit report hash does not match human semantic review")
    for marker in ("限定範囲の技術的検証", "quality-profile.json", "requirements-matrix.csv"):
        if marker not in report:
            errors.append(f"audit report missing required scope marker: {marker}")
    for phrase in ("ISO準拠", "第三者監査済み", "全項目合格", "安全保証", "認証済み", "稼働可"):
        if phrase in report:
            errors.append(f"audit report contains prohibited assurance claim: {phrase}")
    for pattern in (
        r"(?:ISO|IEC|ASVS|MASVS).{0,20}(?:準拠|認証|適合|合格|クリア)(?![^\n]*(?:ではない|を意味しない|しない))",
        r"(?:第三者|独立|外部).{0,12}(?:監査|保証|V&V).{0,8}(?:済み|完了|合格|クリア)",
        r"(?:認証|保証).{0,6}(?:済み|完了|取得)",
        r"全(?:項目|要求|統制).{0,8}(?:合格|適合|pass|クリア)",
        r"(?:適合性?(?:を)?(?:確認|評価)?済み?).{0,16}(?:ISO|IEC|ASVS|MASVS)",
        r"監査法人.{0,16}監査.{0,12}(?:実施|終了|完了)",
        r"全ての(?:項目|要求|統制).{0,16}(?:満た|充足)",
        r"本番(?:利用|稼働|運用).{0,12}(?:承認|許可)",
        r"\b(?:ISO|IEC|ASVS|MASVS).{0,32}\b(?:compliant|conformant|certified|passed)\b",
        r"\bcertification.{0,16}\bgranted\b",
        r"\bmeets\s+(?:ISO|IEC|ASVS|MASVS).{0,32}\brequirements\b",
        r"\bindependently\s+audited\b",
        r"\ball\s+(?:items|requirements|controls).{0,16}\b(?:satisfied|met)\b",
        r"\bapproved\s+for\s+(?:production|operation|deployment)\b",
        r"\b(?:third[- ]party|external|independent).{0,24}\b(?:audit|assurance).{0,16}\b(?:complete|completed|passed|certified)\b",
        r"\ball\s+(?:items|requirements|controls).{0,16}\b(?:passed|compliant|cleared)\b",
    ):
        if re.search(pattern, report, flags=re.IGNORECASE):
            errors.append(f"audit report contains prohibited assurance pattern: {pattern}")
    declared_entries: list[object] = []
    for field in ("standards", "sector_overlays"):
        value = profile.get(field)
        if isinstance(value, list):
            declared_entries.extend(value)
    for entry in declared_entries:
        if not isinstance(entry, dict):
            continue
        source_id = entry.get("source_id")
        version = entry.get("version")
        if isinstance(source_id, str) and source_id not in report:
            errors.append(f"audit report omits declared source: {source_id}")
        if isinstance(version, str) and version not in report:
            errors.append(f"audit report omits declared source version: {source_id} {version}")
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
    quality = subparsers.add_parser(
        "validate-quality", help="validate quality-profile.json and requirements-matrix.csv"
    )
    quality.add_argument("profile", type=Path)
    quality.add_argument("matrix", type=Path)
    quality.add_argument("audit_root", type=Path)
    report = subparsers.add_parser(
        "validate-report", help="validate report claims against quality-profile.json"
    )
    report.add_argument("profile", type=Path)
    report.add_argument("report", type=Path)
    release = subparsers.add_parser(
        "validate-release", help="validate a customer-signed external release package"
    )
    release.add_argument("profile", type=Path)
    release.add_argument("matrix", type=Path)
    release.add_argument("report", type=Path)
    release.add_argument("audit_root", type=Path)
    release.add_argument("target_root", type=Path)
    release.add_argument("seal", type=Path)
    release.add_argument("allowed_signers", type=Path)
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
    elif args.command == "validate-quality":
        errors = validate_quality_package(args.profile, args.matrix, args.audit_root)
    elif args.command == "validate-report":
        errors = validate_report_consistency(args.profile, args.report)
    elif args.command == "validate-release":
        errors = validate_external_release(
            args.profile, args.matrix, args.report, args.audit_root,
            args.target_root, args.seal, args.allowed_signers
        )
    else:
        errors = validate_bundle(args.root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
