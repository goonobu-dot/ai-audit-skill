#!/usr/bin/env python3
"""Repository entrypoint for the ai-audit bundled guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path


GUARD_PATH = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "ai-audit"
    / "scripts"
    / "audit_guard.py"
)
SPEC = importlib.util.spec_from_file_location("_bundled_audit_guard", GUARD_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load bundled audit guard: {GUARD_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

redact_text = MODULE.redact_text
create_seal = MODULE.create_seal
verify_seal = MODULE.verify_seal
validate_bundle = MODULE.validate_bundle
validate_quality_package = MODULE.validate_quality_package
validate_report_consistency = MODULE.validate_report_consistency
validate_external_release = MODULE.validate_external_release
derive_technical_conclusion = MODULE.derive_technical_conclusion
scan_artifacts = MODULE.scan_artifacts
main = MODULE.main


if __name__ == "__main__":
    raise SystemExit(main())
