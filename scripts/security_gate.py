#!/usr/bin/env python3
"""Repository entrypoint for the ai-audit bundled security gates."""

from __future__ import annotations

import importlib.util
from pathlib import Path


GATE_PATH = (
    Path(__file__).resolve().parents[1]
    / "skills"
    / "ai-audit"
    / "scripts"
    / "security_gate.py"
)
SPEC = importlib.util.spec_from_file_location("_bundled_security_gate", GATE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load bundled security gate: {GATE_PATH}")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

build_prompt_bundle = MODULE.build_prompt_bundle
gate_commit = MODULE.gate_commit
redact_pii = MODULE.redact_pii
scan_deps = MODULE.scan_deps
gen_sbom = MODULE.gen_sbom
parse_osv_results = MODULE.parse_osv_results
main = MODULE.main


if __name__ == "__main__":
    raise SystemExit(main())
