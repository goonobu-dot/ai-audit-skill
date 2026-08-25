"""Regression tests for the fixes made after the 2026-08-25 3-AI council review.

Each test pins a defect that Codex and/or Grok reproduced, so the bypass cannot
silently return. Named by the finding it closes (C4/C5/C6/C7 + DLP/gate honesty).
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

_SCRIPTS = REPO_ROOT / "skills" / "ai-audit" / "scripts"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Load the real bundled modules directly so private helpers are reachable.
ag = _load("_real_audit_guard", "audit_guard.py")
sg = _load("_real_security_gate", "security_gate.py")


def _empty_manifest_sha() -> str:
    m = json.dumps({}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(m).hexdigest()


class C4BundleDeletionTests(unittest.TestCase):
    """C4: build-prompt-bundle must never rmtree an arbitrary existing directory."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_refuses_to_delete_non_bundle_directory(self):
        out = self.root / "precious"
        out.mkdir()
        (out / "keep.txt").write_text("do not delete me\n", encoding="utf-8")
        code, msgs = sg.build_prompt_bundle(self.repo, out)
        self.assertEqual(2, code)
        self.assertTrue((out / "keep.txt").is_file(), "existing user data must survive")
        self.assertTrue(any("not empty" in m for m in msgs))

    def test_refuses_nonempty_existing_dir_even_a_prior_bundle(self):
        # A forgeable marker must not authorise deletion (Grok re-audit 2026-08):
        # once --output is non-empty, a re-run is refused; use a new/empty path.
        out = self.root / "bundle"
        code, _ = sg.build_prompt_bundle(self.repo, out)
        self.assertEqual(0, code)
        self.assertTrue((out / sg.BUNDLE_MARKER).is_file())
        code, msgs = sg.build_prompt_bundle(self.repo, out)
        self.assertEqual(2, code)
        self.assertTrue(any("not empty" in m for m in msgs))
        # an empty pre-existing directory is fine
        empty = self.root / "empty_out"
        empty.mkdir()
        code, _ = sg.build_prompt_bundle(self.repo, empty)
        self.assertEqual(0, code)

    def test_forged_marker_does_not_enable_deletion(self):
        victim = self.root / "victim"
        victim.mkdir()
        (victim / "photo.jpg").write_text("keep\n", encoding="utf-8")
        (victim / sg.BUNDLE_MARKER).write_text("forged\n", encoding="utf-8")
        code, _ = sg.build_prompt_bundle(self.repo, victim)
        self.assertEqual(2, code)
        self.assertTrue((victim / "photo.jpg").is_file())

    def test_ledger_records_destination_model_and_no_abspath(self):
        out = self.root / "bundle"
        code, _ = sg.build_prompt_bundle(
            self.repo, out, destination="codex", model="gpt-5.6-sol"
        )
        self.assertEqual(0, code)
        ledger = json.loads((out / "transmission-ledger.json").read_text(encoding="utf-8"))
        self.assertEqual("codex", ledger["destination"])
        self.assertEqual("gpt-5.6-sol", ledger["model"])
        self.assertNotIn("source_repo", ledger)  # absolute terminal path must not leak
        self.assertEqual("repo", ledger["source_repo_name"])


class C5ScanDepsTests(unittest.TestCase):
    """C5: empty/failed scans are NOT-TESTED, and CVSS is scored (not string-matched)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_empty_results_file_is_not_tested(self):
        empty = self.root / "empty.json"
        empty.write_text("", encoding="utf-8")
        code, _ = sg.scan_deps(self.root, results_path=empty)
        self.assertEqual(3, code)

    def test_missing_results_key_is_not_tested(self):
        bad = self.root / "bad.json"
        bad.write_text("{}", encoding="utf-8")
        code, _ = sg.scan_deps(self.root, results_path=bad)
        self.assertEqual(3, code)

    def test_cvss_98_vector_is_critical_and_blocks(self):
        report = {
            "results": [{
                "source": {"path": "requirements.txt"},
                "packages": [{
                    "package": {"name": "evil", "version": "1.0"},
                    "vulnerabilities": [{
                        "id": "OSV-TEST-1",
                        "severity": [{"type": "CVSS_V3",
                                      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    }],
                }],
            }],
        }
        path = self.root / "r.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        findings = sg.parse_osv_results(report)
        self.assertEqual("CRITICAL", findings[0]["severity"])
        code, _ = sg.scan_deps(self.root, results_path=path)
        self.assertEqual(1, code)

    def test_unknown_severity_is_treated_as_blocking(self):
        report = {
            "results": [{
                "source": {"path": "requirements.txt"},
                "packages": [{
                    "package": {"name": "mystery", "version": "1.0"},
                    "vulnerabilities": [{"id": "OSV-TEST-2", "severity": []}],
                }],
            }],
        }
        path = self.root / "u.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        code, _ = sg.scan_deps(self.root, results_path=path)
        self.assertEqual(1, code)

    def test_cvss_v4_unparsable_does_not_downgrade_to_low(self):
        # CVSS_V4 is not graded here; it must become unknown (blocking), never fall
        # back to a lower database_specific label (Grok re-audit 2026-08).
        report = {
            "results": [{
                "source": {"path": "requirements.txt"},
                "packages": [{
                    "package": {"name": "evil4", "version": "1.0"},
                    "vulnerabilities": [{
                        "id": "OSV-V4",
                        "severity": [{"type": "CVSS_V4",
                                      "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
                        "database_specific": {"severity": "LOW"},
                    }],
                }],
            }],
        }
        path = self.root / "v4.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual("", sg.parse_osv_results(report)[0]["severity"])
        code, _ = sg.scan_deps(self.root, results_path=path)
        self.assertEqual(1, code)

    def test_unparsable_cvss_with_low_numeric_still_blocks(self):
        # compound severity: an ungradeable CVSS must not be masked by a low number
        report = {"results": [{"source": {"path": "r"}, "packages": [{
            "package": {"name": "x", "version": "1"}, "vulnerabilities": [{
                "id": "M", "severity": [
                    {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
                    {"type": "CVSS_V3", "score": "1.0"},
                ]}]}]}]}
        path = self.root / "cmp.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        self.assertEqual(1, sg.scan_deps(self.root, results_path=path)[0])

    def test_malformed_reports_are_not_tested(self):
        for label, payload in (
            ("null", "null"),
            ("list", "[{}]"),
            ("bad-result", '{"results":["bad"]}'),
            ("bad-package", '{"results":[{"packages":["x"]}]}'),
        ):
            path = self.root / f"{label}.json"
            path.write_text(payload, encoding="utf-8")
            code, _ = sg.scan_deps(self.root, results_path=path)
            self.assertEqual(3, code, f"{label} should be NOT-TESTED")

    def test_empty_results_array_is_clean(self):
        path = self.root / "clean.json"
        path.write_text('{"results":[]}', encoding="utf-8")
        self.assertEqual(0, sg.scan_deps(self.root, results_path=path)[0])

    def test_cvss_base_score_math(self):
        self.assertEqual(9.8, sg._cvss3_base_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertEqual(10.0, sg._cvss3_base_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"))
        self.assertEqual(0.0, sg._cvss3_base_from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"))
        self.assertIsNone(sg._cvss3_base_from_vector("not-a-vector"))


class GateCommitHonestyTests(unittest.TestCase):
    """Grok: without gitleaks, a clean result is NOT-TESTED, and strict fails closed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.repo, check=True)
        (self.repo / "a.txt").write_text("hello\n", encoding="utf-8")
        subprocess.run(["git", "add", "a.txt"], cwd=self.repo, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_strict_without_gitleaks_is_not_tested(self):
        with mock.patch.object(sg, "_gitleaks_available", return_value=False):
            code, msgs = sg.gate_commit(self.repo, strict=True)
        self.assertEqual(3, code)
        self.assertTrue(any("NOT-TESTED" in m for m in msgs))

    def test_nonstrict_without_gitleaks_does_not_claim_clean(self):
        with mock.patch.object(sg, "_gitleaks_available", return_value=False):
            code, msgs = sg.gate_commit(self.repo, strict=False)
        self.assertEqual(0, code)
        self.assertFalse(any("no secret detected by gitleaks" in m for m in msgs))
        self.assertTrue(any("NOT-TESTED" in m for m in msgs))


class C6SealHollowingTests(unittest.TestCase):
    """C6: a seal cannot hollow its own scope by excluding source / empty artifacts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def _write_seal(self, exclusions, artifacts):
        seal = {
            "schema_version": ag.SCHEMA_VERSION,
            "source_manifest_sha256": _empty_manifest_sha() if not artifacts else "sha256:x",
            "exclusions": exclusions,
            "artifacts": artifacts,
        }
        path = self.repo / "seal.json"
        path.write_text(json.dumps(seal), encoding="utf-8")
        return path

    def test_excluding_source_is_rejected(self):
        path = self._write_seal(["memo.py", "plan.md", "tests/", "audit/"], {})
        errors = ag.verify_seal(self.repo, path)
        self.assertTrue(errors)
        self.assertTrue(any("tampering" in e for e in errors))

    def test_empty_artifacts_is_rejected(self):
        path = self._write_seal(["audit/", "atlas/"], {})  # only allowed roots, but empty
        errors = ag.verify_seal(self.repo, path)
        self.assertTrue(any("zero files" in e for e in errors))

    def _init_repo_with_source(self):
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.repo, check=True)
        (self.repo / "app.py").write_text("x = 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "app.py"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=self.repo, check=True, capture_output=True)

    def test_create_seal_refuses_source_exclusion(self):
        self._init_repo_with_source()
        with self.assertRaises(ValueError):
            ag.create_seal(self.repo, self.repo / "audit" / "seal.json", exclusions=["app.py"])

    def test_create_seal_refuses_zero_file_seal(self):
        # excluding all real source via an allowed generated-dir name → zero files
        self._init_repo_with_source()
        (self.repo / "audit").mkdir()
        (self.repo / "audit" / "app.py").write_text("x = 1\n", encoding="utf-8")
        # move the only source under audit/ and exclude audit/ -> zero coverage
        (self.repo / "app.py").unlink()
        subprocess.run(["git", "rm", "app.py"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "move"], cwd=self.repo, check=True, capture_output=True)
        with self.assertRaises(ValueError):
            ag.create_seal(self.repo, self.repo / "audit" / "seal.json", exclusions=["audit/"])


class C7VerifyAtlasTests(unittest.TestCase):
    """C7: a generated view whose cites/line-count drift from source is detected."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.src = self.root / "memo.py"
        self.src.write_text("\n".join(f"line {i}" for i in range(1, 21)) + "\n", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_out_of_range_cite_is_flagged(self):
        atlas = self.root / "atlas.html"
        atlas.write_text("<p>see memo.py:5-999 here</p>", encoding="utf-8")
        errors = ag.verify_atlas(atlas, self.src)
        self.assertTrue(any("out of range" in e for e in errors))

    def test_wrong_line_count_is_flagged(self):
        atlas = self.root / "atlas.html"
        atlas.write_text("<p>memo.py・111行 の道具</p>", encoding="utf-8")
        errors = ag.verify_atlas(atlas, self.src)
        self.assertTrue(any("line count" in e for e in errors))

    def test_accurate_atlas_passes(self):
        atlas = self.root / "atlas.html"
        atlas.write_text("<p>memo.py・20行, see memo.py:5-10</p>", encoding="utf-8")
        self.assertEqual([], ag.verify_atlas(atlas, self.src))

    def test_parenthetical_and_english_counts_are_checked(self):
        # "memo.py(本体・190行)" slipped past the earlier narrow pattern (Grok).
        atlas = self.root / "atlas.html"
        atlas.write_text("<td>memo.py(本体・190行)</td> and memo.py has 111 lines", encoding="utf-8")
        errors = ag.verify_atlas(atlas, self.src)
        self.assertTrue(any("190" in e for e in errors))
        self.assertTrue(any("111" in e for e in errors))

    def test_cite_digits_do_not_bleed_into_count(self):
        atlas = self.root / "atlas.html"
        atlas.write_text("see memo.py:5-10 then plain text 20行", encoding="utf-8")
        # the '20行' is not adjacent to the basename through non-digits, so no false count
        self.assertEqual([], ag.verify_atlas(atlas, self.src))


class TamperingExclusionTests(unittest.TestCase):
    """C6 hardening: exclusions with .. or absolute paths are rejected outright."""

    def test_dotdot_traversal_is_flagged(self):
        self.assertTrue(ag._tampering_exclusions(["audit/../../memo.py"]))

    def test_absolute_path_is_flagged(self):
        self.assertTrue(ag._tampering_exclusions(["/etc/passwd"]))

    def test_generated_dirs_are_allowed(self):
        self.assertEqual([], ag._tampering_exclusions(["audit/", "atlas/", "critical-review/"]))


if __name__ == "__main__":
    unittest.main()
