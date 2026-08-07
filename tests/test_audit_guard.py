import csv
import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_COLUMNS = (
    "requirement_id", "source_id", "source_version", "source_requirement",
    "applicability", "applicability_approver", "mandatory", "severity",
    "test_method", "expected_result", "actual_result", "evidence_id", "evidence",
    "evidence_sha256", "result", "limitation", "owner", "hazard_id",
    "design_item_id", "test_id", "deviation_id", "residual_risk_id",
    "stage_approval_id",
)


class AuditGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp_dir.name)
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "audit@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Audit Test"], cwd=self.repo, check=True)
        (self.repo / "app.py").write_text("print('safe')\n", encoding="utf-8")
        (self.repo / "config.toml").write_text("mode = 'local'\n", encoding="utf-8")
        (self.repo / ".audit").mkdir()
        (self.repo / ".audit" / "source.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.repo / "audit").mkdir()
        (self.repo / "audit" / "audit-report.md").write_text("# report\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "test fixture"], cwd=self.repo, check=True, capture_output=True)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_redact_text_masks_common_secret_formats(self):
        from scripts.audit_guard import redact_text

        raw = (
            'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n'
            "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
            "aws=AKIAIOSFODNN7EXAMPLE\n"
            "password: CorrectHorseBatteryStaple\n"
            "password=CorrectHorseBatteryStaple123A4567\n"
            "pin=123456\n"
            "recovery_code=RecoverMe1234567890ABC\n"
            "Authorization: Bearer vendorToken_0123456789abcdef\n"
            "Authorization: Bearer AAAAAAAAAAAAAAAA\n"
            "Authorization: Bearer abc123\n"
            "password=abc\n"
            'password="correct horse battery staple"\n'
            '{"password": "correct \\"horse\\" battery staple"}\n'
            'private_key="-----BEGIN PRIVATE KEY----- secret material -----END PRIVATE KEY-----"\n'
            'access_token: "opaqueVendorToken0123456789abcdef"\n'
            '{"access_token": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}\n'
            "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature0123456789\n"
        )

        redacted = redact_text(raw)

        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("CorrectHorseBatteryStaple", redacted)
        self.assertNotIn("vendorToken_0123456789abcdef", redacted)
        self.assertNotIn("Bearer AAAAAAAAAAAAAAAA", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("horse battery staple", redacted)
        self.assertNotIn("secret material", redacted)
        self.assertNotIn("opaqueVendorToken0123456789abcdef", redacted)
        self.assertNotIn("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", redacted)
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", redacted)
        self.assertIn("password: [REDACTED]", redacted)
        self.assertGreaterEqual(redacted.count("password=[REDACTED]"), 2)
        self.assertIn("pin=[REDACTED]", redacted)
        self.assertIn("recovery_code=[REDACTED]", redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED:sha256:"), 2)
        self.assertEqual(redacted, redact_text(redacted))

    def test_redact_cli_can_delete_raw_temporary_input_after_safe_output(self):
        from scripts.audit_guard import main

        raw_path = self.repo / "audit" / "raw.yaml"
        safe_path = self.repo / "audit" / "safe.yaml"
        raw_path.write_text("Authorization: Bearer vendorToken_0123456789abcdef\n", encoding="utf-8")

        result = main(
            ["redact", str(raw_path), "--output", str(safe_path), "--delete-source"]
        )

        self.assertEqual(0, result)
        self.assertFalse(raw_path.exists())
        self.assertNotIn("vendorToken_0123456789abcdef", safe_path.read_text(encoding="utf-8"))

    def test_redact_cli_rejects_same_input_and_output_path(self):
        from scripts.audit_guard import main

        raw_path = self.repo / "audit" / "raw.txt"
        raw_path.write_text("password=do-not-delete-me\n", encoding="utf-8")

        result = main(
            ["redact", str(raw_path), "--output", str(raw_path), "--delete-source"]
        )

        self.assertEqual(2, result)
        self.assertTrue(raw_path.exists())

    def test_seal_verifies_all_non_audit_tracked_files(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        seal = create_seal(self.repo, seal_path, exclusions=("audit/", "atlas/"))

        self.assertEqual({".audit/source.py", "app.py", "config.toml"}, set(seal["artifacts"]))
        self.assertEqual([], verify_seal(self.repo, seal_path))

    def test_default_seal_does_not_blanket_exclude_audit_source_directory(self):
        from scripts.audit_guard import create_seal

        seal = create_seal(self.repo, self.repo / "audit" / "seal.json")

        self.assertIn("audit/audit-report.md", seal["artifacts"])

    def test_seal_ignores_generated_audit_outputs(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        create_seal(self.repo, seal_path, exclusions=("audit/", "atlas/"))
        (self.repo / "audit" / "audit-report.md").write_text("# updated report\n", encoding="utf-8")

        self.assertEqual([], verify_seal(self.repo, seal_path))

    def test_seal_detects_modified_deleted_and_untracked_source(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        create_seal(self.repo, seal_path, exclusions=("audit/", "atlas/"))
        (self.repo / "app.py").write_text("print('changed')\n", encoding="utf-8")
        (self.repo / "config.toml").unlink()
        (self.repo / "new_source.py").write_text("print('new')\n", encoding="utf-8")

        errors = verify_seal(self.repo, seal_path)

        self.assertTrue(any("hash mismatch: app.py" in error for error in errors))
        self.assertTrue(any("missing: config.toml" in error for error in errors))
        self.assertTrue(any("unexpected: new_source.py" in error for error in errors))

    def test_seal_is_deterministic_except_for_timestamp(self):
        from scripts.audit_guard import create_seal

        first_path = self.repo / "audit" / "seal-1.json"
        second_path = self.repo / "audit" / "seal-2.json"
        first = create_seal(self.repo, first_path, exclusions=("audit/", "atlas/"))
        second = create_seal(self.repo, second_path, exclusions=("audit/", "atlas/"))
        first.pop("sealed_at")
        second.pop("sealed_at")

        self.assertEqual(first, second)
        json.dumps(first, sort_keys=True)

    def test_create_seal_rejects_dirty_tracked_source(self):
        from scripts.audit_guard import create_seal

        (self.repo / "app.py").write_text("print('dirty')\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "modified audited files"):
            create_seal(
                self.repo,
                self.repo / "audit" / "seal.json",
                exclusions=("audit/", "atlas/"),
            )

    def test_verify_seal_detects_tampered_manifest_digest(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        seal = create_seal(self.repo, seal_path, exclusions=("audit/", "atlas/"))
        seal["source_manifest_sha256"] = "sha256:" + "0" * 64
        seal_path.write_text(json.dumps(seal), encoding="utf-8")

        self.assertIn("manifest digest mismatch", verify_seal(self.repo, seal_path))

    def test_create_seal_rejects_tracked_symlink(self):
        from scripts.audit_guard import create_seal

        external = self.repo.parent / "outside.txt"
        external.write_text("outside\n", encoding="utf-8")
        (self.repo / "linked.txt").symlink_to(external)
        subprocess.run(["git", "add", "linked.txt"], cwd=self.repo, check=True)
        subprocess.run(
            ["git", "commit", "-m", "add symlink"],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )

        with self.assertRaisesRegex(ValueError, "symlink"):
            create_seal(
                self.repo,
                self.repo / "audit" / "seal.json",
                exclusions=("audit/", "atlas/"),
            )

    def test_publication_scan_checks_yaml_for_bearer_tokens(self):
        from scripts.audit_guard import scan_artifacts

        evidence = self.repo / "audit" / "evidence.yaml"
        evidence.write_text(
            "Authorization: Bearer vendorToken_0123456789abcdef\n", encoding="utf-8"
        )

        errors = scan_artifacts(self.repo / "audit")

        self.assertTrue(any("raw secret-like value: evidence.yaml" in error for error in errors))

    def test_publication_scan_rejects_spaced_quoted_password(self):
        from scripts.audit_guard import redact_text, scan_artifacts

        evidence = self.repo / "audit" / "spaced.json"
        raw = '{"password": "correct \\"horse\\" battery staple"}\n'
        evidence.write_text(raw, encoding="utf-8")

        self.assertTrue(scan_artifacts(self.repo / "audit"))
        evidence.write_text(redact_text(raw), encoding="utf-8")

        self.assertNotIn("horse battery staple", evidence.read_text(encoding="utf-8"))
        self.assertEqual([], scan_artifacts(self.repo / "audit"))

    def test_redaction_removes_yaml_secret_block_scalar_body(self):
        from scripts.audit_guard import redact_text, scan_artifacts

        evidence = self.repo / "audit" / "secret.yaml"
        raw = "password: |\n  correct horse battery staple\n  second secret line\nmode: safe\n"
        redacted = redact_text(raw)
        evidence.write_text(redacted, encoding="utf-8")

        self.assertNotIn("correct horse", redacted)
        self.assertNotIn("second secret", redacted)
        self.assertIn("mode: safe", redacted)
        self.assertEqual([], scan_artifacts(self.repo / "audit"))

    def _quality_profile(self, **overrides):
        profile = {
            "schema_version": 1,
            "quality_profile_version": "1.2.0",
            "system_name": "example-system",
            "target_types": ["cli"],
            "assurance_model": "limited-scope-technical-verification",
            "certification_claimed": False,
            "third_party_audit_claimed": False,
            "technical_conclusion": "conditional",
            "report_release_gate": {
                "status": "draft",
                "semantic_review_required": True,
            },
            "standards": [
                {
                    "source_id": "AI-AUDIT",
                    "version": "1.2.0",
                    "role": "internal-control-inventory",
                    "claim_level": "mapped",
                    "coverage_scope": "all published AA controls",
                    "official_uri": "https://github.com/goonobu-dot/ai-audit-skill/",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "ISO-IEC-25010",
                    "version": "2023",
                    "role": "quality-model",
                    "claim_level": "mapped",
                    "coverage_scope": "all nine product quality characteristics",
                    "official_uri": "https://www.iso.org/standard/78176.html",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "ISO-IEC-IEEE-29119-2",
                    "version": "2021",
                    "role": "test-process",
                    "claim_level": "referenced",
                    "coverage_scope": "test process structure",
                    "official_uri": "https://www.iso.org/standard/79428.html",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "ISO-IEC-IEEE-29119-3",
                    "version": "2021",
                    "role": "test-documentation",
                    "claim_level": "referenced",
                    "coverage_scope": "test documentation structure",
                    "official_uri": "https://www.iso.org/standard/79429.html",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "NIST-SP-800-218",
                    "version": "1.1",
                    "role": "secure-development",
                    "claim_level": "mapped",
                    "coverage_scope": "PO PS PW and RV practice groups",
                    "official_uri": "https://csrc.nist.gov/pubs/sp/800/218/final",
                    "retrieved_at": "2026-08-07",
                },
            ],
            "sector_overlays": [],
            "specialist_review_required": False,
        }
        profile.update(overrides)
        return profile

    def _matrix_text(self, rows):
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=MATRIX_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def _quality_row(self, **overrides):
        evidence_hash = "sha256:" + hashlib.sha256(b"pass\n").hexdigest()
        row = {
            "requirement_id": "QA-FUNC-001",
            "source_id": "ISO-IEC-25010",
            "source_version": "2023",
            "source_requirement": "functional-suitability",
            "applicability": "applicable",
            "applicability_approver": "",
            "mandatory": "true",
            "severity": "important",
            "test_method": "acceptance test",
            "expected_result": "expected behavior",
            "actual_result": "observed expected behavior",
            "evidence_id": "EV-001",
            "evidence": "evidence/test.log",
            "evidence_sha256": evidence_hash,
            "result": "pass",
            "limitation": "",
            "owner": "quality-owner",
            "hazard_id": "",
            "design_item_id": "",
            "test_id": "",
            "deviation_id": "",
            "residual_risk_id": "",
            "stage_approval_id": "",
        }
        row.update(overrides)
        return row

    def _valid_core_rows(self):
        from scripts.audit_guard import MODULE

        rows = []
        for index, control_id in enumerate(sorted(MODULE.AUDIT_CONTROL_IDS), start=1):
            rows.append(
                self._quality_row(
                    requirement_id=f"QA-AA-{index:03d}",
                    source_id="AI-AUDIT",
                    source_version="1.2.0",
                    source_requirement=control_id,
                    severity="critical" if control_id in MODULE.AUDIT_CRITICAL_IDS else "important",
                )
            )
        for index, characteristic in enumerate(sorted(MODULE.ISO_25010_CHARACTERISTICS), start=1):
            rows.append(
                self._quality_row(
                    requirement_id=f"QA-ISO-{index:03d}",
                    source_requirement=characteristic,
                    mandatory="false" if characteristic == "safety" else "true",
                    severity="critical" if characteristic == "safety" else "important",
                )
            )
        for index, requirement in enumerate(sorted(MODULE.NIST_SSDF_TASK_IDS), start=1):
            rows.append(
                self._quality_row(
                    requirement_id=f"QA-SSDF-{index:03d}",
                    source_id="NIST-SP-800-218",
                    source_version="1.1",
                    source_requirement=requirement,
                )
            )
        for row in rows:
            content = (
                f"requirement_id={row['requirement_id']}\n"
                f"source_requirement={row['source_requirement']}\n"
                "result=pass\n"
            ).encode()
            row["evidence_id"] = f"EV-{row['requirement_id']}"
            row["evidence"] = f"evidence/{row['requirement_id']}.log"
            row["evidence_sha256"] = "sha256:" + hashlib.sha256(content).hexdigest()
        return rows

    def _write_quality_package(self, profile, matrix_text):
        audit = self.repo / "audit"
        evidence = audit / "evidence"
        evidence.mkdir(exist_ok=True)
        (evidence / "test.log").write_text("pass\n", encoding="utf-8")
        profile_path = audit / "quality-profile.json"
        matrix_path = audit / "requirements-matrix.csv"
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        matrix_path.write_text(matrix_text, encoding="utf-8")
        for row in csv.DictReader(io.StringIO(matrix_text)):
            expected_reference = f"evidence/{row['requirement_id']}.log"
            if row.get("evidence") != expected_reference:
                continue
            evidence_path = audit / expected_reference
            if not evidence_path.exists():
                evidence_path.write_text(
                    f"requirement_id={row['requirement_id']}\n"
                    f"source_requirement={row['source_requirement']}\n"
                    "result=pass\n",
                    encoding="utf-8",
                )
        return profile_path, matrix_path, audit

    def test_technical_conclusion_is_deterministic_and_fail_closed(self):
        from scripts.audit_guard import derive_technical_conclusion

        base = {
            "applicability": "applicable",
            "mandatory": "true",
            "severity": "important",
            "result": "pass",
        }

        self.assertEqual("not-acceptable", derive_technical_conclusion([]))
        self.assertEqual("acceptable-within-scope", derive_technical_conclusion([base]))
        self.assertEqual(
            "conditional",
            derive_technical_conclusion([{**base, "result": "not-tested"}]),
        )
        self.assertEqual(
            "not-acceptable",
            derive_technical_conclusion([{**base, "result": "fail"}]),
        )
        self.assertEqual(
            "not-acceptable",
            derive_technical_conclusion(
                [{**base, "mandatory": "false", "severity": "critical", "result": "not-tested"}]
            ),
        )

    def test_quality_package_requires_versioned_core_and_ios_sources(self):
        from scripts.audit_guard import validate_quality_package

        profile = self._quality_profile(target_types=["ios"], standards=[])
        profile_path, matrix_path, audit = self._write_quality_package(
            profile,
            self._matrix_text([]),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        for source_id in (
            "ISO-IEC-25010",
            "ISO-IEC-IEEE-29119-2",
            "ISO-IEC-IEEE-29119-3",
            "NIST-SP-800-218",
            "OWASP-MASVS",
            "APPLE-APP-REVIEW",
            "APPLE-PRIVACY-MANIFEST",
            "APPLE-PLATFORM-SECURITY",
        ):
            self.assertTrue(any(source_id in error for error in errors), errors)

        android_profile = self._quality_profile(target_types=["android"])
        profile_path, matrix_path, audit = self._write_quality_package(
            android_profile, self._matrix_text(self._valid_core_rows())
        )
        android_errors = validate_quality_package(profile_path, matrix_path, audit)
        self.assertTrue(any("OWASP-MASVS" in error for error in android_errors), android_errors)

    def test_ios_verified_claim_requires_canonical_masvs_and_apple_inventories(self):
        from scripts.audit_guard import validate_quality_package

        profile = self._quality_profile(target_types=["ios"], technical_conclusion="acceptable-within-scope")
        profile["standards"].extend(
            [
                {
                    "source_id": "OWASP-MASVS",
                    "version": "2.1.0",
                    "role": "mobile-security",
                    "claim_level": "verified",
                    "coverage_scope": "claimed all MASVS controls",
                    "official_uri": "https://mas.owasp.org/MASVS/",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "APPLE-APP-REVIEW",
                    "version": "current",
                    "role": "store-review",
                    "claim_level": "mapped",
                    "coverage_scope": "privacy and security review requirements",
                    "official_uri": "https://developer.apple.com/app-store/review/guidelines/",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "APPLE-PRIVACY-MANIFEST",
                    "version": "current",
                    "role": "privacy-manifest",
                    "claim_level": "mapped",
                    "coverage_scope": "manifest and required reason APIs",
                    "official_uri": "https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
                    "retrieved_at": "2026-08-07",
                },
                {
                    "source_id": "APPLE-PLATFORM-SECURITY",
                    "version": "current",
                    "role": "platform-security",
                    "claim_level": "mapped",
                    "coverage_scope": "entitlements signing data protection and transport",
                    "official_uri": "https://developer.apple.com/security/",
                    "retrieved_at": "2026-08-07",
                },
            ]
        )
        rows = self._valid_core_rows() + [
            self._quality_row(
                requirement_id="QA-MASVS-001",
                source_id="OWASP-MASVS",
                source_version="2.1.0",
                source_requirement="MASVS-NOT-A-REAL-CONTROL",
                evidence_id="EV-MASVS-001",
            )
        ]
        profile_path, matrix_path, audit = self._write_quality_package(
            profile, self._matrix_text(rows)
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("inventory incomplete for OWASP-MASVS" in error for error in errors), errors)
        self.assertTrue(any("unknown IDs for OWASP-MASVS" in error for error in errors), errors)
        self.assertTrue(any("inventory incomplete for APPLE-PRIVACY-MANIFEST" in error for error in errors), errors)

    def test_quality_package_gates_safety_related_targets(self):
        from scripts.audit_guard import validate_quality_package

        profile = self._quality_profile(target_types=["safety-related"])
        profile_path, matrix_path, audit = self._write_quality_package(
            profile,
            self._matrix_text([]),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("sector_overlays" in error for error in errors), errors)
        self.assertTrue(any("specialist_review_required" in error for error in errors), errors)
        self.assertTrue(any("sector_gate" in error for error in errors), errors)

    def test_quality_package_rejects_undeclared_matrix_source(self):
        from scripts.audit_guard import validate_quality_package

        matrix = self._matrix_text(
            [
                self._quality_row(
                    requirement_id="QA-UNKNOWN-001",
                    source_id="UNKNOWN-STANDARD",
                    source_version="9.9",
                    source_requirement="X.1",
                )
            ]
        )
        profile = self._quality_profile(technical_conclusion="acceptable-within-scope")
        profile_path, matrix_path, audit = self._write_quality_package(profile, matrix)

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("undeclared source" in error for error in errors), errors)

    def test_quality_package_fails_closed_on_malformed_csv_and_windows_traversal(self):
        from scripts.audit_guard import validate_quality_package

        row = self._quality_row(requirement_id="QA-001", evidence="..\\outside.log")
        malformed = self._matrix_text([row]).rstrip("\n") + ",unexpected\n"
        profile = self._quality_profile(technical_conclusion="acceptable-within-scope")
        profile_path, matrix_path, audit = self._write_quality_package(profile, malformed)

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("malformed row" in error for error in errors), errors)
        self.assertTrue(any("unsafe evidence path" in error for error in errors), errors)

    def test_completed_sector_gate_requires_lifecycle_evidence(self):
        from scripts.audit_guard import validate_quality_package

        overlay = {
            "source_id": "IEC-61513",
            "version": "2026",
            "role": "nuclear-instrumentation-and-control",
            "claim_level": "referenced",
            "coverage_scope": "IEC 61513 requirements selected by nuclear I&C specialist",
            "official_uri": "https://webstore.iec.ch/en/publication/76309",
            "retrieved_at": "2026-08-07",
        }
        profile = self._quality_profile(
            target_types=["safety-related"],
            sector_overlays=[overlay],
            specialist_review_required=True,
            sector_gate={"status": "complete"},
        )
        profile_path, matrix_path, audit = self._write_quality_package(
            profile,
            self._matrix_text([]),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        for field in (
            "hazard_traceability_evidence",
            "configuration_baseline_evidence",
            "verification_plan_evidence",
            "independent_review_evidence",
            "stage_approval_evidence",
            "responsible_approver",
            "supplier_organization",
            "independent_reviewer",
            "reviewer_organization",
        ):
            self.assertTrue(any(field in error for error in errors), errors)

    def test_blocked_sector_gate_forces_not_acceptable_even_when_rows_pass(self):
        from scripts.audit_guard import validate_quality_package

        catalog_text = "IEC-61513 2026 selected requirement: 6.1\n"
        overlay = {
            "source_id": "IEC-61513",
            "version": "2026",
            "role": "nuclear-instrumentation-and-control",
            "claim_level": "mapped",
            "coverage_scope": "specialist-selected clause",
            "official_uri": "https://webstore.iec.ch/en/publication/76309",
            "retrieved_at": "2026-08-07",
            "requirement_catalog": ["6.1"],
            "catalog_approver": "nuclear-I&C-specialist",
            "catalog_evidence": "evidence/catalog.txt",
            "catalog_evidence_sha256": (
                "sha256:" + hashlib.sha256(catalog_text.encode()).hexdigest()
            ),
        }
        profile = self._quality_profile(
            target_types=["safety-related"],
            sector_overlays=[overlay],
            specialist_review_required=True,
            sector_gate={
                "status": "blocked",
                "blocking_reasons": ["regulatory approval pending"],
            },
            technical_conclusion="not-acceptable",
        )
        rows = self._valid_core_rows() + [
            self._quality_row(
                requirement_id="QA-SAFE-001",
                source_id="IEC-61513",
                source_version="2026",
                source_requirement="6.1",
                evidence_id="EV-SAFE-001",
                hazard_id="HAZ-001",
                design_item_id="DES-001",
                test_id="TEST-001",
                deviation_id="DEV-NONE",
                residual_risk_id="RISK-001",
                stage_approval_id="STAGE-BLOCKED",
            )
        ]
        profile_path, matrix_path, audit = self._write_quality_package(
            profile, self._matrix_text(rows)
        )
        (audit / "evidence" / "catalog.txt").write_text(catalog_text, encoding="utf-8")

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertFalse(any("technical_conclusion mismatch" in error for error in errors), errors)

    def test_safety_gate_rejects_referenced_overlay_shared_evidence_and_missing_chain(self):
        from scripts.audit_guard import validate_quality_package

        overlay = {
            "source_id": "IEC-61513",
            "version": "2026",
            "role": "nuclear-instrumentation-and-control",
            "claim_level": "referenced",
            "coverage_scope": "supplier-selected clause",
            "official_uri": "https://webstore.iec.ch/en/publication/76309",
            "retrieved_at": "2026-08-07",
        }
        gate = {
            "status": "complete",
            **{field: "evidence/test.log" for field in (
                "hazard_traceability_evidence", "configuration_baseline_evidence",
                "verification_plan_evidence", "independent_review_evidence",
                "stage_approval_evidence",
            )},
            "responsible_approver": "supplier",
            "supplier_organization": "supplier",
            "independent_reviewer": "supplier",
            "reviewer_organization": "supplier",
        }
        profile = self._quality_profile(
            target_types=["safety-related", "ot", "regulated"],
            sector_overlays=[overlay],
            specialist_review_required=True,
            sector_gate=gate,
            technical_conclusion="acceptable-within-scope",
        )
        rows = self._valid_core_rows() + [
            self._quality_row(
                requirement_id="QA-SAFE-001",
                source_id="IEC-61513",
                source_version="2026",
                source_requirement="6.1",
                evidence_id="EV-SAFE-001",
            )
        ]
        profile_path, matrix_path, audit = self._write_quality_package(
            profile, self._matrix_text(rows)
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("overlay must be mapped" in error for error in errors), errors)
        self.assertTrue(any("distinct evidence" in error for error in errors), errors)
        self.assertTrue(any("reviewer_organization must differ" in error for error in errors), errors)
        self.assertTrue(any("hazard_id" in error for error in errors), errors)

    def test_non_applicable_critical_control_requires_independent_approval(self):
        from scripts.audit_guard import validate_quality_package

        rows = self._valid_core_rows()
        rows[0].update(
            applicability="not-applicable",
            applicability_approver="quality-owner",
            result="not-applicable",
            limitation="not applicable by owner assertion",
            expected_result="",
            actual_result="",
            evidence_id="",
            evidence="",
            evidence_sha256="",
            severity="critical",
        )
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"),
            self._matrix_text(rows),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("independent of owner" in error for error in errors), errors)

    def test_canonical_control_policy_cannot_be_downgraded_to_minor_optional(self):
        from scripts.audit_guard import validate_quality_package

        rows = self._valid_core_rows()
        critical = next(row for row in rows if row["source_requirement"] == "AA-1.1")
        critical.update(
            mandatory="false",
            severity="minor",
            applicability="not-applicable",
            applicability_approver="quality-owner",
            result="not-applicable",
            limitation="downgraded under delivery pressure",
            expected_result="",
            actual_result="",
            evidence_id="",
            evidence="",
            evidence_sha256="",
        )
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"),
            self._matrix_text(rows),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("changes canonical mandatory/severity" in error for error in errors), errors)

    def test_pass_evidence_must_be_nonempty_and_hash_matched(self):
        from scripts.audit_guard import validate_quality_package

        rows = self._valid_core_rows()
        rows[0].update(
            evidence="evidence/empty.log",
            evidence_sha256="sha256:" + hashlib.sha256(b"").hexdigest(),
        )
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"),
            self._matrix_text(rows),
        )
        (audit / "evidence" / "empty.log").write_bytes(b"")

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("evidence is empty" in error for error in errors), errors)

    def test_report_claims_must_match_machine_profile(self):
        from scripts.audit_guard import validate_report_consistency

        profile_path, _, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="conditional"),
            self._matrix_text(self._valid_core_rows()),
        )
        report = audit / "audit-report.md"
        report.write_text(
            "# ISO/IEC 25010適合済み・外部監査済み・全統制クリア\n\n"
            "ISO compliant / third-party audit completed / all controls passed\n\n"
            "**技術評価結論:acceptable-within-scope**\n",
            encoding="utf-8",
        )

        errors = validate_report_consistency(profile_path, report)

        self.assertTrue(any("does not exactly match" in error for error in errors), errors)
        self.assertTrue(any("prohibited assurance" in error for error in errors), errors)

    def test_report_rejects_semantic_overclaim_paraphrases_and_unapproved_release(self):
        from scripts.audit_guard import validate_report_consistency

        profile_path, _, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="conditional"),
            self._matrix_text(self._valid_core_rows()),
        )
        report = audit / "audit-report.md"
        report.write_text(
            "# Report\n\n"
            "**技術評価結論:conditional**\n\n"
            "限定範囲の技術的検証 quality-profile.json requirements-matrix.csv\n\n"
            "AI-AUDIT 1.2.0 ISO-IEC-25010 2023 ISO-IEC-IEEE-29119-2 "
            "ISO-IEC-IEEE-29119-3 2021 NIST-SP-800-218 1.1\n\n"
            "適合性確認済み: ISO/IEC 25010:2023。監査法人による監査を実施。"
            "全ての統制を満たしており、本番利用を承認する。\n\n"
            "Certification granted by an external assessor. Meets ISO/IEC 25010 "
            "requirements. Independently audited. All requirements satisfied. "
            "Approved for production.\n",
            encoding="utf-8",
        )

        errors = validate_report_consistency(profile_path, report)

        self.assertTrue(any("human semantic review" in error for error in errors), errors)
        self.assertTrue(any("prohibited assurance" in error for error in errors), errors)

        report.write_text(
            report.read_text(encoding="utf-8")
            + "\n**外部提出:不可（人間による意味レビュー未承認）**\n"
            + "\n**外部提出:承認済み**\n",
            encoding="utf-8",
        )
        errors = validate_report_consistency(profile_path, report)
        self.assertTrue(any("exactly one external release marker" in error for error in errors), errors)

    def test_approved_report_is_bound_to_human_review_evidence_and_report_hash(self):
        from scripts.audit_guard import validate_quality_package, validate_report_consistency

        report_text = (
            "# Report\n\n"
            "**技術評価結論:acceptable-within-scope**\n\n"
            "**外部提出:承認済み**\n\n"
            "限定範囲の技術的検証 quality-profile.json requirements-matrix.csv\n\n"
            "AI-AUDIT 1.2.0 ISO-IEC-25010 2023 ISO-IEC-IEEE-29119-2 "
            "ISO-IEC-IEEE-29119-3 2021 NIST-SP-800-218 1.1\n"
        )
        approval_text = "{\"decision\":\"external-release-approved\"}\n"
        release_gate = {
            "status": "approved",
            "semantic_review_required": True,
            "reviewer_identity": "reviewer@example.invalid",
            "reviewer_name": "Human Reviewer",
            "reviewer_role": "quality manager",
            "reviewer_organization": "customer organization",
            "approved_at": "2026-08-07T12:00:00+09:00",
            "approval_record": "evidence/report-approval.json",
            "approval_record_sha256": (
                "sha256:" + hashlib.sha256(approval_text.encode()).hexdigest()
            ),
            "approval_signature": "evidence/report-approval.json.sig",
            "report_sha256": "sha256:" + hashlib.sha256(report_text.encode()).hexdigest(),
        }
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(
                technical_conclusion="acceptable-within-scope",
                report_release_gate=release_gate,
            ),
            self._matrix_text(self._valid_core_rows()),
        )
        report = audit / "audit-report.md"
        report.write_text(report_text, encoding="utf-8")
        (audit / "evidence" / "report-approval.json").write_text(
            approval_text, encoding="utf-8"
        )
        (audit / "evidence" / "report-approval.json.sig").write_text(
            "detached signature placeholder\n", encoding="utf-8"
        )

        self.assertEqual([], validate_quality_package(profile_path, matrix_path, audit))
        self.assertEqual([], validate_report_consistency(profile_path, report))

        report.write_text(report_text + "\npost-approval change\n", encoding="utf-8")
        errors = validate_report_consistency(profile_path, report)
        self.assertTrue(any("does not match human semantic review" in error for error in errors), errors)

        approval = audit / "evidence" / "report-approval.json"
        approval.unlink()
        approval_target = audit / "evidence" / "approval-target.txt"
        approval_target.write_text(approval_text, encoding="utf-8")
        approval.symlink_to(approval_target.name)
        errors = validate_quality_package(profile_path, matrix_path, audit)
        self.assertTrue(any("approval_record path contains symlink" in error for error in errors), errors)

    @unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen is required")
    def test_external_release_requires_detached_signature_from_trusted_signer(self):
        from scripts.audit_guard import (
            create_seal,
            validate_external_release,
            validate_quality_package,
        )

        report_text = (
            "# Report\n\n"
            "**技術評価結論:acceptable-within-scope**\n\n"
            "**外部提出:承認済み**\n\n"
            "限定範囲の技術的検証 quality-profile.json requirements-matrix.csv\n\n"
            "AI-AUDIT 1.2.0 ISO-IEC-25010 2023 ISO-IEC-IEEE-29119-2 "
            "ISO-IEC-IEEE-29119-3 2021 NIST-SP-800-218 1.1\n"
        )
        report_hash = "sha256:" + hashlib.sha256(report_text.encode()).hexdigest()
        approval_record = {
            "schema_version": 1,
            "decision": "external-release-approved",
            "system_name": "example-system",
            "quality_profile_version": "1.2.0",
            "technical_conclusion": "acceptable-within-scope",
            "report_sha256": report_hash,
            "reviewer_identity": "reviewer@example.invalid",
            "reviewer_name": "Human Reviewer",
            "reviewer_role": "quality manager",
            "reviewer_organization": "customer organization",
            "approved_at": "2026-08-07T12:00:00+09:00",
        }
        gate = {
            "status": "approved",
            "semantic_review_required": True,
            **{key: approval_record[key] for key in (
                "reviewer_identity", "reviewer_name", "reviewer_role",
                "reviewer_organization", "approved_at", "report_sha256",
            )},
            "approval_record": "evidence/release-approval.json",
            "approval_record_sha256": "sha256:" + "0" * 64,
            "approval_signature": "evidence/release-approval.json.sig",
        }
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(
                technical_conclusion="acceptable-within-scope",
                report_release_gate=gate,
            ),
            self._matrix_text(self._valid_core_rows()),
        )
        report = audit / "audit-report.md"
        report.write_text(report_text, encoding="utf-8")
        (audit / "audit-workpaper.md").write_text("reviewed workpaper\n", encoding="utf-8")
        (audit / "unverified-ledger.md").write_text("no omitted items\n", encoding="utf-8")
        seal_path = audit / "seal.json"
        create_seal(self.repo, seal_path, exclusions=["audit/"])
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        unsigned_profile = dict(profile)
        unsigned_profile.pop("report_release_gate")
        profile_payload = json.dumps(
            unsigned_profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        manifest = {}
        for candidate in sorted(audit.rglob("*")):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(audit).as_posix()
            if relative in {
                "quality-profile.json",
                "evidence/release-approval.json",
                "evidence/release-approval.json.sig",
            }:
                continue
            manifest[relative] = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        manifest_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode()
        approval_record.update(
            audit_artifact_manifest_sha256=(
                "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
            ),
            profile_payload_sha256=(
                "sha256:" + hashlib.sha256(profile_payload).hexdigest()
            ),
            requirements_matrix_sha256=(
                "sha256:" + hashlib.sha256(matrix_path.read_bytes()).hexdigest()
            ),
            source_seal_sha256=(
                "sha256:" + hashlib.sha256(seal_path.read_bytes()).hexdigest()
            ),
        )
        approval_bytes = (json.dumps(approval_record, sort_keys=True) + "\n").encode()
        record_path = audit / "evidence" / "release-approval.json"
        record_path.write_bytes(approval_bytes)
        profile["report_release_gate"]["approval_record_sha256"] = (
            "sha256:" + hashlib.sha256(approval_bytes).hexdigest()
        )
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        trust_dir = tempfile.TemporaryDirectory()
        self.addCleanup(trust_dir.cleanup)
        private_key = Path(trust_dir.name) / "reviewer-key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
            check=True,
        )
        subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-q", "-f", str(private_key),
             "-n", "ai-audit-release", str(record_path)],
            check=True,
        )
        allowed_signers = Path(trust_dir.name) / "customer-allowed-signers"
        allowed_signers.write_text(
            f"reviewer@example.invalid {private_key.with_suffix('.pub').read_text().strip()}\n",
            encoding="utf-8",
        )

        self.assertEqual([], validate_quality_package(profile_path, matrix_path, audit))
        self.assertEqual(
            [],
            validate_external_release(
                profile_path, matrix_path, report, audit, self.repo, seal_path, allowed_signers
            ),
        )

        ledger = audit / "unverified-ledger.md"
        ledger.unlink()
        errors = validate_external_release(
            profile_path, matrix_path, report, audit, self.repo, seal_path, allowed_signers
        )
        self.assertTrue(any("missing required artifact" in error for error in errors), errors)
        ledger.write_text("no omitted items\n", encoding="utf-8")

        tampered_report = report_text + "\npost-approval semantic change\n"
        tampered_hash = "sha256:" + hashlib.sha256(tampered_report.encode()).hexdigest()
        report.write_text(tampered_report, encoding="utf-8")
        approval_record["report_sha256"] = tampered_hash
        tampered_manifest = {}
        for candidate in sorted(audit.rglob("*")):
            if not candidate.is_file():
                continue
            relative = candidate.relative_to(audit).as_posix()
            if relative in {
                "quality-profile.json",
                "evidence/release-approval.json",
                "evidence/release-approval.json.sig",
            }:
                continue
            tampered_manifest[relative] = (
                "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
            )
        approval_record["audit_artifact_manifest_sha256"] = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(
                    tampered_manifest, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
        )
        record_path.write_text(json.dumps(approval_record, sort_keys=True) + "\n", encoding="utf-8")
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["report_release_gate"]["report_sha256"] = tampered_hash
        profile["report_release_gate"]["approval_record_sha256"] = (
            "sha256:" + hashlib.sha256(record_path.read_bytes()).hexdigest()
        )
        profile_path.write_text(json.dumps(profile), encoding="utf-8")

        errors = validate_external_release(
            profile_path, matrix_path, report, audit, self.repo, seal_path, allowed_signers
        )
        self.assertTrue(any("signature verification failed" in error for error in errors), errors)

    def test_quality_package_links_mapped_controls_to_safe_evidence(self):
        from scripts.audit_guard import validate_quality_package

        matrix = self._matrix_text(self._valid_core_rows())
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"), matrix
        )

        self.assertEqual([], validate_quality_package(profile_path, matrix_path, audit))

    def test_requirement_inventory_rejects_duplicate_source_requirement(self):
        from scripts.audit_guard import validate_quality_package

        rows = self._valid_core_rows()
        duplicate = dict(rows[0])
        duplicate["requirement_id"] = "QA-AA-DUPLICATE"
        rows.append(duplicate)
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"),
            self._matrix_text(rows),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("duplicate source_requirement" in error for error in errors), errors)

    def test_evidence_cannot_be_reused_across_requirements_or_within_one_row(self):
        from scripts.audit_guard import validate_quality_package

        rows = self._valid_core_rows()
        rows[1].update(
            evidence_id=rows[0]["evidence_id"],
            evidence=rows[0]["evidence"],
            evidence_sha256=rows[0]["evidence_sha256"],
        )
        rows[2].update(
            evidence_id=f"{rows[2]['evidence_id']};{rows[2]['evidence_id']}",
            evidence=f"{rows[2]['evidence']};{rows[2]['evidence']}",
            evidence_sha256=(
                f"{rows[2]['evidence_sha256']};{rows[2]['evidence_sha256']}"
            ),
        )
        profile_path, matrix_path, audit = self._write_quality_package(
            self._quality_profile(technical_conclusion="acceptable-within-scope"),
            self._matrix_text(rows),
        )

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("reused across requirement rows" in error for error in errors), errors)
        self.assertTrue(any("duplicate evidence reference" in error for error in errors), errors)

    def test_quality_package_rejects_overclaim_formula_duplicate_and_traversal(self):
        from scripts.audit_guard import validate_quality_package

        matrix = self._matrix_text(
            [
                self._quality_row(
                    requirement_id="QA-001",
                    source_requirement="security",
                    severity="critical",
                    test_method='=HYPERLINK("https://example.invalid")',
                    evidence="../outside.log",
                ),
                self._quality_row(
                    requirement_id="QA-001",
                    source_id="NIST-SP-800-218",
                    source_version="1.1",
                    source_requirement="PW.4.1",
                    evidence_id="EV-002",
                ),
            ]
        )
        profile = self._quality_profile(
            certification_claimed=True,
            third_party_audit_claimed=True,
            technical_conclusion="acceptable-within-scope",
        )
        profile_path, matrix_path, audit = self._write_quality_package(profile, matrix)

        errors = validate_quality_package(profile_path, matrix_path, audit)

        self.assertTrue(any("certification_claimed" in error for error in errors), errors)
        self.assertTrue(any("third_party_audit_claimed" in error for error in errors), errors)
        self.assertTrue(any("spreadsheet formula" in error for error in errors), errors)
        self.assertTrue(any("duplicate requirement_id" in error for error in errors), errors)
        self.assertTrue(any("unsafe evidence path" in error for error in errors), errors)

    def test_bundle_requires_machine_readable_quality_evidence(self):
        from scripts.audit_guard import validate_bundle

        errors = validate_bundle(self.repo)

        self.assertTrue(any("quality-profile.json" in error for error in errors), errors)
        self.assertTrue(any("requirements-matrix.csv" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
