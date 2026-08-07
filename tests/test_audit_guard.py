import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


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
            "password=abc\n"
            'password="correct horse battery staple"\n'
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
        raw = '{"password": "correct horse battery staple"}\n'
        evidence.write_text(raw, encoding="utf-8")

        self.assertTrue(scan_artifacts(self.repo / "audit"))
        evidence.write_text(redact_text(raw), encoding="utf-8")

        self.assertNotIn("horse battery staple", evidence.read_text(encoding="utf-8"))
        self.assertEqual([], scan_artifacts(self.repo / "audit"))


if __name__ == "__main__":
    unittest.main()
