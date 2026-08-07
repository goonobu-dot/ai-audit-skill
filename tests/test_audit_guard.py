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
        )

        redacted = redact_text(raw)

        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwxyz123456", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", redacted)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", redacted)
        self.assertNotIn("CorrectHorseBatteryStaple", redacted)
        self.assertGreaterEqual(redacted.count("[REDACTED:sha256:"), 4)

    def test_seal_verifies_all_non_audit_tracked_files(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        seal = create_seal(self.repo, seal_path)

        self.assertEqual({"app.py", "config.toml"}, set(seal["artifacts"]))
        self.assertEqual([], verify_seal(self.repo, seal_path))

    def test_seal_ignores_generated_audit_outputs(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        create_seal(self.repo, seal_path)
        (self.repo / "audit" / "audit-report.md").write_text("# updated report\n", encoding="utf-8")

        self.assertEqual([], verify_seal(self.repo, seal_path))

    def test_seal_detects_modified_deleted_and_untracked_source(self):
        from scripts.audit_guard import create_seal, verify_seal

        seal_path = self.repo / "audit" / "seal.json"
        create_seal(self.repo, seal_path)
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
        first = create_seal(self.repo, first_path)
        second = create_seal(self.repo, second_path)
        first.pop("sealed_at")
        second.pop("sealed_at")

        self.assertEqual(first, second)
        json.dumps(first, sort_keys=True)


if __name__ == "__main__":
    unittest.main()
