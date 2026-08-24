import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


class SecurityGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name) / "repo"
        (self.repo / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.repo, check=True)

    def tearDown(self):
        self.temp.cleanup()

    def _out(self):
        return Path(self.temp.name) / "bundle"

    # --- redact_pii ---
    def test_redact_pii_masks_real_but_keeps_example(self):
        from scripts.security_gate import redact_pii
        text, n = redact_pii("real@company.co.jp 03-1234-5678 4111 1111 1111 1111 x@example.com")
        self.assertIn("[REDACTED-EMAIL]", text)
        self.assertIn("[REDACTED-PHONE]", text)
        self.assertIn("[REDACTED-CARD]", text)
        self.assertIn("x@example.com", text)  # example domain preserved
        self.assertEqual(3, n)

    # --- build-prompt-bundle ---
    def test_bundle_redacts_secret_but_keeps_logic(self):
        from scripts.security_gate import build_prompt_bundle
        (self.repo / "src" / "app.py").write_text(
            'API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz012345"\n'
            'email = "real.person@company.co.jp"\n'
            "def run():\n    return 42\n",
            encoding="utf-8",
        )
        code, _ = build_prompt_bundle(self.repo, self._out())
        self.assertEqual(0, code)
        out = (self._out() / "src" / "app.py").read_text(encoding="utf-8")
        self.assertNotIn("sk-live-abcdefghijklmnopqrstuvwxyz012345", out)
        self.assertNotIn("real.person@company.co.jp", out)
        self.assertIn("def run():", out)  # implementation context preserved
        self.assertIn("return 42", out)

    def test_bundle_writes_ledger_and_owner_only(self):
        import stat
        from scripts.security_gate import build_prompt_bundle
        (self.repo / "src" / "app.py").write_text("ok = True\n", encoding="utf-8")
        code, _ = build_prompt_bundle(self.repo, self._out())
        self.assertEqual(0, code)
        ledger = json.loads((self._out() / "transmission-ledger.json").read_text(encoding="utf-8"))
        self.assertEqual("external-llm-transmission-ledger", ledger["kind"])
        self.assertEqual(1, ledger["files_included"])
        mode = stat.S_IMODE((self._out()).stat().st_mode)
        self.assertEqual(0, mode & (stat.S_IRWXG | stat.S_IRWXO))

    def test_bundle_excludes_binary_files(self):
        from scripts.security_gate import build_prompt_bundle
        (self.repo / "src" / "app.py").write_text("ok = True\n", encoding="utf-8")
        (self.repo / "logo.png").write_bytes(b"\x89PNG\x00\xff\xfe\x00binary")
        code, _ = build_prompt_bundle(self.repo, self._out())
        self.assertEqual(0, code)
        self.assertFalse((self._out() / "logo.png").exists())
        ledger = json.loads((self._out() / "transmission-ledger.json").read_text(encoding="utf-8"))
        self.assertTrue(any("logo.png" in e for e in ledger["excluded_binaries"]))

    def test_bundle_refuses_output_inside_repo(self):
        from scripts.security_gate import build_prompt_bundle
        (self.repo / "src" / "app.py").write_text("ok = True\n", encoding="utf-8")
        code, msgs = build_prompt_bundle(self.repo, self.repo / "out")
        self.assertEqual(2, code)
        self.assertTrue(any("outside the source repo" in m for m in msgs))

    def test_bundle_allowlist_mode_sends_only_permitted(self):
        from scripts.security_gate import build_prompt_bundle
        (self.repo / "src" / "app.py").write_text("ok = True\n", encoding="utf-8")
        (self.repo / "src" / "secret_notes.py").write_text("plans = 'confidential'\n", encoding="utf-8")
        manifest = Path(self.temp.name) / "allow.txt"
        manifest.write_text("src/app.py\n", encoding="utf-8")
        code, _ = build_prompt_bundle(self.repo, self._out(), mode="allowlist", allow_manifest=manifest)
        self.assertEqual(0, code)
        self.assertTrue((self._out() / "src" / "app.py").exists())
        self.assertFalse((self._out() / "src" / "secret_notes.py").exists())

    # --- gate-commit ---
    def _stage(self, rel, content):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", rel], cwd=self.repo, check=True)

    def test_gate_commit_blocks_staged_secret(self):
        from scripts.security_gate import gate_commit
        self._stage("src/app.py", 'API_KEY = "sk-live-abcdefghijklmnopqrstuvwxyz012345"\n')
        code, msgs = gate_commit(self.repo)
        self.assertEqual(1, code)
        self.assertTrue(any("BLOCKED" in m for m in msgs))
        # the secret value itself must not be echoed
        self.assertFalse(any("sk-live-abcdefghijklmnopqrstuvwxyz012345" in m for m in msgs))

    def test_gate_commit_passes_clean_staged(self):
        from scripts.security_gate import gate_commit
        self._stage("src/app.py", "def run():\n    return 1\n")
        code, _ = gate_commit(self.repo)
        self.assertEqual(0, code)

    def test_gate_commit_warns_pii_without_blocking(self):
        from scripts.security_gate import gate_commit
        self._stage("src/app.py", "owner = 'real.person@company.co.jp'\n")
        code, msgs = gate_commit(self.repo)
        self.assertEqual(0, code)
        self.assertTrue(any("WARNING" in m and "PII" in m for m in msgs))


if __name__ == "__main__":
    unittest.main()
