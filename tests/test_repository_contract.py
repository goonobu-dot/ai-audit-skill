import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_skill_defaults_to_read_only_and_requires_mutation_approval(self):
        skill = (ROOT / "skills" / "ai-audit" / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("audit-only", skill)
        self.assertIn("明示承認", skill)
        self.assertIn("本番環境で能動的試験を実行しない", skill)
        self.assertNotIn("resume --last", skill)
        self.assertRegex(skill, r"resume[^\n]+<SESSION_ID>")

    def test_skill_forbids_persisting_raw_secrets(self):
        skill = (ROOT / "skills" / "ai-audit" / "SKILL.md").read_text(encoding="utf-8")
        workpaper = (ROOT / "skills" / "ai-audit" / "templates" / "workpaper-template.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("秘密値そのものを保存しない", skill)
        self.assertIn("マスキング済み", workpaper)
        self.assertIn("外部共有前", skill)

    def test_public_install_command_and_sources_are_resolved(self):
        manual = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        standards = (ROOT / "skills" / "ai-audit" / "references" / "audit-standards.md").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("&lt;this-repo&gt;", manual)
        self.assertIn("https://github.com/goonobu-dot/ai-audit-skill.git", manual)
        self.assertIn("https://owasp.org/", standards)
        self.assertIn("https://www.digital.go.jp/", standards)
        self.assertIn("https://www.nist.gov/", standards)

    def test_ci_is_least_privilege_and_actions_are_sha_pinned(self):
        workflow = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")

        self.assertIn("contents: read", workflow)
        self.assertIn("concurrency:", workflow)
        uses = re.findall(r"uses:\s*([^\s]+)", workflow)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"@[0-9a-f]{40}$")

    def test_sample_bundle_passes_repository_validator(self):
        from scripts.audit_guard import validate_bundle

        errors = validate_bundle(ROOT / "examples" / "memo-tool")

        self.assertEqual([], errors)


if __name__ == "__main__":
    unittest.main()
