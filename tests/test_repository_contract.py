import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_enterprise_quality_profile_assets_exist(self):
        skill_root = ROOT / "skills" / "ai-audit"

        self.assertTrue((skill_root / "references" / "quality-profile.md").is_file())
        self.assertTrue((skill_root / "references" / "ios-quality-profile.md").is_file())
        self.assertTrue((skill_root / "references" / "safety-critical-boundary.md").is_file())
        self.assertTrue((skill_root / "templates" / "quality-profile-template.json").is_file())
        self.assertTrue((skill_root / "templates" / "requirements-matrix-template.csv").is_file())
        self.assertTrue((skill_root / "templates" / "quality-requirements-template.md").is_file())
        self.assertTrue((skill_root / "templates" / "release-approval-record-template.json").is_file())

    def test_guard_exposes_machine_readable_quality_validation(self):
        from scripts import audit_guard

        self.assertTrue(hasattr(audit_guard, "validate_quality_package"))
        self.assertTrue(hasattr(audit_guard, "derive_technical_conclusion"))
        self.assertTrue(hasattr(audit_guard, "validate_external_release"))

    def test_standards_are_versioned_and_claim_language_is_non_certifying(self):
        skill_root = ROOT / "skills" / "ai-audit"
        standards = (skill_root / "references" / "audit-standards.md").read_text(
            encoding="utf-8"
        )
        report = (skill_root / "templates" / "report-template.md").read_text(
            encoding="utf-8"
        )

        for marker in (
            "ISO/IEC 25010:2023",
            "9特性",
            "ISO/IEC/IEEE 29119-2:2021",
            "ISO/IEC/IEEE 29119-3:2021",
            "NIST SP 800-218 SSDF v1.1",
            "OWASP MASVS v2.1.0",
            "OWASP ASVS v5.0.0",
        ):
            self.assertIn(marker, standards)
        self.assertNotIn("品質8特性", standards)
        self.assertNotIn("限定的保証", report)
        self.assertIn("限定範囲の技術的検証", report)
        self.assertIn("非認証", report)

    def test_skill_requires_requirement_level_traceability_and_safety_gate(self):
        skill = (ROOT / "skills" / "ai-audit" / "SKILL.md").read_text(encoding="utf-8")

        self.assertIn("quality-profile.json", skill)
        self.assertIn("requirements-matrix.csv", skill)
        self.assertIn("安全関連", skill)
        self.assertIn("専門規格", skill)
        self.assertIn("FAT", skill)
        self.assertIn("法定検査", skill)
        self.assertIn("validate-release", skill)
        self.assertIn("allowed_signers", skill)

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

    def test_sample_contains_quality_profile_and_requirement_matrix(self):
        audit = ROOT / "examples" / "memo-tool" / "audit"

        self.assertTrue((audit / "quality-profile.json").is_file())
        self.assertTrue((audit / "requirements-matrix.csv").is_file())

    def test_public_docs_describe_v1_2_without_inflated_assurance_language(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")

        for text in (readme, manual):
            self.assertIn("v1.2", text)
            self.assertIn("quality-profile.json", text)
            self.assertIn("requirements-matrix.csv", text)
            self.assertIn("安全関連", text)
            self.assertIn("validate-release", text)
            self.assertNotIn("限定的保証", text)
            self.assertNotIn("条件付き稼働可", text)
            self.assertNotIn("Codex独立監査", text)

        self.assertIn("個人開発者", readme)
        self.assertIn("セキュリティ担当", readme)


if __name__ == "__main__":
    unittest.main()
