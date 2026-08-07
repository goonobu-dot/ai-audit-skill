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

    def test_public_guides_cover_onboarding_audit_notes_freelance_and_privacy(self):
        required_guides = {
            "getting-started.md": "5分",
            "audit-notes.md": "監査内容の詳しい備考",
            "freelance-playbook.md": "説明できる工程",
            "privacy-checklist.md": "公開前プライバシー",
            "github-growth-guide.md": "Star",
        }

        for filename, marker in required_guides.items():
            guide = ROOT / "docs" / filename
            self.assertTrue(guide.is_file(), filename)
            self.assertIn(marker, guide.read_text(encoding="utf-8"), filename)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        for filename in required_guides:
            self.assertIn(filename.removesuffix(".md") + ".html", readme)
        for filename in required_guides:
            rendered_url = f"{filename.removesuffix('.md')}.html"
            self.assertIn(rendered_url, manual)

    def test_public_guides_are_generated_as_html_pages(self):
        guide_names = (
            "getting-started",
            "audit-notes",
            "freelance-playbook",
            "privacy-checklist",
            "github-growth-guide",
        )
        layout = ROOT / "docs" / "_layouts" / "guide.html"
        stylesheet = ROOT / "docs" / "assets" / "guide.css"

        self.assertTrue(layout.is_file())
        self.assertTrue(stylesheet.is_file())
        layout_text = layout.read_text(encoding="utf-8")
        self.assertIn("{{ content }}", layout_text)
        self.assertIn("guide.css", layout_text)

        for name in guide_names:
            source = (ROOT / "docs" / f"{name}.md").read_text(encoding="utf-8")
            self.assertTrue(source.startswith("---\n"), name)
            self.assertIn("layout: guide", source, name)
            self.assertIn(f"permalink: /{name}.html", source, name)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        manual = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        for name in guide_names:
            public_url = f"https://goonobu-dot.github.io/ai-audit-skill/{name}.html"
            self.assertIn(public_url, readme, name)
            self.assertIn(f"{name}.html", manual, name)

    def test_client_security_assurance_brief_is_complete_and_linked(self):
        page = ROOT / "docs" / "client-security-assurance.html"
        stylesheet = ROOT / "docs" / "assets" / "client-security-assurance.css"

        self.assertTrue(page.is_file())
        self.assertTrue(stylesheet.is_file())

        page_text = page.read_text(encoding="utf-8")
        for marker in (
            "個人開発者による納品前技術監査",
            "第三者機関による独立監査",
            "提案・見積もり",
            "要求・監査範囲の合意",
            "修正・全体再検証",
            "第三者監査への引継ぎパック",
            "提案書に使える説明文",
            "本資料は第三者監査を代替しません",
            "quality-profile.json",
            "unverified-ledger.md",
            "seal.json",
        ):
            self.assertIn(marker, page_text)

        self.assertIn('href="assets/client-security-assurance.css"', page_text)
        self.assertIn('href="https://github.com/goonobu-dot/ai-audit-skill"', page_text)

        css = stylesheet.read_text(encoding="utf-8")
        self.assertIn("@media print", css)
        self.assertIn("@media (max-width: 760px)", css)
        self.assertIn("td:nth-child(1)::before", css)
        self.assertIn('content: "第三者監査での用途"', css)
        self.assertIn("display: table-header-group", css)
        self.assertIn("break-inside: avoid", css)

        linked_files = (
            ROOT / "README.md",
            ROOT / "docs" / "index.html",
            ROOT / "docs" / "_layouts" / "guide.html",
            ROOT / "docs" / "freelance-playbook.md",
        )
        for linked_file in linked_files:
            self.assertIn(
                "client-security-assurance.html",
                linked_file.read_text(encoding="utf-8"),
                linked_file.name,
            )

    def test_public_material_does_not_expose_local_paths_or_private_email(self):
        public_files = [
            ROOT / "README.md",
            ROOT / "CONTRIBUTING.md",
            *sorted((ROOT / "docs").glob("*.md")),
            ROOT / "docs" / "index.html",
        ]
        forbidden_markers = ("/Users/", "/private/tmp/")
        private_email = re.compile(
            r"[A-Z0-9._%+-]+@(?!example\.invalid\b)(?!users\.noreply\.github\.com\b)"
            r"[A-Z0-9.-]+\.[A-Z]{2,}",
            re.IGNORECASE,
        )

        for path in public_files:
            text = path.read_text(encoding="utf-8")
            for marker in forbidden_markers:
                self.assertNotIn(marker, text, f"{marker!r} found in {path}")
            self.assertIsNone(private_email.search(text), f"private email found in {path}")

        manual = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("公開された品質・セキュリティ標準", manual)

    def test_public_documentation_passes_artifact_scan(self):
        from scripts.audit_guard import scan_artifacts

        self.assertEqual([], scan_artifacts(ROOT / "docs"))


if __name__ == "__main__":
    unittest.main()
