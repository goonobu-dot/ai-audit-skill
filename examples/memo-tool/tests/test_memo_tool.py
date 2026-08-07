import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


DEFAULT_TOOL = Path(__file__).resolve().parents[1] / "memo.py"
TOOL_PATH = Path(os.environ.get("MEMO_TOOL_PATH", DEFAULT_TOOL)).resolve()


def run_tool(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL_PATH), *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


class MemoToolAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "memos").mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_search_returns_matching_lines(self):
        (self.root / "memos" / "today.txt").write_text("meeting: alpha\nother\n", encoding="utf-8")

        result = run_tool(self.root, "search", "alpha")

        self.assertEqual(0, result.returncode)
        self.assertIn("today.txt:1: meeting: alpha", result.stdout)

    def test_search_preserves_trailing_spaces(self):
        (self.root / "memos" / "spacing.txt").write_text("alpha  \n", encoding="utf-8")

        result = run_tool(self.root, "search", "alpha")

        self.assertEqual(0, result.returncode)
        self.assertIn("spacing.txt:1: alpha  \n", result.stdout)

    def test_search_rejects_empty_keyword(self):
        result = run_tool(self.root, "search", "")

        self.assertEqual(1, result.returncode)
        self.assertIn("空", result.stdout)

    def test_archive_moves_instead_of_deleting(self):
        source = self.root / "memos" / "old.txt"
        source.write_text("keep me\n", encoding="utf-8")
        os.utime(source, (1, 1))

        result = run_tool(self.root, "archive", "30")

        self.assertEqual(0, result.returncode)
        self.assertFalse(source.exists())
        self.assertEqual("keep me\n", (self.root / "archive" / "old.txt").read_text(encoding="utf-8"))

    def test_archive_rejects_negative_days(self):
        result = run_tool(self.root, "archive", "-1")

        self.assertEqual(1, result.returncode)
        self.assertIn("1〜36500", result.stdout)

    def test_archive_preserves_existing_destination(self):
        source = self.root / "memos" / "old.txt"
        source.write_text("new\n", encoding="utf-8")
        os.utime(source, (1, 1))
        (self.root / "archive").mkdir()
        (self.root / "archive" / "old.txt").write_text("existing\n", encoding="utf-8")

        result = run_tool(self.root, "archive", "30")

        self.assertEqual(0, result.returncode)
        self.assertEqual("existing\n", (self.root / "archive" / "old.txt").read_text(encoding="utf-8"))
        self.assertEqual("new\n", (self.root / "archive" / "old.1.txt").read_text(encoding="utf-8"))

    def test_symlinked_memo_directory_is_rejected(self):
        real_dir = self.root / "real-memos"
        real_dir.mkdir()
        (self.root / "memos").rmdir()
        (self.root / "memos").symlink_to(real_dir, target_is_directory=True)

        result = run_tool(self.root, "search", "anything")

        self.assertEqual(1, result.returncode)
        self.assertIn("シンボリックリンク", result.stdout)

    def test_symlinked_memo_file_is_reported_as_failure(self):
        outside = self.root / "outside.txt"
        outside.write_text("private\n", encoding="utf-8")
        (self.root / "memos" / "linked.txt").symlink_to(outside)

        result = run_tool(self.root, "search", "private")

        self.assertEqual(1, result.returncode)
        self.assertNotIn("private", result.stdout)

    def test_extra_arguments_are_rejected(self):
        result = run_tool(self.root, "search", "word", "extra")

        self.assertEqual(1, result.returncode)
        self.assertIn("usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
