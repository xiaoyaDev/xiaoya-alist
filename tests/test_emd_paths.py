"""Exercise the crawler directory menu without running installer side effects."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "all_in_one.sh"
MENU_STUBS = r"""
clear() { :; }
touch_chmod() { touch "$1"; }
sedsh() {
    local temporary_file
    temporary_file=$(mktemp)
    sed "$1" "$2" > "$temporary_file"
    cat "$temporary_file" > "$2"
    rm -f "$temporary_file"
}
"""


class CrawlerPathMenuTests(unittest.TestCase):
    """Test default categories while preserving legacy and custom configuration."""

    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("function xiaoya_emd_pathlib()")
        end = source.index("function install_xiaoya_emd()", start)
        cls.menu_functions = source[start:end]

    def run_menu(self, commands, initial=None, mode="install"):
        """Return saved paths and output after interacting with the actual menu."""
        with tempfile.TemporaryDirectory() as directory:
            media = Path(directory)
            name = "pathlib.txt" if mode == "install" else "once_pathlib.txt"
            config = media / name
            if initial is not None:
                config.write_text(initial, encoding="utf-8")
            command = MENU_STUBS + self.menu_functions + '\nxiaoya_emd_pathlib "$1" "$2"\n'
            result = subprocess.run(
                ["bash", "-c", command, "menu-test", mode, str(media)],
                input=commands,
                capture_output=True,
                text=True,
                encoding="utf-8",
                env={**os.environ, "LC_ALL": "C"},
                timeout=5,
                check=True,
            )
            return config.read_text(encoding="utf-8").splitlines(), result.stdout

    def test_default_choices_omit_obsolete_test_category(self):
        """Remove the old category while keeping the separate picture demo."""
        paths, output = self.run_menu("0\n")
        self.assertEqual(paths, ["每日更新/", "纪录片（已刮削）/"])
        self.assertNotIn("、测试/", output)
        self.assertIn("9、📺画质演示测试（4K，8K，HDR，Dolby）/（未选中）", output)

    def test_legacy_category_is_preserved_as_custom(self):
        """Keep saved paths for users of other crawler versions or servers."""
        paths, output = self.run_menu("0\n", "每日更新/\n测试/\n")
        self.assertEqual(paths, ["每日更新/", "测试/"])
        self.assertIn("10、测试/（用户自定义）（已选中）", output)

    def test_legacy_category_can_be_deselected(self):
        """Allow removing the legacy item from the appended custom choices."""
        paths, _ = self.run_menu("10\n0\n", "每日更新/\n测试/\n")
        self.assertEqual(paths, ["每日更新/"])

    def test_custom_subdirectory_is_preserved(self):
        """Keep nested paths and spaces beneath a media category."""
        paths, _ = self.run_menu("'电影/豆瓣 top 1000部/'\n0\n")
        self.assertIn("电影/豆瓣 top 1000部/", paths)

    def test_custom_categories_are_not_globally_restricted(self):
        """Do not impose one crawler version's allowlist on custom input."""
        paths, _ = self.run_menu("'测试/' '115/' 'PikPak/'\n0\n")
        for path in ("测试/", "115/", "PikPak/"):
            self.assertIn(path, paths)

    def test_once_menu_keeps_picture_demo_choice(self):
        """Apply the same default categories to a one-off synchronization."""
        paths, _ = self.run_menu("9\n0\n", mode="once")
        self.assertEqual(paths, ["📺画质演示测试（4K，8K，HDR，Dolby）/"])


if __name__ == "__main__":
    unittest.main()
