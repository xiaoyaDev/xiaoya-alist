"""Exercise the crawler directory menu without running installer side effects."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "all_in_one.sh"
MENU_STUBS = r"""
clear() { :; }
ERROR() { printf '%s\n' "$1"; }
WARN() { printf '%s\n' "$1"; }
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
    """Test real menu input, including configurations saved by older installers."""

    @classmethod
    def setUpClass(cls):
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("function xiaoya_emd_pathlib()")
        helper_start = source.find("function xiaoya_emd_path_supported()")
        if 0 <= helper_start < start:
            start = helper_start
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
                env={**os.environ, "LC_ALL": "C.UTF-8"},
                timeout=5,
                check=True,
            )
            return config.read_text(encoding="utf-8").splitlines(), result.stdout

    def test_default_choices_match_crawler_roots(self):
        """Offer supported roots without the obsolete test category."""
        paths, output = self.run_menu("0\n")
        self.assertEqual(paths, ["每日更新/", "纪录片（已刮削）/"])
        self.assertNotIn("、测试/", output)
        self.assertIn("、115/", output)
        self.assertIn("、PikPak/", output)

    def test_legacy_invalid_path_must_be_deselected_before_saving(self):
        """Do not silently save an old configuration that the crawler rejects."""
        paths, output = self.run_menu("0\n12\n0\n", "每日更新/\n测试/\n")
        self.assertEqual(paths, ["每日更新/"])
        self.assertIn("爬虫不支持目录：测试/", output)

    def test_invalid_custom_root_is_not_written(self):
        """Reject an unsupported category entered as a custom path."""
        paths, output = self.run_menu("'测试/'\n0\n")
        self.assertNotIn("测试/", paths)
        self.assertIn("爬虫不支持目录：测试/", output)

    def test_supported_custom_subdirectory_is_preserved(self):
        """Keep nested paths and spaces beneath a supported category."""
        paths, _ = self.run_menu("'电影/豆瓣 top 1000部/'\n0\n")
        self.assertIn("电影/豆瓣 top 1000部/", paths)

    def test_cloud_roots_are_builtin_choices(self):
        """Recognize both cloud categories without marking them as custom."""
        paths, output = self.run_menu("10 11\n0\n")
        self.assertIn("115/", paths)
        self.assertIn("PikPak/", paths)
        self.assertNotIn("115/（已选中）（用户自定义）", output)
        self.assertNotIn("PikPak/（已选中）（用户自定义）", output)

    def test_empty_selection_cannot_be_saved(self):
        """Require a selection and allow resetting to the default categories."""
        paths, output = self.run_menu("2 6\n0\n101\n0\n")
        self.assertEqual(paths, ["每日更新/", "纪录片（已刮削）/"])
        self.assertIn("请至少选择一个爬取目录", output)

    def test_once_menu_rejects_invalid_custom_root(self):
        """Apply the same validation when configuring a one-off sync."""
        paths, output = self.run_menu("'测试/' '电影/经典/'\n0\n", mode="once")
        self.assertEqual(paths, ["电影/经典/"])
        self.assertIn("爬虫不支持目录：测试/", output)


if __name__ == "__main__":
    unittest.main()
