"""Regression tests for installing StrmAssistant into a fresh configuration."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "strmassistanthelper.py"
SPEC = importlib.util.spec_from_file_location("strmassistanthelper", SCRIPT_PATH)
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


class InstallTests(unittest.TestCase):
    """Exercise installation and updates using temporary plugin directories."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.data_dir = root / "bundled"
        self.data_dir.mkdir()
        self.config_dir = root / "config"
        self.source_file = self.data_dir / "StrmAssistant.dll"
        self.source_file.write_bytes(b"bundled plugin")
        self.plugin_file = self.config_dir / "plugins" / "StrmAssistant.dll"
        self.config_file = self.config_dir / "plugins" / "configurations" / "Strm Assistant.json"
        self.installed_version = "2.0.0.27"
        paths = patch.multiple(helper, BASE_DATA_PATH=str(self.data_dir), BASE_CONFIG_PATH=str(self.config_dir))
        paths.start()
        self.addCleanup(paths.stop)
        versions = patch.object(helper, "get_file_version", side_effect=self.read_version)
        self.read_version_mock = versions.start()
        self.addCleanup(versions.stop)

    def read_version(self, file_path):
        """Model version lookup while rejecting reads of nonexistent DLLs."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(file_path)
        if path == self.source_file:
            return "2.0.0.30"
        return self.installed_version

    def write_config(self):
        """Create a configuration with Chinese search disabled."""
        self.config_file.parent.mkdir(parents=True)
        self.config_file.write_text(json.dumps({"ModOptions": {"EnhanceChineseSearch": False}}), encoding="utf-8")

    def test_first_install_creates_plugin_directory(self):
        """A fresh install copies the DLL without reading an absent old version."""
        helper.main()

        self.assertEqual(self.plugin_file.read_bytes(), self.source_file.read_bytes())
        self.read_version_mock.assert_called_once_with(str(self.source_file))
        self.assertFalse(self.config_file.exists())

    def test_first_install_enables_existing_config(self):
        """A missing DLL can be installed into a pre-extracted configuration."""
        self.write_config()

        helper.main()

        self.assertEqual(self.plugin_file.read_bytes(), self.source_file.read_bytes())
        self.assertTrue(json.loads(self.config_file.read_text(encoding="utf-8"))["ModOptions"]["EnhanceChineseSearch"])

    def test_updates_older_plugin(self):
        """Existing older plugins are still replaced and configured."""
        self.write_config()
        self.plugin_file.write_bytes(b"old plugin")

        helper.main()

        self.assertEqual(self.plugin_file.read_bytes(), self.source_file.read_bytes())
        self.assertTrue(json.loads(self.config_file.read_text(encoding="utf-8"))["ModOptions"]["EnhanceChineseSearch"])

    def test_preserves_equal_or_newer_plugin(self):
        """An installed equal or newer version is not overwritten."""
        self.plugin_file.parent.mkdir(parents=True)
        for version in ("2.0.0.30", "2.0.0.31"):
            with self.subTest(version=version):
                self.installed_version = version
                self.plugin_file.write_bytes(b"installed plugin")

                helper.main()

                self.assertEqual(self.plugin_file.read_bytes(), b"installed plugin")

    def test_failed_install_does_not_enable_config(self):
        """A copy failure must not enable a feature whose DLL was not installed."""
        self.write_config()

        with patch.object(helper.shutil, "copy2", side_effect=OSError("disk full")):
            helper.main()

        self.assertFalse(self.plugin_file.exists())
        self.assertFalse(json.loads(self.config_file.read_text(encoding="utf-8"))["ModOptions"]["EnhanceChineseSearch"])

    def test_failed_update_does_not_enable_config(self):
        """The update path also skips configuration when copying fails."""
        self.write_config()
        self.plugin_file.write_bytes(b"old plugin")

        with patch.object(helper.shutil, "copy2", side_effect=OSError("disk full")):
            helper.main()

        self.assertFalse(json.loads(self.config_file.read_text(encoding="utf-8"))["ModOptions"]["EnhanceChineseSearch"])

    def test_missing_bundled_version_does_not_install(self):
        """Unversioned bundled files are not copied into a fresh installation."""
        self.read_version_mock.side_effect = None
        self.read_version_mock.return_value = None

        helper.main()

        self.assertFalse(self.plugin_file.exists())


if __name__ == "__main__":
    unittest.main()
