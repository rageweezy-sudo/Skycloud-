import tomllib
import unittest
from pathlib import Path


class LicenseTests(unittest.TestCase):
    def test_project_and_distribution_license(self):
        root = Path(__file__).resolve().parents[1]
        with (root / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source)["project"]
        self.assertEqual(project["license"], "MIT")
        self.assertIn("LICENSE", project["license-files"])
        notice = (root / "LICENSE").read_text(encoding="utf-8")
        self.assertTrue(notice.startswith("MIT License\n"))
        self.assertIn("Account Privacy contributors", notice)
        installer = (root / "packaging" / "installer.iss").read_text(encoding="utf-8")
        self.assertIn(r'Source: "..\LICENSE"; DestDir: "{app}"', installer)
        psl = root / "src" / "account_privacy" / "resources" / "public_suffix_list.dat"
        self.assertIn("Mozilla Public", psl.read_text(encoding="utf-8").splitlines()[0])
