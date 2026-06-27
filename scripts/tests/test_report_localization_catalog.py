from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import load_script_module


module = load_script_module("report_localization_catalog", "scripts/report_localization_catalog.py")


class LocalizationCatalogReportTests(unittest.TestCase):
    def test_report_finds_stale_missing_locale_and_plural_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_name:
            catalog = Path(temp_dir_name) / "Localizable.xcstrings"
            catalog.write_text(
                json.dumps(
                    {
                        "strings": {
                            "complete.entry": {
                                "localizations": {
                                    "en": {"stringUnit": {"state": "translated", "value": "Complete"}},
                                    "zh-Hans": {"stringUnit": {"state": "translated", "value": "Complete zh"}},
                                }
                            },
                            "stale.entry": {
                                "extractionState": "stale",
                                "localizations": {
                                    "en": {"stringUnit": {"state": "translated", "value": "Stale"}},
                                    "zh-Hans": {"stringUnit": {"state": "translated", "value": "Stale zh"}},
                                },
                            },
                            "missing.locale": {
                                "localizations": {
                                    "en": {"stringUnit": {"state": "new", "value": "Missing"}}
                                }
                            },
                            "plural.entry": {
                                "localizations": {
                                    "en": {
                                        "variations": {
                                            "plural": {
                                                "other": {"stringUnit": {"state": "translated", "value": "%lld items"}}
                                            }
                                        }
                                    },
                                    "zh-Hans": {
                                        "variations": {
                                            "plural": {
                                                "one": {"stringUnit": {"state": "translated", "value": "%lld item zh"}}
                                            }
                                        }
                                    },
                                }
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )

            report = module.analyze_catalog(catalog)
            codes = {(issue.key, issue.locale, issue.code) for issue in report.issues}

            self.assertIn(("stale.entry", "", "stale"), codes)
            self.assertIn(("missing.locale", "en", "untranslated"), codes)
            self.assertIn(("missing.locale", "zh-Hans", "missing-locale"), codes)
            self.assertIn(("plural.entry", "en", "missing-plural-one"), codes)
            self.assertIn(("plural.entry", "zh-Hans", "missing-plural-other"), codes)

    def test_markdown_report_is_summary_friendly(self) -> None:
        report = module.CatalogReport(path=Path("Localizable.xcstrings"), entry_count=1, issues=[])
        markdown = module.render_markdown([report])

        self.assertIn("# Localization Catalog Report", markdown)
        self.assertIn("No stale or incomplete required localizations found.", markdown)


if __name__ == "__main__":
    unittest.main()
