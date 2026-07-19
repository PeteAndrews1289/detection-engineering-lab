from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from detection_engine import (  # noqa: E402
    condition_matches,
    detection_matches,
    evaluate,
    load_detections,
    load_fixtures,
    validate_catalog,
)


class DetectionEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.detections = load_detections()
        cls.fixtures = load_fixtures()

    def test_catalog_is_structurally_valid(self) -> None:
        self.assertEqual(validate_catalog(self.detections, self.fixtures), [])

    def test_fixture_expectations_match_observed_results(self) -> None:
        results = evaluate(self.detections, self.fixtures)
        self.assertTrue(results["validation"]["passed"])
        self.assertEqual(results["validation"]["false_positive_count"], 0)
        self.assertEqual(results["validation"]["false_negative_count"], 0)

    def test_catalog_contains_cloud_and_endpoint_coverage(self) -> None:
        ids = {detection["id"] for detection in self.detections}
        self.assertEqual(
            ids,
            {"AWS-IAM-001", "AWS-ROOT-001", "ENDPOINT-LSASS-001", "ENDPOINT-PS-001"},
        )

    def test_nested_cloudtrail_fields_are_resolved(self) -> None:
        event = {"userIdentity": {"type": "Root"}}
        condition = {"field": "userIdentity.type", "operator": "equals", "value": "Root"}
        self.assertTrue(condition_matches(event, condition))

    def test_contains_any_is_case_insensitive(self) -> None:
        event = {"CommandLine": "PowerShell.EXE -EncodedCommand TEST"}
        condition = {
            "field": "CommandLine",
            "operator": "contains_any",
            "values": ["-encodedcommand"],
        }
        self.assertTrue(condition_matches(event, condition))

    def test_missing_fields_fail_closed(self) -> None:
        condition = {"field": "missing", "operator": "equals", "value": "x"}
        self.assertFalse(condition_matches({}, condition))

    def test_allowlisted_lsass_source_does_not_match(self) -> None:
        detection = next(d for d in self.detections if d["id"] == "ENDPOINT-LSASS-001")
        fixture = next(f for f in self.fixtures if f["fixture_id"] == "endpoint-lsass-benign")
        self.assertFalse(detection_matches(detection, fixture))

    def test_benign_powershell_does_not_match(self) -> None:
        detection = next(d for d in self.detections if d["id"] == "ENDPOINT-PS-001")
        fixture = next(f for f in self.fixtures if f["fixture_id"] == "endpoint-powershell-benign")
        self.assertFalse(detection_matches(detection, fixture))


if __name__ == "__main__":
    unittest.main()
