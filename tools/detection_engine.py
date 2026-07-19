"""Small, dependency-free validator for the portfolio detection catalog."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DETECTIONS_DIR = ROOT / "detections"
FIXTURES_DIR = ROOT / "fixtures"

REQUIRED_FIELDS = {
    "id",
    "name",
    "status",
    "description",
    "log_source",
    "severity",
    "attack",
    "query",
    "match",
    "false_positives",
    "triage",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_STATUSES = {"experimental", "test", "stable"}


def load_detections() -> list[dict[str, Any]]:
    return [json.loads(path.read_text()) for path in sorted(DETECTIONS_DIR.rglob("*.json"))]


def load_fixtures() -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for path in sorted(FIXTURES_DIR.rglob("*.jsonl")):
        for line_number, raw_line in enumerate(path.read_text().splitlines(), start=1):
            if not raw_line.strip():
                continue
            event = json.loads(raw_line)
            event["_fixture_source"] = f"{path.relative_to(ROOT)}:{line_number}"
            fixtures.append(event)
    return fixtures


def field_value(event: dict[str, Any], field: str) -> Any:
    value: Any = event
    for component in field.split("."):
        if not isinstance(value, dict) or component not in value:
            return None
        value = value[component]
    return value


def condition_matches(event: dict[str, Any], condition: dict[str, Any]) -> bool:
    actual = field_value(event, condition["field"])
    operator = condition["operator"]

    if actual is None:
        return False
    if operator == "equals":
        return actual == condition["value"]
    if operator == "iequals":
        return str(actual).casefold() == str(condition["value"]).casefold()
    if operator == "in":
        return actual in condition["values"]
    if operator == "endswith":
        return str(actual).casefold().endswith(str(condition["value"]).casefold())
    if operator == "contains_any":
        candidate = str(actual).casefold()
        return any(str(value).casefold() in candidate for value in condition["values"])
    if operator == "not_contains_any":
        candidate = str(actual).casefold()
        return not any(str(value).casefold() in candidate for value in condition["values"])
    raise ValueError(f"Unsupported operator: {operator}")


def detection_matches(detection: dict[str, Any], event: dict[str, Any]) -> bool:
    rules = detection["match"]
    all_conditions = rules.get("all", [])
    any_conditions = rules.get("any", [])
    none_conditions = rules.get("none", [])

    return (
        all(condition_matches(event, condition) for condition in all_conditions)
        and (not any_conditions or any(condition_matches(event, condition) for condition in any_conditions))
        and not any(condition_matches(event, condition) for condition in none_conditions)
    )


def validate_catalog(
    detections: list[dict[str, Any]], fixtures: list[dict[str, Any]]
) -> list[str]:
    errors: list[str] = []
    ids: set[str] = set()

    for detection in detections:
        detection_id = detection.get("id", "<missing-id>")
        missing = sorted(REQUIRED_FIELDS - detection.keys())
        if missing:
            errors.append(f"{detection_id}: missing fields {', '.join(missing)}")
        if detection_id in ids:
            errors.append(f"{detection_id}: duplicate id")
        ids.add(detection_id)
        if not re.fullmatch(r"[A-Z][A-Z0-9-]+", detection_id):
            errors.append(f"{detection_id}: invalid id format")
        if detection.get("severity") not in VALID_SEVERITIES:
            errors.append(f"{detection_id}: invalid severity")
        if detection.get("status") not in VALID_STATUSES:
            errors.append(f"{detection_id}: invalid status")
        if not detection.get("false_positives"):
            errors.append(f"{detection_id}: false-positive guidance is required")
        if not detection.get("triage"):
            errors.append(f"{detection_id}: triage guidance is required")

        attack = detection.get("attack", {})
        attack_id = attack.get("id", "")
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", attack_id):
            errors.append(f"{detection_id}: invalid ATT&CK id")
        attack_path = attack_id.replace(".", "/")
        if attack_id and attack_path not in attack.get("url", ""):
            errors.append(f"{detection_id}: ATT&CK URL does not match id")
        if not attack.get("mapping_condition"):
            errors.append(f"{detection_id}: conditional ATT&CK rationale is required")

        query = detection.get("query", {})
        if query.get("language") != "spl":
            errors.append(f"{detection_id}: only SPL examples are currently supported")
        query_text = query.get("text", "")
        if "index=*" in query_text:
            errors.append(f"{detection_id}: broad index=* query is not allowed")
        if "index=<configured-index>" not in query_text:
            errors.append(f"{detection_id}: query must require an explicit index")

        try:
            for group in ("all", "any", "none"):
                for condition in detection.get("match", {}).get(group, []):
                    condition_matches({}, condition)
        except (KeyError, ValueError) as exc:
            errors.append(f"{detection_id}: invalid match condition: {exc}")

    for fixture in fixtures:
        fixture_id = fixture.get("fixture_id", fixture.get("_fixture_source", "<unknown>"))
        expected = set(fixture.get("expected_detection_ids", []))
        unknown = sorted(expected - ids)
        if unknown:
            errors.append(f"{fixture_id}: unknown expected ids {', '.join(unknown)}")

    return errors


def evaluate(
    detections: list[dict[str, Any]], fixtures: list[dict[str, Any]]
) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    false_positive_count = 0
    false_negative_count = 0
    match_count = 0

    for fixture in fixtures:
        expected = sorted(set(fixture.get("expected_detection_ids", [])))
        observed = sorted(
            detection["id"]
            for detection in detections
            if detection_matches(detection, fixture)
        )
        false_positives = sorted(set(observed) - set(expected))
        false_negatives = sorted(set(expected) - set(observed))
        false_positive_count += len(false_positives)
        false_negative_count += len(false_negatives)
        match_count += len(observed)
        cases.append(
            {
                "fixture_id": fixture["fixture_id"],
                "expected": expected,
                "observed": observed,
                "false_positives": false_positives,
                "false_negatives": false_negatives,
            }
        )

    return {
        "catalog": {
            "detection_count": len(detections),
            "fixture_count": len(fixtures),
            "observed_match_count": match_count,
        },
        "validation": {
            "false_positive_count": false_positive_count,
            "false_negative_count": false_negative_count,
            "passed": false_positive_count == 0 and false_negative_count == 0,
        },
        "cases": cases,
    }
