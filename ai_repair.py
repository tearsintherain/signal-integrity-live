"""Gemini-assisted detection diagnosis with deterministic verification."""

import json
import os
import sys

from dotenv import load_dotenv
from google import genai

from detection_engine import (
    DETECTION_RULE,
    ORIGINAL_EVENTS,
    detect,
    introduce_schema_drift,
    run_tests,
)

load_dotenv()

MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")


def get_nested_value(event, field_path):
    """Safely retrieve a value from a dotted event-field path."""
    value = event

    for part in field_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]

    return value


def validate_patch(patch, changed_events):
    """Allow only a field-path change supported by the event evidence."""
    if not isinstance(patch, dict):
        raise ValueError("Patch must be a JSON object.")

    if set(patch) != {"expected_field", "expected_value"}:
        raise ValueError("Unexpected patch fields.")

    field = patch["expected_field"]
    value = patch["expected_value"]

    if not isinstance(field, str) or not field:
        raise ValueError("expected_field must be a nonempty string.")

    if not isinstance(value, str) or not value:
        raise ValueError("expected_value must be a nonempty string.")

    # Restrict the patch to a field path actually present in an event.
    # Do not let the model invent arbitrary matching logic.
    matching_fields = []

    for event in changed_events:
        if get_nested_value(event, field) is not None:
            matching_fields.append(field)

    if not matching_fields:
        raise ValueError(
            f"Proposed field {field!r} does not exist in the event evidence."
        )

    # The patch must match the known positive event's actual value.
    positive_event = next(
        event for event in changed_events
        if event.get("event_id") == "EVT-001"
    )

    actual_value = get_nested_value(positive_event, field)

    if not isinstance(actual_value, str) or actual_value.lower() != value.lower():
        raise ValueError(
            "Proposed value does not match the known positive event."
        )

    return {
        "expected_field": field,
        "expected_value": value,
    }


def ask_gemini(rule, changed_events, failed_tests):
    """Ask Gemini for a diagnosis and a constrained field-path patch."""
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is missing from .env.")

    client = genai.Client(api_key=api_key)

    evidence = {
        "rule": rule,
        "failing_tests": failed_tests,
        "events": changed_events,
        "allowed_patch": {
            "expected_field": "A dotted field path present in an event",
            "expected_value": "The expected process name",
        },
    }

    prompt = f"""
You are diagnosing a synthetic security detection regression.

Analyze the supplied evidence. The detection rule used to read a field
that may have moved into a nested object.

Return ONLY a JSON object with these exact keys:
- root_cause: concise explanation
- evidence: list of specific observations from the supplied data
- patch: object with expected_field and expected_value
- limitations: list of uncertainties or limitations

Constraints:
- Do not propose executable code.
- Do not add new detection logic.
- Choose a field path actually present in the positive event.
- The expected value must match that event's process name.
- Do not claim that synthetic test results prove production protection.

Evidence:
{json.dumps(evidence, indent=2)}
"""

    # Prefer the configured model, then discover alternatives available
    # to this API key. Limit attempts to keep the demo moving.
    candidates = [MODEL]
    try:
        available = []
        for item in client.models.list():
            name = getattr(item, "name", "") or ""
            actions = getattr(item, "supported_actions", []) or []
            if name.startswith("models/"):
                name = name[len("models/"):]
            if name and "generateContent" in actions:
                available.append(name)

        preferred = [
            "gemini-3.8-flash",
            "gemini-3.5-flash-lite",
        ]
        for name in preferred + sorted(available):
            if name not in candidates and name in available:
                candidates.append(name)
            if len(candidates) >= 3:
                break
    except Exception as exc:
        print(
            "Model discovery unavailable; trying configured model only:",
            type(exc).__name__,
        )

    response = None
    last_error = None

    for candidate in candidates[:3]:
        try:
            print(f"Requesting diagnosis with model: {candidate}")
            response = client.models.generate_content(
                model=candidate,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )
            print(f"Diagnosis received from: {candidate}")
            break
        except Exception as exc:
            last_error = exc
            print(f"Model attempt failed: {type(exc).__name__}: {exc}")

    if response is None:
        raise RuntimeError(
            "No available Gemini model completed the diagnosis. "
            "The local regression evidence is still valid."
        ) from last_error

    result = json.loads(response.text)

    required = {"root_cause", "evidence", "patch", "limitations"}
    if not isinstance(result, dict) or set(result) != required:
        raise ValueError("Gemini returned an unexpected response structure.")

    if not isinstance(result["root_cause"], str):
        raise ValueError("Invalid root_cause.")

    if not isinstance(result["evidence"], list):
        raise ValueError("Invalid evidence list.")

    if not isinstance(result["limitations"], list):
        raise ValueError("Invalid limitations list.")

    return result


def main():
    changed_events = introduce_schema_drift(ORIGINAL_EVENTS)

    print("=" * 64)
    print("SIGNAL INTEGRITY LIVE — AI REPAIR")
    print("=" * 64)

    failed_tests = run_tests(changed_events)

    print("\n[1] Baseline regression")
    print(json.dumps(failed_tests, indent=2))

    if failed_tests["overall_passed"]:
        print("Unexpected result: the regression did not reproduce.")
        sys.exit(1)

    print(f"\n[2] Requesting diagnosis from {MODEL}...")

    try:
        diagnosis = ask_gemini(
            DETECTION_RULE,
            changed_events,
            failed_tests,
        )

        print("\nRoot cause:")
        print(diagnosis["root_cause"])

        print("\nEvidence:")
        for item in diagnosis["evidence"]:
            print(f"- {item}")

        print("\nLimitations:")
        for item in diagnosis["limitations"]:
            print(f"- {item}")

        validated_patch = validate_patch(
            diagnosis["patch"],
            changed_events,
        )

        print("\n[3] Proposed, validated patch")
        print(json.dumps(validated_patch, indent=2))

        repaired_rule = {
            **DETECTION_RULE,
            **validated_patch,
        }

        print("\n[4] Independent regression verification")
        verification = run_tests(changed_events, repaired_rule)
        print(json.dumps(verification, indent=2))

        if verification["overall_passed"]:
            print("\nRESULT: PATCH PASSED ALL DEMONSTRATION TESTS")
        else:
            print("\nRESULT: PATCH FAILED VERIFICATION")
            sys.exit(2)

        print(
            "\nScope: synthetic events and a constrained test harness. "
            "Production effectiveness is not established."
        )

    except Exception as exc:
        print(f"\nAI REPAIR FAILED: {type(exc).__name__}: {exc}")
        print("The original detection failure remains available for diagnosis.")
        sys.exit(1)


if __name__ == "__main__":
    main()
