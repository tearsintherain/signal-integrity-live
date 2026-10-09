"""
Signal Integrity Live — deterministic detection engine.

All events are synthetic.
This prototype deliberately demonstrates a detection failure caused by
an event-schema change.
"""

from copy import deepcopy


# Synthetic endpoint telemetry using the ORIGINAL schema.
ORIGINAL_EVENTS = [
    {
        "event_id": "EVT-001",
        "event_type": "process_start",
        "host": "WORKSTATION-01",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NoProfile -Command Get-Process",
    },
    {
        "event_id": "EVT-002",
        "event_type": "process_start",
        "host": "WORKSTATION-02",
        "process_name": "notepad.exe",
        "command_line": "notepad.exe",
    },
    {
        "event_id": "EVT-003",
        "event_type": "process_start",
        "host": "WORKSTATION-03",
        "process_name": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
    },
]

# The logging pipeline changes the field name from process_name
# to process.executable. The old rule no longer sees that field.
def introduce_schema_drift(events):
    changed = []

    for event in events:
        new_event = deepcopy(event)

        if "process_name" in new_event:
            new_event["process"] = {
                "executable": new_event.pop("process_name")
            }

        changed.append(new_event)

    return changed


# A deliberately simple rule:
# Alert when a PowerShell process starts.
#
# This is a synthetic demonstration rule, not a production detection.
DETECTION_RULE = {
    "id": "SIG-001",
    "name": "PowerShell Process Start",
    "description": "Detect a PowerShell process-start event.",
    "expected_field": "process_name",
    "expected_value": "powershell.exe",
}


def get_nested_value(event, field_path):
    """Read a field using a dotted path such as process.executable."""
    value = event
    for part in field_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def evaluate_event(event, rule=DETECTION_RULE):
    """Evaluate an event using a flat or nested field path."""
    actual_value = get_nested_value(event, rule["expected_field"])
    expected_value = rule["expected_value"]

    return (
        isinstance(actual_value, str)
        and isinstance(expected_value, str)
        and actual_value.lower() == expected_value.lower()
    )
def detect(events, rule=DETECTION_RULE):
    """Return the IDs of events that trigger the rule."""
    return [
        event["event_id"]
        for event in events
        if evaluate_event(event, rule)
    ]


def run_tests(events, rule=DETECTION_RULE):
    """
    Test the rule against known positive and negative examples.

    In a real deployment, fixtures would need careful curation and
    independent review. These fixtures are synthetic.
    """
    expected_positive = "EVT-001"
    expected_negative = {"EVT-002", "EVT-003"}

    alerts = set(detect(events, rule))

    positive_pass = expected_positive in alerts
    negative_pass = not bool(alerts & expected_negative)

    return {
        "positive_test": {
            "expected": expected_positive,
            "detected": expected_positive in alerts,
            "passed": positive_pass,
        },
        "negative_test": {
            "expected_no_alerts_for": sorted(expected_negative),
            "unexpected_alerts": sorted(alerts & expected_negative),
            "passed": negative_pass,
        },
        "overall_passed": positive_pass and negative_pass,
        "alerted_event_ids": sorted(alerts),
    }


def main():
    print("=" * 64)
    print("SIGNAL INTEGRITY LIVE — DETECTION REGRESSION DEMO")
    print("=" * 64)

    print("\n[1] Test original events against the original rule")
    baseline = run_tests(ORIGINAL_EVENTS)
    print(f"Alerts: {baseline['alerted_event_ids']}")
    print(f"Positive test: {'PASS' if baseline['positive_test']['passed'] else 'FAIL'}")
    print(f"Negative test: {'PASS' if baseline['negative_test']['passed'] else 'FAIL'}")
    print(f"Overall:       {'PASS' if baseline['overall_passed'] else 'FAIL'}")

    print("\n[2] Introduce a logging-schema change")
    changed_events = introduce_schema_drift(ORIGINAL_EVENTS)
    print("Changed field: process_name -> process.executable")

    print("\n[3] Run the unchanged rule against changed events")
    regression = run_tests(changed_events)
    print(f"Alerts: {regression['alerted_event_ids']}")
    print(f"Positive test: {'PASS' if regression['positive_test']['passed'] else 'FAIL'}")
    print(f"Negative test: {'PASS' if regression['negative_test']['passed'] else 'FAIL'}")
    print(f"Overall:       {'PASS' if regression['overall_passed'] else 'FAIL'}")

    print("\n[4] Diagnostic evidence for the AI")
    print(f"Rule expects field: {DETECTION_RULE['expected_field']}")
    print(f"Changed event fields: {list(changed_events[0].keys())}")
    print("Observed failure: expected PowerShell event did not trigger the rule.")

    print("\n" + "=" * 64)
    print("DEMO RESULT: schema drift caused a reproducible detection failure")
    print("=" * 64)


if __name__ == "__main__":
    main()
