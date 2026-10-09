import json
import streamlit as st

from detection_engine import (
    DETECTION_RULE,
    ORIGINAL_EVENTS,
    introduce_schema_drift,
    run_tests,
)
from ai_repair import ask_gemini, validate_patch
from clickhouse_store import log_event, recent_runs


st.set_page_config(
    page_title="Signal Integrity Live",
    page_icon="🛡️",
    layout="wide",
)

st.title("SIGNAL INTEGRITY LIVE")
st.caption(
    "AI-assisted detection regression diagnosis and repair"
)

st.markdown(
    """
    Security detections can silently fail when upstream logging schemas change.
    Signal Integrity Live reproduces a detection failure, diagnoses the change,
    proposes a repair, and verifies that the repair works.
    """
)

st.divider()

# Establish reproducible test data.
baseline_results = run_tests(ORIGINAL_EVENTS)
changed_events = introduce_schema_drift(ORIGINAL_EVENTS)
regression_results = run_tests(changed_events)

# Initialize UI state.
if "diagnosis" not in st.session_state:
    st.session_state.diagnosis = None
if "repair_results" not in st.session_state:
    st.session_state.repair_results = None
if "ai_error" not in st.session_state:
    st.session_state.ai_error = None
if "diagnostic_mode" not in st.session_state:
    st.session_state.diagnostic_mode = None

# Record initial baseline and regression once per Streamlit session.
if not st.session_state.get("initial_audit_recorded", False):
    baseline_passed = sum((
        baseline_results["positive_test"]["passed"],
        baseline_results["negative_test"]["passed"],
    ))
    regression_passed = sum((
        regression_results["positive_test"]["passed"],
        regression_results["negative_test"]["passed"],
    ))
    baseline_saved = log_event(
        "baseline",
        "PASS" if baseline_results["overall_passed"] else "FAIL",
        baseline_passed,
        2,
        {"source": "synthetic demonstration events"},
    )
    regression_saved = log_event(
        "schema_drift",
        "REGRESSION_REPRODUCED" if not regression_results["overall_passed"] else "NOT_REPRODUCED",
        regression_passed,
        2,
        {"changed_field": "process_name -> process.executable"},
    )
    st.session_state.initial_audit_recorded = True
    st.session_state.audit_storage_available = baseline_saved and regression_saved


# Top-level status indicators.
col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Baseline detection",
        "PASS" if baseline_results["overall_passed"] else "FAIL",
    )

with col2:
    st.metric(
        "After schema drift",
        "FAIL" if not regression_results["overall_passed"] else "PASS",
    )

with col3:
    repaired = st.session_state.repair_results
    st.metric(
        "Repair verification",
        (
            "PASS"
            if repaired and repaired["overall_passed"]
            else "NOT VERIFIED"
        ),
    )

st.divider()

# Stage 1: Baseline.
st.header("01 · Baseline")

with st.expander("Original detection rule", expanded=True):
    st.json(DETECTION_RULE)

baseline_col1, baseline_col2 = st.columns(2)

with baseline_col1:
    st.subheader("Synthetic event stream")
    st.dataframe(ORIGINAL_EVENTS, use_container_width=True)

with baseline_col2:
    st.subheader("Baseline test results")
    st.json(baseline_results)

if baseline_results["overall_passed"]:
    st.success("Original rule detects the expected PowerShell event.")
else:
    st.error("Baseline tests failed. Stop and investigate before continuing.")

st.divider()

# Stage 2: Regression.
st.header("02 · Schema drift")

st.markdown(
    """
    The simulated logging pipeline changes the event structure:

    `process_name` → `process.executable`

    The original rule still expects the old field, so the expected event
    should no longer trigger an alert.
    """
)

drift_col1, drift_col2 = st.columns(2)

with drift_col1:
    st.subheader("Events after schema drift")
    st.dataframe(changed_events, use_container_width=True)

with drift_col2:
    st.subheader("Regression test results")
    st.json(regression_results)

if not regression_results["overall_passed"]:
    st.error(
        "REGRESSION REPRODUCED: the positive detection test fails "
        "while the negative tests remain clean."
    )
else:
    st.warning(
        "The expected regression was not reproduced. Investigate before proceeding."
    )

st.divider()

# Stage 3: AI diagnosis.
st.header("03 · AI diagnosis")

st.write(
    "Gemini receives the synthetic events, original rule, and failed test "
    "evidence. Its response is treated as a proposal, not as proof."
)

if st.button(
    "Run AI diagnosis",
    type="primary",
    disabled=regression_results["overall_passed"],
):
    st.session_state.diagnosis = None
    st.session_state.repair_results = None
    st.session_state.ai_error = None
    st.session_state.diagnostic_mode = None

    with st.spinner("Requesting diagnosis from Gemini..."):
        try:
            diagnosis = ask_gemini(
                DETECTION_RULE,
                changed_events,
                regression_results,
            )
            st.session_state.diagnosis = diagnosis
            st.session_state.diagnostic_mode = "AI"
            saved = log_event(
                "diagnosis", "AI_PROPOSED", 0, 0,
                {"root_cause": str(diagnosis.get("root_cause", ""))[:1000]},
            )
            st.session_state.audit_storage_available = (
                saved and st.session_state.get("audit_storage_available", True)
            )
        except Exception as exc:
            st.session_state.ai_error = (
                f"{type(exc).__name__}: {exc}"
            )

if st.session_state.diagnosis:
    diagnosis = st.session_state.diagnosis

    st.subheader("Root cause")
    st.write(diagnosis["root_cause"])

    evidence_col, patch_col = st.columns(2)

    with evidence_col:
        st.subheader("Supporting evidence")
        for item in diagnosis["evidence"]:
            st.write(f"- {item}")

    with patch_col:
        st.subheader("Proposed rule patch")
        st.json(diagnosis["patch"])

    st.subheader("Limitations")
    for item in diagnosis["limitations"]:
        st.write(f"- {item}")

if st.session_state.ai_error:
    st.error(
        "Gemini diagnosis failed. The regression is still reproducible, "
        "but no AI diagnosis was received."
    )
    with st.expander("Technical error"):
        st.code(st.session_state.ai_error)

    st.info(
        "You can use the explicitly labeled manual fallback below to "
        "demonstrate deterministic verification. It is not an AI-generated repair."
    )

    if st.button("Use manual diagnostic fallback"):
        st.session_state.diagnosis = {
            "root_cause": (
                "Manual fallback: the event's process name moved into "
                "a nested process.executable field."
            ),
            "evidence": [
                "The original rule expects process_name.",
                "The changed positive event contains process.executable.",
                "The positive regression test fails with the original rule.",
            ],
            "patch": {
                "expected_field": "process.executable",
                "expected_value": "powershell.exe",
            },
            "limitations": [
                "This fallback was supplied by the application, not generated by Gemini.",
                "The test data is synthetic and does not establish production effectiveness.",
            ],
        }
        st.session_state.diagnostic_mode = "MANUAL FALLBACK"
        saved = log_event(
            "diagnosis", "MANUAL_FALLBACK", 0, 0,
            {"source": "application-provided fallback; not AI-generated"},
        )
        st.session_state.audit_storage_available = (
            saved and st.session_state.get("audit_storage_available", True)
        )
        st.session_state.repair_results = None
        st.rerun()

st.divider()

# Stage 4: Validate and verify the patch.
st.header("04 · Deterministic verification")

diagnosis = st.session_state.diagnosis

if diagnosis:
    mode = st.session_state.diagnostic_mode or "UNKNOWN"
    st.caption(f"Proposal source: {mode}")

    if st.button("Validate patch and run tests", type="primary"):
        st.session_state.repair_results = None

        try:
            validated_patch = validate_patch(
                diagnosis["patch"],
                changed_events,
            )

            repaired_rule = {
                **DETECTION_RULE,
                **validated_patch,
            }

            results = run_tests(changed_events, repaired_rule)

            st.session_state.repair_results = results
            st.session_state.repaired_rule = repaired_rule
            tests_passed = sum((
                results["positive_test"]["passed"],
                results["negative_test"]["passed"],
            ))
            saved = log_event(
                "repair_verification",
                "PASS" if results["overall_passed"] else "FAIL",
                tests_passed,
                2,
                {
                    "proposal_source": mode,
                    "repaired_rule": repaired_rule,
                    "alerted_event_ids": results.get("alerted_event_ids", []),
                },
            )
            st.session_state.audit_storage_available = (
                saved and st.session_state.get("audit_storage_available", True)
            )

        except Exception as exc:
            st.error(
                f"Patch rejected or verification failed: "
                f"{type(exc).__name__}: {exc}"
            )

    if st.session_state.repair_results:
        results = st.session_state.repair_results

        st.subheader("Repaired detection rule")
        st.json(st.session_state.repaired_rule)

        result_col1, result_col2 = st.columns(2)

        with result_col1:
            st.subheader("Positive test")
            st.json(results["positive_test"])

        with result_col2:
            st.subheader("Negative test")
            st.json(results["negative_test"])

        if results["overall_passed"]:
            st.success(
                "PATCH PASSED ALL DEMONSTRATION TESTS"
            )
        else:
            st.error(
                "PATCH FAILED VERIFICATION. Do not treat the repair as successful."
            )

        with st.expander("Complete verification report"):
            st.json(results)

else:
    st.info(
        "Run the AI diagnosis, or select the manual fallback if Gemini is unavailable, "
        "before validating a repair."
    )

st.divider()

st.header("05 · Persistent audit history")
st.caption(
    "Recent events stored in ClickHouse. Test data is synthetic; "
    "audit history does not establish production security effectiveness."
)

history = recent_runs(limit=25)
if history is None:
    st.warning(
        "ClickHouse audit history is currently unavailable. "
        "The detection demo can continue without persistence."
    )
elif history:
    st.dataframe(history, use_container_width=True, hide_index=True)
else:
    st.info("No audit events are available yet.")

st.caption(
    "Prototype demonstration · Synthetic events · "
    "AI proposals require deterministic verification · "
    "Not a production security guarantee"
)
