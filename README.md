# Signal Integrity Live

**AI-assisted security detection regression diagnosis and repair validation.**

Signal Integrity Live is a cybersecurity prototype developed for Erebus Security. It demonstrates how AI can help diagnose and validate repairs when security detections break because upstream logging schemas change.

## What It Does

Security detection rules depend on consistent event data. When a logging pipeline changes a field name or structure, a detection can silently stop working.

Signal Integrity Live demonstrates a workflow to:

1. Establish a baseline for a security detection.
2. Simulate an upstream schema change.
3. Reproduce the resulting detection failure.
4. Use Google's Gemini AI to diagnose the issue.
5. Validate a constrained repair proposal.
6. Run positive and negative regression tests.
7. Record workflow events in ClickHouse.
8. Display the results in a Streamlit dashboard.

## Technology

- Python
- Streamlit
- Google Gemini API
- ClickHouse
- Deterministic regression testing

## Architecture

The Streamlit dashboard coordinates the demonstration.

- `app.py` — interactive dashboard and workflow.
- `detection_engine.py` — synthetic events, detection rules, schema drift, and regression tests.
- `ai_repair.py` — Gemini diagnosis and repair proposal validation.
- `clickhouse_store.py` — audit-event storage and history retrieval.
- `gemini_smoke_test.py` — Gemini integration smoke test.
- `requirements.txt` — Python dependencies.
- `.env.example` — example configuration.

## Installation

Clone the repository:

```bash
git clone https://github.com/tearsintherain/signal-integrity-live.git
cd signal-integrity-live
