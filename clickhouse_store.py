"""Optional ClickHouse audit storage for Signal Integrity Live."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).with_name(".env"), override=False)


def _client():
    import clickhouse_connect

    mode = os.getenv("CLICKHOUSE_MODE", "local").strip().lower()

    if mode == "cloud":
        return clickhouse_connect.get_client(
            host=os.environ["CLICKHOUSE_CLOUD_HOST"].strip(),
            port=int(os.getenv("CLICKHOUSE_CLOUD_PORT", "8443")),
            secure=True,
            username=os.environ["CLICKHOUSE_CLOUD_USER"],
            password=os.environ["CLICKHOUSE_CLOUD_PASSWORD"],
            database=os.getenv("CLICKHOUSE_CLOUD_DB", "signal_integrity"),
            connect_timeout=10,
            send_receive_timeout=15,
        )

    if mode == "local":
        return clickhouse_connect.get_client(
            host=os.getenv("CLICKHOUSE_HOST", "127.0.0.1"),
            port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            secure=os.getenv("CLICKHOUSE_SECURE", "false").lower()
                in {"1", "true", "yes"},
            username=os.environ["CLICKHOUSE_USER"],
            password=os.environ["CLICKHOUSE_PASSWORD"],
            database=os.getenv("CLICKHOUSE_DB", "signal_integrity"),
            connect_timeout=2,
            send_receive_timeout=5,
        )

    raise ValueError("CLICKHOUSE_MODE must be 'cloud' or 'local'")


def log_event(stage, status, tests_passed=0, tests_total=0, details=None):
    """Store one event. Return False instead of disrupting the demo."""
    client = None
    try:
        client = _client()
        client.insert(
            "detection_runs",
            [[
                str(uuid4()),
                datetime.now(timezone.utc),
                str(stage)[:100],
                str(status)[:100],
                max(0, int(tests_passed)),
                max(0, int(tests_total)),
                json.dumps(details or {}, ensure_ascii=False, default=str),
            ]],
            column_names=[
                "run_id",
                "event_time",
                "stage",
                "status",
                "tests_passed",
                "tests_total",
                "details",
            ],
        )
        return True
    except Exception:
        return False
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def recent_runs(limit=25):
    """Return recent audit events, or an empty list if storage is unavailable."""
    client = None
    try:
        client = _client()
        result = client.query(
            """
            SELECT
                event_time,
                stage,
                status,
                tests_passed,
                tests_total,
                details
            FROM detection_runs
            ORDER BY event_time DESC
            LIMIT {limit:UInt32}
            """,
            parameters={"limit": max(1, min(int(limit), 100))},
        )
        return [
            {
                "Time (UTC)": row[0],
                "Stage": row[1],
                "Status": row[2],
                "Tests passed": row[3],
                "Tests total": row[4],
                "Details": row[5],
            }
            for row in result.result_rows
        ]
    except Exception:
        return None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
