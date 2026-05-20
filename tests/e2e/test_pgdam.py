"""
pgDAM End-to-End Test Suite
============================
Prerequisites:
    pip install -r tests/e2e/requirements.txt

Usage:
    # Run against a live cluster (default)
    pytest tests/e2e/test_pgdam.py -v

    # Run with custom connection settings
    PGDAM_PG_HOST=localhost PGDAM_ES_URL=http://localhost:9200 pytest tests/e2e/test_pgdam.py -v

Notes:
    - All tests share a single persistent Postgres connection (pg_conn fixture).
      This is intentional: the agent registers a PID in PID_INFO when it first
      sees the process. Short-lived connections spawn and exit so fast that the
      PID is never registered, causing every event to be marked "incomplete" and
      dropped by the processor. A persistent connection gives the agent time to
      register the PID before any test query fires.
"""

import os
import time
import random
import pytest
import psycopg2
import requests
from requests.auth import HTTPBasicAuth

# ── Connection settings (override via env vars) ────────────────────────────────

PG_HOST = os.getenv("PGDAM_PG_HOST", "localhost")
PG_PORT = int(os.getenv("PGDAM_PG_PORT", "5432"))
PG_USER = os.getenv("PGDAM_PG_USER", "postgres")
PG_PASS = os.getenv("PGDAM_PG_PASS", "postgres")
PG_DB   = os.getenv("PGDAM_PG_DB",   "postgres")

ES_URL  = os.getenv("PGDAM_ES_URL",  "http://localhost:9200")
ES_USER = os.getenv("PGDAM_ES_USER", "elastic")
ES_PASS = os.getenv("PGDAM_ES_PASS", "pgdam-elastic-pass")

ES_POLL_TIMEOUT  = int(os.getenv("PGDAM_ES_POLL_TIMEOUT",  "15"))
ES_POLL_INTERVAL = float(os.getenv("PGDAM_ES_POLL_INTERVAL", "1"))

# How long to wait after opening the persistent connection before firing
# any queries — gives the agent time to register the PID in PID_INFO.
PID_REGISTRATION_WAIT = float(os.getenv("PGDAM_PID_WAIT", "3"))


# ── Helpers ────────────────────────────────────────────────────────────────────

def unique_id() -> int:
    """
    Generate a unique 9-digit integer to embed as a marker in SQL queries.
    Using an integer instead of a SQL comment because PostgreSQL strips
    comments before pg_parse_query sees them, so comment-based markers
    never reach Elasticsearch.
    """
    return random.randint(100_000_000, 999_999_999)


def run(conn, sql: str):
    """Execute SQL on an existing connection, swallowing DB-level errors."""
    cur = conn.cursor()
    try:
        cur.execute(sql)
    except Exception as e:
        print(f"\nrun() error: {e}")
        conn.rollback()
    finally:
        cur.close()


def es_auth():
    return HTTPBasicAuth(ES_USER, ES_PASS)


def poll_es_for(raw_sql_fragment: str, timeout: int = ES_POLL_TIMEOUT) -> dict | None:
    """
    Poll Elasticsearch until a document whose raw_sql contains
    raw_sql_fragment appears, or timeout is reached.
    Returns the matching document's _source, or None on timeout.

    No sort is applied — timestamp is mapped as text in this index
    and cannot be sorted without enabling fielddata.
    """
    deadline = time.time() + timeout
    query = {
        "query": {"match_phrase": {"raw_sql": raw_sql_fragment}},
        "size": 1
    }
    while time.time() < deadline:
        resp = requests.post(
            f"{ES_URL}/pgdam-audit-*/_search",
            json=query,
            auth=es_auth(),
            timeout=5
        )
        if resp.status_code == 200:
            hits = resp.json().get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_source"]
        time.sleep(ES_POLL_INTERVAL)
    return None


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def wait_for_es():
    """Block until Elasticsearch is reachable before running any tests."""
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            r = requests.get(ES_URL, auth=es_auth(), timeout=3)
            if r.status_code == 200:
                return
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(2)
    pytest.fail("Elasticsearch not reachable after 30s — is the cluster running?")


@pytest.fixture(scope="session")
def pg_conn():
    """
    Single persistent Postgres connection shared across the entire test session.

    Persistent connection is required because the pgDAM agent registers a PID
    in PID_INFO when it first discovers the process. Short-lived connections
    (one per query) spawn and exit faster than the agent's reconcile interval,
    so those PIDs are never registered and every event is marked incomplete
    and dropped. A single long-lived connection is registered once and all
    subsequent queries from it are captured correctly.

    A 3-second sleep after connect gives the agent time to register the PID
    before the first test query fires.
    """
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT,
        user=PG_USER, password=PG_PASS, dbname=PG_DB
    )
    conn.autocommit = True

    # Create test table
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT)")
    cur.execute("INSERT INTO users (name) SELECT 'Alice' WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Alice')")
    cur.execute("INSERT INTO users (name) SELECT 'Bob' WHERE NOT EXISTS (SELECT 1 FROM users WHERE name = 'Bob')")
    cur.close()

    # Wait for agent to register this PID in PID_INFO
    print(f"\nWaiting {PID_REGISTRATION_WAIT}s for agent to register PID...")
    time.sleep(PID_REGISTRATION_WAIT)

    yield conn
    conn.close()


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestCapture:
    """Basic capture: verify events reach Elasticsearch at all."""

    def test_normal_query_is_captured(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = 1 AND 1={marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None, "Query was not captured in Elasticsearch"
        assert doc["event_type"] == "user_query"
        assert doc["db"] == PG_DB
        assert doc["user"] == PG_USER

    def test_captured_event_has_required_fields(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT {marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None

        required = [
            "pid", "timestamp", "event_type", "user", "db", "src_ip",
            "raw_sql", "normalized_sql", "masked_sql",
            "session_id", "session_start", "query_sequence",
            "transaction_id", "transaction_state",
        ]
        for field in required:
            assert field in doc, f"Missing required field: {field}"


class TestNormalization:
    """SQL normalization: literals replaced with $1, $2, ..."""

    def test_integer_literal_normalized(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = {marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "$1" in doc["normalized_sql"]
        assert str(marker) not in doc["normalized_sql"]

    def test_string_literal_normalized(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE name = 'user{marker}'")

        doc = poll_es_for(f"user{marker}")
        assert doc is not None
        assert "$1" in doc["normalized_sql"]
        assert f"user{marker}" not in doc["normalized_sql"]

    def test_multiple_literals_normalized(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = {marker} AND name = 'Bob'")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "$1" in doc["normalized_sql"]
        assert "$2" in doc["normalized_sql"]


class TestMasking:
    """PII masking: sensitive values replaced with <REDACTED>."""

    def test_credit_card_in_select_is_redacted(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT '4111111111111111' AS card_number, {marker} AS marker")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "<REDACTED>" in doc["masked_sql"]
        assert "4111111111111111" not in doc["masked_sql"]

    def test_credit_card_alongside_real_data_is_redacted(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT id, name, '5500005555555559' AS card FROM users WHERE id = 1 AND 1={marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "<REDACTED>" in doc["masked_sql"]
        assert "5500005555555559" not in doc["masked_sql"]

    def test_safe_integer_not_redacted(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = {marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "<REDACTED>" not in doc["masked_sql"]

    def test_raw_sql_is_never_modified(self, pg_conn):
        """raw_sql must always contain the original unmodified query."""
        marker = unique_id()
        run(pg_conn, f"SELECT '4111111111111111' AS card_number, {marker} AS marker")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert "4111111111111111" in doc["raw_sql"]


class TestKillPolicy:
    """Kill policy: malicious queries should set kill_triggered = true."""

    pytestmark = pytest.mark.skipif(
        PG_HOST == "localhost",
        reason="Kill policy tests require a non-loopback src_ip — run from inside the cluster"
    )

    def test_union_injection_triggers_kill(self, pg_conn):
        marker = unique_id()
        run(pg_conn,
            f"SELECT id, name FROM users WHERE id = {marker} "
            "UNION SELECT 1, table_name FROM information_schema.tables"
        )
        doc = poll_es_for(str(marker))
        assert doc is not None
        assert doc["kill_triggered"] is True, "UNION injection should trigger kill"

    def test_boolean_injection_triggers_kill(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = {marker} OR 1=1")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert doc["kill_triggered"] is True, "Boolean injection should trigger kill"

    def test_privilege_escalation_triggers_kill(self, pg_conn):
        marker = unique_id()
        # Embed marker as a comment in the role name so the query is unique
        # but still matches the kill policy regex
        run(pg_conn, f"ALTER ROLE postgres WITH SUPERUSER")

        doc = poll_es_for("ALTER ROLE postgres WITH SUPERUSER")
        assert doc is not None
        assert doc["kill_triggered"] is True, "Privilege escalation should trigger kill"

    def test_normal_select_does_not_trigger_kill(self, pg_conn):
        marker = unique_id()
        run(pg_conn, f"SELECT * FROM users WHERE id = {marker}")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert doc["kill_triggered"] is False, "Normal query should not trigger kill"


class TestSessionTracking:
    """Session and transaction tracking."""

    def test_session_id_stable_across_queries(self, pg_conn):
        """Two queries on the same connection share a session_id."""
        marker1 = unique_id()
        marker2 = unique_id()

        run(pg_conn, f"SELECT {marker1}")
        run(pg_conn, f"SELECT {marker2}")

        doc1 = poll_es_for(str(marker1))
        doc2 = poll_es_for(str(marker2))

        assert doc1 is not None and doc2 is not None
        assert doc1["session_id"] == doc2["session_id"], \
            "Queries from same connection must share session_id"

    def test_query_sequence_increments(self, pg_conn):
        marker1 = unique_id()
        marker2 = unique_id()

        run(pg_conn, f"SELECT {marker1}")
        run(pg_conn, f"SELECT {marker2}")

        doc1 = poll_es_for(str(marker1))
        doc2 = poll_es_for(str(marker2))

        assert doc1 is not None and doc2 is not None
        assert doc2["query_sequence"] > doc1["query_sequence"], \
            "query_sequence must increment within a session"

    def test_transaction_tracking(self, pg_conn):
        """Queries inside BEGIN/COMMIT share a transaction_id."""
        marker = unique_id()

        run(pg_conn, "BEGIN")
        run(pg_conn, f"SELECT {marker}")
        run(pg_conn, "COMMIT")

        doc = poll_es_for(str(marker))
        assert doc is not None
        assert doc["transaction_id"] != "", \
            "Query inside BEGIN should have a transaction_id"
        assert doc["transaction_state"] == "open"

    def test_different_connections_have_different_session_ids(self, pg_conn):
        """A second independent connection gets a different session_id."""
        marker1 = unique_id()
        marker2 = unique_id()

        # Fire marker1 on the shared persistent connection
        run(pg_conn, f"SELECT {marker1}")

        # Open a second connection, wait for PID registration, fire marker2
        conn2 = psycopg2.connect(
            host=PG_HOST, port=PG_PORT,
            user=PG_USER, password=PG_PASS, dbname=PG_DB
        )
        conn2.autocommit = True
        time.sleep(PID_REGISTRATION_WAIT)
        cur = conn2.cursor()
        cur.execute(f"SELECT {marker2}")
        cur.close()
        conn2.close()

        doc1 = poll_es_for(str(marker1))
        doc2 = poll_es_for(str(marker2))

        assert doc1 is not None and doc2 is not None
        assert doc1["session_id"] != doc2["session_id"], \
            "Different connections must have different session_ids"
        