"""
tests/test_resilience.py — Aequitas Privacy Engine  |  Crash/Restart Acceptance Tests
=======================================================================================
Verifies the zero-duplicate guarantee after a mid-run crash and restart
under the Transactional Outbox Pattern, and the new hardening invariants.

Transactional Outbox semantics
-------------------------------
JSONL files are NOT written during the processing loop.  After a hard kill:
  * SQLite contains all committed rows (no duplicates).
  * JSONL files are absent -- this is CORRECT, not a failure.
  * The next restart processes remaining events and exports JSONL atomically.

Hardening assertions (added in hardened release)
-------------------------------------------------
  * P0: export produces correct per-file counts (streaming, no OOM).
  * P1: WAL_CHECKPOINT_INTERVAL is defined and is 100.
  * P3: skipped_events field present in audit_metrics.json.
  * P4: pipeline survives a corrupt-byte input (errors="replace").
  * P5: oversized event routed to REVIEW without regex execution.

Run:
  pytest tests/test_resilience.py -v -s
  (or standalone: python scripts/crash_restart_test.py)
"""

import json
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
import time

import pytest

# -- constants ----------------------------------------------------------------
SAMPLE_SIZE       = 2_000
GENERATOR_SEED    = 42
KILL_AFTER_S      = 1.5
PIPELINE_TIMEOUT  = 90
OUTPUT_DIR        = pathlib.Path("data/output")
INPUT_FILE        = pathlib.Path("data/raw_samples/tracker_stream.log")
GENERATOR_INPUT   = pathlib.Path("data/raw_samples/crash_test_events.log")

JSONL_FILES = [
    OUTPUT_DIR / "sanitized.jsonl",
    OUTPUT_DIR / "sanitized_corrected.jsonl",
    OUTPUT_DIR / "review_queue.jsonl",
]
DB_FILE          = OUTPUT_DIR / "audit_ledger.db"
METRICS_FILE     = OUTPUT_DIR / "audit_metrics.json"
CKPT_FILE        = OUTPUT_DIR / "audit_checkpoint.json"
DEAD_LETTER_FILE = OUTPUT_DIR / "skipped_ranges.jsonl"

# MALFORMED events (eid % 1000 == 0) have no END marker -- always discarded.
_MALFORMED_COUNT = SAMPLE_SIZE // 1000
PROCESSABLE      = SAMPLE_SIZE - _MALFORMED_COUNT

_UNLINK_RETRIES = 10
_UNLINK_DELAY_S = 0.25


# -- helpers ------------------------------------------------------------------

def _safe_remove(path: pathlib.Path) -> bool:
    """Unlink with retries to handle transient Windows file locks."""
    for _ in range(_UNLINK_RETRIES):
        if not path.exists():
            return True
        try:
            path.unlink()
            return True
        except PermissionError:
            time.sleep(_UNLINK_DELAY_S)
        except Exception:
            break
    return not path.exists()


def _clean() -> None:
    targets = [
        *JSONL_FILES,
        DB_FILE,
        DB_FILE.with_suffix(".db-wal"),
        DB_FILE.with_suffix(".db-shm"),
        METRICS_FILE,
        CKPT_FILE,
        OUTPUT_DIR / "audit_checkpoint.json.tmp",
        OUTPUT_DIR / "audit_metrics.json.tmp",
        DEAD_LETTER_FILE,
    ]
    for jf in JSONL_FILES:
        targets.append(jf.with_suffix(".jsonl.tmp"))
    for f in targets:
        if not _safe_remove(f):
            import warnings
            warnings.warn(f"_clean: could not remove {f} after {_UNLINK_RETRIES} retries")


def _assert_clean_state() -> None:
    still_present = [str(p) for p in [DB_FILE, CKPT_FILE] if p.exists()]
    if still_present:
        time.sleep(_UNLINK_DELAY_S * 2)
        _clean()
        still_present = [str(p) for p in [DB_FILE, CKPT_FILE] if p.exists()]
    if still_present:
        try:
            proc_list = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq python.exe"]
                if sys.platform == "win32"
                else ["pgrep", "-la", "python"],
                text=True, timeout=5,
            )
        except Exception as exc:
            proc_list = f"(process list unavailable: {exc})"
        raise RuntimeError(
            "Safe Start failed: files still present after cleanup: "
            + str(still_present)
            + "\nRunning Python processes:\n" + proc_list
        )


def _safe_spawn() -> subprocess.Popen:
    """Assert clean state, then spawn main.py."""
    _assert_clean_state()
    return subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def _spawn() -> subprocess.Popen:
    """Spawn without the pre-spawn guard (DB may exist from prior run)."""
    return subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )


def _jsonl_ids() -> list[int]:
    """Collect all event_ids from the three JSONL output files."""
    ids: list[int] = []
    for path in JSONL_FILES:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    ids.append(int(json.loads(line)["event_id"]))
                except Exception:
                    pass
    return ids


def _db_ids() -> list[int]:
    """Return all event_ids from the DB, ordered.

    Uses explicit conn.close() rather than the with-statement context manager.
    The sqlite3 context manager commits/rolls back but does NOT close the
    connection.  An unclosed handle on Windows blocks _clean() from deleting
    the DB file and causes _assert_clean_state() to fail at the next test.
    """
    if not DB_FILE.exists():
        return []
    conn = sqlite3.connect(str(DB_FILE))
    try:
        return [
            r[0] for r in conn.execute(
                "SELECT event_id FROM processed ORDER BY event_id"
            ).fetchall()
        ]
    finally:
        conn.close()


def _kill(proc: subprocess.Popen) -> None:
    try:
        if sys.platform == "win32":
            proc.terminate()
        else:
            os.kill(proc.pid, signal.SIGTERM)
        proc.wait(timeout=8)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=4)
        except Exception:
            pass


# -- fixtures -----------------------------------------------------------------

@pytest.fixture(scope="module")
def generated_input():
    result = subprocess.run(
        [
            sys.executable, "-m", "src.generator",
            "--total", str(SAMPLE_SIZE),
            "--seed",  str(GENERATOR_SEED),
            "--output", str(GENERATOR_INPUT),
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, f"Generator failed:\n{result.stderr}"
    return GENERATOR_INPUT


@pytest.fixture(autouse=True)
def use_crash_input(generated_input):
    import shutil
    backup       = INPUT_FILE.with_suffix(".bak.log")
    had_original = INPUT_FILE.exists()
    if had_original:
        INPUT_FILE.rename(backup)
    shutil.copy(str(generated_input), str(INPUT_FILE))

    _clean()
    yield

    _clean()
    if had_original and backup.exists():
        INPUT_FILE.unlink(missing_ok=True)
        backup.rename(INPUT_FILE)
    if not generated_input.exists() and INPUT_FILE.exists():
        shutil.copy(str(INPUT_FILE), str(generated_input))


# =============================================================================
# Tests
# =============================================================================

class TestCrashRestart:

    def test_no_duplicates_after_crash_and_restart(self) -> None:
        """
        Full crash/restart cycle under the Transactional Outbox Pattern.

        Phase 1 -- hard kill mid-processing:
          JSONL files are NOT written during the processing loop (by design).
          After the kill, JSONL may be absent.  This is correct.
          The DB must have no duplicate event_ids.

        Phase 2 -- restart to completion:
          The pipeline resumes, skips already-committed events (idempotency),
          exports JSONL atomically, then writes audit_metrics.json.
          After completion:
            a. Zero duplicate event_ids in JSONL.
            b. DB row count == JSONL unique-id count.
            c. DB holds all processable events.
        """
        proc1 = _safe_spawn()
        time.sleep(KILL_AFTER_S)
        _kill(proc1)
        time.sleep(0.1)

        db_ids_after_crash = _db_ids()
        assert len(db_ids_after_crash) == len(set(db_ids_after_crash)), (
            "DB duplicates found after crash -- idempotency guard broken"
        )

        proc2 = _spawn()
        try:
            proc2.communicate(timeout=PIPELINE_TIMEOUT)
        except subprocess.TimeoutExpired:
            _kill(proc2)
            pytest.fail(f"Pipeline timed out after {PIPELINE_TIMEOUT}s on restart")

        jsonl_ids = _jsonl_ids()
        dupes = len(jsonl_ids) - len(set(jsonl_ids))
        assert dupes == 0, f"Found {dupes} duplicate event_ids in JSONL after restart"

        db_ids = _db_ids()
        assert len(db_ids) == len(set(jsonl_ids)), (
            f"DB has {len(db_ids)} rows but JSONL has {len(set(jsonl_ids))} unique ids"
        )

        assert len(db_ids) == PROCESSABLE, (
            f"DB should contain {PROCESSABLE} processable events; "
            f"got {len(db_ids)}  (MALFORMED_discarded={_MALFORMED_COUNT})"
        )

    def test_db_stores_full_payload(self) -> None:
        """The outbox DB must store status and the full JSON payload per row."""
        from main import open_db, insert_batch, close_db

        conn = open_db(DB_FILE)
        payload = {
            "event_id":        99999,
            "status":          "SANITIZED",
            "tracker":         "ad-metrics",
            "timestamp":       "01/01/2024",
            "payload_size":    "512",
            "routing_reasons": [],
        }
        first  = insert_batch(conn, [payload])
        second = insert_batch(conn, [payload])

        row = conn.execute(
            "SELECT status, payload FROM processed WHERE event_id = 99999"
        ).fetchone()
        close_db(conn)

        assert len(first)  == 1, "First insert must succeed"
        assert len(second) == 0, "Second insert must be silently ignored"
        assert row is not None, "Row must exist in DB"
        assert row[0] == "SANITIZED", f"Expected status=SANITIZED, got {row[0]!r}"
        stored = json.loads(row[1])
        assert stored["event_id"] == 99999
        assert stored["tracker"]  == "ad-metrics"

    def test_export_audit_logs_is_idempotent(self) -> None:
        """export_audit_logs() called twice on the same DB must produce identical files."""
        from main import open_db, insert_batch, close_db, export_audit_logs

        conn = open_db(DB_FILE)
        payloads = [
            {
                "event_id": i, "status": "SANITIZED",
                "tracker": "ad-metrics", "timestamp": "01/01/2024",
                "payload_size": "512", "routing_reasons": [],
            }
            for i in range(1, 6)
        ]
        insert_batch(conn, payloads)
        close_db(conn)

        conn2 = sqlite3.connect(str(DB_FILE), timeout=30)
        counts1 = export_audit_logs(conn2)
        conn2.close()
        snap1 = {p: p.read_text() for p in JSONL_FILES if p.exists()}

        conn3 = sqlite3.connect(str(DB_FILE), timeout=30)
        counts2 = export_audit_logs(conn3)
        conn3.close()
        snap2 = {p: p.read_text() for p in JSONL_FILES if p.exists()}

        assert counts1 == counts2, "counts must match on re-export"
        assert snap1   == snap2,   "file contents must be identical on re-export"

    def test_metrics_json_written_on_clean_run(self) -> None:
        """A clean run must produce valid audit_metrics.json with correct totals."""
        proc = _safe_spawn()
        try:
            proc.communicate(timeout=PIPELINE_TIMEOUT)
        except subprocess.TimeoutExpired:
            _kill(proc)
            pytest.fail("Pipeline timed out")

        assert METRICS_FILE.exists(), "audit_metrics.json must exist after clean run"
        m = json.loads(METRICS_FILE.read_text())

        assert "last_audited_event_id" in m, "missing last_audited_event_id"
        assert "events_audited_total"  in m, "missing events_audited_total"
        assert "events_per_second"     in m, "missing events_per_second"
        assert "audit_counts"          in m, "missing audit_counts"
        assert "skipped_events"        in m, "missing skipped_events (P3 DLQ field)"

        assert m["events_audited_total"] == PROCESSABLE, (
            f"expected events_audited_total={PROCESSABLE}, "
            f"got {m['events_audited_total']}"
        )
        assert m["skipped_events"] == 0, (
            f"expected skipped_events=0 on clean run, got {m['skipped_events']}"
        )


class TestHardeningInvariants:
    """Unit-level checks for each hardening item that does not require a
    subprocess.  These run in-process and are fast (<1 s total)."""

    def test_p0_export_streams_no_fetchall(self) -> None:
        """P0: export_audit_logs must not call .fetchall() on the main cursor."""
        import ast, inspect, main as m
        tree  = ast.parse(inspect.getsource(m.export_audit_logs))
        calls = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and n.attr == "fetchall"
        ]
        assert len(calls) == 0, (
            f"Found {len(calls)} .fetchall() call(s) in export_audit_logs -- "
            "this would OOM at 100M+ events"
        )

    def test_p0_export_per_file_isolation(self) -> None:
        """P2: export_audit_logs must use per-file exception handling."""
        import inspect, main as m
        src = inspect.getsource(m.export_audit_logs)
        assert "counts[status] = -1" in src, (
            "Per-file error sentinel (-1) not found in export_audit_logs"
        )

    def test_p1_wal_checkpoint_interval(self) -> None:
        """P1: WAL_CHECKPOINT_INTERVAL must be defined and equal to 100."""
        import main as m
        assert hasattr(m, "WAL_CHECKPOINT_INTERVAL"), "WAL_CHECKPOINT_INTERVAL not defined"
        assert m.WAL_CHECKPOINT_INTERVAL == 100, (
            f"Expected WAL_CHECKPOINT_INTERVAL=100, got {m.WAL_CHECKPOINT_INTERVAL}"
        )

    def test_p1_passive_checkpoint_in_drain(self) -> None:
        """P1: _drain_checkpoint must issue PRAGMA wal_checkpoint(PASSIVE)."""
        import inspect, main as m
        src = inspect.getsource(m.main)
        assert "wal_checkpoint(PASSIVE)" in src, (
            "PASSIVE WAL checkpoint not found in main() body"
        )
        assert "WAL_CHECKPOINT_INTERVAL" in src, (
            "WAL_CHECKPOINT_INTERVAL not used in main() body"
        )

    def test_p3_dead_letter_file_constant(self) -> None:
        """P3: DEAD_LETTER_FILE constant must exist and point to correct path."""
        import main as m
        assert hasattr(m, "DEAD_LETTER_FILE")
        assert "skipped_ranges.jsonl" in str(m.DEAD_LETTER_FILE)

    def test_p3_record_dead_letter_function(self) -> None:
        """P3: _record_dead_letter must write an append-only JSON entry."""
        import main as m, inspect
        src = inspect.getsource(m._record_dead_letter)
        assert 'open("a"' in src,           "_record_dead_letter must use append mode"
        assert "event_id_first" in src,     "must record event_id_first"
        assert "event_id_last"  in src,     "must record event_id_last"
        assert "log.warning"    in src,     "DLQ write failure must be non-fatal"

    def test_p3_drain_one_wires_skipped_ref(self) -> None:
        """P3: drain_one must accept skipped_ref and call _record_dead_letter."""
        import main as m, inspect
        src = inspect.getsource(m.drain_one)
        assert "skipped_ref"          in src
        assert "_record_dead_letter(" in src
        assert "skipped_ref[0] +="    in src

    def test_p3_skipped_events_in_metrics(self) -> None:
        """P3: save_metrics must write skipped_events to audit_metrics.json."""
        import main as m, inspect
        src = inspect.getsource(m.save_metrics)
        assert '"skipped_events"'  in src
        assert '"dead_letter_file"' in src

    def test_p3_dlq_functional(self, tmp_path) -> None:
        """P3 functional: _record_dead_letter produces a valid JSON entry."""
        import main as m
        orig = m.DEAD_LETTER_FILE
        m.DEAD_LETTER_FILE = tmp_path / "skipped_ranges.jsonl"
        try:
            chunk = [(10, "raw"), (11, "raw"), (12, "raw")]
            m._record_dead_letter(chunk, RuntimeError("worker died"))
            entry = json.loads(m.DEAD_LETTER_FILE.read_text().strip())
            assert entry["event_id_first"] == 10
            assert entry["event_id_last"]  == 12
            assert entry["event_count"]    == 3
            assert "RuntimeError"          in entry["error"]
            assert "ts_utc"                in entry
        finally:
            m.DEAD_LETTER_FILE = orig

    def test_p4_errors_replace_on_input(self) -> None:
        """P4: INPUT_FILE.open must use errors='replace'."""
        import main as m, inspect
        src = inspect.getsource(m.main)
        assert 'errors="replace"' in src, (
            "errors='replace' not found in main() -- corrupt bytes will kill the pipeline"
        )

    def test_p5_max_event_bytes_defined(self) -> None:
        """P5: MAX_EVENT_BYTES must be defined in worker and equal to 65536."""
        from src import worker as w
        assert hasattr(w, "MAX_EVENT_BYTES")
        assert w.MAX_EVENT_BYTES == 65_536

    def test_p5_oversized_event_routed_to_review(self) -> None:
        """P5 functional: an event exceeding 64 KB must be immediately routed
        to REVIEW without running any regex."""
        from src.worker import sanitize_event
        oversized = "--- START EVENT 1 ---\n" + ("X" * 70_000) + "\n--- END EVENT 1 ---\n"
        r = sanitize_event(1, oversized)
        assert r["status"] == "REVIEW"
        assert any("too large" in reason for reason in r["routing_reasons"]), (
            f"Expected 'too large' in routing_reasons, got {r['routing_reasons']}"
        )
        assert r["tracker"] == "UNKNOWN", (
            "Tracker classification should not run on oversized event"
        )

    def test_p5_guard_fires_before_regex(self) -> None:
        """P5 structural: byte-length guard must appear before body_lines slicing."""
        import inspect
        from src import worker as w
        src = inspect.getsource(w.sanitize_event)
        assert src.index("MAX_EVENT_BYTES") < src.index("body_lines = ["), (
            "P5 guard is not the first operation in sanitize_event"
        )

    def test_p7_http_short_circuit(self) -> None:
        """P7 structural: _TRACKER_URL_RE.sub must be guarded by 'http' presence check."""
        import inspect
        from src import worker as w
        src = inspect.getsource(w.sanitize_event)
        assert '"http" in redacted_body' in src
        assert src.index('"http" in redacted_body') < src.index("_TRACKER_URL_RE.sub"), (
            "P7 short-circuit must precede _TRACKER_URL_RE.sub"
        )

    def test_p7_clean_event_still_sanitized(self) -> None:
        """P7 functional: the short-circuit must not break normal event processing."""
        from src.worker import sanitize_event
        r = sanitize_event(1, (
            "--- START EVENT 1 ---\n"
            "  tracker:    track.analytics-beacon.io\n"
            "  timestamp:  15/03/2024\n"
            "  client_ip:  10.1.2.3\n"
            "  session_id: abcdef1234567890abcdef1234567890\n"
            "  SIZE: B: 1,024\n"
            "--- END EVENT 1 ---\n"
        ))
        assert r["status"] == "SANITIZED"
        assert r["tracker"] == "analytics-beacon"
