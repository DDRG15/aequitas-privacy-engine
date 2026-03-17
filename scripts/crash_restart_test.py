"""
scripts/crash_restart_test.py — Aequitas Privacy Engine  |  Standalone Crash/Restart Test
===========================================================================================
Run directly (no pytest required):
  python scripts/crash_restart_test.py

Transactional Outbox semantics
-------------------------------
JSONL files are NOT written during the processing loop.  After a hard kill,
JSONL absence is correct; the DB holds all committed rows.  After restart,
export_audit_logs() writes the JSONL files atomically from the DB.

Algorithm
---------
1. Clean output state.
2. Generate SAMPLE_SIZE tracker events (deterministic seed).
3. Spawn main.py; kill after KILL_AFTER_S seconds.
4. Assert DB has no duplicate event_ids (JSONL absence is acceptable).
5. Restart main.py; let it complete.
6. Assert:
   a. Zero duplicate event_ids in final JSONL output.
   b. DB row count == JSONL unique-id count.
   c. DB contains all processable events (SAMPLE_SIZE - MALFORMED_count).
   d. audit_metrics.json exists and is valid.
"""

import json
import logging
import os
import pathlib
import signal
import sqlite3
import subprocess
import sys
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("crash_test")

SAMPLE_SIZE      = 2_000
GENERATOR_SEED   = 42
KILL_AFTER_S     = 1.5
PIPELINE_TIMEOUT = 90

# MALFORMED events (eid % 1000 == 0) have no END marker -- always discarded.
_MALFORMED_COUNT = SAMPLE_SIZE // 1000
PROCESSABLE      = SAMPLE_SIZE - _MALFORMED_COUNT

OUTPUT_DIR   = pathlib.Path("data/output")
INPUT_FILE   = pathlib.Path("data/raw_samples/tracker_stream.log")
CRASH_INPUT  = pathlib.Path("data/raw_samples/crash_test_events.log")

JSONL_FILES  = [
    OUTPUT_DIR / "sanitized.jsonl",
    OUTPUT_DIR / "sanitized_corrected.jsonl",
    OUTPUT_DIR / "review_queue.jsonl",
]
DB_FILE          = OUTPUT_DIR / "audit_ledger.db"
METRICS_FILE     = OUTPUT_DIR / "audit_metrics.json"
DEAD_LETTER_FILE = OUTPUT_DIR / "skipped_ranges.jsonl"


def _clean() -> None:
    targets = [
        *JSONL_FILES,
        DB_FILE,
        METRICS_FILE,
        OUTPUT_DIR / "audit_checkpoint.json",
        OUTPUT_DIR / "audit_checkpoint.json.tmp",
        OUTPUT_DIR / "audit_metrics.json.tmp",
        DEAD_LETTER_FILE,
    ]
    for jf in JSONL_FILES:
        targets.append(jf.with_suffix(".jsonl.tmp"))
    for f in targets:
        if f.exists():
            f.unlink()
    log.info("Output state cleared.")


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


def _db_count() -> int:
    if not DB_FILE.exists():
        return 0
    conn = sqlite3.connect(str(DB_FILE))
    try:
        return conn.execute("SELECT COUNT(*) FROM processed").fetchone()[0]
    finally:
        conn.close()


def _db_has_no_duplicates() -> bool:
    if not DB_FILE.exists():
        return True
    conn = sqlite3.connect(str(DB_FILE))
    try:
        dup = conn.execute(
            "SELECT COUNT(*) FROM ("
            "  SELECT event_id FROM processed"
            "  GROUP BY event_id HAVING COUNT(*) > 1"
            ")"
        ).fetchone()[0]
        return dup == 0
    finally:
        conn.close()


def _kill(proc: subprocess.Popen) -> None:
    try:
        if sys.platform == "win32":
            proc.terminate()
        else:
            os.kill(proc.pid, signal.SIGTERM)
        proc.wait(timeout=8)
        log.info("PID %d terminated.", proc.pid)
    except Exception as exc:
        log.warning("Kill failed: %s -- forcing.", exc)
        try:
            proc.kill()
            proc.wait(timeout=4)
        except Exception:
            pass


def _spawn() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    log.info("Started PID=%d.", proc.pid)
    return proc


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        log.error("FAIL: %s", msg)
        sys.exit(1)
    log.info("OK  -- %s", msg)


def main() -> None:
    log.info("=" * 60)
    log.info("CRASH/RESTART ACCEPTANCE TEST  --  Aequitas Hardened")
    log.info("=" * 60)

    _clean()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    log.info("STEP 1: Generating %d tracker events (seed=%d) ...",
             SAMPLE_SIZE, GENERATOR_SEED)
    r = subprocess.run(
        [
            sys.executable, "-m", "src.generator",
            "--total",  str(SAMPLE_SIZE),
            "--seed",   str(GENERATOR_SEED),
            "--output", str(CRASH_INPUT),
        ],
        capture_output=True, text=True, timeout=60,
    )
    _assert(r.returncode == 0, f"Generator succeeded (rc={r.returncode})")

    import shutil
    backup       = INPUT_FILE.with_suffix(".bak.log")
    had_original = INPUT_FILE.exists()
    if had_original:
        INPUT_FILE.rename(backup)
    shutil.copy(str(CRASH_INPUT), str(INPUT_FILE))

    try:
        # ── First run: kill mid-processing ────────────────────────────────────
        log.info("STEP 2: First run -- killing after %.1fs ...", KILL_AFTER_S)
        proc1 = _spawn()
        time.sleep(KILL_AFTER_S)
        _kill(proc1)
        time.sleep(0.1)   # let OS release file handles

        # After a hard kill, JSONL is absent (outbox: no in-loop writes).
        # Assert DB integrity only.
        _assert(
            _db_has_no_duplicates(),
            "DB has no duplicate event_ids after crash"
        )
        db_after_crash = _db_count()
        log.info("DB rows after crash: %d", db_after_crash)

        # ── Restart: run to completion ─────────────────────────────────────────
        log.info("STEP 3: Restarting pipeline ...")
        proc2 = _spawn()
        try:
            proc2.communicate(timeout=PIPELINE_TIMEOUT)
        except subprocess.TimeoutExpired:
            _kill(proc2)
            _assert(False, f"Pipeline completed within {PIPELINE_TIMEOUT}s")

        # ── Assertions ─────────────────────────────────────────────────────────
        log.info("STEP 4: Verifying assertions ...")

        jsonl_ids = _jsonl_ids()
        dupes     = len(jsonl_ids) - len(set(jsonl_ids))
        _assert(
            dupes == 0,
            f"Zero duplicate event_ids in JSONL "
            f"({len(jsonl_ids)} total, {len(set(jsonl_ids))} unique)",
        )

        db_count = _db_count()
        _assert(
            db_count == len(set(jsonl_ids)),
            f"DB rows ({db_count}) == JSONL unique ids ({len(set(jsonl_ids))})",
        )

        _assert(METRICS_FILE.exists(), "audit_metrics.json exists")

        _assert(
            db_count == PROCESSABLE,
            f"DB contains all {PROCESSABLE} processable events "
            f"(db_count={db_count}, MALFORMED_discarded={_MALFORMED_COUNT})",
        )

        # ── Metrics JSON validation ────────────────────────────────────────────
        # NOTE: after a crash-and-restart cycle where all events were already
        # committed in the first run, events_audited_total is correctly 0
        # (no new rows were inserted in the restart run).  The authoritative
        # completeness check is DB row count, not events_audited_total.
        metrics = json.loads(METRICS_FILE.read_text())
        _assert(
            "last_audited_event_id" in metrics,
            "audit_metrics.json has last_audited_event_id",
        )
        _assert(
            "events_audited_total" in metrics,
            "audit_metrics.json has events_audited_total",
        )
        _assert(
            "skipped_events" in metrics,
            "audit_metrics.json has skipped_events (P3 DLQ field)",
        )
        _assert(
            metrics.get("skipped_events", -1) == 0,
            f"skipped_events == 0 (got {metrics.get('skipped_events')})",
        )

        log.info("=" * 60)
        log.info("ALL ACCEPTANCE TESTS PASSED")
        log.info("=" * 60)

    finally:
        if had_original and backup.exists():
            INPUT_FILE.unlink(missing_ok=True)
            backup.rename(INPUT_FILE)


if __name__ == "__main__":
    main()
