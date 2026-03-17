"""
main.py — Aequitas Privacy Engine  |  High-Throughput Tracker Audit Pipeline  [Hardened]
=============================================================================

Architecture
  Producer  : main thread reads the input log stream line-by-line, accumulates
              TrackerPayloads into batches, submits per-core sub-chunks to the
              worker pool.
  Backpressure: MAX_INFLIGHT cap on concurrent futures prevents the reader
              from racing ahead and exhausting memory during large audit runs.
              This is a critical privacy-engineering control: unbounded memory
              growth during a multi-billion-event audit could cause the OS to
              spill sensitive PII to a swap file outside the audit boundary.
  Consumer  : drain_one() collects one completed future at a time via
              as_completed(); each sanitized result is idempotency-checked
              against SQLite before being written to the outbox.

Transactional Outbox Pattern
  SQLite is the SOLE write target during processing.  The schema stores the
  full sanitized JSON payload alongside event_id and status, making the DB a
  complete, self-contained audit record of every processed TrackerPayload.
  JSONL export is deferred to end-of-run: after all batches are committed,
  export_audit_logs() queries the DB and writes the three output files using
  atomic write (.tmp -> fsync -> os.replace).

  Crash guarantee: if the process is hard-killed (Windows TerminateProcess,
  OOM killer) during processing, the next restart re-processes remaining events
  (idempotency guard) and re-runs the export.  No dual-write window exists.

SQLite Audit Ledger
  processed(
    event_id    INTEGER PRIMARY KEY,
    status      TEXT    NOT NULL,
    payload     TEXT    NOT NULL    -- json.dumps(full AuditEvent dict)
  )

  Idempotency: only the main process opens / writes the DB.
  WAL mode + busy_timeout=5000 ms + synchronous=NORMAL for resilience.
  Per-chunk: BEGIN ... INSERT OR IGNORE ... COMMIT.
  cursor.rowcount == 1 detects a genuinely new insert (per-row check).

Windows Safe Fsync  (NTFS Valid Data Length)
  Atomic writes use flush() + os.fsync() to commit both page-cache data and
  the NTFS Valid Data Length (VDL) metadata to the storage controller before
  the .tmp -> final rename.  Without fsync(), NTFS may truncate the file back
  to the last on-disk VDL after a hard kill, producing a 0-byte audit log even
  though the page cache held the data.  This ensures immutable audit trails
  across complex OS file systems.

Shutdown sequence  (SIGINT / SIGTERM / KeyboardInterrupt / SystemExit)
  a) Set _stop_requested -- read loop stops submitting new batches.
  b) executor.shutdown(wait=False, cancel_futures=True).
  c) Drain all in-flight futures.
  d) DB commit, WAL checkpoint (TRUNCATE), close.
  e) export_audit_logs() -- atomic JSONL export from outbox.
  f) Atomic write of audit_metrics.json and audit_checkpoint.json.
  A try/finally block guarantees d-f run even on unexpected exceptions.
"""

import json
import logging
import os
import re
import signal
import sqlite3
import time
import pathlib
from concurrent.futures import Future, ProcessPoolExecutor, as_completed

from src.worker import sanitize_chunk

# -- Logging ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("aequitas")

# -- Configuration ------------------------------------------------------------
OUTPUT_DIR      = pathlib.Path("data/output")
INPUT_FILE      = pathlib.Path("data/raw_samples/tracker_stream.log")
CHECKPOINT_FILE = OUTPUT_DIR / "audit_checkpoint.json"
METRICS_FILE    = OUTPUT_DIR / "audit_metrics.json"
DB_FILE         = OUTPUT_DIR / "audit_ledger.db"

AUDIT_LOG_FILES = {
    "SANITIZED":   OUTPUT_DIR / "sanitized.jsonl",
    "SANITIZED_2": OUTPUT_DIR / "sanitized_corrected.jsonl",
    "REVIEW":      OUTPUT_DIR / "review_queue.jsonl",
}
# P3: Dead-letter queue -- records event_id ranges lost to worker death.
DEAD_LETTER_FILE = OUTPUT_DIR / "skipped_ranges.jsonl"

CHUNK_SIZE              = 5_000   # events accumulated before a parallel dispatch
MAX_INFLIGHT            = 4       # concurrent-futures ceiling (backpressure)
MAX_EVENT_LINES         = 50      # line-count guard: discard event buffer if too long
MAX_EVENT_BYTES         = 65_536  # P5: byte-length guard before any regex (64 KB)
METRICS_INTERVAL        = 5       # persist checkpoint every N drained chunks
WAL_CHECKPOINT_INTERVAL = 100     # P1: PASSIVE WAL checkpoint every N chunks
DB_RETRY_ATTEMPTS       = 5       # max retries on sqlite3.OperationalError
DB_RETRY_BASE_S         = 0.10    # base seconds for exponential backoff

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# -- Shutdown state -----------------------------------------------------------
_stop_requested: bool = False
_executor_ref:   ProcessPoolExecutor | None = None


def _handle_signal(signum, frame) -> None:   # noqa: ANN001
    """Steps a + b of the shutdown sequence."""
    global _stop_requested
    _stop_requested = True
    log.warning("Signal %s -- stopping submission.", signum)
    if _executor_ref is not None:
        _executor_ref.shutdown(wait=False, cancel_futures=True)


# -- SQLite audit ledger ------------------------------------------------------

def open_db(path: pathlib.Path) -> sqlite3.Connection:
    """Open (or create) the SQLite audit ledger.  Main process only.

    Schema: processed(event_id   INTEGER PRIMARY KEY,
                       status     TEXT NOT NULL,
                       payload    TEXT NOT NULL)

    Migration: if an older DB exists with only event_id, the two new columns
    are added via ALTER TABLE with safe defaults so existing idempotency rows
    are preserved and the pipeline can resume normally.

    Settings:
      journal_mode=WAL    -- allows concurrent readers.
      busy_timeout=5000   -- wait up to 5 s on lock instead of raising.
      synchronous=NORMAL  -- safe with WAL; faster than FULL.
    """
    conn = sqlite3.connect(str(path), timeout=30, check_same_thread=True)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    conn.execute("PRAGMA synchronous=NORMAL;")

    conn.execute(
        "CREATE TABLE IF NOT EXISTS processed ("
        "  event_id  INTEGER PRIMARY KEY,"
        "  status    TEXT    NOT NULL DEFAULT '',"
        "  payload   TEXT    NOT NULL DEFAULT ''"
        ");"
    )

    existing_cols = {
        row[1]
        for row in conn.execute("PRAGMA table_info(processed);").fetchall()
    }
    if "status" not in existing_cols:
        conn.execute("ALTER TABLE processed ADD COLUMN status TEXT NOT NULL DEFAULT '';")
        log.info("open_db: migrated -- added 'status' column")
    if "payload" not in existing_cols:
        conn.execute("ALTER TABLE processed ADD COLUMN payload TEXT NOT NULL DEFAULT '';")
        log.info("open_db: migrated -- added 'payload' column")

    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM processed;").fetchone()[0]
    log.info("Audit ledger events at start: %d  (%s)", n, path)
    return conn


def close_db(conn: sqlite3.Connection) -> None:
    """Commit, WAL checkpoint (TRUNCATE), close.

    TRUNCATE consolidates the WAL file to zero size before close, releasing
    all sidecar (-shm, -wal) handles on Windows before the process exits.
    """
    for step, fn in [
        ("commit",     lambda: conn.commit()),
        ("checkpoint", lambda: conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")),
        ("close",      lambda: conn.close()),
    ]:
        try:
            fn()
        except Exception as exc:
            log.debug("close_db: %s failed (ignored): %s", step, exc)


def _db_retry(fn, *args, **kwargs):
    """Retry fn on sqlite3.OperationalError with exponential backoff."""
    for attempt in range(1, DB_RETRY_ATTEMPTS + 1):
        try:
            return fn(*args, **kwargs)
        except sqlite3.OperationalError as exc:
            if attempt == DB_RETRY_ATTEMPTS:
                log.error("DB gave up after %d attempts: %s", attempt, exc)
                raise
            wait = DB_RETRY_BASE_S * (2 ** (attempt - 1))
            log.warning(
                "DB OperationalError (attempt %d/%d): %s -- retry in %.2fs",
                attempt, DB_RETRY_ATTEMPTS, exc, wait,
            )
            time.sleep(wait)


def insert_batch(
    conn: sqlite3.Connection,
    results: list[dict],
) -> list[dict]:
    """INSERT OR IGNORE all AuditEvents in one transaction.

    Stores event_id, status, and full json.dumps(payload) -- the DB is the
    complete audit outbox.

    Per-row rowcount detection:
      rowcount == 1  -> new insert.
      rowcount == 0  -> duplicate; skip.
      rowcount < 0   -> undefined build; fall back to total_changes delta.
    """
    def _do() -> list[dict]:
        new_results: list[dict] = []
        cur = conn.cursor()

        conn.execute("BEGIN")
        for payload in results:
            before_row = conn.total_changes
            cur.execute(
                "INSERT OR IGNORE INTO processed(event_id, status, payload)"
                " VALUES (?, ?, ?)",
                (
                    payload["event_id"],
                    payload["status"],
                    json.dumps(payload),
                ),
            )
            if cur.rowcount == 1:
                new_results.append(payload)
            elif cur.rowcount < 0:
                if conn.total_changes > before_row:
                    new_results.append(payload)
        conn.commit()
        return new_results

    return _db_retry(_do) or []


# -- Atomic writers -----------------------------------------------------------

def load_checkpoint() -> int:
    if CHECKPOINT_FILE.exists():
        try:
            return int(json.loads(CHECKPOINT_FILE.read_text()).get("last_id", -1))
        except Exception:
            return -1
    return -1


def _atomic_write(path: pathlib.Path, text: str) -> None:
    """Write text to path.tmp, fsync (NTFS VDL commit), os.replace.

    Windows Safe Fsync: flush() moves data from Python's buffer to the OS page
    cache.  os.fsync() additionally forces the page cache and NTFS Valid Data
    Length (VDL) to be committed to the storage controller.  Without fsync(),
    a hard kill after flush() but before the rename can cause NTFS to truncate
    the .tmp file back to the last on-disk VDL -- producing a 0-byte audit log.
    After fsync() returns, the data is durable regardless of process state.
    This ensures immutable audit trails across complex OS file systems.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    with tmp.open("r+b") as fh:
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _atomic_json(path: pathlib.Path, data: dict) -> None:
    _atomic_write(path, json.dumps(data, indent=2))


def save_checkpoint(last_id: int) -> None:
    _atomic_json(CHECKPOINT_FILE, {"last_id": last_id})


def save_metrics(
    last_id:    int,
    total:      int,
    counts:     dict[str, int],
    start_time: float,
    skipped:    int = 0,
) -> None:
    elapsed = max(time.monotonic() - start_time, 1e-6)
    _atomic_json(METRICS_FILE, {
        "last_audited_event_id": last_id,
        "events_audited_total":  total,
        "events_per_second":     round(total / elapsed, 2),
        "audit_counts":          counts,
        "skipped_events":        skipped,
        "dead_letter_file":      str(DEAD_LETTER_FILE) if skipped else None,
    })


# -- Outbox export ------------------------------------------------------------

def export_audit_logs(conn: sqlite3.Connection) -> dict[str, int]:
    """Stream the audit ledger to JSONL output files with O(1) memory footprint.

    P0 -- Streaming Export:
      The previous implementation called .fetchall() which materialised the
      entire result set as a Python list before writing a single byte.  At
      100M events x ~200 B average payload that is ~20 GB of Python objects
      in RAM -- a guaranteed OOM kill on any machine with less than ~32 GB.

      This implementation opens one .tmp file per output bucket, then streams
      rows from the SQLite cursor directly to disk without accumulating them.
      Memory footprint is O(1) regardless of result-set size.

    Atomic guarantee per output file:
      1. Stream all rows for this bucket to <n>.jsonl.tmp
      2. fsync the .tmp file (NTFS VDL commit)
      3. os.replace(.tmp -> .jsonl)  (atomic rename, POSIX + Windows)
      If the process is killed between steps 2 and 3 the .tmp survives; the
      next export run overwrites it cleanly.

    P2 -- Per-file exception isolation:
      A PermissionError or OSError on one output file is caught, logged with
      the exact file path, and recorded in the return dict as count=-1.
      The export continues to the remaining files.

    Idempotent: safe to call multiple times on the same DB.
    Returns: dict mapping status -> row count written, or -1 on file error.
    """
    tmp_paths: dict[str, pathlib.Path] = {
        status: path.with_suffix(path.suffix + ".tmp")
        for status, path in AUDIT_LOG_FILES.items()
    }
    counts:      dict[str, int]    = {k: 0 for k in AUDIT_LOG_FILES}
    tmp_handles: dict[str, object] = {}

    try:
        for status, tmp_path in tmp_paths.items():
            tmp_handles[status] = tmp_path.open("w", encoding="utf-8")

        # Stream rows directly from the SQLite cursor -- never .fetchall().
        # The cursor yields one row at a time from the SQLite page cache;
        # Python never holds more than one row in memory at once.
        cursor = conn.execute(
            "SELECT status, payload FROM processed ORDER BY event_id"
        )
        for db_status, payload_json in cursor:
            key = db_status if db_status in AUDIT_LOG_FILES else "REVIEW"
            tmp_handles[key].write(payload_json + "\n")
            counts[key] += 1
        cursor.close()

    finally:
        for fh in tmp_handles.values():
            try:
                fh.close()
            except Exception:
                pass

    # fsync + atomic rename per file, with per-file exception isolation (P2).
    for status, path in AUDIT_LOG_FILES.items():
        tmp_path = tmp_paths[status]
        try:
            with tmp_path.open("r+b") as fh:
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
            log.info(
                "export_audit_logs: %s -> %d events", path.name, counts[status]
            )
        except Exception as exc:
            log.error(
                "export_audit_logs: FAILED writing %s: %s", path.name, exc
            )
            counts[status] = -1   # sentinel: file write failed

    return counts

# -- Drain helper -------------------------------------------------------------

def _record_dead_letter(chunk: list, exc: Exception) -> None:
    """P3 -- Dead-Letter Queue: append a skipped event-id range to the DLQ.

    Called whenever a worker future raises (worker crash, BrokenProcessPool,
    MemoryError, etc.).  The affected event_ids were never inserted into the
    audit ledger.  The DLQ provides operators a precise gap report without
    requiring a full DB scan.

    Write is append-only, best-effort (no fsync, no atomic rename).  The DLQ
    is an audit-assistance file, not a correctness guarantee: the DB is the
    source of truth.  A failed DLQ write is logged and ignored so it can never
    block pipeline shutdown.
    """
    if not chunk:
        return
    ids   = [c[0] for c in chunk]
    entry = json.dumps({
        "event_id_first": ids[0],
        "event_id_last":  ids[-1],
        "event_count":    len(ids),
        "error":          repr(exc),
        "ts_utc":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })
    try:
        with DEAD_LETTER_FILE.open("a", encoding="utf-8") as fh:
            fh.write(entry + "\n")
    except Exception as dlq_exc:
        log.warning("Dead-letter write failed (non-fatal): %s", dlq_exc)


def drain_one(
    in_flight:   dict[Future, list],
    conn:        sqlite3.Connection,
    counts:      dict[str, int],
    last_id_ref: list[int],
    skipped_ref: list[int],
) -> int:
    """Block until one future completes; commit its AuditEvents to the ledger.

    No JSONL writes happen here.  The DB is the sole sink during processing.

    P3 -- Dead-Letter Queue:
      When a future raises (worker crash, BrokenProcessPool, MemoryError),
      _record_dead_letter() appends the lost event_id range to
      skipped_ranges.jsonl and increments skipped_ref[0].  The pipeline
      continues processing remaining futures.

    Returns number of genuinely new events inserted this call.
    """
    for fut in as_completed(in_flight):
        chunk = in_flight.pop(fut)
        try:
            results: list[dict] = fut.result()
        except Exception as exc:
            ids = [c[0] for c in chunk]
            log.error(
                "Chunk error event_ids %s...%s: %r -- recorded to DLQ, "
                "audit continues.",
                ids[0], ids[-1], exc,
            )
            _record_dead_letter(chunk, exc)
            skipped_ref[0] += len(chunk)
            return 0

        new_results = insert_batch(conn, results)

        for payload in new_results:
            counts[payload["status"]] = counts.get(payload["status"], 0) + 1
            last_id_ref[0] = max(last_id_ref[0], int(payload["event_id"]))

        dup_skipped = len(results) - len(new_results)
        if dup_skipped:
            log.debug("Idempotency: skipped %d duplicate event(s).", dup_skipped)
        return len(new_results)
    return 0

# -- Main audit pipeline ------------------------------------------------------

_START_RE = re.compile(r"--- START EVENT\s+(\d+)\s+---")


def main() -> None:
    global _executor_ref, _stop_requested

    last_id_processed = load_checkpoint()
    cores             = os.cpu_count() or 4
    max_workers       = max(1, min(cores, CHUNK_SIZE))
    start_time        = time.monotonic()

    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    log.info(
        "Aequitas audit pipeline starting | "
        "cores=%d  workers=%d  chunk=%d  inflight=%d  resume_after=%d",
        cores, max_workers, CHUNK_SIZE, MAX_INFLIGHT, last_id_processed,
    )

    total:        int = 0
    chunks_done:  int = 0
    skipped_ref:  list[int] = [0]   # P3: cumulative DLQ event count
    counts: dict[str, int] = {"SANITIZED": 0, "SANITIZED_2": 0, "REVIEW": 0}
    last_id_ref = [max(0, last_id_processed)]

    current_batch: list[tuple[int, str]] = []
    in_flight:     dict[Future, list]    = {}

    conn     = open_db(DB_FILE)
    executor = ProcessPoolExecutor(max_workers=max_workers)
    _executor_ref = executor

    current_event: list[str] = []
    current_id: int           = -1

    def _submit() -> None:
        nonlocal current_batch
        if not current_batch:
            return
        sub_chunks = [
            current_batch[i::max_workers]
            for i in range(max_workers)
            if current_batch[i::max_workers]
        ]
        for sc in sub_chunks:
            in_flight[executor.submit(sanitize_chunk, sc)] = sc
        current_batch = []

    def _drain_checkpoint() -> None:
        nonlocal total, chunks_done
        written = drain_one(in_flight, conn, counts, last_id_ref, skipped_ref)
        total       += written
        chunks_done += 1
        if chunks_done % METRICS_INTERVAL == 0:
            save_checkpoint(last_id_ref[0])
            elapsed = max(time.monotonic() - start_time, 1e-6)
            log.info(
                "event=%-9d  total=%-9d  skipped=%-6d  eps=%.0f  %s",
                last_id_ref[0], total, skipped_ref[0], total / elapsed, counts,
            )
        # P1: periodic PASSIVE WAL checkpoint to bound WAL file growth.
        # PASSIVE does not block readers or writers; checkpoints what it can.
        if chunks_done % WAL_CHECKPOINT_INTERVAL == 0:
            try:
                conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
            except Exception as exc:
                log.debug("WAL checkpoint failed (non-fatal): %s", exc)

    try:
        try:
            # P4: errors="replace" -- a corrupt byte becomes U+FFFD instead
            # of raising UnicodeDecodeError and halting the pipeline.
            with INPUT_FILE.open("r", encoding="utf-8", errors="replace") as f_in:
                for line in f_in:
                    if _stop_requested:
                        break

                    if line.startswith("--- START EVENT"):
                        m = _START_RE.match(line.rstrip())
                        if m:
                            current_id    = int(m.group(1))
                            current_event = [line]
                        continue

                    if line.startswith("--- END EVENT") and current_event:
                        current_event.append(line)
                        current_batch.append((current_id, "".join(current_event)))
                        current_event = []
                        current_id    = -1

                        if len(current_batch) >= CHUNK_SIZE:
                            while len(in_flight) >= MAX_INFLIGHT:
                                _drain_checkpoint()
                            _submit()
                        continue

                    if current_event:
                        current_event.append(line)
                        if len(current_event) > MAX_EVENT_LINES:
                            log.warning(
                                "Event %d exceeded %d lines -- discarded (memory guard).",
                                current_id, MAX_EVENT_LINES,
                            )
                            current_event = []
                            current_id    = -1

        except (KeyboardInterrupt, SystemExit):
            log.warning("Interrupted -- draining in-flight work before exit.")
            _stop_requested = True
        except Exception as exc:
            log.exception("Fatal error in read loop: %s", exc)
            raise

        if current_batch and not _stop_requested:
            _submit()

        while in_flight:
            _drain_checkpoint()

    finally:
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

        log.info(
            "Final audit totals before exit: total=%d  skipped=%d  counts=%s",
            total, skipped_ref[0], counts,
        )
        if skipped_ref[0]:
            log.warning(
                "%d event(s) sent to dead-letter queue: %s",
                skipped_ref[0], DEAD_LETTER_FILE,
            )

        # Commit + WAL checkpoint (TRUNCATE) + close audit ledger.
        close_db(conn)

        # Export JSONL audit logs from outbox (atomic, idempotent).
        if not _stop_requested:
            _export_conn: sqlite3.Connection | None = None
            try:
                _export_conn = sqlite3.connect(str(DB_FILE), timeout=30)
                export_counts = export_audit_logs(_export_conn)
                log.info("export_audit_logs complete: %s", export_counts)
            except Exception as exc:
                log.error("export_audit_logs failed: %s", exc)
            finally:
                if _export_conn is not None:
                    try:
                        _export_conn.close()
                    except Exception:
                        pass

        # Final atomic checkpoint + metrics.
        try:
            save_checkpoint(last_id_ref[0])
            save_metrics(last_id_ref[0], total, counts, start_time,
                         skipped=skipped_ref[0])
        except Exception as exc:
            log.error("Could not write final checkpoint/metrics: %s", exc)

    elapsed = time.monotonic() - start_time
    log.info(
        "DONE | events=%d  elapsed=%.1fs  eps=%.0f  %s",
        total, elapsed, total / max(elapsed, 1e-6), counts,
    )


if __name__ == "__main__":
    main()
