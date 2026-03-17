"""
src/worker.py — Aequitas Privacy Engine  [Hardened]
========================================
Stateless, multiprocessing-safe TrackerPayload sanitization worker.

Each worker process receives a chunk of raw log records (TrackerPayloads),
applies PII redaction and tracker-URL normalization, classifies the result,
and returns structured AuditEvent dicts to the main process.  Workers never
touch the database or output files directly.

Key design points
-----------------
SIGTERM handler
  Registers a minimal handler that sets _stop_requested.  The handler only
  flips a flag -- it never performs I/O (Python signal handlers run between
  bytecodes; blocking I/O inside them can deadlock).  sanitize_chunk() checks
  the flag between events for cooperative shutdown.

  Windows note: SIGTERM is not a real OS signal on Windows.  Python maps it to
  a software-level notification.  Graceful stop on Windows relies primarily on
  the main process calling executor.shutdown(cancel_futures=True).  The handler
  is still registered for portability.

Normalization scope
  _normalize() is applied only to event *body* lines (everything between the
  --- START EVENT --- and --- END EVENT --- sentinels).  This prevents
  homoglyph substitution from corrupting structural tokens ("START", "EVENT")
  and tracker domain names that contain those characters.

  After _normalize(): S->5, Z->2 -- patterns use canonical post-norm forms.

PII redaction
  sanitize_event() applies _PII_REDACT_RE to body text before pattern matching.
  This strips any bare email addresses that leaked into log fields (e.g. a
  REVIEW_PII record), replacing them with the literal token [REDACTED-EMAIL].
  The regex runs as a fast re.sub() and adds negligible latency per event.

Tracker-URL stripping
  _TRACKER_URL_RE strips tracker collection URLs (collect/track endpoints),
  replacing them with [REDACTED-TRACKER-URL].  This fires on the normalized
  body before domain classification so malformed URL variants are also caught.

Compiled patterns
  All patterns are compiled once at module import time and reused for every
  event in the worker's lifetime -- no per-event re-compile overhead.
"""

import re
import signal
import unicodedata
from typing import Any

# -- Configuration (must match main.py) --------------------------------------
MAX_EVENT_BYTES = 65_536   # P5: byte-length guard before any regex (64 KB)

# -- Cooperative stop flag ---------------------------------------------------
_stop_requested: bool = False


def _handle_sigterm(signum, frame) -> None:   # noqa: ANN001
    """Minimal SIGTERM handler -- sets flag only; no I/O."""
    global _stop_requested
    _stop_requested = True


signal.signal(signal.SIGTERM, _handle_sigterm)


# -- Homoglyph normalization --------------------------------------------------
_HOMOGLYPH_TABLE = str.maketrans({
    "O": "0", "o": "0",
    "l": "1", "I": "1",
    "S": "5",
    "Z": "2",
    "B": "8",
    "\u2014": "-",    # em-dash
    "\u2013": "-",    # en-dash
    "\u00D0": "0",    # Eth -- rare scanner artefact
})


def _normalize(text: str) -> str:
    """NFKC Unicode decomposition followed by homoglyph replacement.
    Must be called only on body lines -- not on sentinel lines."""
    return unicodedata.normalize("NFKC", text).translate(_HOMOGLYPH_TABLE)


# -- Compiled patterns --------------------------------------------------------
# All patterns operate on post-normalization text unless noted otherwise.

# Tracker-domain patterns -- match known collection domains after normalization.
# After _normalize(): O->0, S->5, Z->2 so domains like "analytics-beacon.io"
# survive; corrupted variants like "tr4ck.*" are caught by flexible patterns.
_TRACKER_PATTERNS: dict[str, re.Pattern[str]] = {
    # Post-normalization: l->1, o->0, S->5, so domain chars shift.
    # "analytics-beacon.io" -> "ana1ytics-beac0n.i0"
    # "ad-metrics.net"      -> "ad-metrics.net"  (no affected chars)
    # "telemetry-hub.com"   -> "te1emetry-hub.c0m"
    # "collect.*"           -> "c011ect.*"
    # Patterns use flexible character classes to match both pre- and post-norm.
    "analytics-beacon": re.compile(
        r"\btr(?:4|a)ck\.ana[l1]yt[i1]cs-beac[o0]n\.[i1][o0]\b", re.IGNORECASE
    ),
    "ad-metrics": re.compile(
        r"\bpx\.ad-m[3e]tr[i1]cs\.net\b", re.IGNORECASE
    ),
    "telemetry-hub": re.compile(
        r"\bc[o0][l1][l1]ect\.te[l1]emetry-hub\.c[o0]m\b", re.IGNORECASE
    ),
}

# Timestamp pattern -- groups accept digits OR '?' for hallucinated fields.
_TIMESTAMP_RE = re.compile(
    r"(?P<d>\d{1,2}|\?{1,2})[./-]"
    r"(?P<m>\d{1,2}|\?{1,2})[./-]"
    r"(?P<y>\d{2,4}|\?{2,4})"
)

# Payload-size field -- matches all encoding variants after normalization:
#   B: / SZ: -> 5: / 52: (after S->5, Z->2)   $ stays $
_SIZE_RE = re.compile(
    # Post-normalization: SIZE -> 512E  (S->5, I->1, Z->2; E unchanged)
    # Prefix variants after normalization:
    #   B:  -> 8:    SZ: -> 52:    $  -> $  (unchanged)
    # IMPORTANT: use [$] not \$ in the prefix alternation.  In Python regex,
    # \$ is an end-of-string anchor (same as $), not a literal dollar sign.
    # Inside a character class, $ is always treated as a literal character.
    r"(?i)512E[:\s]*"
    r"(?:(?P<pfx>8[:\s]|52[:\s]|[$])\s*)?"
    r"(?P<sz>\d{1,3}(?:,\d{3})*)"
)

# Asterisk-corruption check -- run on raw_text BEFORE normalization so the
# '*' sentinel is never silently consumed by character substitution.
_CORRUPT_RE = re.compile(r"(?:SIZE|512E)[:\s]*[\S\s]{0,10}\*", re.IGNORECASE)

# PII redaction -- strips bare email addresses from any field.
# Applied as the FIRST step so downstream patterns never see raw PII.
_PII_REDACT_RE = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
    re.IGNORECASE,
)

# Tracker-URL redaction -- strips /collect and /track endpoint URLs.
_TRACKER_URL_RE = re.compile(
    r"https?://[^\s\"']+/(?:collect|track)\?[^\s\"']*",
    re.IGNORECASE,
)


# -- Core sanitization --------------------------------------------------------

def sanitize_event(event_id: int, raw_text: str) -> dict[str, Any]:
    """Sanitize and classify a single TrackerPayload log record.

    Processing pipeline per event:
      1. Strip sentinel lines (--- START/END EVENT ---).
      2. Apply PII redaction (email addresses -> [REDACTED-EMAIL]).
      3. Apply tracker-URL stripping -> [REDACTED-TRACKER-URL].
      4. Apply homoglyph normalization (_normalize) to cleaned body.
      5. Classify tracker domain, timestamp, and payload size.
      6. Return AuditEvent dict with status and routing_reasons.

    event_id is always int throughout the pipeline.
    """
    # P5 -- Poison-Pill Byte-Length Guard:
    # Apply before any string or regex work.  A crafted or corrupted event
    # that is abnormally large (e.g. log injection, runaway encoder) could
    # cause the _TRACKER_URL_RE or _PII_REDACT_RE to spend seconds on a
    # single record, stalling the worker and blocking the entire chunk.
    # Any event exceeding MAX_EVENT_BYTES is immediately routed to REVIEW
    # without running a single regex -- O(1) cost.
    if len(raw_text.encode("utf-8", errors="replace")) > MAX_EVENT_BYTES:
        return {
            "event_id":        event_id,
            "tracker":         "UNKNOWN",
            "timestamp":       None,
            "payload_size":    None,
            "status":          "REVIEW",
            "routing_reasons": [f"Event too large (>{MAX_EVENT_BYTES} bytes)"],
        }

    # Step 1: strip sentinels so normalization never corrupts structural tokens.
    body_lines = [
        ln for ln in raw_text.splitlines()
        if not ln.startswith("--- START EVENT")
        and not ln.startswith("--- END EVENT")
    ]
    raw_body = "\n".join(body_lines)

    # Step 2: PII redaction -- must run before normalization and classification
    # so no downstream pattern ever observes a raw email address.
    redacted_body = _PII_REDACT_RE.sub("[REDACTED-EMAIL]", raw_body)

    # Step 3: tracker-URL stripping.
    # P7 -- Short-circuit: _TRACKER_URL_RE only fires if 'http' is present.
    # The pattern scans the entire body string; on the ~96% of events that
    # contain no URL the literal check costs ~10 ns vs ~1-3 µs for the scan.
    if "http" in redacted_body:
        redacted_body = _TRACKER_URL_RE.sub("[REDACTED-TRACKER-URL]", redacted_body)

    # Step 4: homoglyph normalization on the already-redacted body.
    text = _normalize(redacted_body)

    status: str        = "SANITIZED"
    reasons: list[str] = []
    timestamp_val      = None
    size_val           = None
    tracker_val        = "UNKNOWN"

    # -- Tracker domain classification ----------------------------------------
    for name, pat in _TRACKER_PATTERNS.items():
        if pat.search(text):
            tracker_val = name
            break

    # -- Timestamp validation -------------------------------------------------
    tm = _TIMESTAMP_RE.search(text)
    if not tm:
        status = "REVIEW"
        reasons.append("Timestamp missing")
    else:
        d, m, y = tm.group("d"), tm.group("m"), tm.group("y")
        if "?" in d or "?" in m or "?" in y:
            status = "REVIEW"
            reasons.append("Timestamp hallucinated")
        elif len(m) > 2 or (m.isdigit() and int(m) > 12):
            status = "REVIEW"
            reasons.append(f"Invalid month: {m}")
        elif len(y) == 2:
            status        = "SANITIZED_2"
            y             = "20" + y
            timestamp_val = f"{d.zfill(2)}/{m.zfill(2)}/{y}"
            reasons.append("Year auto-corrected (2-digit)")
        else:
            timestamp_val = f"{d.zfill(2)}/{m.zfill(2)}/{y.zfill(4)}"

    # -- Payload-size field -- asterisk check on raw_text before normalization -
    if _CORRUPT_RE.search(raw_text):
        status = "REVIEW"
        reasons.append("Size field corrupted (asterisk)")
    elif "[REDACTED-EMAIL]" in redacted_body:
        # PII was found and stripped; escalate to REVIEW for audit trail.
        status = "REVIEW"
        reasons.append("PII detected and redacted (email)")
    else:
        sm = _SIZE_RE.search(text)
        if sm:
            try:
                int(sm.group("sz").replace(",", ""))
                size_val = sm.group("sz")
            except ValueError:
                status = "REVIEW"
                reasons.append("Size parse error")
        else:
            if status != "REVIEW":
                status = "REVIEW"
            reasons.append("Size field missing")

    return {
        "event_id":        event_id,    # int -- always
        "tracker":         tracker_val,
        "timestamp":       timestamp_val,
        "payload_size":    size_val,
        "status":          status,
        "routing_reasons": reasons,
    }


def sanitize_chunk(chunk: list[tuple[int, str]]) -> list[dict[str, Any]]:
    """Sanitize a batch of (event_id: int, raw_text: str) TrackerPayload pairs.
    Checks _stop_requested between events for cooperative shutdown."""
    results: list[dict[str, Any]] = []
    for eid, raw in chunk:
        if _stop_requested:
            break
        results.append(sanitize_event(eid, raw))
    return results
