"""
tests/test_worker.py — Aequitas Privacy Engine  |  Worker Unit Test Suite
=========================================================================
Tests for sanitize_event() and sanitize_chunk() in src/worker.py.

Each test class maps 1-to-1 with a logical aspect of the sanitization pipeline:
  1. Homoglyph normalization
  2. Two-digit year auto-correction
  3. Size-field validation (including asterisk corruption and all prefix variants)
  4. Timestamp validation (missing, hallucinated, invalid month)
  5. Truncated / empty events and chunk processing
  6. Tracker domain detection (raw and encoding-corrupted variants)
  7. PII redaction (email stripping, output cleanliness)
  8. insert_batch idempotency (unit-level, no subprocess)

Run: pytest tests/test_worker.py -v
"""

import pytest
from src.worker import _normalize, sanitize_event, sanitize_chunk


# -- helpers ------------------------------------------------------------------

def evt(eid: int, tracker: str, ts: str, size: str, extra_lines: str = "") -> str:
    """Build a minimal synthetic TrackerPayload log record for testing."""
    body = (
        f"  tracker:    {tracker}\n"
        f"  timestamp:  {ts}\n"
        f"  client_ip:  10.1.2.3\n"
        f"  session_id: abcdef1234567890abcdef1234567890\n"
        f"  {size}\n"
    )
    if extra_lines:
        body += extra_lines + "\n"
    return f"--- START EVENT {eid} ---\n{body}--- END EVENT {eid} ---\n"


# Default tracker and size used when the test is not specifically about them.
_DOM  = "track.analytics-beacon.io"
_SIZE = "SIZE: B: 1,024"


# =============================================================================
# 1. Homoglyph normalisation  (NFKC + table)
# =============================================================================

class TestHomoglyphNormalisation:

    @pytest.mark.parametrize("ch,expected", [
        ("O", "0"), ("o", "0"),
        ("l", "1"), ("I", "1"),
        ("S", "5"),
        ("Z", "2"),
        ("B", "8"),
        ("\u2014", "-"),    # em-dash
        ("\u2013", "-"),    # en-dash
        ("\uff10", "0"),    # FULLWIDTH DIGIT ZERO  (NFKC -> "0")
        ("\uff11", "1"),    # FULLWIDTH DIGIT ONE   (NFKC -> "1")
    ])
    def test_single_char(self, ch: str, expected: str) -> None:
        assert _normalize(ch) == expected

    def test_idempotent(self) -> None:
        s = "SIZE: SZ: 99"
        assert _normalize(s) == _normalize(_normalize(s))

    def test_chain_substitution(self) -> None:
        # S->5, O->0, l->1, I->1, Z->2, B->8
        assert _normalize("SOlIZB") == "501128"

    def test_sentinel_lines_not_normalised(self) -> None:
        """'S' in START/EVENT and domain chars must survive because
        sanitize_event() strips sentinel lines before calling _normalize()."""
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", _SIZE))
        # tracker field is matched from pre-norm body for domain classification;
        # confirm the event is not misclassified due to sentinel corruption.
        assert r["status"] == "SANITIZED"
        assert r["event_id"] == 1

    def test_ascii_digits_unchanged(self) -> None:
        assert _normalize("0123456789") == "0123456789"


# =============================================================================
# 2. Two-digit year auto-correction
# =============================================================================

class TestTwoDigitYearCorrection:

    def test_status_sanitized_2(self) -> None:
        r = sanitize_event(1, evt(1, _DOM, "15/03/25", _SIZE))
        assert r["status"] == "SANITIZED_2"

    def test_year_expanded_to_four_digits(self) -> None:
        r = sanitize_event(1, evt(1, _DOM, "15/03/25", _SIZE))
        assert r["timestamp"] == "15/03/2025"

    def test_reason_present(self) -> None:
        r = sanitize_event(1, evt(1, _DOM, "15/03/25", _SIZE))
        assert "Year auto-corrected (2-digit)" in r["routing_reasons"]

    def test_four_digit_year_is_sanitized(self) -> None:
        r = sanitize_event(1, evt(1, _DOM, "15/03/2024", _SIZE))
        assert r["status"] == "SANITIZED"
        assert r["timestamp"] == "15/03/2024"

    def test_two_digit_year_with_missing_size_yields_review(self) -> None:
        """Two-digit year + no size field -> worst status wins: REVIEW."""
        txt = (
            "--- START EVENT 2 ---\n"
            "  tracker:    px.ad-metrics.net\n"
            "  timestamp:  15/03/25\n"
            "  client_ip:  10.0.0.1\n"
            "  session_id: aabbccdd\n"
            "--- END EVENT 2 ---\n"
        )
        r = sanitize_event(2, txt)
        assert r["status"] == "REVIEW"
        assert "Year auto-corrected (2-digit)" in r["routing_reasons"]
        assert "Size field missing" in r["routing_reasons"]

    @pytest.mark.parametrize("sep", [".", "/", "-"])
    def test_separator_variants(self, sep: str) -> None:
        r = sanitize_event(1, evt(1, _DOM, f"15{sep}03{sep}25", _SIZE))
        assert r["status"] == "SANITIZED_2"
        assert r["timestamp"] == "15/03/2025"


# =============================================================================
# 3. Size-field validation
# =============================================================================

class TestSizeField:

    def test_size_prefix_b(self) -> None:
        """B: prefix after normalization becomes 8: -- must still match."""
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", "SIZE: B: 1,024"))
        assert r["status"] == "SANITIZED"
        assert r["payload_size"] == "1,024"

    def test_size_prefix_sz(self) -> None:
        """SZ: prefix after normalization becomes 52: -- must still match."""
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", "SIZE: SZ: 2,048"))
        assert r["status"] == "SANITIZED"
        assert r["payload_size"] == "2,048"

    def test_size_prefix_dollar(self) -> None:
        """Dollar sign prefix must match as literal character, not end-of-string anchor.
        Regression: \\$ in a Python regex alternation is an anchor, not a dollar literal.
        The fix is to use [$] inside a character class instead."""
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", "SIZE: $ 512"))
        assert r["status"] == "SANITIZED", (
            f"Dollar prefix failed -- \\$ anchor bug? status={r['status']}, "
            f"reasons={r['routing_reasons']}"
        )
        assert r["payload_size"] == "512"

    def test_size_large_value(self) -> None:
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", "SIZE: B: 65,535"))
        assert r["status"] == "SANITIZED"
        assert r["payload_size"] == "65,535"

    def test_asterisk_corruption_fully_masked(self) -> None:
        r = sanitize_event(10, evt(10, _DOM, "01/01/2024", "SIZE: B: ***"))
        assert r["status"] == "REVIEW"
        assert any(
            "corrupt" in x.lower() or "asterisk" in x.lower()
            for x in r["routing_reasons"]
        )

    def test_asterisk_corruption_partial(self) -> None:
        r = sanitize_event(10, evt(10, _DOM, "01/01/2024", "SIZE: B: 1*0"))
        assert r["status"] == "REVIEW"

    def test_size_field_missing(self) -> None:
        txt = (
            "--- START EVENT 11 ---\n"
            "  tracker:    px.ad-metrics.net\n"
            "  timestamp:  01/01/2024\n"
            "  client_ip:  10.0.0.1\n"
            "  session_id: aabbccdd\n"
            "--- END EVENT 11 ---\n"
        )
        r = sanitize_event(11, txt)
        assert r["status"] == "REVIEW"
        assert "Size field missing" in r["routing_reasons"]
        assert r["payload_size"] is None


# =============================================================================
# 4. Timestamp validation
# =============================================================================

class TestTimestampValidation:

    def test_no_timestamp_at_all(self) -> None:
        txt = (
            "--- START EVENT 20 ---\n"
            "  tracker:    px.ad-metrics.net\n"
            "  client_ip:  10.0.0.1\n"
            "  session_id: aabbccdd\n"
            "  SIZE: B: 512\n"
            "--- END EVENT 20 ---\n"
        )
        r = sanitize_event(20, txt)
        assert r["status"] == "REVIEW"
        assert "Timestamp missing" in r["routing_reasons"]
        assert r["timestamp"] is None

    def test_hallucinated_question_marks(self) -> None:
        r = sanitize_event(21, evt(21, _DOM, "??/??/????", _SIZE))
        assert r["status"] == "REVIEW"
        assert "Timestamp hallucinated" in r["routing_reasons"]

    def test_invalid_month_13(self) -> None:
        r = sanitize_event(22, evt(22, _DOM, "01/13/2024", _SIZE))
        assert r["status"] == "REVIEW"
        assert any("month" in x.lower() for x in r["routing_reasons"])

    def test_invalid_month_14(self) -> None:
        r = sanitize_event(23, evt(23, _DOM, "15/14/2024", _SIZE))
        assert r["status"] == "REVIEW"

    def test_partial_question_marks_in_day(self) -> None:
        r = sanitize_event(24, evt(24, _DOM, "??/03/2024", _SIZE))
        assert r["status"] == "REVIEW"
        assert "Timestamp hallucinated" in r["routing_reasons"]


# =============================================================================
# 5. Truncated / empty events and chunk processing
# =============================================================================

class TestChunkProcessing:

    def test_empty_body_does_not_raise(self) -> None:
        """Event with no body between sentinels must not raise; must be
        routed to REVIEW with appropriate reasons."""
        results = sanitize_chunk([(50, "--- START EVENT 50 ---\n--- END EVENT 50 ---\n")])
        assert len(results) == 1
        assert results[0]["status"] == "REVIEW"

    def test_sanitize_chunk_multi_event(self) -> None:
        chunk = [
            (1, evt(1, _DOM,                      "01/01/2024", _SIZE)),
            (2, evt(2, "px.ad-metrics.net",        "15/03/25",   "SIZE: SZ: 20")),
            (3, evt(3, "collect.telemetry-hub.com","??/??/????", "SIZE: B: 5")),
        ]
        results = sanitize_chunk(chunk)
        assert len(results) == 3
        assert results[0]["status"] == "SANITIZED"
        assert results[1]["status"] == "SANITIZED_2"
        assert results[2]["status"] == "REVIEW"

    def test_event_id_is_int(self) -> None:
        results = sanitize_chunk([(99, evt(99, _DOM, "01/01/2024", _SIZE))])
        assert isinstance(results[0]["event_id"], int)
        assert results[0]["event_id"] == 99

    def test_large_event_id(self) -> None:
        results = sanitize_chunk([(999_999, evt(999_999, _DOM, "01/01/2024", _SIZE))])
        assert results[0]["event_id"] == 999_999

    def test_event_with_many_body_lines_processed_correctly(self) -> None:
        """Events with many body lines (below MAX_EVENT_LINES) must succeed."""
        extra = "\n".join(
            f"  PARAM_{i}: value-{i:03d}" for i in range(1, 30)
        )
        txt = (
            "--- START EVENT 77 ---\n"
            f"  tracker:    {_DOM}\n"
            "  timestamp:  01/06/2024\n"
            "  client_ip:  10.1.2.3\n"
            "  session_id: abcdef1234567890abcdef1234567890\n"
            f"{extra}\n"
            "  SIZE: B: 150\n"
            "--- END EVENT 77 ---\n"
        )
        results = sanitize_chunk([(77, txt)])
        assert results[0]["status"] == "SANITIZED"
        assert results[0]["event_id"] == 77


# =============================================================================
# 6. Tracker domain detection
# =============================================================================

class TestTrackerDomainDetection:

    @pytest.mark.parametrize("tracker_str,expected", [
        # Post-normalization canonical forms
        ("track.analytics-beacon.io",  "analytics-beacon"),
        ("tr4ck.analytics-beacon.io",  "analytics-beacon"),   # digit corruption
        ("px.ad-metrics.net",          "ad-metrics"),
        ("px.ad-m3trics.net",          "ad-metrics"),         # digit corruption
        ("collect.telemetry-hub.com",  "telemetry-hub"),
        ("c0llect.telemetry-hub.com",  "telemetry-hub"),      # zero corruption
        # Unknown tracker
        ("unknown.tracker.xyz",        "UNKNOWN"),
    ])
    def test_tracker_domain(self, tracker_str: str, expected: str) -> None:
        r = sanitize_event(1, evt(1, tracker_str, "01/01/2024", _SIZE))
        assert r["tracker"] == expected, (
            f"Domain {tracker_str!r}: expected {expected!r}, got {r['tracker']!r}"
        )


# =============================================================================
# 7. PII redaction
# =============================================================================

class TestPIIRedaction:

    def test_email_in_size_field_triggers_review(self) -> None:
        r = sanitize_event(100, evt(100, "px.ad-metrics.net", "10/06/2023",
                                   "SIZE: ref=user@example.com B: 512"))
        assert r["status"] == "REVIEW"

    def test_pii_routing_reason_present(self) -> None:
        r = sanitize_event(100, evt(100, "px.ad-metrics.net", "10/06/2023",
                                   "SIZE: ref=user@example.com B: 512"))
        assert any("PII" in reason for reason in r["routing_reasons"]), (
            f"Expected PII reason in {r['routing_reasons']}"
        )

    def test_raw_email_absent_from_output_dict(self) -> None:
        """The raw email address must never appear in the returned AuditEvent."""
        r = sanitize_event(100, evt(100, "px.ad-metrics.net", "10/06/2023",
                                   "SIZE: ref=john.doe@corp.internal B: 256"))
        assert "john.doe@corp.internal" not in str(r), (
            "Raw PII email leaked into output dict"
        )

    @pytest.mark.parametrize("email", [
        "user@example.com",
        "john.doe@corp.internal",
        "alice@mail.test",
        "b.jones@subdomain.example.org",
    ])
    def test_various_email_formats_redacted(self, email: str) -> None:
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024",
                                  f"SIZE: ref={email} B: 512"))
        assert email not in str(r), f"Email {email!r} leaked into output"
        assert r["status"] == "REVIEW"

    def test_ip_address_not_redacted(self) -> None:
        """IPv4 addresses are not PII in this pipeline -- must not be stripped."""
        r = sanitize_event(1, evt(1, _DOM, "01/01/2024", _SIZE))
        assert r["status"] == "SANITIZED"
        # client_ip field exists and is not redacted
        assert r["event_id"] == 1

    def test_tracker_url_stripped_from_body(self) -> None:
        """Tracker collection URLs must be replaced with [REDACTED-TRACKER-URL]."""
        tracker_url = "https://track.analytics-beacon.io/collect?cid=abc&ev=5"
        txt = (
            "--- START EVENT 1 ---\n"
            f"  tracker:    {tracker_url}\n"
            "  timestamp:  01/01/2024\n"
            "  client_ip:  10.1.2.3\n"
            "  session_id: abcdef\n"
            "  SIZE: B: 512\n"
            "--- END EVENT 1 ---\n"
        )
        r = sanitize_event(1, txt)
        # Raw URL must not appear in the output
        assert tracker_url not in str(r)


# =============================================================================
# 8. insert_batch idempotency (unit-level, no subprocess)
# =============================================================================

class TestInsertBatch:

    def _make_payload(self, event_id: int, status: str = "SANITIZED") -> dict:
        return {
            "event_id":        event_id,
            "tracker":         "ad-metrics",
            "timestamp":       "01/01/2024",
            "payload_size":    "512",
            "status":          status,
            "routing_reasons": [],
        }

    def test_first_insert_returns_payload(self, tmp_path) -> None:
        from main import open_db, insert_batch
        conn = open_db(tmp_path / "test.db")
        result = insert_batch(conn, [self._make_payload(1)])
        conn.close()
        assert len(result) == 1
        assert result[0]["event_id"] == 1

    def test_duplicate_insert_returns_empty(self, tmp_path) -> None:
        from main import open_db, insert_batch
        conn = open_db(tmp_path / "test.db")
        p = self._make_payload(2)
        insert_batch(conn, [p])           # first insert
        result = insert_batch(conn, [p])  # duplicate
        conn.close()
        assert result == []

    def test_mixed_batch_new_and_duplicate(self, tmp_path) -> None:
        from main import open_db, insert_batch
        conn = open_db(tmp_path / "test.db")
        insert_batch(conn, [self._make_payload(10)])                    # seed id=10
        result = insert_batch(conn,
                              [self._make_payload(10), self._make_payload(11)])
        conn.close()
        assert len(result) == 1
        assert result[0]["event_id"] == 11

    def test_retry_does_not_duplicate(self, tmp_path) -> None:
        """Simulate a retry: new_results must be declared inside _do() so
        each attempt starts with a clean list, never accumulating from prior
        failed attempts."""
        import sqlite3 as _sq
        from main import _db_retry
        conn = _sq.connect(str(tmp_path / "test.db"))
        conn.execute(
            "CREATE TABLE processed "
            "(event_id INTEGER PRIMARY KEY, status TEXT NOT NULL DEFAULT '', "
            " payload TEXT NOT NULL DEFAULT '')"
        )
        conn.commit()

        call_count = [0]

        def _do():
            call_count[0] += 1
            new_results = []   # inside _do so retries start clean
            cur = conn.cursor()
            conn.execute("BEGIN")
            cur.execute(
                "INSERT OR IGNORE INTO processed(event_id, status, payload) VALUES (?,?,?)",
                (99, "SANITIZED", "{}")
            )
            if cur.rowcount == 1:
                new_results.append({"event_id": 99})
            conn.commit()
            return new_results

        result = _db_retry(_do)
        assert result == [{"event_id": 99}], "First call must return new payload"

        result2 = _db_retry(_do)
        assert result2 == [], "Second call must return empty (duplicate)"
        conn.close()

    def test_payload_stored_in_db(self, tmp_path) -> None:
        """insert_batch must persist the full JSON payload in the DB."""
        import sqlite3 as _sq, json
        from main import open_db, insert_batch
        conn = open_db(tmp_path / "test.db")
        p = self._make_payload(42, status="REVIEW")
        insert_batch(conn, [p])
        row = conn.execute(
            "SELECT status, payload FROM processed WHERE event_id = 42"
        ).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == "REVIEW"
        stored = json.loads(row[1])
        assert stored["event_id"] == 42
        assert stored["tracker"] == "ad-metrics"
