"""
src/generator.py — Aequitas Privacy Engine
==========================================
Deterministic synthetic web-traffic log generator for pipeline benchmarking
and regression testing.

Each generated record is a TrackerPayload: a simulated browser request that
may contain PII (IP address, session token, email) and/or third-party tracker
URLs.  The distribution ladder injects known-bad patterns at controlled rates
so the sanitization pipeline can be validated against expected output counts.

Ladder (rarest -> most-common; mutually exclusive via largest-divisor-first):
  eid % 1000 == 0  ->  MALFORMED    (truncated record, no END marker)    ~0.10 %
  eid % 500  == 0  ->  REVIEW_LOGIC (impossible timestamp: month 14)     ~0.10 %
  eid % 200  == 0  ->  REVIEW_HALLU (hallucinated timestamp ??/??/????)  ~0.30 %
  eid % 100  == 0  ->  REVIEW_PII   (unredacted email in size field)     ~0.20 %
  eid % 33   == 0  ->  SANITIZED_2  (two-digit year -> auto-corrected)   ~2.98 %
  else             ->  SANITIZED    (clean, fully redacted payload)      ~96.32 %

Checking the largest divisor first prevents shadowing (e.g., % 100 would
incorrectly absorb % 200 and % 500 records because every multiple of 200/500
is also a multiple of 100).

Run: python -m src.generator [--total N] [--output PATH] [--seed S]
"""

import argparse
import random
import pathlib

DEFAULT_OUTPUT = pathlib.Path("data/raw_samples/tracker_stream.log")
DEFAULT_TOTAL  = 1_000_000

# Simulated third-party tracker domains injected into tracker fields.
TRACKER_DOMAINS = [
    "track.analytics-beacon.io",
    "tr4ck.analytics-beacon.io",
    "px.ad-metrics.net",
    "px.ad-m3trics.net",
    "collect.telemetry-hub.com",
    "c0llect.telemetry-hub.com",
]

# Encoding-artefact noise table -- simulates character corruption in log pipelines.
_ENCODING_NOISE: dict[str, str] = {
    "0": "O", "1": "l", "5": "S", "8": "B", "2": "Z", "O": "0", "l": "1",
}


# -- helpers ------------------------------------------------------------------

def corrupt(text: str, rate: float = 0.05) -> str:
    """Inject random encoding-artefact noise at the given character-level rate."""
    chars = list(text)
    for i, ch in enumerate(chars):
        if ch in _ENCODING_NOISE and random.random() < rate:
            chars[i] = _ENCODING_NOISE[ch]
    return "".join(chars)


def _fake_ip() -> str:
    """Generate a synthetic IPv4 address in a non-routable RFC-1918 range."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _fake_session() -> str:
    """Generate a synthetic 32-hex-char session token."""
    return "".join(random.choices("0123456789abcdef", k=32))


def _fake_email() -> str:
    """Synthetic email address, injected into REVIEW_PII payloads."""
    user   = random.choice(["user", "john.doe", "j.smith", "alice", "b.jones"])
    domain = random.choice(["example.com", "corp.internal", "mail.test"])
    return f"{user}@{domain}"


def _tracker_url() -> str:
    domain = random.choice(TRACKER_DOMAINS)
    path   = f"/collect?cid={_fake_session()[:8]}&ev={random.randint(1,99)}"
    return corrupt(f"https://{domain}{path}")


def _clean_timestamp() -> str:
    day   = str(random.randint(1, 28)).zfill(2)
    month = str(random.randint(1, 12)).zfill(2)
    year  = str(random.choice([2022, 2023, 2024]))
    sep   = random.choice([".", "/", "-"])
    return corrupt(f"{day}{sep}{month}{sep}{year}", rate=0.03)


def _clean_payload_size() -> str:
    size     = random.randint(128, 65535)
    prefix   = random.choice(["B:", "SZ:", "$"])
    return corrupt(f"SIZE: {prefix} {size:,}", rate=0.03)


def _domain() -> str:
    return corrupt(random.choice(TRACKER_DOMAINS))


def _assemble(
    event_id: int,
    tracker: str,
    timestamp: str,
    size_field: str,
    client_ip: str,
    session_id: str,
    include_end: bool = True,
) -> str:
    lines = [
        f"  tracker:    {tracker}",
        f"  timestamp:  {timestamp}",
        f"  client_ip:  {client_ip}",
        f"  session_id: {session_id}",
        f"  {size_field}",
    ]
    body = "\n".join(lines)
    end  = f"--- END EVENT {event_id} ---\n" if include_end else ""
    return f"--- START EVENT {event_id} ---\n{body}\n{end}"


# -- deterministic injection ladder -------------------------------------------

def make_event(event_id: int) -> str:
    """
    Generate one synthetic TrackerPayload log record.

    Rarest-first modulo ladder -- every bucket is mutually exclusive.
    """
    eid = event_id
    ip  = _fake_ip()
    sid = _fake_session()

    # MALFORMED ~0.10 %: truncated record (no END marker)
    if eid % 1000 == 0:
        return _assemble(eid, _domain(), _clean_timestamp(),
                         _clean_payload_size(), ip, sid, include_end=False)

    # REVIEW_LOGIC ~0.10 %: impossible timestamp (month 14)
    if eid % 500 == 0:
        day = str(random.randint(1, 28)).zfill(2)
        sep = random.choice([".", "/", "-"])
        return _assemble(eid, _domain(), f"{day}{sep}14{sep}2024",
                         _clean_payload_size(), ip, sid)

    # REVIEW_HALLU ~0.30 %: hallucinated timestamp
    if eid % 200 == 0:
        return _assemble(eid, _domain(), "??/??/????",
                         _clean_payload_size(), ip, sid)

    # REVIEW_PII ~0.20 %: unredacted email leaks into size field
    if eid % 100 == 0:
        leaky = corrupt(f"SIZE: ref={_fake_email()} B: {random.randint(128,4096):,}")
        return _assemble(eid, _domain(), _clean_timestamp(),
                         leaky, ip, sid)

    # SANITIZED_2 ~2.98 %: two-digit year
    if eid % 33 == 0:
        day        = str(random.randint(1, 28)).zfill(2)
        month      = str(random.randint(1, 12)).zfill(2)
        sep        = random.choice([".", "/", "-"])
        short_year = str(random.randint(20, 29)).zfill(2)
        ts         = corrupt(f"{day}{sep}{month}{sep}{short_year}", rate=0.02)
        return _assemble(eid, _domain(), ts, _clean_payload_size(), ip, sid)

    # SANITIZED baseline ~96.32 %
    return _assemble(eid, _domain(), _clean_timestamp(),
                     _clean_payload_size(), ip, sid)


# -- expected-distribution banner ---------------------------------------------

def expected_counts(total: int) -> dict[str, int]:
    """Exact bucket counts by direct simulation of the generator's ladder.

    O(1) closed-form formulas are tempting but fail when divisors share common
    factors -- e.g. 33 and 100 share lcm=3300, so the simple
    (total//33 - total//100) formula under-counts SANITIZED_2 by exactly
    total//3300 events for any total where 3300 divides total.

    The direct simulation (one pass over range(1, total+1)) is unambiguous,
    matches the generator by construction, and is called only once offline
    (not on the hot path), so O(N) is acceptable.
    """
    counts: dict[str, int] = {
        "SANITIZED":     0,
        "SANITIZED_2":   0,
        "REVIEW_pii":    0,
        "REVIEW_halluc": 0,
        "REVIEW_logic":  0,
        "MALFORMED":     0,
    }
    for eid in range(1, total + 1):
        if   eid % 1000 == 0: counts["MALFORMED"]     += 1
        elif eid % 500  == 0: counts["REVIEW_logic"]  += 1
        elif eid % 200  == 0: counts["REVIEW_halluc"] += 1
        elif eid % 100  == 0: counts["REVIEW_pii"]    += 1
        elif eid % 33   == 0: counts["SANITIZED_2"]   += 1
        else:                 counts["SANITIZED"]     += 1
    return counts


# -- entry point --------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate synthetic tracker-payload audit stream"
    )
    parser.add_argument("--total",  type=int,          default=DEFAULT_TOTAL)
    parser.add_argument("--output", type=pathlib.Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed",   type=int,          default=None,
                        help="Integer seed for reproducible output.")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    exp  = expected_counts(args.total)
    step = max(1, args.total // 10)

    print(f"Generating {args.total:,} tracker events -> {args.output}"
          + (f"  [seed={args.seed}]" if args.seed is not None else ""))
    for k, v in exp.items():
        print(f"  {k:<20}: {v:>8,}  ({v / args.total * 100:.3f} %)")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        for eid in range(1, args.total + 1):
            fh.write(make_event(eid))
            if eid % step == 0:
                print(f"  {eid:>9,} / {args.total:,}")
    print("Done.")


if __name__ == "__main__":
    main()
