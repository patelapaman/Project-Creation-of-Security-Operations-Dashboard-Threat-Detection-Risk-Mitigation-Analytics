"""Lightweight local performance test for 1K/5K/10K event records.

Run from backend with: python performance_test.py
This intentionally measures application-side CSV parsing/filtering only; use a
running MongoDB/API for end-to-end timings in the final report.
"""
from pathlib import Path
from time import perf_counter
import pandas as pd

DATA = Path(__file__).resolve().parent / "data" / "security_events.csv"

for size in (1000, 5000, 10000):
    frame = pd.read_csv(DATA).head(size)
    started = perf_counter()
    records = frame.astype(object).where(pd.notna(frame), None).to_dict("records")
    parse_filter_ms = (perf_counter() - started) * 1000

    started = perf_counter()
    filtered = [r for r in records if str(r.get("severity", "")).lower() == "critical"]
    filter_ms = (perf_counter() - started) * 1000

    print(f"records={size:5d} materialize={parse_filter_ms:8.2f} ms critical_filter={filter_ms:8.2f} ms matches={len(filtered)}")
