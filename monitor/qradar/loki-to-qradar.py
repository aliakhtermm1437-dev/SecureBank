"""Tail Loki security streams and forward to IBM QRadar as CEF events."""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.parse
from typing import Iterable

import httpx


CEF_VERSION = "CEF:0"
DEVICE_VENDOR = "SecureBank"
DEVICE_PRODUCT = "Platform"
DEVICE_VERSION = "1.0.0"


def to_cef(entry: dict) -> str:
    event = entry.get("event", "audit")
    severity = {"INFO": 3, "WARNING": 6, "ERROR": 8, "CRITICAL": 10}.get(entry.get("level", "INFO"), 3)
    extension = " ".join(f"{k}={json.dumps(v) if isinstance(v,(dict,list)) else v}"
                         for k, v in entry.items() if k not in ("event","level"))
    return (f"{CEF_VERSION}|{DEVICE_VENDOR}|{DEVICE_PRODUCT}|{DEVICE_VERSION}|"
            f"{event}|{event}|{severity}|{extension}")


def stream_loki(base: str, query: str, since_s: int = 30) -> Iterable[dict]:
    params = {
        "query": query,
        "start": int(time.time_ns() - since_s * 1e9),
        "limit": "1000",
    }
    with httpx.Client(timeout=30.0) as c:
        last_ts = params["start"]
        while True:
            params["start"] = str(last_ts + 1)
            r = c.get(f"{base}/loki/api/v1/query_range",
                      params={"query": query, "start": params["start"], "limit": "1000"})
            r.raise_for_status()
            for stream in r.json().get("data", {}).get("result", []):
                for ts, line in stream.get("values", []):
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
                    last_ts = max(last_ts, int(ts))
            time.sleep(5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--loki-url", required=True)
    ap.add_argument("--qradar-url", required=True)
    ap.add_argument("--query", default='{job=~"securebank.*"} |= "audit"')
    args = ap.parse_args()

    with httpx.Client(timeout=10, verify=False) as c:  # noqa: S501 - on-prem cert in academic demo
        for ev in stream_loki(args.loki_url, args.query):
            cef = to_cef(ev)
            c.post(args.qradar_url, content=cef, headers={"Content-Type": "text/plain"})
            print("→ qradar", cef[:120], file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
