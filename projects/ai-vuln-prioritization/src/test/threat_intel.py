#!/usr/bin/env python3
"""
threat_intel.py — Open Source Threat Intelligence

Fetches and caches:
  CISA KEV (Known Exploited Vulnerabilities catalog)
  Source: CISA — updated daily
  Free, no API key required.

A CVE present in CISA KEV means it is confirmed to be actively
exploited in the wild by real threat actors. This is the strongest
available signal for exploitation risk beyond CVSS scores.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

CISA_KEV_URL     = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE_NAME  = "cisa_kev.json"
CACHE_MAX_AGE_H  = 24   # refresh once per day


def fetch_cisa_kev(cache_dir: Path | None = None) -> dict[str, dict]:
    """
    Return CISA KEV as {cve_id: entry}.

    Tries the local cache first; fetches from CISA if stale or absent.
    On any network error returns whatever is cached (or an empty dict).
    """
    cache_file: Path | None = (cache_dir / CACHE_FILE_NAME) if cache_dir else None

    # ── try cache ──────────────────────────────────────────────────────────
    if cache_file and cache_file.exists():
        age = datetime.now(tz=timezone.utc) - datetime.fromtimestamp(
            cache_file.stat().st_mtime, tz=timezone.utc
        )
        if age < timedelta(hours=CACHE_MAX_AGE_H):
            return _parse_kev(json.loads(cache_file.read_text(encoding="utf-8")))

    # ── fetch from CISA ────────────────────────────────────────────────────
    try:
        resp = requests.get(CISA_KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if cache_dir:
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        count = data.get("count", len(data.get("vulnerabilities", [])))
        print(f"[threat_intel] CISA KEV fetched — {count} known exploited CVEs.")
        return _parse_kev(data)

    except Exception as exc:
        print(f"[threat_intel] Warning: Could not fetch CISA KEV: {exc}")
        # Fall back to stale cache if available
        if cache_file and cache_file.exists():
            print("[threat_intel] Using stale cached KEV data.")
            return _parse_kev(json.loads(cache_file.read_text(encoding="utf-8")))
        return {}


def _parse_kev(data: dict) -> dict[str, dict]:
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
