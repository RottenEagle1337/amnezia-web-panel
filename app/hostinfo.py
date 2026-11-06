"""External host info (what the server looks like from the internet).

Uses ipinfo.io (free tier, HTTPS, no key). Cached for 5 minutes: geolocation
does not change often and the free tier is rate-limited. The free API exposes
no hosting/proxy flags, so the address type is reported as "Unknown".
"""
from __future__ import annotations

import json
import time
import urllib.request

IP_API_URL = "https://ipinfo.io/json"

_cache: tuple[float, dict] | None = None
CACHE_TTL = 300

MOCK_INFO = {
    "ip": "203.0.113.10",
    "country": "Netherlands",
    "countryCode": "NL",
    "region": "North Holland",
    "city": "Amsterdam",
    "isp": "Mock Hosting BV",
    "org": "Mock Hosting BV",
    "as": "AS64496 MockNet",
    "address_type": "Data center",
    "source": "mock",
}


def fetch_host_info(backend_kind: str = "docker") -> dict:
    global _cache
    if backend_kind == "mock":
        return dict(MOCK_INFO)
    if _cache and time.time() - _cache[0] < CACHE_TTL:
        return dict(_cache[1])
    try:
        req = urllib.request.Request(IP_API_URL, headers={"User-Agent": "amnezia-web-panel"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if "ip" not in data:
            raise RuntimeError(f"ipinfo: {data.get('error', {}).get('message', 'failed')}")
        org = data.get("org", "")          # e.g. "AS64496 Mock Hosting BV"
        asn, _, isp = org.partition(" ")
        info = {
            "ip": data.get("ip", ""),
            "country": "",
            "countryCode": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "isp": isp,
            "org": isp,
            "as": asn,
            "address_type": "Unknown",     # not exposed by the free API
            "source": "ipinfo.io",
        }
    except Exception as exc:
        info = {"ip": "", "error": str(exc), "source": "ipinfo.io"}
    _cache = (time.time(), info)
    return dict(info)
