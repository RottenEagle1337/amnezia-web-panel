"""External host info (what the server looks like from the internet).

Uses ip-api.com (free, no key). Cached for 5 minutes: geolocation does not
change often and the free tier is rate-limited.
"""
from __future__ import annotations

import json
import time
import urllib.request

IP_API_URL = (
    "http://ip-api.com/json/?fields="
    "status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,query"
)

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


def _address_type(hosting: bool, proxy: bool) -> str:
    if hosting:
        return "Data center"
    if proxy:
        return "Proxy/VPN"
    return "Residential"


def fetch_host_info(backend_kind: str = "docker") -> dict:
    global _cache
    if backend_kind == "mock":
        return dict(MOCK_INFO)
    if _cache and time.time() - _cache[0] < CACHE_TTL:
        return dict(_cache[1])
    try:
        with urllib.request.urlopen(IP_API_URL, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") != "success":
            raise RuntimeError(f"ip-api: {data.get('message', 'failed')}")
        info = {
            "ip": data.get("query", ""),
            "country": data.get("country", ""),
            "countryCode": data.get("countryCode", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "org": data.get("org", ""),
            "as": data.get("as", ""),
            "address_type": _address_type(bool(data.get("hosting")), bool(data.get("proxy"))),
            "source": "ip-api.com",
        }
    except Exception as exc:
        info = {"ip": "", "error": str(exc), "source": "ip-api.com"}
    _cache = (time.time(), info)
    return dict(info)
