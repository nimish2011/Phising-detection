import time
from urllib.parse import urlparse

import requests

FEED_URL = "https://openphish.com/feed.txt"
CACHE_TTL_SECONDS = 60 * 60
REQUEST_TIMEOUT = 8

_cache = {"urls": set(), "domains": set(), "fetched_at": 0.0}


def _refresh_feed():
    try:
        resp = requests.get(FEED_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        lines = [line.strip() for line in resp.text.splitlines() if line.strip()]

        domains = set()
        for line in lines:
            try:
                host = urlparse(line).hostname
                if host:
                    domains.add(host.lower())
            except Exception:
                continue

        _cache["urls"] = set(lines)
        _cache["domains"] = domains
        _cache["fetched_at"] = time.time()
    except Exception:
        pass


def _ensure_fresh():
    if time.time() - _cache["fetched_at"] > CACHE_TTL_SECONDS:
        _refresh_feed()


def is_known_phishing(url: str) -> bool:
    _ensure_fresh()

    if not _cache["urls"] and not _cache["domains"]:
        return False

    if url in _cache["urls"] or url.rstrip("/") in _cache["urls"]:
        return True

    hostname = (urlparse(url).hostname or "").lower()
    return hostname in _cache["domains"]