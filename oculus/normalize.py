"""Canonical URLs, HTML stripping, content/title hashing, token sets.

These small pure functions are what make deduplication and clustering reliable:
two outlets linking the same story with different tracking params must produce
the same canonical URL, and two differently-worded headlines about one flaw must
share enough tokens to cluster.
"""
from __future__ import annotations

import hashlib
import re
from html import unescape
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

_TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source",
}
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "is", "are", "as", "at", "by", "from", "new", "how", "why", "what",
}


def canonical_url(url: str) -> str:
    try:
        p = urlparse(url.strip())
    except ValueError:
        return url.strip()
    scheme = (p.scheme or "https").lower()
    netloc = p.netloc.lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    query = [(k, v) for k, v in parse_qsl(p.query) if k.lower() not in _TRACKING_PARAMS]
    path = p.path.rstrip("/") or "/"
    return urlunparse((scheme, netloc, path, "", urlencode(query), ""))


def strip_html(text: str) -> str:
    if not text:
        return ""
    return _WS_RE.sub(" ", unescape(_TAG_RE.sub(" ", text))).strip()


def content_hash(title: str, body: str) -> str:
    h = hashlib.sha256()
    h.update(normalize_title(title).encode())
    h.update(b"\x00")
    h.update(strip_html(body).lower().encode())
    return h.hexdigest()


def normalize_title(title: str) -> str:
    t = strip_html(title).lower()
    t = re.sub(r"[^a-z0-9\s-]", " ", t)
    return _WS_RE.sub(" ", t).strip()


def token_set(title: str) -> frozenset[str]:
    return frozenset(
        w for w in normalize_title(title).split() if w not in _STOPWORDS and len(w) > 2
    )
