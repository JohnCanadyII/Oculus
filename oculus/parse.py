"""RSS / Atom parsing via feedparser, into normalized article records."""
from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

import feedparser

from . import normalize
from .cve import extract_cves


@dataclass
class Article:
    source_name: str
    canonical_url: str
    content_hash: str
    title: str
    summary: str
    body: str
    author: str
    published_at: int  # unix seconds
    cves: tuple[str, ...]


def _published(entry) -> int:
    for key in ("published_parsed", "updated_parsed"):
        val = entry.get(key)
        if val:
            return int(time.mktime(val))
    return int(datetime.now(timezone.utc).timestamp())


def parse(source_name: str, raw: bytes) -> list[Article]:
    feed = feedparser.parse(raw)
    out: list[Article] = []
    for e in feed.entries:
        link = e.get("link", "")
        if not link:
            continue
        title = normalize.strip_html(e.get("title", "(untitled)"))
        summary = normalize.strip_html(e.get("summary", ""))
        # Prefer full content when the feed ships it (only some do).
        body = summary
        if e.get("content"):
            body = normalize.strip_html(e["content"][0].get("value", "")) or summary
        author = e.get("author", "")
        searchable = f"{title} {body}"
        out.append(
            Article(
                source_name=source_name,
                canonical_url=normalize.canonical_url(link),
                content_hash=normalize.content_hash(title, body),
                title=title,
                summary=summary,
                body=body,
                author=author,
                published_at=_published(e),
                cves=extract_cves(searchable),
            )
        )
    return out
