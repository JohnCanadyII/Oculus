"""Concurrent, polite HTTP: worker pool, per-host rate limiting, conditional GET.

Politeness is enforced, not optional. Each feed is fetched with the ETag /
Last-Modified we saved last time, so an unchanged feed costs one cheap 304.
Requests to the same host are spaced out. One broken feed never aborts a run.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from .config import Fetch, Source


@dataclass
class FetchResult:
    source: Source
    status: int
    body: bytes | None
    etag: str | None
    last_modified: str | None
    error: str | None = None

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    @property
    def ok(self) -> bool:
        return self.error is None and (self.status == 200 or self.status == 304)


class _HostLimiter:
    """Serialise + space out requests per host."""

    def __init__(self, delay: float):
        self._delay = delay
        self._locks: dict[str, asyncio.Lock] = {}
        self._last: dict[str, float] = {}

    def _lock(self, host: str) -> asyncio.Lock:
        return self._locks.setdefault(host, asyncio.Lock())

    async def wait(self, host: str):
        async with self._lock(host):
            elapsed = time.monotonic() - self._last.get(host, 0.0)
            if elapsed < self._delay:
                await asyncio.sleep(self._delay - elapsed)
            self._last[host] = time.monotonic()


async def _fetch_one(client, limiter, sem, src, prev):
    host = urlparse(src.url).netloc
    async with sem:
        await limiter.wait(host)
        headers = {}
        if prev.get("etag"):
            headers["If-None-Match"] = prev["etag"]
        if prev.get("last_modified"):
            headers["If-Modified-Since"] = prev["last_modified"]
        try:
            r = await client.get(src.url, headers=headers)
        except (httpx.HTTPError, httpx.InvalidURL) as e:
            return FetchResult(src, 0, None, None, None, error=f"{type(e).__name__}: {e}")
        if r.status_code == 304:
            return FetchResult(src, 304, None, prev.get("etag"), prev.get("last_modified"))
        if r.status_code != 200:
            return FetchResult(src, r.status_code, None, None, None,
                               error=f"HTTP {r.status_code}")
        return FetchResult(
            src, 200, r.content,
            r.headers.get("etag"), r.headers.get("last-modified"),
        )


async def _run(sources, cfg: Fetch, state: dict[str, dict]):
    limiter = _HostLimiter(cfg.per_host_delay)
    sem = asyncio.Semaphore(cfg.workers)
    async with httpx.AsyncClient(
        timeout=cfg.timeout,
        follow_redirects=True,
        headers={"User-Agent": cfg.user_agent, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"},
    ) as client:
        tasks = [
            _fetch_one(client, limiter, sem, s, state.get(s.name, {}))
            for s in sources if s.enabled
        ]
        return await asyncio.gather(*tasks)


def fetch_all(sources, cfg: Fetch, state: dict[str, dict]) -> list[FetchResult]:
    """Fetch every enabled source. `state` maps source name -> {etag, last_modified}."""
    return asyncio.run(_run(sources, cfg, state))
