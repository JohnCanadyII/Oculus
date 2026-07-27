"""Union-find clustering: group articles that describe the same story.

Two articles join a cluster when they fall inside a time window AND either
share a CVE ID, or (across different outlets) have similar-enough titles by
token-set Jaccard overlap. The cross-outlet condition prevents merging one
publisher's own follow-up posts. Cluster size + growth rate becomes velocity.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import normalize


@dataclass
class Item:
    id: int
    source_name: str
    title: str
    cves: tuple[str, ...]
    published_at: int


@dataclass
class Cluster:
    key: str
    member_ids: list[int]
    source_names: set[str]
    first_seen: int
    last_seen: int

    @property
    def size(self) -> int:
        return len(self.member_ids)

    @property
    def source_count(self) -> int:
        return len(self.source_names)


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    if inter == 0:
        return 0.0
    return inter / len(a | b)


def compute(items: list[Item], jaccard_threshold: float, window_seconds: int) -> list[Cluster]:
    n = len(items)
    tokens = [normalize.token_set(it.title) for it in items]
    cvesets = [frozenset(it.cves) for it in items]
    uf = _UnionFind(n)

    for i in range(n):
        for j in range(i + 1, n):
            if abs(items[i].published_at - items[j].published_at) > window_seconds:
                continue
            shared_cve = bool(cvesets[i] & cvesets[j])
            cross = items[i].source_name != items[j].source_name
            title_match = cross and _jaccard(tokens[i], tokens[j]) >= jaccard_threshold
            if shared_cve or title_match:
                uf.union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    clusters: list[Cluster] = []
    for members in groups.values():
        ids = sorted(items[m].id for m in members)
        srcs = {items[m].source_name for m in members}
        times = [items[m].published_at for m in members]
        earliest = min(members, key=lambda m: (items[m].published_at, items[m].id))
        clusters.append(
            Cluster(
                key=str(items[earliest].id),
                member_ids=ids,
                source_names=srcs,
                first_seen=min(times),
                last_seen=max(times),
            )
        )
    clusters.sort(key=lambda c: (c.first_seen, c.member_ids[0]))
    return clusters
