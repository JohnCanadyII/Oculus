"""The pipeline seam: fetch -> parse -> store -> enrich -> cluster -> rank.

Both `scrape` and the `watch` daemon call ingest_and_rank(), so when a step is
added to the pipeline both paths get it — there is only one place to add it.
Everything is fail-soft: one broken feed never aborts the run, and failed
enrichment never blocks the news.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import cluster as cluster_mod
from . import parse as parse_mod
from . import rank as rank_mod
from .cve import Enricher, severity_band
from .config import Config
from .fetch import fetch_all
from .store import Store


@dataclass
class RankedCVE:
    id: str
    cvss_score: float | None
    cvss_severity: str
    is_kev: bool
    kev_ransomware: bool
    epss: float | None


@dataclass
class RankedArticle:
    title: str
    source_name: str
    url: str
    summary: str
    published_at: int


@dataclass
class RankedCluster:
    key: str
    score: float
    size: int
    source_count: int
    first_seen: int
    last_seen: int
    articles: list[RankedArticle]
    cves: list[RankedCVE]
    tags: set[str] = field(default_factory=set)

    @property
    def worst_severity(self) -> str:
        best = None
        for c in self.cves:
            if c.cvss_score is not None and (best is None or c.cvss_score > best):
                best = c.cvss_score
        return severity_band(best)

    @property
    def max_cvss(self) -> float | None:
        scores = [c.cvss_score for c in self.cves if c.cvss_score is not None]
        return max(scores) if scores else None

    @property
    def any_kev(self) -> bool:
        return any(c.is_kev for c in self.cves)


@dataclass
class ScrapeReport:
    per_source: dict[str, dict]
    new_articles: int
    clusters: int
    multi_source: int
    enriched: int
    kev: int


def _ingest(cfg: Config, store: Store) -> ScrapeReport:
    store.upsert_sources(cfg.sources)
    state = store.fetch_state()
    results = fetch_all(cfg.sources, cfg.fetch, state)
    now = int(time.time())
    per_source: dict[str, dict] = {}
    new_total = 0

    for res in results:
        info = {"status": res.status, "parsed": 0, "new": 0, "error": res.error}
        if res.ok and not res.not_modified and res.body:
            articles = parse_mod.parse(res.source.name, res.body)
            info["parsed"] = len(articles)
            for art in articles:
                if store.insert_article(art, now) is not None:
                    info["new"] += 1
            store.commit()
            new_total += info["new"]
            store.save_fetch_state(res.source.name, res.etag, res.last_modified, res.status, now)
        elif res.not_modified:
            store.save_fetch_state(res.source.name, res.etag, res.last_modified, 304, now)
        per_source[res.source.name] = info

    # ── enrich CVEs (best-effort, non-fatal) ──
    enriched = kev = 0
    if cfg.enrich_cves:
        pending = store.pending_cve_ids()
        if pending:
            enr = Enricher(cfg.fetch.user_agent, cfg.fetch.timeout)
            try:
                for cid, rec in enr.enrich(pending).items():
                    store.upsert_cve(rec, now)
                    enriched += 1
                    kev += int(rec.is_kev)
            finally:
                enr.close()

    ranked = build_ranked(cfg, store)
    return ScrapeReport(
        per_source=per_source, new_articles=new_total, clusters=len(ranked),
        multi_source=sum(1 for c in ranked if c.source_count > 1),
        enriched=enriched, kev=kev,
    )


def build_ranked(cfg: Config, store: Store) -> list[RankedCluster]:
    """Read everything currently stored, cluster + rank it. Pure over the store."""
    rows = store.all_articles()
    cve_by_article = store.article_cves_map()
    items = [
        cluster_mod.Item(
            id=r["id"], source_name=r["source_name"], title=r["title"],
            cves=cve_by_article.get(r["id"], ()), published_at=r["published_at"],
        )
        for r in rows
    ]
    window = cfg.cluster.window_hours * 3600
    clusters = cluster_mod.compute(items, cfg.cluster.jaccard_threshold, window)

    weights = store.source_weights()
    tags = store.source_tags()
    cve_map = store.cve_map()
    now = int(time.time())
    out: list[RankedCluster] = []

    for c in clusters:
        arts = store.articles_by_ids(c.member_ids)
        r_articles = [
            RankedArticle(a["title"], a["source_name"], a["canonical_url"],
                          a["summary"] or "", a["published_at"])
            for a in arts
        ]
        cve_ids = sorted({cve for aid in c.member_ids for cve in cve_by_article.get(aid, ())})
        r_cves = []
        for cid in cve_ids:
            row = cve_map.get(cid)
            if row:
                r_cves.append(RankedCVE(
                    cid, row["cvss_score"], row["cvss_severity"] or "NONE",
                    bool(row["is_kev"]), bool(row["kev_ransomware"]), row["epss"],
                ))
            else:
                r_cves.append(RankedCVE(cid, None, "NONE", False, False, None))

        cluster_tags = set()
        for a in r_articles:
            cluster_tags |= set(tags.get(a.source_name, ()))

        sig = rank_mod.Signals(
            age_hours=(now - c.last_seen) / 3600.0,
            cluster_size=c.size,
            cluster_age_hours=(c.last_seen - c.first_seen) / 3600.0,
            source_weight=max((weights.get(a.source_name, 0.5) for a in r_articles), default=0.5),
            keyword_match=_watchlist_hit(r_articles, r_cves, cfg.rank.watchlist),
            max_cvss=max((c.cvss_score or 0.0 for c in r_cves), default=0.0),
            max_epss=max((c.epss or 0.0 for c in r_cves), default=0.0),
            kev=any(c.is_kev for c in r_cves),
        )
        out.append(RankedCluster(
            key=c.key, score=rank_mod.score(sig, cfg.rank), size=c.size,
            source_count=c.source_count, first_seen=c.first_seen, last_seen=c.last_seen,
            articles=r_articles, cves=r_cves, tags=cluster_tags,
        ))

    out.sort(key=lambda x: (x.score, x.last_seen), reverse=True)
    return out


def _watchlist_hit(articles, cves, watchlist) -> bool:
    if not watchlist:
        return False
    hay = " ".join(a.title.lower() for a in articles) + " " + " ".join(c.id.lower() for c in cves)
    return any(term.lower() in hay for term in watchlist if term)


def ingest_and_rank(cfg: Config, store: Store) -> ScrapeReport:
    return _ingest(cfg, store)
