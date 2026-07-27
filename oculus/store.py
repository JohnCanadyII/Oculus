"""SQLite store: schema, dedup-on-insert, and the queries the pipeline needs.

Dedup is enforced by the DB (UNIQUE on canonical_url and content_hash), not by
application logic — re-ingesting an item is a caught constraint violation, a
normal "already have it", not an error. WAL mode lets a reader (dashboard) and
a writer (scrape) coexist.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY, title TEXT, url TEXT, weight REAL, tags TEXT, enabled INTEGER
);
CREATE TABLE IF NOT EXISTS fetch_state (
    source_name TEXT PRIMARY KEY, etag TEXT, last_modified TEXT,
    last_fetched INTEGER, last_status INTEGER
);
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    canonical_url TEXT UNIQUE NOT NULL,
    content_hash TEXT UNIQUE NOT NULL,
    title TEXT, summary TEXT, body TEXT, author TEXT,
    published_at INTEGER, fetched_at INTEGER
);
CREATE TABLE IF NOT EXISTS article_cves (
    article_id INTEGER, cve_id TEXT, PRIMARY KEY (article_id, cve_id)
);
CREATE TABLE IF NOT EXISTS cves (
    id TEXT PRIMARY KEY, description TEXT,
    cvss_score REAL, cvss_version TEXT, cvss_severity TEXT, cwe TEXT,
    is_kev INTEGER, kev_ransomware INTEGER,
    epss REAL, epss_percentile REAL, enriched_at INTEGER, enrich_status TEXT
);
"""


@dataclass
class Store:
    conn: sqlite3.Connection

    @classmethod
    def open(cls, path: Path) -> "Store":
        conn = sqlite3.connect(str(path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(SCHEMA)
        return cls(conn)

    def close(self):
        self.conn.close()

    # ── sources / fetch state ────────────────────────────────────────────
    def upsert_sources(self, sources):
        for s in sources:
            self.conn.execute(
                "INSERT INTO sources(name,title,url,weight,tags,enabled) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET title=excluded.title,url=excluded.url,"
                "weight=excluded.weight,tags=excluded.tags,enabled=excluded.enabled",
                (s.name, s.title, s.url, s.weight, ",".join(s.tags), int(s.enabled)),
            )
        self.conn.commit()

    def fetch_state(self) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT source_name, etag, last_modified FROM fetch_state"
        ).fetchall()
        return {r["source_name"]: {"etag": r["etag"], "last_modified": r["last_modified"]} for r in rows}

    def save_fetch_state(self, name, etag, last_modified, status, now):
        self.conn.execute(
            "INSERT INTO fetch_state(source_name,etag,last_modified,last_fetched,last_status) "
            "VALUES(?,?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET "
            "etag=excluded.etag,last_modified=excluded.last_modified,"
            "last_fetched=excluded.last_fetched,last_status=excluded.last_status",
            (name, etag, last_modified, now, status),
        )
        self.conn.commit()

    # ── articles ─────────────────────────────────────────────────────────
    def insert_article(self, art, now) -> int | None:
        """Returns new article id, or None if it was a duplicate."""
        try:
            cur = self.conn.execute(
                "INSERT INTO articles(source_name,canonical_url,content_hash,title,"
                "summary,body,author,published_at,fetched_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (art.source_name, art.canonical_url, art.content_hash, art.title,
                 art.summary, art.body, art.author, art.published_at, now),
            )
        except sqlite3.IntegrityError:
            return None  # already have it — normal outcome
        aid = cur.lastrowid
        for cve in art.cves:
            self.conn.execute(
                "INSERT OR IGNORE INTO article_cves(article_id,cve_id) VALUES(?,?)", (aid, cve)
            )
        return aid

    def commit(self):
        self.conn.commit()

    def all_articles(self):
        return self.conn.execute(
            "SELECT id, source_name, title, published_at FROM articles"
        ).fetchall()

    def article_cves_map(self) -> dict[int, tuple[str, ...]]:
        out: dict[int, list[str]] = {}
        for r in self.conn.execute("SELECT article_id, cve_id FROM article_cves"):
            out.setdefault(r["article_id"], []).append(r["cve_id"])
        return {k: tuple(v) for k, v in out.items()}

    def pending_cve_ids(self) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT ac.cve_id FROM article_cves ac "
            "LEFT JOIN cves c ON c.id = ac.cve_id "
            "WHERE c.id IS NULL OR c.enrich_status != 'ok'"
        ).fetchall()
        return [r["cve_id"] for r in rows]

    def upsert_cve(self, rec, now):
        self.conn.execute(
            "INSERT INTO cves(id,description,cvss_score,cvss_version,cvss_severity,cwe,"
            "is_kev,kev_ransomware,epss,epss_percentile,enriched_at,enrich_status) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "description=excluded.description,cvss_score=excluded.cvss_score,"
            "cvss_version=excluded.cvss_version,cvss_severity=excluded.cvss_severity,"
            "cwe=excluded.cwe,is_kev=excluded.is_kev,kev_ransomware=excluded.kev_ransomware,"
            "epss=excluded.epss,epss_percentile=excluded.epss_percentile,"
            "enriched_at=excluded.enriched_at,enrich_status=excluded.enrich_status",
            (rec.id, rec.description, rec.cvss_score, rec.cvss_version, rec.cvss_severity,
             rec.cwe, int(rec.is_kev), int(rec.kev_ransomware), rec.epss,
             rec.epss_percentile, now, rec.enrich_status),
        )
        self.conn.commit()

    def cve_map(self) -> dict[str, sqlite3.Row]:
        return {r["id"]: r for r in self.conn.execute("SELECT * FROM cves")}

    def source_weights(self) -> dict[str, float]:
        return {r["name"]: r["weight"] for r in self.conn.execute("SELECT name, weight FROM sources")}

    def source_tags(self) -> dict[str, tuple[str, ...]]:
        return {r["name"]: tuple(t for t in (r["tags"] or "").split(",") if t)
                for r in self.conn.execute("SELECT name, tags FROM sources")}

    def articles_by_ids(self, ids):
        q = ",".join("?" * len(ids))
        return self.conn.execute(
            f"SELECT id, source_name, title, canonical_url, summary, published_at "
            f"FROM articles WHERE id IN ({q})", list(ids)
        ).fetchall()
