"""Normalization + DB-enforced dedup."""
import time

from oculus import normalize
from oculus.parse import Article
from oculus.store import Store


def test_canonical_url_strips_tracking_and_www():
    a = normalize.canonical_url("https://www.example.com/path/?utm_source=x&id=5")
    b = normalize.canonical_url("https://example.com/path?id=5")
    assert a == b   # www + trailing slash + utm_* stripped, real params kept


def test_content_hash_ignores_title_case_and_html():
    h1 = normalize.content_hash("Big News", "<p>Hello World</p>")
    h2 = normalize.content_hash("big news", "Hello World")
    assert h1 == h2


def test_token_set_drops_stopwords():
    toks = normalize.token_set("The New Cisco Router Flaw")
    assert "cisco" in toks and "router" in toks
    assert "the" not in toks and "new" not in toks


def _article(url, title="T", body="B"):
    return Article(
        source_name="s", canonical_url=normalize.canonical_url(url),
        content_hash=normalize.content_hash(title, body + url), title=title,
        summary="", body=body, author="", published_at=1000, cves=(),
    )


def test_dedup_on_insert(tmp_path):
    store = Store.open(tmp_path / "t.db")
    now = int(time.time())
    assert store.insert_article(_article("https://x.com/a"), now) is not None
    # same canonical url => duplicate => None, not an error
    assert store.insert_article(_article("https://x.com/a"), now) is None
    assert store.insert_article(_article("https://x.com/b"), now) is not None
    assert len(store.all_articles()) == 2
    store.close()


def test_ttl_cache_skips_fresh_cves(tmp_path):
    from oculus.cve import CVERecord
    store = Store.open(tmp_path / "t.db")
    now = 1_000_000
    aid = store.insert_article(_article("https://x.com/a"), now)
    store.conn.execute("INSERT INTO article_cves(article_id,cve_id) VALUES(?,?)", (aid, "CVE-2025-1"))
    store.commit()
    # not yet enriched -> pending
    assert "CVE-2025-1" in store.pending_cve_ids(ttl_cutoff=now - 3600)
    store.upsert_cve(CVERecord("CVE-2025-1", enrich_status="ok"), now)
    # enriched just now -> within TTL -> skipped
    assert store.pending_cve_ids(ttl_cutoff=now - 3600) == []
    # but stale (enriched before cutoff) -> pending again
    assert "CVE-2025-1" in store.pending_cve_ids(ttl_cutoff=now + 3600)
    store.close()
