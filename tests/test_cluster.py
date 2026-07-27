"""Union-find clustering: shared CVE, cross-outlet title match, time window."""
from oculus.cluster import Item, compute

WINDOW = 72 * 3600


def _item(id, src, title, cves=(), t=1000):
    return Item(id=id, source_name=src, title=title, cves=cves, published_at=t)


def test_shared_cve_joins_across_outlets():
    items = [
        _item(1, "krebs", "Flaw in Widget", cves=("CVE-2025-1",)),
        _item(2, "bleeping", "Totally different words here", cves=("CVE-2025-1",)),
    ]
    clusters = compute(items, 0.6, WINDOW)
    assert len(clusters) == 1
    assert clusters[0].size == 2
    assert clusters[0].source_count == 2


def test_similar_titles_only_cluster_across_outlets():
    # Same outlet, near-identical titles => must NOT merge (publisher follow-ups).
    same = [
        _item(1, "cisa", "Critical advisory for Acme router firmware"),
        _item(2, "cisa", "Critical advisory for Acme router firmware update"),
    ]
    assert len(compute(same, 0.6, WINDOW)) == 2

    cross = [
        _item(1, "cisa", "Critical advisory for Acme router firmware"),
        _item(2, "krebs", "Critical advisory for Acme router firmware update"),
    ]
    assert len(compute(cross, 0.6, WINDOW)) == 1


def test_time_window_separates_old_and_new():
    items = [
        _item(1, "krebs", "Shared story", cves=("CVE-2025-9",), t=0),
        _item(2, "bleeping", "Shared story", cves=("CVE-2025-9",), t=WINDOW + 10),
    ]
    assert len(compute(items, 0.6, WINDOW)) == 2


def test_unrelated_stories_stay_separate():
    items = [
        _item(1, "krebs", "Bank breach disclosed"),
        _item(2, "verge", "New phone launch event"),
    ]
    assert len(compute(items, 0.6, WINDOW)) == 2
