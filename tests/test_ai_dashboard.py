"""AI summarizer fail-soft behaviour + dashboard render smoke test."""
from oculus.ai import Summarizer, Provider, build_prompt
from oculus.dashboard import render, render_email, _vendor_counts
from oculus.ingest import RankedCluster, RankedArticle, RankedCVE


class _Mock(Provider):
    name = "mock"

    def __init__(self, text):
        self._text = text

    def generate(self, prompt):
        return self._text


def test_summarizer_returns_text_from_provider():
    s = Summarizer(_Mock("This is a summary."))
    assert s.summarize("t", "krebs", ["CVE-2025-1"], "ctx") == "This is a summary."


def test_summarizer_failsoft_when_no_model():
    # provider returns None (unreachable model) -> summarize yields None, never raises
    assert Summarizer(_Mock(None)).summarize("t", "o", [], "") is None


def test_prompt_includes_signals():
    p = build_prompt("Big Flaw", "krebs, bleeping", ["CVE-2025-1"], "some context")
    assert "Big Flaw" in p and "CVE-2025-1" in p and "krebs" in p


def _cluster(title, tags, cves=(), kev=False):
    return RankedCluster(
        key=title, score=0.5, size=1, source_count=1, first_seen=0, last_seen=0,
        articles=[RankedArticle(title, "src", "http://x", "sum", 0)],
        cves=[RankedCVE(c, 9.8, "CRITICAL", kev, False, 0.9) for c in cves],
        tags=set(tags), ai_summary="🤖 mock",
    )


def test_render_produces_all_views():
    clusters = [
        _cluster("Cisco IOS XE flaw", ["networking"], ["CVE-2025-1"], kev=True),
        _cluster("Microsoft patch", ["bigtech", "security"], ["CVE-2025-2"]),
    ]
    html = render(clusters, top=10)
    for token in ("Command Center", "Threat Wire", "Triage Board", "Executive Brief",
                  "Cisco IOS XE flaw", "mock", "EPSS"):
        assert token in html


def test_render_email_is_static():
    html = render_email([_cluster("X", ["security"])], top=5)
    # no view-switcher *buttons* in email (the CSS class may still be defined)
    assert "<html" in html and "data-go=" not in html


def test_vendor_counts_from_titles():
    clusters = [_cluster("Cisco and Juniper race", ["networking"]),
                _cluster("Cisco patch day", ["security"])]
    vc = _vendor_counts(clusters)
    assert vc.get("Cisco") == 2 and vc.get("Juniper") == 1
