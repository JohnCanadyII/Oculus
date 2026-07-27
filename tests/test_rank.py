"""Ranking is a pure, deterministic function — assert a fixed golden order."""
from oculus.config import Rank
from oculus.rank import Signals, score, _recency, _velocity


CFG = Rank()


def _sig(**kw):
    base = dict(age_hours=1.0, cluster_size=1, cluster_age_hours=1.0,
                source_weight=0.8, keyword_match=False, max_cvss=0.0,
                max_epss=0.0, kev=False)
    base.update(kw)
    return Signals(**base)


def test_score_is_deterministic():
    s = _sig(max_cvss=9.8, kev=True)
    assert score(s, CFG) == score(s, CFG)


def test_recency_decays_monotonically():
    assert _recency(0, 18) == 1.0
    assert _recency(18, 18) < _recency(9, 18) < _recency(0, 18)
    assert abs(_recency(18, 18) - 0.5) < 1e-9   # one half-life => 0.5


def test_velocity_rewards_multi_outlet_bursts():
    assert _velocity(1, 1, 3.0) == 0.0          # single outlet => no velocity
    assert _velocity(6, 2, 3.0) > _velocity(2, 2, 3.0)


def test_kev_lifts_a_modest_cve_over_a_scarier_dormant_one():
    kev_mid = _sig(max_cvss=6.5, kev=True)
    dormant_high = _sig(max_cvss=9.8, kev=False)
    assert score(kev_mid, CFG) > score(dormant_high, CFG)


def test_golden_order():
    # Fixed inputs must always produce this exact ordering.
    cases = {
        "kev_fresh_multi": _sig(age_hours=1, cluster_size=5, cluster_age_hours=2,
                                max_cvss=9.8, kev=True, source_weight=1.0),
        "networking_fresh": _sig(age_hours=2, cluster_size=1, source_weight=0.7),
        "old_security": _sig(age_hours=600, cluster_size=1, source_weight=0.8),
    }
    ordered = sorted(cases, key=lambda k: score(cases[k], CFG), reverse=True)
    assert ordered == ["kev_fresh_multi", "networking_fresh", "old_security"]
