"""Deterministic, news-first weighted ranking.

score =  w_recency  * recency_decay(age)
       + w_velocity * normalized(cluster_size / age)
       + w_source   * source_weight
       + w_keyword  * watchlist_match
       + w_kev      * is_kev
       + w_cvss     * normalized(max_cvss)
       + w_epss     * max_epss

Weights live in config, never in code. Because the score is a pure function of
stored inputs, the same corpus always sorts the same way (testable golden order).
Default weights are news-first: recency+velocity+source+keyword = 70%, CVE = 30%.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .config import Rank

_CVSS_MAX = 10.0
_LN2 = math.log(2)


@dataclass
class Signals:
    age_hours: float
    cluster_size: int
    cluster_age_hours: float
    source_weight: float
    keyword_match: bool
    max_cvss: float
    max_epss: float
    kev: bool


def _clamp01(v: float) -> float:
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def _recency(age_hours: float, half_life: int) -> float:
    age_hours = max(age_hours, 0.0)
    half_life = max(half_life, 1)
    return math.exp(-_LN2 * age_hours / half_life)


def _velocity(size: int, age_hours: float, norm: float) -> float:
    if size <= 1 or norm <= 0:
        return 0.0
    age_hours = max(age_hours, 1.0)
    return _clamp01((size / age_hours) / norm)


def score(s: Signals, cfg: Rank) -> float:
    w = cfg.weights
    return (
        w.recency * _recency(s.age_hours, cfg.half_life_hours)
        + w.velocity * _velocity(s.cluster_size, s.cluster_age_hours, cfg.velocity_norm)
        + w.source * _clamp01(s.source_weight)
        + w.keyword * (1.0 if s.keyword_match else 0.0)
        + w.kev * (1.0 if s.kev else 0.0)
        + w.cvss * _clamp01(s.max_cvss / _CVSS_MAX)
        + w.epss * _clamp01(s.max_epss)
    )
