"""Configuration: source list + all tunable knobs, loaded from YAML with env overrides.

Every magic number the pipeline uses lives here, not scattered in code — so the
ranking model and delivery behaviour are fully tunable without touching logic.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

APP_NAME = "oculus"  # <- change this one string to rename the whole tool
DISPLAY_NAME = "Oculus"

_PKG_DIR = Path(__file__).resolve().parent


def config_home() -> Path:
    base = os.environ.get("OCULUS_HOME")
    if base:
        home = Path(base).expanduser()
    else:
        home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
    home.mkdir(parents=True, exist_ok=True)
    return home


def db_path() -> Path:
    p = config_home() / "oculus.db"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


@dataclass(frozen=True)
class Source:
    name: str
    title: str
    url: str
    weight: float = 0.8
    tags: tuple[str, ...] = ()
    enabled: bool = True


@dataclass(frozen=True)
class Weights:
    recency: float = 0.30
    velocity: float = 0.20
    source: float = 0.10
    keyword: float = 0.10
    kev: float = 0.15
    cvss: float = 0.08
    epss: float = 0.07


@dataclass(frozen=True)
class Rank:
    weights: Weights = field(default_factory=Weights)
    half_life_hours: int = 18
    velocity_norm: float = 3.0  # (articles/hour) that maps to a full velocity score
    watchlist: tuple[str, ...] = ()


@dataclass(frozen=True)
class Fetch:
    workers: int = 8
    per_host_delay: float = 1.0      # seconds between requests to the same host
    timeout: float = 20.0
    user_agent: str = f"{DISPLAY_NAME}/0.1 (+news aggregator; contact: set OCULUS_CONTACT)"


@dataclass(frozen=True)
class Cluster:
    window_hours: int = 72
    jaccard_threshold: float = 0.6


@dataclass(frozen=True)
class Email:
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""           # prefer OCULUS_SMTP_PASSWORD env over storing this
    use_tls: bool = True
    sender: str = ""
    recipients: tuple[str, ...] = ()
    subject_prefix: str = f"[{DISPLAY_NAME}]"
    top: int = 15


@dataclass(frozen=True)
class Config:
    sources: tuple[Source, ...]
    rank: Rank = field(default_factory=Rank)
    fetch: Fetch = field(default_factory=Fetch)
    cluster: Cluster = field(default_factory=Cluster)
    email: Email = field(default_factory=Email)
    enrich_cves: bool = True
    # Rolling display window: only show stories with activity in the last N days,
    # so the dashboard reflects *current* news and the count rises/falls over time.
    # 0 = no limit (keep everything). Overridable via config.yaml.
    retention_days: int = 14


def _load_sources(path: Path) -> tuple[Source, ...]:
    raw = yaml.safe_load(path.read_text()) or []
    out = []
    for r in raw:
        out.append(
            Source(
                name=r["name"],
                title=r.get("title", r["name"]),
                url=r["url"],
                weight=float(r.get("weight", 0.8)),
                tags=tuple(r.get("tags", [])),
                enabled=bool(r.get("enabled", True)),
            )
        )
    return tuple(out)


def load() -> Config:
    """Load config: bundled sources.yaml, overridden by ~/.config/oculus/sources.yaml
    if present, plus email settings from ~/.config/oculus/config.yaml and env vars."""
    user_sources = config_home() / "sources.yaml"
    src_path = user_sources if user_sources.exists() else _PKG_DIR / "sources.yaml"
    cfg = Config(sources=_load_sources(src_path))

    user_cfg = config_home() / "config.yaml"
    if user_cfg.exists():
        cfg = _apply_overrides(cfg, yaml.safe_load(user_cfg.read_text()) or {})

    cfg = _apply_env(cfg)
    return cfg


def _apply_overrides(cfg: Config, data: dict) -> Config:
    email = cfg.email
    if "email" in data:
        e = data["email"]
        email = replace(
            email,
            enabled=e.get("enabled", email.enabled),
            host=e.get("host", email.host),
            port=int(e.get("port", email.port)),
            username=e.get("username", email.username),
            password=e.get("password", email.password),
            use_tls=e.get("use_tls", email.use_tls),
            sender=e.get("sender", email.sender),
            recipients=tuple(e.get("recipients", email.recipients)),
            top=int(e.get("top", email.top)),
        )
    rank = cfg.rank
    if "watchlist" in data:
        rank = replace(rank, watchlist=tuple(data["watchlist"]))
    retention = int(data.get("retention_days", cfg.retention_days))
    return replace(cfg, email=email, rank=rank, retention_days=retention)


def _apply_env(cfg: Config) -> Config:
    email = cfg.email
    pw = os.environ.get("OCULUS_SMTP_PASSWORD")
    if pw:
        email = replace(email, password=pw)
    rcpt = os.environ.get("OCULUS_EMAIL_TO")
    if rcpt:
        email = replace(email, recipients=tuple(x.strip() for x in rcpt.split(",") if x.strip()))
    return replace(cfg, email=email)
