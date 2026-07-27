"""Render ranked clusters as an enhanced HTML dashboard.

The same HTML is used three ways: written to disk for the endpoint, sent as the
email body, and persisted as an artifact. So charts are drawn with inline-styled
<div> bars (email-safe: no JS, no external CSS, no SVG dependency) using the
validated data-viz status palette for CVE severity.
"""
from __future__ import annotations

import html
import time
from datetime import datetime, timezone

from .config import DISPLAY_NAME
from .ingest import RankedCluster

# Validated status palette (dataviz skill) — severity is a *status*, not a series.
SEV_COLOR = {
    "CRITICAL": "#d03b3b",
    "HIGH": "#ec835a",
    "MEDIUM": "#fab219",
    "LOW": "#0ca30c",
    "NONE": "#898781",
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
# Categorical hues for the vendor/tag mix (fixed order, never cycled).
CAT = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#4a3aa7"]


def _esc(s: str) -> str:
    return html.escape(s or "")


def _ago(unix: int, now: int) -> str:
    d = max(now - unix, 0)
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def _bar_row(label, value, total, color, sub=""):
    pct = (value / total * 100) if total else 0
    return f"""
    <div class="row">
      <div class="row-label">{_esc(label)}</div>
      <div class="track"><div class="fill" style="width:{pct:.1f}%;background:{color}"></div></div>
      <div class="row-val">{value}{f' <span class="muted">{_esc(sub)}</span>' if sub else ''}</div>
    </div>"""


def _stat_tile(value, label, accent):
    return f"""
    <div class="tile">
      <div class="tile-val" style="color:{accent}">{value}</div>
      <div class="tile-label">{_esc(label)}</div>
    </div>"""


def _chip(text, color, fg="#fff"):
    return f'<span class="chip" style="background:{color};color:{fg}">{_esc(text)}</span>'


def _severity_counts(clusters):
    counts = {k: 0 for k in SEV_ORDER}
    for c in clusters:
        for cve in c.cves:
            counts[cve.cvss_severity if cve.cvss_severity in counts else "NONE"] += 1
    return counts


def _tag_counts(clusters, tags):
    counts = {t: 0 for t in tags}
    for c in clusters:
        for t in tags:
            if t in c.tags:
                counts[t] += 1
    return counts


def _story_row(idx, c: RankedCluster, now):
    outlets = ", ".join(sorted({a.source_name for a in c.articles}))
    title = c.articles[0].title if c.articles else "(untitled)"
    url = c.articles[0].url if c.articles else "#"
    chips = []
    if c.any_kev:
        chips.append(_chip("KEV", "#d03b3b"))
    if c.max_cvss is not None:
        chips.append(_chip(f"CVSS {c.max_cvss:.1f}", SEV_COLOR[c.worst_severity]))
    if c.source_count > 1:
        chips.append(_chip(f"{c.source_count} outlets", "#2a78d6"))
    for t in ("networking", "bigtech", "advisory"):
        if t in c.tags:
            chips.append(_chip(t, CAT[2] if t == "networking" else CAT[1], "#fff"))
            break
    score_pct = min(c.score * 100 / 0.6, 100)  # 0.6 ~ practical max score
    return f"""
    <tr>
      <td class="rank">{idx}</td>
      <td class="story">
        <a href="{_esc(url)}">{_esc(title)}</a>
        <div class="meta">{_esc(outlets)} · {_ago(c.last_seen, now)} {' '.join(chips)}</div>
      </td>
      <td class="score">
        <div class="score-track"><div class="score-fill" style="width:{score_pct:.0f}%"></div></div>
        <span class="score-num">{c.score:.2f}</span>
      </td>
    </tr>"""


def render(clusters: list[RankedCluster], *, top: int = 25, title: str = None) -> str:
    now = int(time.time())
    title = title or f"{DISPLAY_NAME} — Threat & Tech Intelligence"
    ranked = clusters[:top]

    total_stories = len(clusters)
    kev_count = sum(1 for c in clusters if c.any_kev)
    crit_count = sum(1 for c in clusters for cve in c.cves if cve.cvss_severity == "CRITICAL")
    multi = sum(1 for c in clusters if c.source_count > 1)

    sev = _severity_counts(clusters)
    sev_total = max(sum(sev.values()), 1)
    sev_bars = "".join(
        _bar_row(k.title(), sev[k], sev_total, SEV_COLOR[k]) for k in SEV_ORDER if sev[k] or k != "NONE"
    )

    tags = ["security", "networking", "bigtech", "advisory", "tech"]
    tag_counts = _tag_counts(clusters, tags)
    tag_total = max(sum(tag_counts.values()), 1)
    tag_bars = "".join(
        _bar_row(t.title(), tag_counts[t], tag_total, CAT[i % len(CAT)])
        for i, t in enumerate(tags) if tag_counts[t]
    )

    # Networking / enterprise-tech from top vendors — its own ranked slice.
    net = [c for c in clusters if c.tags & {"networking", "bigtech", "vendor"}][:8]
    net_rows = "".join(_story_row(i + 1, c, now) for i, c in enumerate(net)) or \
        '<tr><td colspan="3" class="muted">No networking/enterprise items in this run.</td></tr>'

    story_rows = "".join(_story_row(i + 1, c, now) for i, c in enumerate(ranked))
    generated = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>
  :root {{
    --plane:#0d0d0d; --surface:#1a1a19; --ink:#fff; --ink2:#c3c2b7;
    --muted:#898781; --grid:#2c2c2a; --track:#2c2c2a; --border:rgba(255,255,255,.10);
    --accent:#3987e5;
  }}
  :root[data-theme="light"] {{
    --plane:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e;
    --muted:#898781; --grid:#e1e0d9; --track:#eceae3; --border:rgba(11,11,11,.10);
    --accent:#2a78d6;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--plane); color:var(--ink);
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.45; }}
  .wrap {{ max-width:1040px; margin:0 auto; padding:28px 20px 60px; }}
  header {{ display:flex; align-items:baseline; justify-content:space-between;
    gap:12px; border-bottom:1px solid var(--border); padding-bottom:16px; margin-bottom:24px; flex-wrap:wrap; }}
  h1 {{ font-size:22px; margin:0; letter-spacing:.02em; }}
  h1 .mark {{ color:var(--accent); }}
  .sub {{ color:var(--muted); font-size:13px; }}
  h2 {{ font-size:14px; text-transform:uppercase; letter-spacing:.06em;
    color:var(--ink2); margin:32px 0 12px; }}
  .tiles {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }}
  .tile {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px 18px; }}
  .tile-val {{ font-size:30px; font-weight:700; line-height:1; }}
  .tile-label {{ color:var(--muted); font-size:12px; margin-top:6px; text-transform:uppercase; letter-spacing:.05em; }}
  .panels {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
  .panel {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:18px 20px; }}
  .row {{ display:grid; grid-template-columns:120px 1fr 64px; align-items:center; gap:10px; margin:8px 0; }}
  .row-label {{ font-size:13px; color:var(--ink2); }}
  .track {{ background:var(--track); border-radius:4px; height:14px; overflow:hidden; }}
  .fill {{ height:100%; border-radius:4px; }}
  .row-val {{ font-size:13px; text-align:right; font-variant-numeric:tabular-nums; }}
  table {{ width:100%; border-collapse:collapse; }}
  td {{ padding:11px 8px; border-bottom:1px solid var(--border); vertical-align:top; }}
  .rank {{ color:var(--muted); font-variant-numeric:tabular-nums; width:34px; font-size:14px; }}
  .story a {{ color:var(--ink); text-decoration:none; font-weight:600; font-size:15px; }}
  .story a:hover {{ color:var(--accent); }}
  .meta {{ color:var(--muted); font-size:12px; margin-top:5px; }}
  .chip {{ display:inline-block; font-size:11px; font-weight:700; padding:1px 7px;
    border-radius:5px; margin-left:4px; vertical-align:middle; letter-spacing:.02em; }}
  .score {{ width:130px; text-align:right; white-space:nowrap; }}
  .score-track {{ display:inline-block; width:72px; height:8px; background:var(--track);
    border-radius:4px; overflow:hidden; vertical-align:middle; margin-right:8px; }}
  .score-fill {{ height:100%; background:var(--accent); border-radius:4px; }}
  .score-num {{ font-variant-numeric:tabular-nums; font-size:13px; color:var(--ink2); }}
  .muted {{ color:var(--muted); }}
  footer {{ color:var(--muted); font-size:12px; margin-top:36px; border-top:1px solid var(--border); padding-top:14px; }}
  .toggle {{ cursor:pointer; background:var(--surface); border:1px solid var(--border);
    color:var(--ink2); border-radius:6px; padding:4px 10px; font-size:12px; }}
  @media (max-width:720px) {{ .tiles{{grid-template-columns:repeat(2,1fr)}} .panels{{grid-template-columns:1fr}} .row{{grid-template-columns:90px 1fr 48px}} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1><span class="mark">▲</span> {_esc(DISPLAY_NAME)} <span class="sub">Threat &amp; Enterprise-Tech Intelligence</span></h1>
      <div class="sub">{total_stories} stories clustered · generated {generated}</div>
    </div>
    <button class="toggle" onclick="var r=document.documentElement;r.dataset.theme=r.dataset.theme==='light'?'dark':'light'">◐ theme</button>
  </header>

  <div class="tiles">
    {_stat_tile(total_stories, "Stories", "var(--accent)")}
    {_stat_tile(kev_count, "KEV (exploited)", "#d03b3b")}
    {_stat_tile(crit_count, "Critical CVEs", "#ec835a")}
    {_stat_tile(multi, "Multi-outlet", "#1baf7a")}
  </div>

  <div class="panels" style="margin-top:16px">
    <div class="panel">
      <h2 style="margin-top:0">CVE severity distribution</h2>
      {sev_bars}
    </div>
    <div class="panel">
      <h2 style="margin-top:0">Coverage by domain</h2>
      {tag_bars}
    </div>
  </div>

  <h2>Top stories</h2>
  <table>{story_rows}</table>

  <h2>Networking &amp; enterprise tech — top vendors</h2>
  <table>{net_rows}</table>

  <footer>
    {_esc(DISPLAY_NAME)} · keyless security + networking/enterprise-tech intelligence ·
    ranking is news-first (recency + velocity + source + keyword = 70%, CVE signals = 30%).
    Severity colors follow the CISA/FIRST status scale. CVE data from CVE Program, CISA KEV, and FIRST EPSS.
  </footer>
</div>
</body>
</html>"""
