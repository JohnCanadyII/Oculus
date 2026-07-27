"""Render ranked clusters as an enhanced HTML dashboard with FOUR selectable layouts.

Views (switch live in the browser, no reload):
  • Command Center  — KPI tiles, charts, ranked table (classic dashboard)
  • Threat Wire     — terminal/SOC-feed homage to the original TUI
  • Triage Board    — kanban columns by urgency (CRITICAL/HIGH/WATCH/NEWS)
  • Executive Brief — KEV banner, hero cards, mini charts (skim / email friendly)

All four render from the same ranked data. Charts are inline-styled <div> bars
(email-safe: no SVG) using the validated data-viz status palette for severity.
`render()` returns the multi-view page; `render_email()` returns a single static
view suitable as an email body.
"""
from __future__ import annotations

import html
import time
from datetime import datetime, timezone

from .config import DISPLAY_NAME
from .ingest import RankedCluster

# ── The palette: FIVE colors only — grey, purple, green, blue, red ─────────────
# Used consistently across every chart and every chip. No orange, yellow, or pink.
RED = "#d84141"
BLUE = "#2f7fd6"
GREEN = "#1f9d6b"
PURPLE = "#8b5cf6"
GREY = "#6f7480"

# Severity (heat, hot→cool within the palette): critical=red … none=grey.
SEV_COLOR = {
    "CRITICAL": RED, "HIGH": PURPLE, "MEDIUM": BLUE, "LOW": GREEN, "NONE": GREY,
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

# Domains — same five colors, one per category, used by BOTH the coverage chart
# and the story chips so a category is the same color everywhere.
DOMAIN_ORDER = ["security", "networking", "bigtech", "advisory", "tech"]
DOMAIN_COLOR = {
    "security": BLUE,        # blue
    "networking": PURPLE,    # purple
    "bigtech": GREEN,        # green
    "advisory": RED,         # red
    "tech": GREY,            # grey
}
OUTLETS_COLOR = GREY         # neutral grey — velocity metadata, not a category
NEWS_COLOR = GREY            # plain news (no CVE/domain) fallback


def _esc(s: str) -> str:
    return html.escape(s or "")


def _ago(unix: int, now: int) -> str:
    d = max(now - unix, 0)
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def _title(c):
    return c.articles[0].title if c.articles else "(untitled)"


def _url(c):
    return c.articles[0].url if c.articles else "#"


def _outlets(c):
    return ", ".join(sorted({a.source_name for a in c.articles}))


def _score_pct(c):
    return min(c.score * 100 / 0.6, 100)


def _domain_tag(c):
    for t in ("networking", "bigtech", "advisory", "security", "tech"):
        if t in c.tags:
            return t
    return ""


def _chip(text, color, fg="#fff"):
    return f'<span class="chip" style="background:{color};color:{fg}">{_esc(text)}</span>'


def _max_epss(c):
    return max((v.epss or 0.0 for v in c.cves), default=0.0)


def _story_chips(c):
    chips = []
    if c.any_kev:
        chips.append(_chip("KEV", SEV_COLOR["CRITICAL"]))          # red = Critical bar
    if c.max_cvss is not None:
        chips.append(_chip(f"CVSS {c.max_cvss:.1f}", SEV_COLOR[c.worst_severity]))  # matches severity chart
    epss = _max_epss(c)
    if epss >= 0.10:                                               # exploitation likelihood
        chips.append(f'<span class="chip chip-outline">EPSS {epss * 100:.0f}%</span>')
    if c.source_count > 1:
        chips.append(_chip(f"{c.source_count} outlets", OUTLETS_COLOR))
    dt = _domain_tag(c)
    if dt in ("networking", "bigtech", "advisory", "tech"):        # matches coverage chart
        chips.append(_chip(dt, DOMAIN_COLOR[dt]))
    return " ".join(chips)


# ── vendor rollup: which enterprise vendors are in the news ────────────────────
VENDORS = ["Cisco", "Microsoft", "Palo Alto", "Fortinet", "Juniper", "VMware",
           "Citrix", "Google", "AWS", "Nvidia", "Apple", "Oracle", "Ivanti"]


def _vendor_counts(clusters):
    counts = {v: 0 for v in VENDORS}
    for c in clusters:
        hay = " ".join(a.title for a in c.articles).lower()
        for v in VENDORS:
            if v.lower() in hay:
                counts[v] += 1
    return {v: n for v, n in sorted(counts.items(), key=lambda x: -x[1]) if n}


def _vendor_chart(clusters):
    counts = _vendor_counts(clusters)
    if not counts:
        return '<div class="muted">No named vendors in this run.</div>'
    total = max(counts.values())
    return "".join(_bar_row(v, n, total, DOMAIN_COLOR["networking"]) for v, n in counts.items())


# ── shared chart pieces ────────────────────────────────────────────────────────
def _severity_counts(clusters):
    counts = {k: 0 for k in SEV_ORDER}
    for c in clusters:
        for cve in c.cves:
            counts[cve.cvss_severity if cve.cvss_severity in counts else "NONE"] += 1
    return counts


def _tag_counts(clusters, tags):
    return {t: sum(1 for c in clusters if t in c.tags) for t in tags}


def _bar_row(label, value, total, color, small=False):
    pct = (value / total * 100) if total else 0
    cls = "row small" if small else "row"
    return (f'<div class="{cls}"><div class="row-label">{_esc(label)}</div>'
            f'<div class="track"><div class="fill" style="width:{pct:.1f}%;background:{color}"></div></div>'
            f'<div class="row-val">{value}</div></div>')


def _severity_chart(clusters, small=False):
    sev = _severity_counts(clusters)
    total = max(sum(sev.values()), 1)
    return "".join(_bar_row(k.title(), sev[k], total, SEV_COLOR[k], small)
                   for k in SEV_ORDER if sev[k] or k != "NONE")


def _coverage_chart(clusters, small=False):
    tc = _tag_counts(clusters, DOMAIN_ORDER)
    total = max(sum(tc.values()), 1)
    return "".join(_bar_row(t.title(), tc[t], total, DOMAIN_COLOR[t], small)
                   for t in DOMAIN_ORDER if tc[t])


def _stat_tile(value, label, accent):
    return (f'<div class="tile"><div class="tile-val" style="color:{accent}">{value}</div>'
            f'<div class="tile-label">{_esc(label)}</div></div>')


def _kpis(clusters):
    return {
        "stories": len(clusters),
        "kev": sum(1 for c in clusters if c.any_kev),
        "crit": sum(1 for c in clusters for cve in c.cves if cve.cvss_severity == "CRITICAL"),
        "multi": sum(1 for c in clusters if c.source_count > 1),
    }


# ── VIEW 1: Command Center ─────────────────────────────────────────────────────
def _ai_line(c):
    return f'<div class="ai">🤖 {_esc(c.ai_summary)}</div>' if getattr(c, "ai_summary", "") else ""


def _story_row(idx, c, now):
    dom = _domain_tag(c) or "security"
    return f"""<tr class="srow" data-domain="{dom}" data-kev="{1 if c.any_kev else 0}">
      <td class="rank">{idx}</td>
      <td class="story"><a href="{_esc(_url(c))}">{_esc(_title(c))}</a>
        <div class="meta">{_esc(_outlets(c))} · {_ago(c.last_seen, now)} {_story_chips(c)}</div>
        {_ai_line(c)}</td>
      <td class="score"><div class="score-track"><div class="score-fill" style="width:{_score_pct(c):.0f}%"></div></div>
        <span class="score-num">{c.score:.2f}</span></td>
    </tr>"""


def _view_command(clusters, now, top):
    k = _kpis(clusters)
    tiles = (_stat_tile(k["stories"], "Stories", BLUE)
             + _stat_tile(k["kev"], "KEV (exploited)", RED)
             + _stat_tile(k["crit"], "Critical CVEs", PURPLE)
             + _stat_tile(k["multi"], "Multi-outlet", GREEN))
    rows = "".join(_story_row(i + 1, c, now) for i, c in enumerate(clusters[:top]))
    net = [c for c in clusters if c.tags & {"networking", "bigtech", "vendor"}][:8]
    net_rows = "".join(_story_row(i + 1, c, now) for i, c in enumerate(net)) or \
        '<tr><td colspan="3" class="muted">No networking/enterprise items.</td></tr>'
    filters = ("".join(
        f'<button class="filter-btn{" active" if f == "all" else ""}" data-filter="{f}">{label}</button>'
        for f, label in [("all", "All"), ("kev", "KEV only"), ("networking", "Networking"),
                         ("bigtech", "Big tech"), ("advisory", "Advisory"), ("security", "Security")]))
    return f"""
    <div class="tiles">{tiles}</div>
    <div class="panels">
      <div class="panel"><h2>CVE severity distribution</h2>{_severity_chart(clusters)}</div>
      <div class="panel"><h2>Coverage by domain</h2>{_coverage_chart(clusters)}</div>
    </div>
    <div class="panels">
      <div class="panel"><h2>Enterprise vendors in the news</h2>{_vendor_chart(clusters)}</div>
      <div class="panel"><h2>Exploited &amp; critical</h2>
        {_severity_chart([c for c in clusters if c.any_kev or (c.max_cvss or 0) >= 7]) or '<div class="muted">Nothing high-severity right now.</div>'}
      </div>
    </div>
    <h2>Top stories</h2>
    <div class="filters">{filters}</div>
    <table id="story-table">{rows}</table>
    <h2>Networking &amp; enterprise tech — top vendors</h2><table>{net_rows}</table>"""


# ── VIEW 2: Threat Wire (terminal) ─────────────────────────────────────────────
def _spark(pct):
    n = 12
    filled = round(pct / 100 * n)
    return "".join("█" if i < filled else "·" for i in range(n))


def _wire_row(idx, c, now):
    sev = c.worst_severity if c.cves else "NONE"
    edge = SEV_COLOR["CRITICAL"] if c.any_kev else SEV_COLOR[sev]
    tag = "KEV" if c.any_kev else (f"{c.max_cvss:.1f}" if c.max_cvss is not None else
                                   (_domain_tag(c)[:3].upper() or "—"))
    return f"""<a class="wire-row" href="{_esc(_url(c))}" style="--edge:{edge}">
      <span class="w-idx">{idx:>2}</span>
      <span class="w-title">{_esc(_title(c))}</span>
      <span class="w-spark">{_spark(_score_pct(c))}</span>
      <span class="w-score">{c.score:.2f}</span>
      <span class="w-tag" style="color:{edge}">{_esc(tag)}</span></a>"""


def _view_wire(clusters, now, top):
    k = _kpis(clusters)
    rows = "".join(_wire_row(i + 1, c, now) for i, c in enumerate(clusters[:top]))
    legend = (f"<span style='color:{RED}'>▪ KEV/CRIT</span> "
              f"<span style='color:{PURPLE}'>▪ HIGH</span> "
              f"<span style='color:{BLUE}'>▪ MED</span> "
              f"<span style='color:{GREEN}'>▪ LOW</span>")
    return f"""<div class="wire">
      <div class="wire-head">▛▀ {_esc(DISPLAY_NAME.upper())} ▪ THREAT.WIRE ▪▪▪▪▪▪
        <span class="wire-count">{k['stories']} stories · {k['kev']} KEV</span></div>
      <div class="wire-body">{rows}</div>
      <div class="wire-foot">{legend}</div>
    </div>"""


# ── VIEW 3: Triage Board (kanban) ──────────────────────────────────────────────
def _urgency(c):
    if c.any_kev or (c.max_cvss or 0) >= 9.0:
        return "CRITICAL"
    if (c.max_cvss or 0) >= 7.0:
        return "HIGH"
    if c.cves:
        return "WATCH"
    return "NEWS"


def _card(c, now):
    return f"""<a class="card" href="{_esc(_url(c))}">
      <div class="card-title">{_esc(_title(c))}</div>
      <div class="card-meta">{_esc(_outlets(c))} · {_ago(c.last_seen, now)}</div>
      <div class="card-chips">{_story_chips(c) or _chip(_domain_tag(c) or 'news', DOMAIN_COLOR.get(_domain_tag(c), NEWS_COLOR))}</div></a>"""


def _view_triage(clusters, now, top):
    cols = {"CRITICAL": [], "HIGH": [], "WATCH": [], "NEWS": []}
    for c in clusters[:top]:
        cols[_urgency(c)].append(c)
    head_color = {"CRITICAL": RED, "HIGH": PURPLE, "WATCH": BLUE, "NEWS": GREY}
    out = []
    for name, items in cols.items():
        cards = "".join(_card(c, now) for c in items) or '<div class="muted card-empty">—</div>'
        out.append(f"""<div class="col">
          <div class="col-head" style="border-color:{head_color[name]};color:{head_color[name]}">
            {name} <span class="col-count">{len(items)}</span></div>
          <div class="col-body">{cards}</div></div>""")
    return f'<div class="board">{"".join(out)}</div>'


# ── VIEW 4: Executive Brief ────────────────────────────────────────────────────
def _hero(c, now):
    return f"""<a class="hero" href="{_esc(_url(c))}">
      <div class="hero-chips">{_story_chips(c)}</div>
      <div class="hero-title">{_esc(_title(c))}</div>
      {_ai_line(c)}
      <div class="hero-meta">{_esc(_outlets(c))} · {_ago(c.last_seen, now)} · score {c.score:.2f}</div></a>"""


def _view_exec(clusters, now, top):
    k = _kpis(clusters)
    banner = ""
    if k["kev"]:
        kev_titles = ", ".join(_title(c) for c in clusters if c.any_kev)[:120]
        banner = f'<div class="alert">⚠ {k["kev"]} exploited (KEV) stories need attention — {_esc(kev_titles)}…</div>'
    heroes = "".join(_hero(c, now) for c in clusters[:5])
    rest = "".join(f'<li><a href="{_esc(_url(c))}">{_esc(_title(c))}</a>'
                   f'<span class="li-meta">{_ago(c.last_seen, now)} {_story_chips(c)}</span></li>'
                   for c in clusters[5:15])
    return f"""{banner}
    <div class="hero-grid">{heroes}</div>
    <div class="panels">
      <div class="panel"><h2>Severity</h2>{_severity_chart(clusters, small=True)}</div>
      <div class="panel"><h2>Coverage</h2>{_coverage_chart(clusters, small=True)}</div>
    </div>
    <h2>More stories</h2><ul class="brief-list">{rest}</ul>"""


VIEWS = [
    ("command", "Command Center"),
    ("wire", "Threat Wire"),
    ("triage", "Triage Board"),
    ("exec", "Executive Brief"),
]


def render(clusters: list[RankedCluster], *, top: int = 25, default_view: str = "command") -> str:
    now = int(time.time())
    generated = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = {
        "command": _view_command(clusters, now, top),
        "wire": _view_wire(clusters, now, top),
        "triage": _view_triage(clusters, now, top),
        "exec": _view_exec(clusters, now, top),
    }
    view_sections = "".join(
        f'<section class="view" data-view="{vid}" '
        f'{"" if vid == default_view else "hidden"}>{sections[vid]}</section>'
        for vid, _ in VIEWS
    )
    nav = "".join(
        f'<button class="nav-btn{" active" if vid == default_view else ""}" data-go="{vid}">{label}</button>'
        for vid, label in VIEWS
    )
    return _PAGE.format(
        title=f"{_esc(DISPLAY_NAME)} — Threat & Enterprise-Tech Intelligence",
        display=_esc(DISPLAY_NAME), generated=generated,
        stories=len(clusters), kev=sum(1 for c in clusters if c.any_kev),
        nav=nav, views=view_sections, css=_CSS,
    )


def render_email(clusters, *, top: int = 15) -> str:
    """A single static view (Executive Brief) for email bodies — no view switcher/JS."""
    now = int(time.time())
    body = _view_exec(clusters, now, top)
    return _PAGE.format(
        title=f"{_esc(DISPLAY_NAME)} digest", display=_esc(DISPLAY_NAME),
        generated=datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        stories=len(clusters), kev=sum(1 for c in clusters if c.any_kev),
        nav="", views=f'<section class="view">{body}</section>', css=_CSS,
    )


_CSS = """
  :root { --plane:#0d0d0d; --surface:#1a1a19; --ink:#fff; --ink2:#c3c2b7; --muted:#898781;
    --grid:#2c2c2a; --track:#2c2c2a; --border:rgba(255,255,255,.10); --accent:#3987e5; }
  :root[data-theme="light"] { --plane:#f9f9f7; --surface:#fcfcfb; --ink:#0b0b0b; --ink2:#52514e;
    --muted:#898781; --grid:#e1e0d9; --track:#eceae3; --border:rgba(11,11,11,.10); --accent:#2a78d6; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--plane); color:var(--ink);
    font-family:system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.45; }
  .wrap { max-width:1080px; margin:0 auto; padding:24px 20px 60px; }
  header { display:flex; align-items:center; justify-content:space-between; gap:12px;
    border-bottom:1px solid var(--border); padding-bottom:14px; margin-bottom:18px; flex-wrap:wrap; }
  h1 { font-size:21px; margin:0; letter-spacing:.02em; } h1 .mark { color:var(--accent); }
  .sub { color:var(--muted); font-size:13px; }
  .controls { display:flex; gap:6px; align-items:center; flex-wrap:wrap; }
  .nav-btn, .toggle { cursor:pointer; background:var(--surface); border:1px solid var(--border);
    color:var(--ink2); border-radius:7px; padding:6px 12px; font-size:13px; }
  .nav-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--ink2); margin:26px 0 10px; }
  .panel h2 { margin-top:0; }
  .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .tile { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:15px 18px; }
  .tile-val { font-size:29px; font-weight:700; line-height:1; }
  .tile-label { color:var(--muted); font-size:12px; margin-top:6px; text-transform:uppercase; letter-spacing:.05em; }
  .panels { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:16px; }
  .panel { background:var(--surface); border:1px solid var(--border); border-radius:10px; padding:16px 18px; }
  .row { display:grid; grid-template-columns:110px 1fr 42px; align-items:center; gap:10px; margin:8px 0; }
  .row.small { grid-template-columns:80px 1fr 34px; margin:5px 0; }
  .row-label { font-size:13px; color:var(--ink2); }
  .track { background:var(--track); border-radius:4px; height:14px; overflow:hidden; }
  .row.small .track { height:10px; }
  .fill { height:100%; border-radius:4px; }
  .row-val { font-size:13px; text-align:right; font-variant-numeric:tabular-nums; }
  table { width:100%; border-collapse:collapse; }
  td { padding:11px 8px; border-bottom:1px solid var(--border); vertical-align:top; }
  .rank { color:var(--muted); font-variant-numeric:tabular-nums; width:34px; font-size:14px; }
  .story a { color:var(--ink); text-decoration:none; font-weight:600; font-size:15px; }
  .story a:hover { color:var(--accent); }
  .meta { color:var(--muted); font-size:12px; margin-top:5px; }
  .chip { display:inline-block; font-size:11px; font-weight:700; padding:1px 7px; border-radius:5px;
    margin-left:4px; vertical-align:middle; letter-spacing:.02em; }
  .chip-outline { display:inline-block; font-size:11px; font-weight:700; padding:0 6px; border-radius:5px;
    margin-left:4px; vertical-align:middle; border:1px solid var(--border); color:var(--ink2); }
  .ai { color:var(--ink2); font-size:13px; margin-top:6px; line-height:1.4;
    border-left:2px solid var(--accent); padding-left:9px; }
  .filters { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px; }
  .filter-btn { cursor:pointer; background:var(--surface); border:1px solid var(--border);
    color:var(--ink2); border-radius:6px; padding:4px 11px; font-size:12px; }
  .filter-btn.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .score { width:130px; text-align:right; white-space:nowrap; }
  .score-track { display:inline-block; width:70px; height:8px; background:var(--track); border-radius:4px;
    overflow:hidden; vertical-align:middle; margin-right:8px; }
  .score-fill { height:100%; background:var(--accent); border-radius:4px; }
  .score-num { font-variant-numeric:tabular-nums; font-size:13px; color:var(--ink2); }
  .muted { color:var(--muted); }
  .legend { display:flex; flex-wrap:wrap; gap:14px; align-items:center; margin-top:12px; font-size:12px; color:var(--ink2); }
  .legend:first-of-type { margin-top:30px; padding-top:14px; border-top:1px solid var(--border); }
  .lg-title { font-weight:700; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); min-width:78px; font-size:11px; }
  .lg { display:inline-flex; align-items:center; gap:6px; }
  .lg i { width:11px; height:11px; border-radius:3px; display:inline-block; }
  footer { color:var(--muted); font-size:12px; margin-top:20px; border-top:1px solid var(--border); padding-top:14px; }
  /* Threat Wire */
  .wire { background:#08080c; border:1px solid #1c1c26; border-radius:8px; overflow:hidden;
    font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; }
  .wire-head { background:#0c0c14; color:#4be1e1; padding:9px 12px; font-size:13px; letter-spacing:.04em;
    border-bottom:1px solid #1c1c26; display:flex; justify-content:space-between; }
  .wire-count { color:#8a8aa0; }
  .wire-body { padding:4px 0; }
  .wire-row { display:grid; grid-template-columns:30px 1fr 130px 46px 52px; gap:8px; align-items:center;
    padding:5px 12px 5px 10px; border-left:3px solid var(--edge); text-decoration:none; color:#d6d6e6; font-size:13px; }
  .wire-row:hover { background:#12121c; }
  .w-idx { color:#6a6a80; text-align:right; }
  .w-title { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .w-spark { color:#4be1e1; letter-spacing:-1px; font-size:12px; }
  .w-score { color:#8a8aa0; text-align:right; font-variant-numeric:tabular-nums; }
  .w-tag { text-align:right; font-weight:700; font-size:12px; }
  .wire-foot { padding:8px 12px; border-top:1px solid #1c1c26; font-size:12px; display:flex; gap:14px; }
  /* Triage Board */
  .board { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; }
  .col { background:var(--surface); border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  .col-head { font-size:12px; font-weight:700; letter-spacing:.06em; padding:10px 12px;
    border-bottom:2px solid; display:flex; justify-content:space-between; }
  .col-count { color:var(--muted); }
  .col-body { padding:8px; display:flex; flex-direction:column; gap:8px; min-height:60px; }
  .card { display:block; background:var(--plane); border:1px solid var(--border); border-radius:8px;
    padding:10px; text-decoration:none; color:var(--ink); }
  .card:hover { border-color:var(--accent); }
  .card-title { font-size:13px; font-weight:600; line-height:1.3; }
  .card-meta { color:var(--muted); font-size:11px; margin:5px 0; }
  .card-chips .chip { margin-left:0; margin-right:4px; }
  .card-empty { padding:12px; text-align:center; }
  /* Executive Brief */
  .alert { background:#2a0f0f; border:1px solid #d84141; color:#ffb4b4; border-radius:9px;
    padding:12px 16px; font-weight:600; font-size:14px; margin-bottom:16px; }
  :root[data-theme="light"] .alert { background:#fdecec; color:#8a1c1c; }
  .hero-grid { display:grid; grid-template-columns:repeat(2,1fr); gap:12px; }
  .hero { display:block; background:var(--surface); border:1px solid var(--border); border-radius:10px;
    padding:16px; text-decoration:none; color:var(--ink); }
  .hero:hover { border-color:var(--accent); }
  .hero-chips { margin-bottom:8px; } .hero-chips .chip { margin-left:0; margin-right:4px; }
  .hero-title { font-size:16px; font-weight:700; line-height:1.3; }
  .hero-meta { color:var(--muted); font-size:12px; margin-top:8px; }
  .brief-list { list-style:none; padding:0; margin:0; }
  .brief-list li { padding:9px 0; border-bottom:1px solid var(--border); display:flex;
    justify-content:space-between; gap:12px; align-items:baseline; }
  .brief-list a { color:var(--ink); text-decoration:none; font-weight:600; font-size:14px; }
  .brief-list a:hover { color:var(--accent); }
  .li-meta { color:var(--muted); font-size:12px; white-space:nowrap; }
  @media (max-width:760px){ .tiles,.hero-grid{grid-template-columns:repeat(2,1fr)} .panels,.board{grid-template-columns:1fr}
    .wire-row{grid-template-columns:26px 1fr 46px 48px} .w-spark{display:none} }
"""

_PAGE = """<!doctype html>
<html lang="en" data-theme="dark">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>{css}</style></head>
<body><div class="wrap">
  <header>
    <div><h1><span class="mark">▲</span> {display} <span class="sub">Threat &amp; Enterprise-Tech Intelligence</span></h1>
      <div class="sub">{stories} stories · {kev} KEV · generated {generated}</div></div>
    <div class="controls">{nav}
      <button class="toggle" onclick="var r=document.documentElement;r.dataset.theme=r.dataset.theme==='light'?'dark':'light'">◐ theme</button>
    </div>
  </header>
  {views}
  <div class="legend">
    <span class="lg-title">Severity</span>
    <span class="lg"><i style="background:#d84141"></i>Critical / KEV</span>
    <span class="lg"><i style="background:#8b5cf6"></i>High</span>
    <span class="lg"><i style="background:#2f7fd6"></i>Medium</span>
    <span class="lg"><i style="background:#1f9d6b"></i>Low</span>
    <span class="lg"><i style="background:#6f7480"></i>None</span>
  </div>
  <div class="legend">
    <span class="lg-title">Domain</span>
    <span class="lg"><i style="background:#2f7fd6"></i>Security</span>
    <span class="lg"><i style="background:#8b5cf6"></i>Networking</span>
    <span class="lg"><i style="background:#1f9d6b"></i>Bigtech</span>
    <span class="lg"><i style="background:#d84141"></i>Advisory</span>
    <span class="lg"><i style="background:#6f7480"></i>Tech &amp; N-outlets</span>
  </div>
  <footer>{display} · keyless security + networking/enterprise-tech intelligence · news-first ranking
    (recency + velocity + source + keyword = 70%, CVE signals = 30%). Severity follows the CISA/FIRST
    status scale. CVE data from CVE Program, CISA KEV, and FIRST EPSS.</footer>
</div>
<script>
  document.querySelectorAll('.nav-btn').forEach(function(b){{
    b.addEventListener('click', function(){{
      var v = b.dataset.go;
      document.querySelectorAll('.nav-btn').forEach(function(x){{x.classList.toggle('active', x===b);}});
      document.querySelectorAll('.view').forEach(function(s){{ s.hidden = (s.dataset.view !== v); }});
    }});
  }});
  document.querySelectorAll('.filter-btn').forEach(function(b){{
    b.addEventListener('click', function(){{
      var f = b.dataset.filter;
      document.querySelectorAll('.filter-btn').forEach(function(x){{x.classList.toggle('active', x===b);}});
      document.querySelectorAll('#story-table .srow').forEach(function(r){{
        var show = (f==='all') || (f==='kev' ? r.dataset.kev==='1' : r.dataset.domain===f);
        r.style.display = show ? '' : 'none';
      }});
    }});
  }});
</script>
</body></html>"""
