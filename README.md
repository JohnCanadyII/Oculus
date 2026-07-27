# Oculus

**Keyless security + networking/enterprise-tech news & CVE intelligence engine.**

Oculus points at a set of RSS/Atom feeds, fetches them politely, clusters the same
story as it appears across outlets, extracts every CVE, enriches each one with
authoritative exploit intelligence (CISA KEV, FIRST EPSS, the CVE Program record),
ranks the whole set by real-world significance, and renders it as an **enhanced
HTML dashboard with charts** — which it can also **email** to you or your customers
and run on a schedule on any **endpoint**.

It is a Python port of the Go project *Nadezhda*, personalized: a new name, an
expanded feed set that covers **Cisco, networking, and big-tech / enterprise
vendors** alongside security, a chart-driven dashboard, and email delivery.

No API keys required for the core. The CVE data comes from keyless public sources.

---

## Quick start

```bash
pipx install oculus-intel          # or: pip install oculus-intel
oculus scrape                      # fetch, cluster, enrich, rank
oculus dashboard --open            # build the HTML dashboard and open it
oculus digest --top 15             # quick text digest in the terminal
```

From source:

```bash
git clone <your-repo> oculus && cd oculus
python -m venv .venv && . .venv/bin/activate
pip install -e .
oculus scrape && oculus dashboard --open
```

## Commands

| Command | What it does |
|---|---|
| `oculus scrape` | Fetch every enabled feed, dedup, extract + enrich CVEs, cluster, rank. |
| `oculus dashboard [-o FILE] [--top N] [--open]` | Render the enhanced HTML dashboard. |
| `oculus digest [--top N]` | Print a ranked text digest. |
| `oculus email` | Send the HTML digest by email (see config). |
| `oculus watch [--interval M]` | Endpoint daemon: scrape + email on a timer. |
| `oculus sources` | List configured feeds. |

## Email delivery

Create `~/.config/oculus/config.yaml`:

```yaml
email:
  enabled: true
  host: smtp.gmail.com
  port: 587
  use_tls: true
  username: you@example.com
  sender: you@example.com
  recipients: [team@example.com]
  top: 15
watchlist: [cisco, "ios xe", sharepoint, fortinet, palo alto]
retention_days: 14   # rolling window: only show stories from the last N days (0 = keep all)
```

`oculus scrape` is what pulls fresh headlines — loading the dashboard just
re-renders the current store. With `retention_days` set, the dashboard shows only
recent news, so the story count naturally rises and falls day to day as feeds
update. Set it to `0` to keep an ever-growing archive instead.

Put the SMTP password in the environment, not the file:

```bash
export OCULUS_SMTP_PASSWORD='...'
oculus email
```

## Running on a customer endpoint

Oculus is a self-contained pip package. On a customer machine:

```bash
pipx install oculus-intel
export OCULUS_SMTP_PASSWORD='...'
oculus watch --interval 60          # scrape + email hourly
```

Or as a background service — see `BUILD_PLAN.md` for a ready-to-use `systemd`
unit and a `cron` line, plus a PyInstaller recipe for a single-file binary.

## Personalize

- **Rename the tool:** change `APP_NAME` / `DISPLAY_NAME` in `oculus/config.py`.
- **Change feeds:** edit `oculus/sources.yaml` (or drop a copy at
  `~/.config/oculus/sources.yaml`). Each entry has a `weight` (0–1) and `tags`.
- **Tune ranking:** every weight lives in `oculus/config.py` (`Weights`). Defaults
  are news-first (recency + velocity + source + keyword = 70%, CVE = 30%).

## How it works

See `ARCHITECTURE.md` for the full pipeline and `BUILD_PLAN.md` for the phased
roadmap. In short: `fetch → parse → normalize → ingest/dedup → CVE extract →
cluster (union-find) → enrich (KEV/EPSS/CVE Program) → rank → dashboard/email`.

## License

AGPL-3.0-or-later (matching the upstream project).
