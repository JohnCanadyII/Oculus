# Oculus — Build Plan

A phased roadmap for building Oculus (a Python port of *Nadezhda*), personalized
with a new name, networking/enterprise-tech feeds, a chart dashboard, email
delivery, and endpoint installability. Phases 0–4 are **already scaffolded and
working** in this repo; phases 5+ are the roadmap to a shippable product.

Each phase lists what to build, the module it lives in, and a "done when" check.

---

## Phase 0 — Skeleton & config ✅ (done)

- `pyproject.toml` with a `oculus` console-script entry point.
- `config.py`: dataclasses for sources, ranking weights, fetch, cluster, email —
  every tunable in one place, with env + `config.yaml` overrides.
- `sources.yaml`: the expanded feed set (security + Cisco/networking + big-tech).

**Done when:** `pip install -e .` gives you a working `oculus sources`.

## Phase 1 — Ingestion MVP ✅ (done)

- `fetch.py`: async httpx worker pool, per-host rate limiter, conditional GET.
- `parse.py`: feedparser → normalized `Article` records.
- `normalize.py`: canonical URL, HTML strip, content hash, token sets.
- `store.py`: SQLite schema, dedup-on-insert (UNIQUE constraints), WAL mode.

**Done when:** `oculus scrape` fetches feeds and stores deduped articles. Fail-soft
is verified: a broken feed reports an error and the run continues.

## Phase 2 — CVE extraction & keyless enrichment ✅ (done)

- `cve.py`: `CVE-\d{4}-\d{4,7}` extraction; enrichment from the CVE Program record
  (CVSS version precedence, look in every container), CISA KEV (string→bool
  ransomware flag), FIRST EPSS (string→float parsing).

**Done when:** enriched CVEs carry CVSS/severity/KEV/EPSS. Watch the two known
traps: Log4Shell's score lives in the CISA container; EPSS values are strings.

## Phase 3 — Cluster & rank ✅ (done)

- `cluster.py`: union-find by shared CVE + cross-outlet title Jaccard.
- `rank.py`: deterministic news-first weighted score.
- `ingest.py`: the `ingest_and_rank()` seam.

**Done when:** the same corpus always ranks the same way; KEV/exploited stories
float to the top. (Verified in the demo: two KEV CVEs ranked #1 and #2.)

## Phase 4 — Presentation: dashboard, digest, email ✅ (done)

- `dashboard.py`: chart-driven HTML (stat tiles, severity chart, coverage chart,
  ranked stories, networking/enterprise-tech section). Email-safe div-bar charts.
- `deliver.py`: SMTP HTML email.
- `cli.py`: `dashboard`, `digest`, `email`, `watch`.

**Done when:** `oculus dashboard --open` renders the dashboard and `oculus email`
sends it. (Demo dashboard rendered light + dark.)

---

## Phase 5 — Robustness & tests (next)

- **Golden-order ranking test:** feed fixed fixtures, assert one exact ordering —
  the property that makes ranking trustworthy.
- **Offline enrichment tests:** fixture JSON for CVE Program / KEV / EPSS (the
  repo already ships `_fixtures/`), so tests never touch the network. Include the
  Log4Shell "score in the CISA container" case and the EPSS string-typing case.
- **Fetch tests:** conditional GET (304 path), per-host spacing, one-feed-fails.
- **TTL cache** for enrichment so repeat scrapes don't re-fetch unchanged CVEs.
- Add `pytest` + CI (GitHub Actions) running the suite with no network.

**Effort:** ~1–2 days. **Done when:** `pytest` is green offline and CI runs it.

## Phase 6 — Packaging & endpoint distribution

Goal: any customer can install and run it on their endpoint.

- **PyPI:** publish `oculus-intel`; `pipx install oculus-intel` is the happy path.
- **Single-file binary:** `pyinstaller --onefile -n oculus oculus/__main__.py` for
  customers without Python. Ship per-OS artifacts from CI.
- **systemd service** (Linux endpoints), ship as `packaging/oculus.service`:

  ```ini
  [Unit]
  Description=Oculus intelligence watcher
  After=network-online.target
  [Service]
  Type=simple
  Environment=OCULUS_SMTP_PASSWORD=...
  ExecStart=%h/.local/bin/oculus watch --interval 60
  Restart=on-failure
  [Install]
  WantedBy=default.target
  ```

- **cron alternative:** `0 * * * * OCULUS_SMTP_PASSWORD=... oculus scrape && oculus email`
- **First-run wizard:** `oculus init` to write `config.yaml` and test SMTP.

**Effort:** ~2–3 days. **Done when:** a fresh machine goes from install to a
scheduled emailed digest in under five minutes.

## Phase 7 — Multi-tenant / customer delivery (product)

If "any customer" means *you* run it and mail *them*:

- Per-recipient config: distinct watchlists, feed subsets, and schedules.
- A `recipients.yaml` with per-customer `tags` filters (e.g. a networking customer
  gets `networking`+`security`, not consumer tech).
- Delivery log table (who got which digest when) + suppression on send failure.
- Optional: a transactional email provider (SES/SendGrid) behind the same
  `deliver` interface instead of raw SMTP, for deliverability at volume.

**Effort:** ~3–5 days.

## Phase 8 — Dashboard enrichment (visual polish)

- Sparklines of per-CVE EPSS trend and cluster velocity over time (needs a small
  history table).
- A KEV "exploited today" banner and a ransomware-flagged callout.
- Interactive filters (by tag/vendor/severity) in the standalone dashboard — the
  hover/tooltip and filter layer from the data-viz method. Keep the email body on
  the static div-bar charts (email can't run JS).
- Per-vendor rollups (Cisco / Microsoft / Palo Alto advisory counts).

**Effort:** ~2–4 days.

## Phase 9 — Optional AI summaries

- A `summarize` step that writes a one-paragraph brief per top cluster, off by
  default, keyless via local Ollama, with OpenAI/Anthropic/Gemini as opt-in.
- Cache summaries per cluster so they aren't regenerated each run.

**Effort:** ~2–3 days.

---

## Suggested order & first PR

If you're starting from this scaffold, the highest-value next step is **Phase 5**
(tests) so refactors stay safe, then **Phase 6** (packaging) to hit the
"installable on any endpoint" requirement, then **Phase 7/8** depending on whether
the priority is customer delivery or a richer dashboard.

## Name

Working name is **Oculus** (keeping watch). It's set in one place —
`APP_NAME`/`DISPLAY_NAME` in `oculus/config.py` — so renaming is a one-line change.
A few alternatives if you want to pick your own: **Beacon**, **Sentry**,
**Watchtower**, **Signal**, **Aperture**. Change the string and the package
directory name and you're done.
