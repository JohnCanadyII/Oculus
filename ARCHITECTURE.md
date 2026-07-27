# Oculus — Architecture

This is the map: the pipeline end to end, the module that owns each stage, the
data model underneath, and the design decisions behind it. It mirrors the
architecture of the Go original (*Nadezhda*) but in Python, with two additions of
our own — a chart-driven HTML dashboard and email delivery.

## The pipeline

Everything flows one direction, from a list of feeds to a ranked set of surfaces.

```
        sources.yaml  (bundled default, or ~/.config/oculus/sources.yaml)
              │
              ▼
   fetch      concurrent workers, per-host rate limit,            oculus/fetch.py
              conditional GET (ETag / Last-Modified)
              │  raw bytes + fetch_state
              ▼
   parse      RSS / Atom via feedparser                           oculus/parse.py
              │  raw items
              ▼
   normalize  canonical URL, strip HTML, content hash, tokens     oculus/normalize.py
              │
              ▼
   ingest     fan-out, dedup-on-insert, CVE extract (regex)       oculus/ingest.py
              │
              ├── cluster   union-find by shared CVE / title       oculus/cluster.py
              │
              ▼
   enrich     CVE Program record + CISA KEV + FIRST EPSS          oculus/cve.py
              │  (keyless, best-effort, non-fatal)
              ▼
   rank       deterministic weighted score, news-first           oculus/rank.py
              │  ordered clusters
      ┌───────┼───────────┬───────────────┐
      ▼       ▼           ▼               ▼
   dashboard  digest      email          watch
   (charts)   (text)      (SMTP)         (daemon)
   dashboard.py  cli.py   deliver.py     cli.py
```

A single package owns all of it. No service boundary, no message queue, no
external database. `oculus scrape` runs the whole flow once; `oculus watch` runs it
on a timer.

## Modules and responsibilities

| Module | Responsibility |
|---|---|
| `config` | Load + validate config and the source list. Every tunable lives here. |
| `fetch` | Concurrent async HTTP: worker pool, per-host rate limit, conditional GET. |
| `parse` | RSS/Atom parsing into normalized article records. |
| `normalize` | Canonical URL, HTML stripping, content/title hashing, token sets. |
| `cve` | CVE regex extraction + the keyless enrichment clients (CVE Program, KEV, EPSS). |
| `cluster` | Union-find clustering by shared CVE and cross-outlet title similarity. |
| `rank` | The pure, deterministic scoring model. |
| `store` | SQLite: schema, dedup-on-insert, typed queries. |
| `ingest` | The pipeline seam — one `ingest_and_rank()` both `scrape` and `watch` call. |
| `dashboard` | Render ranked clusters as chart-driven HTML (also the email body). |
| `deliver` | SMTP email of the HTML digest. |
| `cli` | The command surface. |

Orchestration lives in `ingest.py`, not in any leaf module. When a step is added
to the pipeline, both `scrape` and `watch` get it because there is only one place
to add it.

## The CVE intelligence stack (keyless)

A CVE ID is just a name. Four sources each answer a different question, and Oculus
combines them without an API key:

- **CVSS** — how severe, in theory (0–10 + band). Resolved from the CVE Program
  record with version precedence v4.0 → v3.1 → v3.0 → v2.0. The score is
  **nullable** — a missing score is a real possibility, and the parser looks in
  *every* container (CNA **and** the ADP/CISA enrichment container), because for
  Log4Shell the real 10.0 lives in the CISA container, not the vendor's.
- **CWE** — what *kind* of weakness (e.g. CWE-502 deserialization).
- **CISA KEV** — is it being exploited *right now*. The most actionable signal.
  `knownRansomwareCampaignUse` is the string `"Known"`/`"Unknown"`, **not a
  boolean** — mapped explicitly.
- **FIRST EPSS** — probability of exploitation in the next 30 days. The `epss` and
  `percentile` fields arrive as JSON **strings** — parsed as floats, or they
  silently read as zero and disable a ranking signal.

## Clustering turns coverage into velocity

Two articles join a cluster when they fall inside a time window (72h default) and
either **share a CVE ID** or, **across different outlets**, have titles similar
enough by token-set Jaccard overlap. The cross-outlet condition on the title match
is deliberate: it stops a publisher's own follow-up posts from merging into one
blob. Cluster size and growth rate become the *velocity* signal in ranking.

## Ranking is deterministic and news-first

```
score =  w_recency  * recency_decay(age)          # exponential half-life
       + w_velocity * normalized(size / age)
       + w_source   * source_weight
       + w_keyword  * watchlist_match
       + w_kev      * is_kev
       + w_cvss     * normalized(max_cvss)
       + w_epss     * max_epss
```

Every weight lives in config. Defaults are news-first: recency + velocity + source
+ keyword carry 70%, the CVE signals (KEV, CVSS, EPSS) carry 30% — because a breach
with no CVE should not be buried beneath a routine patch note. Because the score is
a pure function of stored inputs, the same corpus always sorts the same way (so it
can be tested against a golden order).

## The data model (SQLite)

```
sources(name PK, title, url, weight, tags, enabled)
fetch_state(source_name PK, etag, last_modified, last_fetched, last_status)
articles(id PK, source_name,
         canonical_url UNIQUE,     -- exact dedup
         content_hash  UNIQUE,     -- exact dedup
         title, summary, body, author, published_at, fetched_at)
article_cves(article_id, cve_id)   -- many-to-many
cves(id PK, description, cvss_score, cvss_version, cvss_severity, cwe,
     is_kev, kev_ransomware, epss, epss_percentile, enriched_at, enrich_status)
```

Deduplication is enforced by the database, not application logic: re-ingesting an
item is a caught `IntegrityError`, a normal "already have it", not an error. The
store opens in WAL mode so the dashboard can read while a scrape writes.

## What we added over the original

- **Expanded feed set** (`sources.yaml`): Cisco PSIRT + Cisco Blogs, Network World,
  Packet Pushers, MSRC, Ars Technica, The Verge, TechCrunch — tagged
  `networking` / `bigtech` / `vendor` / `tech` so they can be filtered and charted
  separately from pure security.
- **Chart-driven dashboard** (`dashboard.py`): stat tiles, a CVE-severity
  distribution chart, a coverage-by-domain chart, ranked stories with score meters
  and KEV/CVSS chips, and a dedicated *Networking & Enterprise Tech — Top Vendors*
  section. Charts are inline-styled `<div>` bars (no JS/SVG) so the **same HTML** is
  the endpoint dashboard *and* the email body. Colors follow the validated
  data-viz status palette (CRITICAL/HIGH/MEDIUM/LOW).
- **Email delivery** (`deliver.py`): multipart SMTP with STARTTLS; password from
  `OCULUS_SMTP_PASSWORD`, never the config file.
- **Endpoint daemon** (`oculus watch`): scrape + email on a timer, packageable as a
  `systemd` service, a `cron` job, or a PyInstaller single-file binary.

## Design decisions carried over

- **Politeness is enforced.** Every fetch is rate-limited per host and uses
  conditional GET so an unchanged feed costs one cheap 304.
- **Fail-soft where it should be, loud where it must be.** One broken feed never
  aborts a scrape (verified live — all 15 feeds 403'd behind a proxy and the run
  still completed). Failed enrichment never blocks the news. But a corrupt DB stops
  the program.
- **Credentials handled carefully.** The SMTP password prefers the environment
  over the config file.
