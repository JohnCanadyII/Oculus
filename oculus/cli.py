"""Oculus command-line interface.

    oculus scrape                 fetch, cluster, enrich, rank
    oculus dashboard [-o FILE]    render the HTML dashboard
    oculus digest [--top N]       print a text digest
    oculus email                  send the HTML digest by email
    oculus watch [--interval M]   run scrape+deliver on a timer (endpoint daemon)
    oculus sources                list configured feeds
"""
from __future__ import annotations

import argparse
import sys
import time
import webbrowser
from pathlib import Path

from . import config as config_mod
from . import deliver
from .config import DISPLAY_NAME, db_path, load
from .dashboard import render, render_email
from .ingest import build_ranked, ingest_and_rank
from .store import Store


def _open_store() -> Store:
    return Store.open(db_path())


def cmd_scrape(args, cfg):
    store = _open_store()
    try:
        rep = ingest_and_rank(cfg, store)
    finally:
        store.close()
    print(f"{'source':<18} {'status':>7} {'parsed':>7} {'new':>5}")
    for name, info in rep.per_source.items():
        err = f"  {info['error']}" if info["error"] else ""
        print(f"{name:<18} {info['status']:>7} {info['parsed']:>7} {info['new']:>5}{err}")
    print(f"\n{rep.new_articles} new articles · {rep.clusters} clusters "
          f"({rep.multi_source} multi-source) · enriched {rep.enriched} CVEs ({rep.kev} KEV) "
          f"· {rep.summaries} AI summaries")


def cmd_dashboard(args, cfg):
    store = _open_store()
    try:
        ranked = build_ranked(cfg, store)
    finally:
        store.close()
    out = Path(args.output or (config_mod.config_home() / "dashboard.html"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(ranked, top=args.top))
    print(f"wrote {out}")
    if args.open:
        webbrowser.open(out.as_uri())


def cmd_digest(args, cfg):
    store = _open_store()
    try:
        ranked = build_ranked(cfg, store)
    finally:
        store.close()
    print(f"{DISPLAY_NAME} — top {args.top}\n")
    print(deliver.text_summary(ranked, top=args.top))


def cmd_email(args, cfg):
    store = _open_store()
    try:
        ranked = build_ranked(cfg, store)
    finally:
        store.close()

    # Multi-customer: if recipients are configured, send each a tailored digest.
    if cfg.recipients:
        from dataclasses import replace
        sent = errs = 0
        for r in cfg.recipients:
            items = deliver.filter_for_recipient(ranked, r)
            html = render_email(items, top=r.top)
            subject = f"{r.name}: {len(items)} stories · {sum(1 for c in items if c.any_kev)} KEV"
            rcfg = replace(cfg.email, recipients=r.emails, enabled=True)
            try:
                deliver.send_digest(rcfg, html, subject, deliver.text_summary(items, r.top))
                print(f"sent '{r.name}' digest to {', '.join(r.emails)}")
                sent += 1
            except deliver.EmailError as e:
                print(f"error sending to {r.name}: {e}", file=sys.stderr)
                errs += 1
        return 1 if errs and not sent else 0

    html = render_email(ranked, top=cfg.email.top)
    subject = f"{len(ranked)} stories · {sum(1 for c in ranked if c.any_kev)} KEV"
    try:
        deliver.send_digest(cfg.email, html, subject, deliver.text_summary(ranked, cfg.email.top))
    except deliver.EmailError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"sent digest to {', '.join(cfg.email.recipients)}")


def cmd_watch(args, cfg):
    interval = args.interval * 60
    print(f"{DISPLAY_NAME} watch: every {args.interval}m "
          f"(email={'on' if cfg.email.enabled else 'off'}). Ctrl-C to stop.")
    while True:
        store = _open_store()
        try:
            rep = ingest_and_rank(cfg, store)
            ranked = build_ranked(cfg, store)
        finally:
            store.close()
        print(f"[{time.strftime('%H:%M:%S')}] {rep.new_articles} new · {rep.clusters} clusters")
        if cfg.email.enabled and rep.new_articles > 0:
            html = render_email(ranked, top=cfg.email.top)
            try:
                deliver.send_digest(cfg.email, html,
                                    f"{rep.new_articles} new stories",
                                    deliver.text_summary(ranked, cfg.email.top))
                print("  emailed digest")
            except deliver.EmailError as e:
                print(f"  email error: {e}", file=sys.stderr)
        time.sleep(interval)


def cmd_sources(args, cfg):
    for s in cfg.sources:
        flag = " " if s.enabled else "x"
        print(f"[{flag}] {s.name:<16} {s.weight:>3} {','.join(s.tags):<28} {s.url}")


def build_parser():
    p = argparse.ArgumentParser(prog="oculus", description=f"{DISPLAY_NAME}: keyless security + tech news intelligence")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scrape", help="fetch, cluster, enrich, rank").set_defaults(func=cmd_scrape)

    d = sub.add_parser("dashboard", help="render HTML dashboard")
    d.add_argument("-o", "--output"); d.add_argument("--top", type=int, default=25)
    d.add_argument("--open", action="store_true"); d.set_defaults(func=cmd_dashboard)

    g = sub.add_parser("digest", help="print text digest")
    g.add_argument("--top", type=int, default=15); g.set_defaults(func=cmd_digest)

    sub.add_parser("email", help="send HTML digest by email").set_defaults(func=cmd_email)

    w = sub.add_parser("watch", help="scrape + deliver on a timer")
    w.add_argument("--interval", type=int, default=60, help="minutes"); w.set_defaults(func=cmd_watch)

    sub.add_parser("sources", help="list feeds").set_defaults(func=cmd_sources)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    cfg = load()
    return args.func(args, cfg) or 0


if __name__ == "__main__":
    raise SystemExit(main())
