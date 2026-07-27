"""Offline demo: parse the bundled fixture feeds + a networking/big-tech set,
seed realistic CVE enrichment, and render the dashboard — no network needed.

Run:  python demo_seed.py  ->  writes demo_dashboard.html
This is a DEV/demo tool, not part of the shipped package.
"""
import time
from pathlib import Path

from oculus import config as config_mod
from oculus.parse import parse
from oculus.cve import CVERecord
from oculus.ingest import build_ranked
from oculus.dashboard import render
from oculus.store import Store

FIX = Path(__file__).parent / "_fixtures" / "feeds"
NOW = int(time.time())

# Map fixture filename -> our source name (so tags/weights apply).
FEEDS = {
    "krebs.xml": "krebs", "thehackernews.xml": "thehackernews",
    "bleepingcomputer.xml": "bleepingcomputer", "securityweek.xml": "securityweek",
    "darkreading.xml": "darkreading", "theregister.xml": "theregister", "cisa.xml": "cisa",
}

# A small networking / enterprise-tech set (what the user asked to add), as raw
# Atom so it flows through the exact same parse path.
NET_ATOM = """<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<title>demo</title>
{entries}</feed>"""
NET_ENTRY = """<entry><title>{title}</title><link href="{url}"/>
<updated>{ts}</updated><summary>{summary}</summary></entry>"""

NET_ITEMS = [
    ("cisco_psirt", "Cisco IOS XE Web UI Privilege Escalation CVE-2025-20337 Actively Exploited",
     "https://sec.cloudapps.cisco.com/a1", "A privilege escalation flaw in the IOS XE web UI (CVE-2025-20337) is under active exploitation."),
    ("cisco_blogs", "Cisco unveils AI-native networking fabric for enterprise data centers",
     "https://blogs.cisco.com/a2", "Cisco announced an AI-driven fabric spanning Nexus and Silicon One."),
    ("networkworld", "Cisco IOS XE bug CVE-2025-20337 lets attackers hijack enterprise routers",
     "https://networkworld.com/a3", "Enterprises running IOS XE should patch CVE-2025-20337 immediately."),
    ("msrc", "Microsoft patches SharePoint RCE CVE-2025-53770 added to CISA KEV",
     "https://msrc.microsoft.com/a4", "CVE-2025-53770, a SharePoint remote code execution flaw, is now on the KEV catalog."),
    ("arstechnica", "SharePoint zero-day CVE-2025-53770 hit dozens of servers before patch",
     "https://arstechnica.com/a5", "Attackers exploited CVE-2025-53770 in the wild for weeks."),
    ("techcrunch", "Nvidia unveils next-gen data-center GPUs as enterprise AI demand surges",
     "https://techcrunch.com/a6", "Nvidia's new accelerators target enterprise networking and AI workloads."),
    ("theverge", "Google Cloud rolls out new zero-trust networking for enterprise customers",
     "https://theverge.com/a7", "Google Cloud's networking update emphasizes zero-trust segmentation."),
    ("packetpushers", "Juniper and Cisco race to ship 800G Ethernet for AI back-end networks",
     "https://packetpushers.net/a8", "800G Ethernet is becoming table stakes for AI cluster networking."),
    ("arstechnica", "AWS outage briefly disrupts enterprise networking across US-East-1",
     "https://arstechnica.com/a9", "An AWS networking fault rippled across enterprise customers."),
    ("networkworld", "Palo Alto Networks warns of firewall flaw CVE-2025-0133 in PAN-OS",
     "https://networkworld.com/a10", "CVE-2025-0133 affects PAN-OS GlobalProtect deployments."),
]

# Realistic enrichment for the CVEs that appear above + famous ones in fixtures.
CVE_FIXTURES = {
    "CVE-2025-20337": CVERecord("CVE-2025-20337", "Cisco IOS XE web UI privilege escalation.",
                                10.0, "V4.0", "CRITICAL", "CWE-269", True, False, 0.72, 0.97, "ok"),
    "CVE-2025-53770": CVERecord("CVE-2025-53770", "Microsoft SharePoint remote code execution.",
                                9.8, "V3.1", "CRITICAL", "CWE-502", True, True, 0.94, 0.99, "ok"),
    "CVE-2025-0133": CVERecord("CVE-2025-0133", "Palo Alto PAN-OS GlobalProtect flaw.",
                               6.9, "V4.0", "MEDIUM", "CWE-79", False, False, 0.08, 0.63, "ok"),
    "CVE-2021-44228": CVERecord("CVE-2021-44228", "Apache Log4j2 JNDI RCE (Log4Shell).",
                                10.0, "V3.1", "CRITICAL", "CWE-502", True, True, 0.975, 0.99, "ok"),
    "CVE-2025-5777": CVERecord("CVE-2025-5777", "Citrix NetScaler out-of-bounds read (Citrix Bleed 2).",
                               9.3, "V4.0", "CRITICAL", "CWE-125", True, False, 0.61, 0.95, "ok"),
}


def main():
    cfg = config_mod.load()
    # The captured fixtures are 22–39 days old; widen the window so the demo stays
    # full. Real installs use the default 14-day rolling window (config.retention_days).
    from dataclasses import replace
    cfg = replace(cfg, retention_days=60)
    db = config_mod.config_home() / "demo.db"
    if db.exists():
        db.unlink()
    store = Store.open(db)
    store.upsert_sources(cfg.sources)

    n = 0
    for fname, sname in FEEDS.items():
        raw = (FIX / fname).read_bytes()
        for art in parse(sname, raw):
            if store.insert_article(art, NOW) is not None:
                n += 1
    store.commit()

    entries = "".join(
        NET_ENTRY.format(title=t, url=u, summary=s,
                         ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - i * 5400)))
        for i, (src, t, u, s) in enumerate(NET_ITEMS)
    )
    # Parse each networking item under its own source name.
    for i, (src, t, u, s) in enumerate(NET_ITEMS):
        one = NET_ATOM.format(entries=NET_ENTRY.format(
            title=t, url=u, summary=s,
            ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW - i * 5400))))
        for art in parse(src, one.encode()):
            if store.insert_article(art, NOW) is not None:
                n += 1
    store.commit()

    for rec in CVE_FIXTURES.values():
        store.upsert_cve(rec, NOW)

    ranked = build_ranked(cfg, store)
    store.close()
    out = Path(__file__).parent / "demo_dashboard.html"
    out.write_text(render(ranked, top=25))
    kev = sum(1 for c in ranked if c.any_kev)
    print(f"seeded {n} articles -> {len(ranked)} clusters ({kev} KEV) -> {out}")


if __name__ == "__main__":
    main()
