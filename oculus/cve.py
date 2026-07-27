"""Keyless CVE intelligence: extraction + enrichment from CVE Program / KEV / EPSS.

No API key required. Four sources each answer a different question:
  CVSS  — how severe is it, in theory (from cvelistV5 record, v4>v3.1>v3.0>v2)
  CWE   — what kind of weakness it is
  KEV   — is it being exploited right now (CISA Known Exploited Vulnerabilities)
  EPSS  — how likely is exploitation in the next 30 days (FIRST)
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_CVSS_PRECEDENCE = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
_SEVERITY_BANDS = [(9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW")]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVELIST_URL = "https://cveawg.mitre.org/api/cve/{cve}"  # keyless CVE Program record


def extract_cves(text: str) -> tuple[str, ...]:
    seen, out = set(), []
    for m in CVE_RE.findall(text or ""):
        u = m.upper()
        if u not in seen:
            seen.add(u)
            out.append(u)
    return tuple(out)


def severity_band(score: float | None) -> str:
    if score is None:
        return "NONE"
    for threshold, name in _SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "NONE"


@dataclass
class CVERecord:
    id: str
    description: str = ""
    cvss_score: float | None = None
    cvss_version: str = ""
    cvss_severity: str = "NONE"
    cwe: str = ""
    is_kev: bool = False
    kev_ransomware: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    enrich_status: str = "pending"


# ── CVSS resolution: look in EVERY container, apply version precedence ──────────
def _resolve_cvss(record: dict) -> tuple[float | None, str, str]:
    """The real score sometimes lives in the ADP/CISA container, not the CNA one
    (this is why Log4Shell reads as 'no score' to naive parsers)."""
    containers = []
    cna = record.get("containers", {}).get("cna")
    if cna:
        containers.append(cna)
    containers.extend(record.get("containers", {}).get("adp", []) or [])

    best = None  # (precedence_index, score, version)
    for c in containers:
        for metric in c.get("metrics", []) or []:
            for idx, key in enumerate(_CVSS_PRECEDENCE):
                cvss = metric.get(key)
                if cvss and cvss.get("baseScore") is not None:
                    cand = (idx, float(cvss["baseScore"]), key)
                    if best is None or cand[0] < best[0]:
                        best = cand
    if best is None:
        return None, "", "NONE"
    _, score, key = best
    return score, key.replace("cvss", "").replace("_", "."), severity_band(score)


def _resolve_cwe(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    for pt in cna.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            if d.get("cweId"):
                return d["cweId"]
    return ""


def _resolve_description(record: dict) -> str:
    cna = record.get("containers", {}).get("cna", {})
    for d in cna.get("descriptions", []) or []:
        if d.get("lang", "en").startswith("en"):
            return d.get("value", "")[:500]
    return ""


class Enricher:
    """Fetches KEV + EPSS in bulk once, then per-CVE cvelistV5 records."""

    def __init__(self, user_agent: str, timeout: float = 20.0):
        self._client = httpx.Client(
            timeout=timeout, follow_redirects=True,
            headers={"User-Agent": user_agent},
        )
        self._kev: dict[str, bool] | None = None  # cve -> ransomware flag

    def close(self):
        self._client.close()

    def _load_kev(self) -> dict[str, bool]:
        if self._kev is not None:
            return self._kev
        self._kev = {}
        try:
            data = self._client.get(KEV_URL).json()
            for v in data.get("vulnerabilities", []):
                # `knownRansomwareCampaignUse` is the string "Known"/"Unknown", not a bool.
                ransom = v.get("knownRansomwareCampaignUse", "Unknown") == "Known"
                self._kev[v["cveID"].upper()] = ransom
        except (httpx.HTTPError, ValueError, KeyError):
            pass
        return self._kev

    def _epss(self, cves: list[str]) -> dict[str, tuple[float, float]]:
        out: dict[str, tuple[float, float]] = {}
        if not cves:
            return out
        # EPSS API takes up to ~100 CVEs per call, comma-separated.
        for i in range(0, len(cves), 100):
            chunk = cves[i:i + 100]
            try:
                r = self._client.get(EPSS_URL, params={"cve": ",".join(chunk)})
                for row in r.json().get("data", []):
                    # epss/percentile arrive as STRINGS — parse as float or they read 0.
                    out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
            except (httpx.HTTPError, ValueError, KeyError):
                continue
        return out

    def _cvelist(self, cve: str) -> tuple[float | None, str, str, str, str]:
        try:
            record = self._client.get(CVELIST_URL.format(cve=cve)).json()
        except (httpx.HTTPError, ValueError):
            return None, "", "NONE", "", ""
        score, ver, sev = _resolve_cvss(record)
        return score, ver, sev, _resolve_cwe(record), _resolve_description(record)

    def enrich(self, cve_ids: list[str]) -> dict[str, CVERecord]:
        cves = sorted({c.upper() for c in cve_ids})
        kev = self._load_kev()
        epss = self._epss(cves)
        out: dict[str, CVERecord] = {}
        for cve in cves:
            score, ver, sev, cwe, desc = self._cvelist(cve)
            e = epss.get(cve)
            out[cve] = CVERecord(
                id=cve, description=desc, cvss_score=score, cvss_version=ver,
                cvss_severity=sev, cwe=cwe,
                is_kev=cve in kev, kev_ransomware=kev.get(cve, False),
                epss=e[0] if e else None, epss_percentile=e[1] if e else None,
                enrich_status="ok",
            )
        return out
