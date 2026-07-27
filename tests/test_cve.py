"""CVE extraction + keyless enrichment parsing — the two famous traps included."""
from conftest import load_fixture

from oculus.cve import (
    extract_cves, severity_band, _resolve_cvss, _resolve_cwe, parse_kev, parse_epss,
)


def test_extract_dedups_and_uppercases():
    text = "cve-2021-44228 and CVE-2021-44228 plus CVE-2025-5777"
    assert extract_cves(text) == ("CVE-2021-44228", "CVE-2025-5777")


def test_extract_none():
    assert extract_cves("no vulns here") == ()


def test_severity_bands():
    assert severity_band(10.0) == "CRITICAL"
    assert severity_band(9.0) == "CRITICAL"
    assert severity_band(7.0) == "HIGH"
    assert severity_band(4.0) == "MEDIUM"
    assert severity_band(0.1) == "LOW"
    assert severity_band(None) == "NONE"


def test_log4shell_cvss_resolves_from_record():
    # The famous trap: Log4Shell's score lives in an enrichment container.
    record = load_fixture("cvelist", "CVE-2021-44228.json")
    score, version, sev = _resolve_cvss(record)
    assert score == 10.0
    assert sev == "CRITICAL"
    assert version  # a version string was resolved


def test_kev_ransomware_is_string_not_bool():
    kev = parse_kev(load_fixture("kev", "kev-sample.json"))
    assert kev["CVE-2021-44228"] is True   # 'Known' -> True
    # a synthetic 'Unknown' must map to False, not truthy-string
    assert parse_kev({"vulnerabilities": [
        {"cveID": "CVE-2000-0001", "knownRansomwareCampaignUse": "Unknown"}]})["CVE-2000-0001"] is False


def test_epss_strings_parse_as_float():
    epss = parse_epss(load_fixture("epss", "CVE-2021-44228.json"))
    val, pct = epss["CVE-2021-44228"]
    assert isinstance(val, float) and val > 0.99   # NOT zero — the string-typing trap
    assert isinstance(pct, float)
