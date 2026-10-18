"""clr_cve: shared CVE prioritisation for clr security tools.

ELI5: a raw CVE id ("CVE-2024-1234") does not tell you how worried to be. This turns an id
into a priority by asking four questions: is it on CISA's Known Exploited list (attackers are
using it right now), is there a public exploit for it, how severe is it (CVSS), and how likely
is exploitation soon (EPSS). From those it sets one severity both clrAssure and Samaritan can
sort and grade on, so the two tools never drift apart on how they rank a vulnerability.

Design notes:
- One small module, one dependency (httpx), no framework assumptions, so it drops into any app.
- All feeds are free and keyless. Every network call degrades to empty on failure and never
  raises, so a feed being down cannot break a scan.
- Feeds are cached in-process for a day, so a scan does not re-download them.
- Set the outbound User-Agent once with configure(user_agent=...). The default is fine.

Public API: configure, resolve_cve_ids, kev_ids, epss_scores, has_public_exploit,
severity_for, enrich.
"""
import csv
import io
import json
import re
import time

import httpx

__version__ = "0.2.0"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
# Public exploit sources, both free and keyless: Exploit-DB's index (CVE ids sit in the "codes"
# column) and ProjectDiscovery's Nuclei CVE template list (one JSON object per line).
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
NUCLEI_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
# pocindex aggregates public PoCs from GitHub, Nuclei, Metasploit, Exploit-DB and Vulhub into
# one keyless JSON. It is a supplementary breadth source (Metasploit and Vulhub are not covered
# by the two feeds above); the authoritative KEV and EPSS signals stay on their official sources.
# Confirm this exact endpoint path once it runs where the host can reach pocindex.io.
POCINDEX_URL = "https://pocindex.io/CVE_list.json"
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Outbound User-Agent. Each app can set its own with configure(); this is a sensible default.
_USER_AGENT = f"clr-cve/{__version__} (+https://github.com/Gardendwarf/clr-cve)"

# Feeds are large and change slowly; cache in-process for a day so a scan does not re-download.
_KEV = {"at": 0.0, "ids": set()}
_KEV_TTL = 86400
_EXPLOIT = {"edb": {"at": 0.0, "ids": set()}, "nuclei": {"at": 0.0, "ids": set()},
            "pocindex": {"at": 0.0, "ids": set()}}


def configure(user_agent: str | None = None) -> None:
    """Set library-wide options. Call once at startup if you want your own User-Agent."""
    global _USER_AGENT
    if user_agent:
        _USER_AGENT = user_agent


def _headers() -> dict:
    return {"User-Agent": _USER_AGENT}


def resolve_cve_ids(ids) -> list[str]:
    """Keep only the CVE ids from a mixed list of advisory ids (CVE, GHSA, OSV, etc.).

    Samaritan keys vulnerabilities on OSV/GHSA ids whose aliases include the CVE; pass that
    alias list here to get the CVE ids this library can score. De-duplicated, upper-cased,
    original order kept.
    """
    out: list[str] = []
    for i in ids or []:
        if isinstance(i, str) and _CVE_RE.fullmatch(i.strip()):
            c = i.strip().upper()
            if c not in out:
                out.append(c)
    return out


def kev_ids() -> set[str]:
    """CISA Known Exploited Vulnerabilities catalogue, cached for a day. Empty on failure."""
    if _KEV["ids"] and (time.time() - _KEV["at"]) < _KEV_TTL:
        return _KEV["ids"]
    try:
        r = httpx.get(KEV_URL, timeout=20, headers=_headers())
        if r.status_code == 200:
            _KEV["ids"] = {v["cveID"] for v in r.json().get("vulnerabilities", []) if v.get("cveID")}
            _KEV["at"] = time.time()
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    return _KEV["ids"]


def _parse_exploitdb(text: str) -> set[str]:
    """CVE ids from the Exploit-DB index CSV (the "codes" column holds e.g. CVE-2009-3699;OSVDB-1)."""
    out: set[str] = set()
    for row in csv.DictReader(io.StringIO(text)):
        out.update(m.upper() for m in _CVE_RE.findall(row.get("codes") or ""))
    return out


def _parse_nuclei(text: str) -> set[str]:
    """CVE ids from the Nuclei cves.json list (JSON lines, each with an "ID" field)."""
    out: set[str] = set()
    for line in text.splitlines():
        try:
            cid = str(json.loads(line).get("ID", "")).upper()
        except (ValueError, AttributeError):
            continue
        if _CVE_RE.fullmatch(cid):
            out.add(cid)
    return out


def _parse_pocindex(text: str) -> set[str]:
    """CVE ids that have a public PoC per pocindex. Tolerant of either layout: a JSON object
    keyed by CVE id, or a list of records carrying a cve/id field. Empty on anything unexpected."""
    out: set[str] = set()
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if isinstance(data, dict):
        for k in data:
            if isinstance(k, str) and _CVE_RE.fullmatch(k.strip()):
                out.add(k.strip().upper())
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, str) and _CVE_RE.fullmatch(item.strip()):
                out.add(item.strip().upper())
            elif isinstance(item, dict):
                for key in ("cve", "id", "CVE", "cve_id", "cveID"):
                    v = item.get(key)
                    if isinstance(v, str) and _CVE_RE.fullmatch(v.strip()):
                        out.add(v.strip().upper())
                        break
    return out


def _exploit_source(key: str, url: str, parse) -> set[str]:
    """One exploit list, cached for a day. Empty (never raises) when the download fails."""
    cache = _EXPLOIT[key]
    if cache["ids"] and (time.time() - cache["at"]) < _KEV_TTL:
        return cache["ids"]
    try:
        r = httpx.get(url, timeout=30, follow_redirects=True, headers=_headers())
        if r.status_code == 200:
            ids = parse(r.text)
            if ids:
                cache["ids"] = ids
                cache["at"] = time.time()
    except (httpx.HTTPError, ValueError, csv.Error):
        pass
    return cache["ids"]


def has_public_exploit(cve_ids: list[str]) -> set[str]:
    """Subset of cve_ids with a published exploit (Exploit-DB or a Nuclei template). Empty on failure.

    Each source degrades on its own, so one being unreachable still leaves the other working.
    """
    wanted = {c.upper() for c in cve_ids if c}
    if not wanted:
        return set()
    known = _exploit_source("edb", EXPLOITDB_URL, _parse_exploitdb) | \
        _exploit_source("nuclei", NUCLEI_URL, _parse_nuclei) | \
        _exploit_source("pocindex", POCINDEX_URL, _parse_pocindex)
    return {c for c in cve_ids if c and c.upper() in known}


def epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """EPSS probability (0..1) per CVE from first.org, batched. Missing ids simply absent."""
    out: dict[str, float] = {}
    ids = list(dict.fromkeys(c for c in cve_ids if c))
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        try:
            r = httpx.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=15, headers=_headers())
            if r.status_code == 200:
                for row in r.json().get("data", []):
                    try:
                        out[row["cve"]] = float(row.get("epss", 0.0))
                    except (ValueError, TypeError):
                        pass
        except (httpx.HTTPError, ValueError):
            pass
    return out


def severity_for(kev: bool, epss: float = 0.0, cvss: float | None = None, exploit: bool = False) -> str:
    """Priority for one CVE. KEV (actively exploited) always wins; a public exploit is next
    (at least high, critical when CVSS is also high); then CVSS and EPSS."""
    if kev:
        return "critical"
    if exploit and cvss is not None and cvss >= 7.0:
        return "critical"
    if cvss is not None and cvss >= 9.0:
        return "critical"
    if exploit:
        return "high"
    if (cvss is not None and cvss >= 7.0) or epss >= 0.30:
        return "high"
    if (cvss is not None and cvss >= 4.0) or epss >= 0.05:
        return "medium"
    return "low"


def enrich(cve_ids: list[str], cvss: dict[str, float] | None = None) -> dict[str, dict]:
    """{cve: {kev, epss, exploit, severity}} for CVE ids. One KEV fetch, one EPSS batch, one exploit lookup."""
    cvss = cvss or {}
    kev = kev_ids()
    epss = epss_scores(cve_ids)
    exploits = has_public_exploit(cve_ids)
    out = {}
    for c in dict.fromkeys(c for c in cve_ids if c):
        is_kev = c in kev
        score = epss.get(c, 0.0)
        has_exploit = c in exploits
        out[c] = {"kev": is_kev, "epss": score, "exploit": has_exploit,
                  "severity": severity_for(is_kev, score, cvss.get(c), has_exploit)}
    return out
