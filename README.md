# clr-cve

Shared CVE prioritisation for clr security tools. One severity, derived the same way everywhere, so clrAssure and Samaritan never disagree on how a vulnerability ranks.

## What it does

Turns a raw CVE id into a priority by combining four signals:

1. CISA KEV (Known Exploited Vulnerabilities) - attackers are using it right now. Always critical.
2. A public exploit exists. At least high, critical when CVSS is also high. Checked across Exploit-DB, Nuclei, and pocindex (which adds Metasploit and Vulhub breadth). KEV and EPSS stay on their official sources; pocindex only widens the exploit signal, so no single aggregator can swing the severity.
3. CVSS base score, when you have one.
4. EPSS - the probability it will be exploited in the near term.

All feeds are free and keyless, cached in-process for a day, and degrade to empty on failure. No network call ever raises, so a feed being down cannot break a scan. The only dependency is httpx.

## Install

```
pip install "clr-cve @ git+https://github.com/Gardendwarf/clr-cve"
```

## Use

```python
import clr_cve

# Optional: set your own outbound User-Agent once.
clr_cve.configure(user_agent="clrAssure/1.0")

# Enrich a list of CVE ids. Pass CVSS scores where you have them.
info = clr_cve.enrich(["CVE-2024-1234", "CVE-2021-44228"], cvss={"CVE-2024-1234": 7.5})
# -> {"CVE-2024-1234": {"kev": False, "epss": 0.12, "exploit": True, "severity": "critical"}, ...}

# Working from OSV or GHSA ids (e.g. Samaritan)? Pull the CVE aliases first.
cve_ids = clr_cve.resolve_cve_ids(osv_record["aliases"])
info = clr_cve.enrich(cve_ids)
```

## Severity rules

KEV wins over everything. Then a public exploit with high CVSS is critical; a public exploit alone is high. Then CVSS 9+ critical, 7+ high, 4+ medium. EPSS raises a no-CVSS item to high at 0.30 and medium at 0.05. Everything else is low.
