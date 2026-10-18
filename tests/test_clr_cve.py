"""clr_cve severity weighting, exploit signal, alias resolution."""
import clr_cve as cve


def test_kev_always_critical():
    assert cve.severity_for(kev=True) == "critical"
    assert cve.severity_for(kev=True, epss=0.0, cvss=2.0) == "critical"  # KEV beats a low CVSS


def test_cvss_bands():
    assert cve.severity_for(False, 0.0, 9.5) == "critical"
    assert cve.severity_for(False, 0.0, 7.2) == "high"
    assert cve.severity_for(False, 0.0, 5.0) == "medium"
    assert cve.severity_for(False, 0.0, 2.0) == "low"


def test_epss_drives_severity_without_cvss():
    assert cve.severity_for(False, 0.40) == "high"
    assert cve.severity_for(False, 0.10) == "medium"
    assert cve.severity_for(False, 0.01) == "low"


def test_exploit_raises_severity():
    assert cve.severity_for(False, 0.0, None, exploit=True) == "high"
    assert cve.severity_for(False, 0.0, 2.0, exploit=True) == "high"
    assert cve.severity_for(False, 0.0, 7.5, exploit=True) == "critical"
    assert cve.severity_for(False, 0.0, 7.5, exploit=False) == "high"
    assert cve.severity_for(True, exploit=True) == "critical"


def test_resolve_cve_ids_filters_and_dedupes():
    got = cve.resolve_cve_ids(["GHSA-xxxx-yyyy-zzzz", "CVE-2024-0001", "cve-2024-0001", "OSV-2024-1", "", None])
    assert got == ["CVE-2024-0001"]


def test_configure_sets_user_agent():
    cve.configure(user_agent="samaritan/2.0")
    assert "samaritan/2.0" in cve._headers()["User-Agent"]
    cve.configure(user_agent=None)  # no-op, keeps current
    assert "samaritan/2.0" in cve._headers()["User-Agent"]


def test_enrich_uses_stubbed_feeds(monkeypatch):
    monkeypatch.setattr(cve, "kev_ids", lambda: {"CVE-2024-0001"})
    monkeypatch.setattr(cve, "epss_scores", lambda ids: {"CVE-2024-0002": 0.5})
    monkeypatch.setattr(cve, "has_public_exploit", lambda ids: set())
    out = cve.enrich(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"])
    assert out["CVE-2024-0001"]["severity"] == "critical"  # KEV
    assert out["CVE-2024-0002"]["severity"] == "high"      # EPSS 0.5
    assert out["CVE-2024-0003"]["severity"] == "low"       # unknown


def test_enrich_includes_exploit_flag(monkeypatch):
    monkeypatch.setattr(cve, "kev_ids", lambda: set())
    monkeypatch.setattr(cve, "epss_scores", lambda ids: {})
    monkeypatch.setattr(cve, "has_public_exploit", lambda ids: {"CVE-2024-0002"})
    out = cve.enrich(["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"], {"CVE-2024-0003": 8.0})
    assert out["CVE-2024-0001"]["exploit"] is False
    assert out["CVE-2024-0002"]["exploit"] is True
    assert out["CVE-2024-0002"]["severity"] == "high"
    assert out["CVE-2024-0003"]["severity"] == "high"  # CVSS 8.0 alone, no exploit


def test_parse_pocindex_dict_and_list():
    d = '{"CVE-2024-0001": {"poc": ["x"]}, "not-a-cve": {}, "CVE-2024-0002": {}}'
    assert cve._parse_pocindex(d) == {"CVE-2024-0001", "CVE-2024-0002"}
    lst = '[{"cve": "CVE-2023-1111", "msf": true}, {"id": "CVE-2023-2222"}, "CVE-2023-3333", {"nope": 1}]'
    assert cve._parse_pocindex(lst) == {"CVE-2023-1111", "CVE-2023-2222", "CVE-2023-3333"}
    assert cve._parse_pocindex("not json") == set()


def test_has_public_exploit_parses_and_degrades(monkeypatch):
    edb = "id,file,codes\n1,a,CVE-2009-3699;OSVDB-1\n2,b,\n"
    nuc = '{"ID":"CVE-2021-0001"}\nnot json\n'

    class R:
        status_code = 200

        def __init__(self, text):
            self.text = text

    def fake_get(url, **kw):
        return R(edb if url == cve.EXPLOITDB_URL else nuc)

    for k in cve._EXPLOIT.values():
        k.update(at=0.0, ids=set())
    monkeypatch.setattr(cve.httpx, "get", fake_get)
    got = cve.has_public_exploit(["CVE-2009-3699", "CVE-2021-0001", "CVE-2020-9999"])
    assert got == {"CVE-2009-3699", "CVE-2021-0001"}

    def boom(url, **kw):
        raise cve.httpx.ConnectError("down")

    for k in cve._EXPLOIT.values():
        k.update(at=0.0, ids=set())
    monkeypatch.setattr(cve.httpx, "get", boom)
    assert cve.has_public_exploit(["CVE-2009-3699"]) == set()  # never raises
    for k in cve._EXPLOIT.values():
        k.update(at=0.0, ids=set())
