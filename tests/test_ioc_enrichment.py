"""Tests for IOC auto-extraction filtering and VirusTotal summarization.

These avoid the network: iocs_for_enrichment is pure, vt_summarize takes a raw
blob, and auto_enrich_iocs is checked only for its no-key no-op path.
"""
import os

os.environ.setdefault("JWT_SECRET", "x" * 40)

from app.connectors.virustotal import vt_summarize


def _main():
    import app.main as m
    return m


def test_private_and_reserved_ips_dropped():
    m = _main()
    assert m.iocs_for_enrichment("10.0.0.5 192.168.1.1 172.16.0.9 127.0.0.1 169.254.1.1") == []


def test_public_ip_kept():
    m = _main()
    assert m.iocs_for_enrichment("beacon to 185.220.101.34") == ["185.220.101.34"]


def test_file_extension_lookalikes_dropped():
    m = _main()
    assert m.iocs_for_enrichment("opened report.pdf ran payload.exe edited config.yaml") == []


def test_real_domain_kept():
    m = _main()
    assert m.iocs_for_enrichment("callback to evil-c2.xyz") == ["evil-c2.xyz"]


def test_only_valid_hash_lengths_kept():
    m = _main()
    assert m.iocs_for_enrichment("junk " + "a" * 50) == []          # 50 != 32/40/64
    assert m.iocs_for_enrichment("md5 " + "b" * 32) == ["b" * 32]
    assert m.iocs_for_enrichment("sha1 " + "c" * 40) == ["c" * 40]
    assert m.iocs_for_enrichment("sha256 " + "d" * 64) == ["d" * 64]


def test_limit_is_respected():
    m = _main()
    text = "1.1.1.1 2.2.2.2 3.3.3.3 8.8.8.8 9.9.9.9 4.4.4.4"
    assert len(m.iocs_for_enrichment(text, limit=4)) == 4
    assert len(m.iocs_for_enrichment(text, limit=2)) == 2


def test_dedup_case_insensitive():
    m = _main()
    out = m.iocs_for_enrichment("Evil.COM and evil.com")
    assert out == ["evil.com"] or out == ["Evil.COM"]
    assert len(out) == 1


def test_auto_enrich_no_key_is_noop(monkeypatch):
    m = _main()
    monkeypatch.setattr("app.connectors.virustotal._get_vt_key", lambda: "")
    assert m.auto_enrich_iocs("investigate 185.220.101.34") == []


def test_auto_enrich_never_raises(monkeypatch):
    m = _main()
    monkeypatch.setattr("app.connectors.virustotal._get_vt_key", lambda: "fake-key")

    def boom(ioc):
        raise RuntimeError("network down")

    monkeypatch.setattr("app.connectors.virustotal.vt_enrich_compact", boom)
    # Exception inside the loop is swallowed — returns [] rather than bubbling.
    assert m.auto_enrich_iocs("investigate 185.220.101.34") == []


def test_vt_summarize_malicious():
    raw = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 60, "undetected": 5},
        "country": "RU", "as_owner": "EvilHost", "reputation": -40,
    }}}
    s = vt_summarize("1.2.3.4", raw)
    assert s["verdict"] == "malicious"
    assert s["malicious_votes"] == 8
    assert s["total_engines"] == 74
    assert s["country"] == "RU"


def test_vt_summarize_clean():
    raw = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 4},
    }}}
    s = vt_summarize("8.8.8.8", raw)
    assert s["verdict"] == "clean"


def test_vt_summarize_suspicious_boundary():
    raw = {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 70},
    }}}
    assert vt_summarize("x", raw)["verdict"] == "suspicious"


def test_vt_summarize_error_passthrough():
    s = vt_summarize("1.2.3.4", {"error": "no_vt_key"})
    assert s["error"] == "no_vt_key"
    assert s["ioc"] == "1.2.3.4"
