"""Pure unit tests for the module-level helpers (no AL runtime / no samples)."""

import json

import pytest

from pdfstudio_.analysis import (
    extract_iocs,
    has_active_trigger,
    heuristic_for_flag,
    parse_report,
    sniff_embedded,
)


@pytest.mark.parametrize(
    "severity,code,expected",
    [
        ("HIGH", "EMBEDDED_PE", 1),
        ("MED", "OBJSTM_PRESENT", 2),
        ("LOW", "XREF_STREAM", 3),
        ("INFO", "HEADER", 4),
        ("high", "anything", 1),          # case-insensitive
        ("???", "unknown", 4),            # unknown tier -> informational
        ("LOW", "MULTI_REV_WEAPONIZATION", 6),  # special-cased code wins over tier
    ],
)
def test_heuristic_for_flag(severity, code, expected):
    assert heuristic_for_flag(severity, code) == expected


def test_extract_iocs_basic():
    raw = b"junk /URI(http://evil.example.com/a) 8.8.8.8 more"
    iocs = extract_iocs(raw)
    assert "http://evil.example.com/a" in iocs["uri"]
    assert "evil.example.com" in iocs["domain"]
    assert "8.8.8.8" in iocs["ip"]


def test_extract_iocs_safelists_namespaces():
    raw = b"xmlns=http://www.w3.org/1999/02/ and http://ns.adobe.com/xap/1.0/"
    iocs = extract_iocs(raw)
    assert iocs["uri"] == []
    assert iocs["domain"] == []


@pytest.mark.parametrize(
    "data,expected_ext",
    [
        (b"MZ" + b"\x00" * 64, "exe"),
        (b"PK\x03\x04" + b"\x00" * 64, "zip"),
        (b"\x7fELF" + b"\x00" * 64, "elf"),
        (b"%PDF-1.7" + b"\x00" * 64, "pdf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64, "ole"),
    ],
)
def test_sniff_embedded_hits(data, expected_ext):
    result = sniff_embedded(data)
    assert result is not None and result[0] == expected_ext


def test_sniff_embedded_ignores_text_and_short():
    assert sniff_embedded(b"BT /F1 12 Tf (hello) Tj ET") is None  # content stream
    assert sniff_embedded(b"MZ") is None  # too short to be a real payload


def test_parse_report_tolerates_surrounding_noise():
    report = {"header": "%PDF-1.4", "flags": []}
    assert parse_report(json.dumps(report)) == report
    assert parse_report("warning: something\n" + json.dumps(report) + "\ntrailing") == report


def test_parse_report_rejects_output_without_json():
    with pytest.raises(json.JSONDecodeError):
        parse_report("Traceback (most recent call last): boom")


@pytest.mark.parametrize(
    "triggers,expected",
    [
        ([], False),
        # Benign: hyperlinks, form widgets, open at page N.
        ([{"trigger": "/Annot", "severity": "LOW"}, {"trigger": "/OpenAction", "severity": "MED"}], False),
        # A click-through URI link is MED; the .exe target is scored by heuristic 1 instead.
        ([{"trigger": "/Annot /A", "severity": "MED"}], False),
        ([{"trigger": "/Annot", "severity": "LOW"}, {"trigger": "/OpenAction", "severity": "HIGH"}], True),
        ([{"trigger": "/AA", "severity": "high"}], True),
        ([{"trigger": "/OpenAction"}], False),
    ],
)
def test_has_active_trigger(triggers, expected):
    assert has_active_trigger(triggers) is expected
