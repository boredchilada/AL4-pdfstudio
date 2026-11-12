"""Pure unit tests for the module-level helpers (no AL runtime / no samples)."""

import json
import time

import pytest

from pdfstudio_.analysis import (
    aa_events,
    aa_javascript_signature,
    extract_iocs,
    find_hidden_urls,
    has_active_trigger,
    heuristic_for_flag,
    is_ip,
    parse_report,
    read_literal_string,
    sniff_embedded,
    uri_action_targets,
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
    assert heuristic_for_flag(severity, code, active_trigger=True) == expected


@pytest.mark.parametrize("active_trigger,expected", [(True, 1), (False, 4)])
def test_openaction_js_scores_only_with_a_confirmed_trigger_path(active_trigger, expected):
    assert heuristic_for_flag("HIGH", "OPENACTION_JS", active_trigger) == expected


@pytest.mark.parametrize("active_trigger", [True, False])
def test_aa_javascript_does_not_need_a_trigger_path(active_trigger):
    # pdfstudio raises it for inline JavaScript, which the trigger walk never reports as HIGH.
    assert heuristic_for_flag("HIGH", "AA_JAVASCRIPT", active_trigger) == 1


@pytest.mark.parametrize(
    "text",
    ["1.0.0.1", "45.0.0.5", "104.16.0.5", "203.0.113.10", "5.101.0.209", "101.2.3.4", "110.1.2.3",
     "192.0.2.1", "100.64.1.1", "8.8.8.8", "254.1.1.1"],
)
def test_ips_are_extracted_whatever_their_octets(text):
    assert extract_iocs(f"seen {text} here".encode())["ip"] == [text]


@pytest.mark.parametrize(
    "text",
    [f"{10}.1.2.3", f"{10}.0.0.1", "127.0.0.1", "0.1.2.3", "255.1.1.1", "256.1.1.1", "1.2.3", "148.0.0.0",
     "01.2.3.4", "1.2.3.4.5", "1.2.3.4-beta", "1.2.3.4a", "lib-1.2.3.4"],
)
def test_non_indicators_are_not_extracted(text):
    assert extract_iocs(f"seen {text} here".encode())["ip"] == []


@pytest.mark.parametrize(
    "raw,expected",
    [
        (b"server 198.51.100.7", ["198.51.100.7"]),
        (b"dev 198.51.100.8", ["198.51.100.8"]),
        (b"srv 198.51.100.9", ["198.51.100.9"]),
        (b"8.8.8.8.", ["8.8.8.8"]),
        (b"-8.8.8.8", ["8.8.8.8"]),
        (b"(8.8.8.8)", ["8.8.8.8"]),
        (b"Adobe PDF Library 15.0.0.1", []),
        (b"InDesign 17.4.1.3", []),
        (b"Version 1.2.3.4", []),
        (b"Version: 1.2.3.4", []),
        (b"v1.2.3.4", []),
        (b"build 1.2.3.4", []),
    ],
)
def test_version_strings_hide_ips_but_ordinary_words_do_not(raw, expected):
    assert extract_iocs(raw)["ip"] == expected


def test_headless_chrome_version_is_not_an_ip():
    raw = rb"/Producer (Mozilla/5.0 \(X11\) AppleWebKit/537.36 HeadlessChrome/150.0.0.0 Safari/537.36)"
    assert extract_iocs(raw)["ip"] == []


def test_ip_extraction_is_linear_on_hostile_input():
    raw = b"1." * 200_000 + b" " + b"1.2.3." * 50_000 + b"\x00" * 100_000
    start = time.perf_counter()
    extract_iocs(raw)
    assert time.perf_counter() - start < 5


@pytest.mark.parametrize(
    "body,events",
    [
        ("<< /AA << /K << /S /JavaScript /JS (x) >> /F 5 0 R >> >>", {"K", "F"}),
        ("<< /AA<</O 4 0 R>> >>", {"O"}),
        ("<< /AA << /K << /JS (a /E b >> c \\) /Fo) >> >> /Other << /X 1 >> >>", {"K"}),
        ("<< /Type /Page >>", set()),
    ],
)
def test_aa_events(body, events):
    assert aa_events(body) == events


@pytest.mark.parametrize(
    "message,expected",
    [
        ("obj 4 has an /AA dictionary", "aa_javascript_field"),
        ("obj 5 has an /AA dictionary", "aa_javascript"),    # a page
        ("obj 6 has an /AA dictionary", "aa_javascript"),    # a field with a mouse event
        ("obj 7 has an /AA dictionary", "aa_javascript"),    # object not in the parsed file
        ("no object number", "aa_javascript"),
    ],
)
def test_aa_javascript_signature(message, expected):
    bodies = {
        4: ["<< /Subtype /Widget /FT /Tx /AA << /K << /S /JavaScript /JS (x) >> >> >>"],
        5: ["<< /Type /Page /AA << /O << /S /JavaScript /JS (x) >> >> >>"],
        6: ["<< /Subtype /Widget /FT /Tx /AA << /E << /S /JavaScript /JS (x) >> >> >>"],
    }
    assert aa_javascript_signature(message, bodies) == expected


def test_extract_iocs_basic():
    raw = b"junk /URI(http://evil.example.com/a) 8.8.8.8 more"
    iocs = extract_iocs(raw)
    assert "http://evil.example.com/a" in iocs["uri"]
    assert "evil.example.com" in iocs["domain"]
    assert "8.8.8.8" in iocs["ip"]


def test_extract_iocs_safelists_namespaces_and_ignores_version_strings():
    raw = (
        b"xmlns=http://www.w3.org/1999/02/ and http://ns.adobe.com/xap/1.0/ "
        b"and http://ns.useplus.org/ldf/xmp/1.0/ "
        b"Adobe PDF Library 15.0.0.1 InDesign 17.4.1.3 "
        b"http://user:pw@evil.example/a http://203.0.113.3/p"
    )
    iocs = extract_iocs(raw)
    assert iocs["uri"] == ["http://203.0.113.3/p", "http://user:pw@evil.example/a"]
    assert iocs["domain"] == ["evil.example"]
    assert iocs["ip"] == ["203.0.113.3"]


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


@pytest.mark.parametrize(
    "literal,expected",
    [
        (r"(plain)", "plain"),
        (r"(nested (parens) kept)", "nested (parens) kept"),
        (r"(h\164tp://x)", "http://x"),            # octal escape hides "t"
        (r"(a\)b\\c\nd)", "a)b\\c\nd"),
        ("(split \\\nline)", "split line"),         # backslash-newline continues the string
        ("(\xfe\xff\x00h\x00i)", "hi"),            # UTF-16BE text string
        (r"(unterminated", None),
    ],
)
def test_read_literal_string(literal, expected):
    assert read_literal_string(literal, 1) == expected


def test_uri_action_targets_decodes_literal_and_hex_forms():
    body = "<</S/URI/URI(h\\164tp://octal.example/a)>> <</URI <687474703a2f2f6865782e6578616d706c652f62>>>"
    assert uri_action_targets(body) == ["http://octal.example/a", "http://hex.example/b"]


def test_uri_action_targets_pads_odd_hex():
    assert uri_action_targets("/URI <41424>") == ["AB@"]


def test_find_hidden_urls_skips_visible_and_safelisted():
    visible = {"http://visible.example/x"}
    bodies = [("obj 3", "/URI (http://visible.example/x)"),
              ("obj 5 (inside object stream 6)", "/URI (http://hidden.example/a)")]
    streams = [("stream of obj 6", b"/URI (http://hidden.example/a)"),
               ("stream of obj 8", b"xmlns:x='http://ns.adobe.com/xap/1.0/' (https://printed.example/doc) Tj")]
    assert find_hidden_urls(bodies, streams, visible) == [
        ("http://hidden.example/a", "obj 5 (inside object stream 6)"),  # the unpacked object wins over its container
        ("https://printed.example/doc", "stream of obj 8"),
    ]


@pytest.mark.parametrize("host,expected", [("203.0.113.3", True), ("256.1.1.1", False), ("evil.example", False)])
def test_is_ip(host, expected):
    assert is_ip(host) is expected
