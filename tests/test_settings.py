"""Service settings: bad values, defaults parity with the manifest, cache fingerprint and each knob's effect."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
os.environ["SERVICE_MANIFEST_PATH"] = str(ROOT / "service_manifest.yml")

from assemblyline_v4_service.common.result import Result  # noqa: E402
from pdfstudio.parser import parse  # noqa: E402

from pdfstudio_ import defaults  # noqa: E402
from pdfstudio_.analysis import extract_iocs, find_hidden_urls, normalize_domains  # noqa: E402
from pdfstudio_.service import PdfStudio  # noqa: E402
from pdfstudio_.settings import (  # noqa: E402
    config_bool,
    config_fingerprint,
    config_float,
    config_int,
    config_list,
    config_str,
    param_bool,
    param_choice,
    param_int,
)
from tests.synthetic import build_pdf  # noqa: E402

MANIFEST = yaml.safe_load((ROOT / "service_manifest.yml").read_text())
CONFIG_DEFAULTS = {
    "internal_timeout": defaults.INTERNAL_TIMEOUT,
    "max_iocs": defaults.MAX_IOCS,
    "max_extracted_payloads": defaults.MAX_EXTRACTED_PAYLOADS,
    "safelist_domains": defaults.SAFELIST_DOMAINS,
}
PARAM_DEFAULTS = {
    "show_object_table": defaults.SHOW_OBJECT_TABLE,
    "extract_payloads": defaults.EXTRACT_PAYLOADS,
}


class Log:
    def __init__(self):
        self.warnings: list[str] = []

    def warning(self, message, *args):
        self.warnings.append(message % args)


def table_rows(section) -> list[dict]:
    assert section.body is not None
    return json.loads(section.body)


def make_service(config=None) -> PdfStudio:
    service = PdfStudio(config=config)
    service.start()
    return service


# --- manifest parity -------------------------------------------------------------------


def test_manifest_config_matches_code_defaults():
    assert MANIFEST["config"] == CONFIG_DEFAULTS


def test_manifest_submission_params_match_code_defaults():
    params = {p["name"]: p for p in MANIFEST["submission_params"]}
    assert set(params) == set(PARAM_DEFAULTS)
    for name, default in PARAM_DEFAULTS.items():
        assert params[name]["type"] == "bool"
        assert params[name]["default"] == default
        assert params[name]["value"] == default


def test_default_internal_timeout_leaves_headroom_below_manifest_timeout():
    assert defaults.INTERNAL_TIMEOUT <= MANIFEST["timeout"] - defaults.TIMEOUT_HEADROOM


def test_default_config_starts_with_default_values():
    service = make_service()
    assert service.internal_timeout == defaults.INTERNAL_TIMEOUT
    assert service.max_iocs == defaults.MAX_IOCS
    assert service.max_extracted_payloads == defaults.MAX_EXTRACTED_PAYLOADS
    assert service.safelist_domains == frozenset()


# --- helpers ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [("abc", 50), (None, 50), (True, 50), ([], 50), (7.5, 50), (float("nan"), 50), (float("inf"), 50),
     (-5, 1), (10**9, 100)],
)
def test_config_int_falls_back_or_clamps_and_warns_once(value, expected):
    log = Log()
    assert config_int({"n": value}, "n", 50, 1, 100, log) == expected
    assert len(log.warnings) == 1
    assert "n" in log.warnings[0]


@pytest.mark.parametrize("value", ["7", 7, 7.0, " 7 "])
def test_config_int_accepts_integral_values(value):
    log = Log()
    assert config_int({"n": value}, "n", 50, 1, 100, log) == 7
    assert log.warnings == []


def test_config_helpers_use_the_default_silently_when_the_key_is_missing():
    log = Log()
    assert config_int({}, "n", 5, 1, 9, log) == 5
    assert config_int(None, "n", 5, 1, 9, log) == 5
    assert config_float({}, "f", 1.5, 0, 9, log) == 1.5
    assert config_bool({}, "b", True, log) is True
    assert config_str({}, "s", "x", log) == "x"
    assert config_list({}, "l", ["a"], log) == ["a"]
    assert log.warnings == []


def test_config_float_bool_and_str_reject_wrong_types():
    log = Log()
    assert config_float({"f": "x"}, "f", 1.5, 0, 9, log) == 1.5
    assert config_float({"f": 99}, "f", 1.5, 0, 9, log) == 9
    assert config_bool({"b": "maybe"}, "b", True, log) is True
    assert config_str({"s": 5}, "s", "x", log) == "x"
    assert len(log.warnings) == 4
    assert config_bool({"b": "false"}, "b", True, log) is False
    assert config_bool({"b": "1"}, "b", False, log) is True
    assert config_str({"s": "  "}, "s", "x", log) == "x"
    assert len(log.warnings) == 4


def test_config_list_accepts_lists_and_comma_separated_text():
    log = Log()
    assert config_list({"l": [" a.com ", "", "b.com"]}, "l", [], log) == ["a.com", "b.com"]
    assert config_list({"l": "a.com, b.com,,"}, "l", [], log) == ["a.com", "b.com"]
    assert log.warnings == []
    assert config_list({"l": 5}, "l", ["d"], log) == ["d"]
    assert config_list({"l": [["x"]]}, "l", ["d"], log) == ["d"]
    assert len(log.warnings) == 2


def test_warnings_never_show_secret_values():
    log = Log()
    config_int({"api_key": "hunter2"}, "api_key", 1, 0, 2, log)
    assert log.warnings and "hunter2" not in log.warnings[0]


def test_param_helpers_accept_a_request_or_a_value():
    request = MagicMock()
    request.get_param.return_value = "false"
    assert param_bool(request, "x", True) is False
    request.get_param.return_value = 999
    assert param_int(request, "x", 5, 1, 10) == 10
    request.get_param.side_effect = Exception("missing")
    assert param_bool(request, "x", True) is True
    assert param_bool("nonsense", "x", False) is False
    assert param_choice("b", ["a", "b"], "a") == "b"
    assert param_choice("z", ["a", "b"], "a") == "a"


# --- start() ---------------------------------------------------------------------------


def test_start_survives_bad_values_and_uses_defaults_or_clamps():
    service = make_service({"internal_timeout": "soon", "max_iocs": None, "max_extracted_payloads": -3,
                            "safelist_domains": 5})
    assert service.internal_timeout == defaults.INTERNAL_TIMEOUT
    assert service.max_iocs == defaults.MAX_IOCS
    assert service.max_extracted_payloads == 1
    assert service.safelist_domains == frozenset()


def test_internal_timeout_is_clamped_below_the_manifest_timeout():
    ceiling = MANIFEST["timeout"] - defaults.TIMEOUT_HEADROOM
    assert make_service({"internal_timeout": 10_000}).internal_timeout == ceiling
    assert make_service({"internal_timeout": ceiling}).internal_timeout == ceiling
    assert make_service({"internal_timeout": 30}).internal_timeout == 30
    assert make_service({"internal_timeout": 0}).internal_timeout == 1


def test_caps_have_upper_bounds():
    service = make_service({"max_iocs": 10**9, "max_extracted_payloads": 10**9})
    assert service.max_iocs == 5000
    assert service.max_extracted_payloads == 500


# --- fingerprint -----------------------------------------------------------------------


def test_fingerprint_changes_with_non_secret_settings_only():
    base = {"max_iocs": 200, "api_key": "one"}
    assert config_fingerprint(base) == config_fingerprint({"max_iocs": 200, "api_key": "two"})
    assert config_fingerprint(base) != config_fingerprint({"max_iocs": 201, "api_key": "one"})
    assert config_fingerprint(base).startswith("cfg-")


def test_tool_version_changes_when_a_setting_changes():
    assert make_service().get_tool_version() != make_service({"safelist_domains": ["example.org"]}).get_tool_version()
    assert make_service({"max_iocs": 5}).get_tool_version().startswith("pdfstudio ")


# --- safelist_domains ------------------------------------------------------------------


def test_normalize_domains():
    assert normalize_domains([" Example.ORG ", "*.cdn.test", ".dot.test.", ""]) == {
        "example.org", "cdn.test", "dot.test"}


def test_extra_domains_and_their_subdomains_are_not_iocs():
    raw = b"http://example.org/a http://www.example.org/b http://notexample.org/c http://bad.test/d"
    assert extract_iocs(raw)["domain"] == ["bad.test", "example.org", "notexample.org", "www.example.org"]
    iocs = extract_iocs(raw, frozenset({"example.org"}))
    assert iocs["domain"] == ["bad.test", "notexample.org"]
    assert iocs["uri"] == ["http://bad.test/d", "http://notexample.org/c"]


def test_built_in_safelist_is_kept_and_still_exact():
    raw = b"http://www.w3.org/x http://sub.w3.org/y"
    assert extract_iocs(raw, frozenset({"example.org"}))["domain"] == ["sub.w3.org"]


def test_extra_domains_apply_to_hidden_urls():
    bodies = [("obj 1", "<< /URI (http://a.example.org/x) >>")]
    assert [u for u, _ in find_hidden_urls(bodies, [], set())] == ["http://a.example.org/x"]
    assert find_hidden_urls(bodies, [], set(), frozenset({"example.org"})) == []


def test_service_applies_safelist_domains_from_config(tmp_path):
    sample = tmp_path / "s.pdf"
    sample.write_bytes(b"%PDF-1.4 http://example.org/a http://sub.example.org/b http://bad.test/c")
    request = MagicMock(file_path=str(sample))

    def tagged(service):
        result = Result()
        service._add_iocs(result, request)
        return sorted(result.sections[0].tags["network.static.domain"])

    assert tagged(make_service()) == ["bad.test", "example.org", "sub.example.org"]
    assert tagged(make_service({"safelist_domains": ["Example.org"]})) == ["bad.test"]
    assert tagged(make_service({"safelist_domains": "example.org, other.test"})) == ["bad.test"]


# --- max_iocs / max_extracted_payloads / extract_payloads ------------------------------


def test_max_iocs_limits_rows_per_type(tmp_path):
    sample = tmp_path / "s.pdf"
    sample.write_bytes(b"%PDF-1.4 " + b" ".join(f"http://h{i}.test/".encode() for i in range(5)))
    result = Result()
    make_service({"max_iocs": 2})._add_iocs(result, MagicMock(file_path=str(sample)))
    rows = table_rows(result.sections[0])
    assert len([row for row in rows if row["type"] == "uri"]) == 2
    assert len([row for row in rows if row["type"] == "domain"]) == 2


def payload_pdf(tmp_path):
    exe = "MZ" + "\x90" * 14
    zipped = "PK\x03\x04" + "\x00" * 12
    objects = {
        1: "<< /Type /Catalog /Pages 2 0 R >>",
        2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>",
        4: f"<< /Length 16 >>\nstream\n{exe}\nendstream",
        5: f"<< /Length 16 >>\nstream\n{zipped}\nendstream",
    }
    path = tmp_path / "payload.pdf"
    path.write_bytes(build_pdf(objects))
    return parse(str(path), decode_streams=True)


def carve(service, pdf, tmp_path, extract):
    service._working_directory = str(tmp_path)
    service._api_interface = MagicMock()
    request = MagicMock()
    result = Result()
    service._extract_embedded(result, request, pdf, extract)
    return request, result


def test_payloads_are_extracted_by_default(tmp_path):
    request, result = carve(make_service(), payload_pdf(tmp_path), tmp_path, True)
    assert request.add_extracted.call_count == 2
    assert result.sections[0].title_text == "Extracted embedded payloads"
    assert all("offset" not in row for row in table_rows(result.sections[0]))


def test_extract_payloads_false_lists_payloads_without_extracting(tmp_path):
    pdf = payload_pdf(tmp_path)
    request, result = carve(make_service(), pdf, tmp_path, False)
    request.add_extracted.assert_not_called()
    assert not list(tmp_path.glob("*_obj_*"))
    rows = table_rows(result.sections[0])
    assert [row["type"] for row in rows] == ["Embedded PE/MZ executable", "Embedded ZIP archive"]
    assert all(row["size"] == 16 and len(row["sha256"]) == 64 and row["offset"] > 0 for row in rows)
    first = next(obj for obj in pdf.objects if obj.index == 4)
    assert first.stream is not None
    assert rows[0]["offset"] == first.stream.raw_offset


def test_max_extracted_payloads_caps_extraction_and_listing(tmp_path):
    pdf = payload_pdf(tmp_path)
    service = make_service({"max_extracted_payloads": 1})
    request, _ = carve(service, pdf, tmp_path, True)
    assert request.add_extracted.call_count == 1
    _, listed = carve(service, pdf, tmp_path, False)
    assert len(table_rows(listed.sections[0])) == 1


@pytest.mark.parametrize("extract,calls", [(True, 2), (False, 0)])
def test_execute_reads_the_extract_payloads_submission_param(tmp_path, extract, calls):
    payload_pdf(tmp_path)
    service = make_service()
    service._working_directory = str(tmp_path)
    service._api_interface = MagicMock()
    request = MagicMock(file_path=str(tmp_path / "payload.pdf"), deep_scan=False)
    request.get_param.side_effect = {"extract_payloads": extract, "show_object_table": False}.__getitem__
    service.execute(request)
    assert request.add_extracted.call_count == calls
