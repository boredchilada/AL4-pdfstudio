"""AA_JAVASCRIPT routing on real PDFs: pdfstudio's flags run on synthetic files, the service scores them."""

import os
from pathlib import Path

import pytest

os.environ["SERVICE_MANIFEST_PATH"] = str(Path(__file__).resolve().parent.parent / "service_manifest.yml")

from assemblyline_v4_service.common.result import Result  # noqa: E402
from pdfstudio.classify import classify  # noqa: E402
from pdfstudio.flags import run_all  # noqa: E402
from pdfstudio.parser import parse  # noqa: E402

from pdfstudio_.service import PdfStudio  # noqa: E402
from tests.synthetic import document_with_aa, form_with_aa, page_with_aa  # noqa: E402

ALERT = r"app.alert\(1\);"
NUMBER_KEYSTROKE = r"AFNumber_Keystroke\(2, 0, 0, 0, \"\", true\);"
NUMBER_FORMAT = r"AFNumber_Format\(2, 0, 0, 0, \"\", true\);"


def score_of(tmp_path, data: bytes) -> tuple[int, set[str]]:
    """Score and signatures of the heuristic 1 section the service builds for ``data``."""
    path = tmp_path / "sample.pdf"
    path.write_bytes(data)
    pdf = parse(str(path), decode_streams=True)
    classify(pdf)
    run_all(pdf)
    flags = [{"severity": s, "code": c, "message": m} for s, c, m in pdf.flags]
    result = Result()
    PdfStudio._add_flags(result, flags, active_trigger=False, pdf=pdf)
    sections = [s for s in result.sections if s.heuristic and s.heuristic.heur_id == 1]
    assert len(sections) <= 1
    if not sections:
        return 0, set()
    assert sections[0].heuristic
    return sections[0].heuristic.score, set(sections[0].heuristic.signatures)


def test_form_field_value_scripts_are_ordinary(tmp_path):
    data = form_with_aa({"K": NUMBER_KEYSTROKE, "F": NUMBER_FORMAT})
    assert score_of(tmp_path, data) == (100, {"aa_javascript_field"})


def test_field_script_text_does_not_hide_other_events(tmp_path):
    # Event names and ">>" inside the script string are not dictionary keys.
    data = form_with_aa({"K": 'x = \\"/E >> /Fo\\";'})
    assert score_of(tmp_path, data) == (100, {"aa_javascript_field"})


@pytest.mark.parametrize("event", ["E", "X", "D", "U", "Fo", "Bl"])
def test_field_interaction_events_keep_the_full_score(tmp_path, event):
    assert score_of(tmp_path, form_with_aa({event: ALERT})) == (500, {"aa_javascript"})


def test_field_with_one_interaction_event_among_value_events_keeps_the_full_score(tmp_path):
    data = form_with_aa({"K": NUMBER_KEYSTROKE, "E": ALERT})
    assert score_of(tmp_path, data) == (500, {"aa_javascript"})


@pytest.mark.parametrize("event", ["O", "C"])
def test_page_additional_actions_score_500(tmp_path, event):
    assert score_of(tmp_path, page_with_aa(event, ALERT)) == (500, {"aa_javascript"})


@pytest.mark.parametrize("event", ["WC", "WS", "DS", "WP", "DP"])
def test_document_additional_actions_score_500(tmp_path, event):
    assert score_of(tmp_path, document_with_aa(event, ALERT)) == (500, {"aa_javascript"})

