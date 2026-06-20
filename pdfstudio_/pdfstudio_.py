"""Assemblyline v4 service wrapping pdfstudio for static PDF structural analysis.

pdfstudio (https://github.com/boredchilada/pdfstudio) is a read-only, stdlib-only
PDF analyzer. This service drives its ``--json`` interface, maps findings onto
Assemblyline heuristics, and tags cleartext IOCs. It never opens a network socket
(pdfstudio's hunt/enrichment modes are intentionally not enabled).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from importlib import metadata

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultSection,
    ResultTableSection,
    TableRow,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded

# --- pdfstudio integration constants -------------------------------------------------

# pdfstudio exposes its CLI through ``pdfstudio.cli:main`` but ships no __main__.py,
# so ``python -m pdfstudio`` is unreliable. Importing main() and calling it directly
# is independent of $PATH and of any ``if __name__ == '__main__'`` guard. argparse
# reads sys.argv[1:], which for ``python -c <code> <file> <flags...>`` is exactly the
# arguments we append after the bootstrap string.
_PDFSTUDIO_BOOTSTRAP = "from pdfstudio.cli import main; main()"

# pdfstudio severity tier -> manifest heuristic id.
SEVERITY_HEURISTIC = {"HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}

# Rule codes that warrant a dedicated heuristic regardless of their reported tier.
CODE_HEURISTIC = {"MULTI_REV_WEAPONIZATION": 6}

# Titles for the per-heuristic flag sections.
HEUR_SECTION_TITLE = {
    1: "High severity indicators",
    2: "Medium severity indicators",
    3: "Low severity indicators",
    4: "Informational observations",
    6: "Multi-revision weaponization",
}

# --- IOC extraction (network-free, best effort over raw PDF bytes) -------------------

_URI_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,512}")
_IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_DOMAIN_FROM_URI_RE = re.compile(r"^[a-z]+://([^/:?#]+)", re.IGNORECASE)

# Domains that appear in nearly every PDF (XMP/metadata namespaces, schemas). Tagging
# these as IOCs would only create noise, so they are dropped before tagging.
IOC_DOMAIN_SAFELIST = {
    "www.w3.org", "w3.org", "ns.adobe.com", "www.adobe.com", "adobe.com",
    "purl.org", "iptc.org", "schemas.microsoft.com", "www.aiim.org",
    "poppler.freedesktop.org", "www.color.org", "creativecommons.org",
}

# --- Embedded-payload carving --------------------------------------------------------

# Magic signatures (matched at offset 0 of a decoded stream) that indicate a genuine
# embedded payload worth carving out and resubmitting for recursive analysis. High-
# signal only: content/font/image streams never start with these bytes.
_EMBEDDED_MAGICS = (
    (b"MZ", "exe", "Embedded PE/MZ executable"),
    (b"\x7fELF", "elf", "Embedded ELF binary"),
    (b"PK\x03\x04", "zip", "Embedded ZIP archive"),
    (b"Rar!\x1a\x07", "rar", "Embedded RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "Embedded 7z archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole", "Embedded OLE/CFB document"),
    (b"%PDF", "pdf", "Embedded PDF document"),
)


def sniff_embedded(data):
    """Return ``(extension, description)`` if ``data`` starts with a known payload
    magic, else ``None``."""
    if not data or len(data) < 8:
        return None
    for magic, ext, description in _EMBEDDED_MAGICS:
        if data.startswith(magic):
            return ext, description
    return None


def heuristic_for_flag(severity, code):
    """Map a pdfstudio flag ``(severity, code)`` to a manifest heuristic id."""
    if code in CODE_HEURISTIC:
        return CODE_HEURISTIC[code]
    return SEVERITY_HEURISTIC.get((severity or "").upper(), 4)


def extract_iocs(raw):
    """Return cleartext IOCs found in raw PDF bytes, with namespace domains removed.

    Only cleartext is matched; URIs hidden inside compressed object streams are not
    recovered here (that requires pdfstudio's network-enabled hunt mode).
    """
    uris, ips, domains = set(), set(), set()

    for match in _URI_RE.findall(raw):
        uri = match.decode("latin-1").rstrip(").>")
        dm = _DOMAIN_FROM_URI_RE.match(uri)
        domain = dm.group(1).lower() if dm else None
        if domain and domain in IOC_DOMAIN_SAFELIST:
            continue
        uris.add(uri)
        if domain:
            domains.add(domain)

    for match in _IP_RE.findall(raw):
        ips.add(match.decode("latin-1"))

    return {"uri": sorted(uris), "domain": sorted(domains), "ip": sorted(ips)}


class PdfStudio(ServiceBase):
    def __init__(self, config=None):
        super().__init__(config)
        self.internal_timeout = self.config.get("internal_timeout", 110)
        self.max_iocs = self.config.get("max_iocs", 200)
        self.max_extracted_payloads = self.config.get("max_extracted_payloads", 30)

    def get_tool_version(self):
        try:
            return f"pdfstudio {metadata.version('pdfstudio')}"
        except Exception:
            return "pdfstudio unknown"

    # -- pdfstudio invocation ---------------------------------------------------------

    def _run_pdfstudio(self, file_path, extra_args):
        cmd = [sys.executable, "-c", _PDFSTUDIO_BOOTSTRAP, file_path, *extra_args]
        # Exit codes 0/5/10/20 encode finding severity, not failure -> check=False.
        return subprocess.run(
            cmd, capture_output=True, timeout=self.internal_timeout, check=False
        )

    @staticmethod
    def _parse_json(stdout):
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            # Be tolerant of any leading/trailing noise on stdout.
            start, end = stdout.find("{"), stdout.rfind("}")
            if start != -1 and end > start:
                return json.loads(stdout[start:end + 1])
            raise

    # -- lifecycle --------------------------------------------------------------------

    def execute(self, request: ServiceRequest):
        result = Result()
        request.result = result

        try:
            proc = self._run_pdfstudio(request.file_path, ["--json"])
        except subprocess.TimeoutExpired:
            section = ResultSection("pdfstudio timed out")
            section.add_line(
                f"Analysis exceeded {self.internal_timeout}s and was aborted."
            )
            result.add_section(section)
            return

        stdout = proc.stdout.decode("utf-8", errors="replace")
        try:
            report = self._parse_json(stdout)
        except json.JSONDecodeError:
            self.log.warning(
                "pdfstudio returned no parseable JSON (rc=%s): %s",
                proc.returncode,
                proc.stderr.decode("utf-8", errors="replace")[:500],
            )
            section = ResultSection("pdfstudio could not analyze the PDF")
            section.add_line("The tool did not return a parseable report; see service logs.")
            result.add_section(section)
            return

        # Persist the full report as a supplementary artifact for analysts.
        report_path = os.path.join(self.working_directory, "pdfstudio_report.json")
        with open(report_path, "w") as handle:
            json.dump(report, handle, indent=2)
        request.add_supplementary(
            report_path, "pdfstudio_report.json", "Full pdfstudio JSON report"
        )

        self._add_summary(result, report)
        self._add_flags(result, report.get("flags") or [])
        self._add_triggers(result, report.get("triggers") or [])
        self._add_revisions(result, report.get("revisions") or [])
        self._add_parse_warnings(result, report.get("parse_warnings") or [])
        self._add_iocs(result, request)
        self._extract_embedded(result, request)
        if request.get_param("show_object_table") or request.deep_scan:
            self._add_objects(result, report.get("objects") or [])

    # -- section builders -------------------------------------------------------------

    def _add_summary(self, result, report):
        summary = ResultKeyValueSection("pdfstudio Summary")
        summary.set_item("Header", report.get("header") or "unknown")
        summary.set_item("Size (bytes)", report.get("size"))
        summary.set_item("Revisions", len(report.get("revisions") or []))
        summary.set_item("Objects", len(report.get("objects") or []))
        summary.set_item("Triggers", len(report.get("triggers") or []))
        summary.set_item("Flags", len(report.get("flags") or []))
        summary.set_item("Parse warnings", len(report.get("parse_warnings") or []))
        result.add_section(summary)

    def _add_flags(self, result, flags):
        if not flags:
            return
        by_heuristic = {}
        for flag in flags:
            heur_id = heuristic_for_flag(flag.get("severity"), flag.get("code", ""))
            by_heuristic.setdefault(heur_id, []).append(flag)

        for heur_id in sorted(by_heuristic):
            items = by_heuristic[heur_id]
            section = ResultSection(HEUR_SECTION_TITLE.get(heur_id, "PDF indicators"))
            heuristic = Heuristic(heur_id)
            for flag in items:
                code = flag.get("code", "?")
                section.add_line(f"[{code}] {flag.get('message', '')}")
                # Signature IDs must be lowercase to satisfy the AL ODM; the
                # signature_score_map keys in the manifest match this form.
                heuristic.add_signature_id(code.lower())
            section.set_heuristic(heuristic)
            result.add_section(section)

    def _add_triggers(self, result, triggers):
        if not triggers:
            return
        section = ResultTableSection("Catalog trigger paths")
        for trig in triggers[:200]:
            path = trig.get("path")
            if isinstance(path, list):
                path = " -> ".join(str(p) for p in path)
            section.add_row(
                TableRow(
                    {
                        "Trigger": trig.get("trigger"),
                        "Path": path,
                        "Detail": trig.get("detail"),
                        "Severity": trig.get("severity"),
                    }
                )
            )
        section.set_heuristic(5)
        result.add_section(section)

    def _add_revisions(self, result, revisions):
        if len(revisions) <= 1:
            return
        section = ResultSection(f"Incremental updates ({len(revisions)} revisions)")
        for rev in revisions:
            new = rev.get("new_objects") or []
            rewritten = rev.get("rewritten_objects") or []
            section.add_line(
                f"Revision {rev.get('index')}: "
                f"+{len(new)} new, {len(rewritten)} rewritten objects"
            )
        result.add_section(section)

    def _add_parse_warnings(self, result, warnings):
        if not warnings:
            return
        section = ResultSection("PDF parse anomalies")
        for warning in warnings[:50]:
            section.add_line(str(warning))
        section.set_heuristic(7)
        result.add_section(section)

    def _add_iocs(self, result, request):
        with open(request.file_path, "rb") as handle:
            raw = handle.read()
        iocs = extract_iocs(raw)
        if not any(iocs.values()):
            return

        section = ResultSection("Cleartext indicators of compromise")
        tag_types = {
            "uri": "network.static.uri",
            "domain": "network.static.domain",
            "ip": "network.static.ip",
        }
        for kind, tag_type in tag_types.items():
            values = iocs[kind][: self.max_iocs]
            if not values:
                continue
            sub = ResultSection(f"{kind.upper()} ({len(values)})", parent=section)
            for value in values:
                sub.add_line(value)
                sub.add_tag(tag_type, value)
        result.add_section(section)

    def _extract_embedded(self, result, request):
        """Carve embedded payloads (PE/ELF/ZIP/PDF/OLE/...) from decoded object
        streams and resubmit them via add_extracted for recursive analysis.

        Uses pdfstudio's parser in-process so we get decoded stream bytes for free.
        The whole pass is fail-soft: any error here must not break the core report.
        """
        try:
            from pdfstudio.parser import parse
        except Exception as exc:  # pragma: no cover - import guard
            self.log.warning("pdfstudio parser unavailable; skipping carving: %s", exc)
            return

        try:
            pdf = parse(request.file_path, decode_streams=True)
        except Exception as exc:
            self.log.warning("pdfstudio in-process parse failed; skipping carving: %s", exc)
            return

        section = ResultSection("Extracted embedded payloads")
        seen_md5 = set()
        extracted = 0

        for obj in getattr(pdf, "objects", []) or []:
            if extracted >= self.max_extracted_payloads:
                section.add_line(
                    f"Reached extraction cap ({self.max_extracted_payloads}); "
                    "further payloads were not carved."
                )
                break

            stream = getattr(obj, "stream", None)
            if stream is None:
                continue

            decoded = getattr(stream, "decoded_bytes", None)
            if isinstance(decoded, (bytes, bytearray)) and decoded:
                data = bytes(decoded)
            else:
                raw = getattr(stream, "raw_bytes", None)
                data = bytes(raw) if isinstance(raw, (bytes, bytearray)) else None
            if not data:
                continue

            sniffed = sniff_embedded(data)
            if not sniffed:
                continue
            ext, description = sniffed

            md5 = hashlib.md5(data).hexdigest()
            if md5 in seen_md5:
                continue
            seen_md5.add(md5)

            name = f"obj_{getattr(obj, 'index', 'x')}.{ext}"
            out_path = os.path.join(self.working_directory, f"{md5}_{name}")
            with open(out_path, "wb") as handle:
                handle.write(data)

            try:
                request.add_extracted(
                    out_path, name, description, safelist_interface=self.api_interface
                )
            except MaxExtractedExceeded:
                section.add_line("Maximum extracted-file limit reached for this task.")
                break

            extracted += 1
            section.add_line(f"{name}: {description} ({len(data)} bytes, md5 {md5})")

        if extracted:
            result.add_section(section)

    def _add_objects(self, result, objects):
        if not objects:
            return
        section = ResultTableSection("PDF objects")
        for obj in objects[:500]:
            section.add_row(
                TableRow(
                    {
                        "Obj": f"{obj.get('index')} {obj.get('generation')}",
                        "Kind": obj.get("kind"),
                        "Labels": ", ".join(obj.get("labels") or []),
                        "Stream filters": ", ".join(obj.get("stream_filters") or []),
                        "MD5": obj.get("md5"),
                    }
                )
            )
        result.add_section(section)
