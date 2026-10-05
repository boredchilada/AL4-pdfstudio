"""AssemblyLine 4 service wrapping pdfstudio for static PDF structural analysis.

pdfstudio (https://github.com/boredchilada/pdfstudio) is a read-only, stdlib-only PDF
analyser. This service drives its ``--json`` interface, maps findings onto AssemblyLine
heuristics, tags cleartext IOCs and carves embedded payloads. It never opens a network
socket: pdfstudio's hunt/enrichment modes are not used.
"""

import hashlib
import json
import os
import subprocess
import sys
from importlib import metadata

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultKeyValueSection,
    ResultTableSection,
    ResultTextSection,
    TableRow,
)
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from pdfstudio_.analysis import (
    HEUR_SECTION_TITLE,
    extract_iocs,
    has_active_trigger,
    heuristic_for_flag,
    parse_report,
    sniff_embedded,
)

# pdfstudio exposes its CLI as ``pdfstudio.cli:main``. Calling main() through ``python -c`` is
# independent of $PATH; argparse reads the arguments appended after the bootstrap string.
_PDFSTUDIO_BOOTSTRAP = "from pdfstudio.cli import main; main()"

IOC_TAGS = {"uri": "network.static.uri", "domain": "network.static.domain", "ip": "network.static.ip"}


class PdfStudio(ServiceBase):
    def start(self) -> None:
        config = self.config or {}
        self.internal_timeout = int(config.get("internal_timeout", 110))
        self.max_iocs = int(config.get("max_iocs", 200))
        self.max_extracted_payloads = int(config.get("max_extracted_payloads", 30))
        self.log.info(f"PdfStudio started with {self.get_tool_version()}")

    def get_tool_version(self) -> str:
        # A changed tool version makes AL re-run cached files, so include the exact build commit.
        try:
            version = metadata.version("pdfstudio")
        except metadata.PackageNotFoundError:
            return "pdfstudio unknown"
        commit = os.environ.get("PDFSTUDIO_COMMIT", "")[:7]
        return f"pdfstudio {version}+{commit}" if commit else f"pdfstudio {version}"

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        try:
            proc = subprocess.run(
                [sys.executable, "-c", _PDFSTUDIO_BOOTSTRAP, request.file_path, "--json"],
                capture_output=True, timeout=self.internal_timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            section = ResultTextSection("pdfstudio timed out")
            section.add_line(f"Analysis exceeded {self.internal_timeout} s and was aborted.")
            result.add_section(section)
            return

        # Exit codes 0/5/10/20 encode finding severity, not failure, so they are not checked.
        try:
            report = parse_report(proc.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            self.log.warning(f"pdfstudio returned no parseable JSON (rc={proc.returncode}): "
                             f"{proc.stderr.decode('utf-8', errors='replace')[:500]}")
            section = ResultTextSection("pdfstudio could not analyse the PDF")
            section.add_line("The tool did not return a parseable report; see service logs.")
            result.add_section(section)
            return

        report_path = os.path.join(self.working_directory, "pdfstudio_report.json")
        with open(report_path, "w") as handle:
            json.dump(report, handle, indent=2)
        request.add_supplementary(report_path, "pdfstudio_report.json", "Full pdfstudio JSON report")

        self._add_summary(result, report)
        self._add_flags(result, report.get("flags") or [])
        self._add_triggers(result, report.get("triggers") or [])
        self._add_revisions(result, report.get("revisions") or [])
        self._add_parse_warnings(result, report.get("parse_warnings") or [])
        self._add_iocs(result, request)
        self._extract_embedded(result, request)
        if request.get_param("show_object_table") or request.deep_scan:
            self._add_objects(result, report.get("objects") or [])

    @staticmethod
    def _add_summary(result: Result, report: dict) -> None:
        summary = ResultKeyValueSection("pdfstudio summary")
        summary.set_item("header", report.get("header") or "unknown")
        summary.set_item("size_bytes", report.get("size") or 0)
        for key in ("revisions", "objects", "triggers", "flags", "parse_warnings"):
            summary.set_item(key, len(report.get(key) or []))
        result.add_section(summary)

    @staticmethod
    def _add_flags(result: Result, flags: list[dict]) -> None:
        by_heuristic: dict[int, list[dict]] = {}
        for flag in flags:
            by_heuristic.setdefault(heuristic_for_flag(flag.get("severity"), flag.get("code", "")), []).append(flag)
        for heur_id in sorted(by_heuristic):
            section = ResultTableSection(HEUR_SECTION_TITLE.get(heur_id, "PDF indicators"))
            heuristic = Heuristic(heur_id)
            for flag in by_heuristic[heur_id]:
                code = flag.get("code", "?")
                section.add_row(TableRow({"code": code, "message": flag.get("message", "")}))
                # Signature ids must be lowercase for the AL ODM; the manifest's score map matches.
                heuristic.add_signature_id(code.lower())
            section.set_heuristic(heuristic)
            result.add_section(section)

    @staticmethod
    def _add_triggers(result: Result, triggers: list[dict]) -> None:
        if not triggers:
            return
        section = ResultTableSection("Catalog trigger paths")
        for trig in triggers[:200]:
            path = trig.get("path")
            if isinstance(path, list):
                path = " -> ".join(str(p) for p in path)
            section.add_row(TableRow({"trigger": trig.get("trigger"), "path": path,
                                      "detail": trig.get("detail"), "severity": trig.get("severity")}))
        if has_active_trigger(triggers):
            section.set_heuristic(5)
        result.add_section(section)

    @staticmethod
    def _add_revisions(result: Result, revisions: list[dict]) -> None:
        if len(revisions) <= 1:
            return
        section = ResultTableSection(f"Incremental updates ({len(revisions)} revisions)")
        for rev in revisions:
            section.add_row(TableRow({"revision": rev.get("index"), "new_objects": len(rev.get("new_objects") or []),
                                      "rewritten_objects": len(rev.get("rewritten_objects") or [])}))
        result.add_section(section)

    @staticmethod
    def _add_parse_warnings(result: Result, warnings: list) -> None:
        if not warnings:
            return
        section = ResultTextSection("PDF parse anomalies")
        for warning in warnings[:50]:
            section.add_line(str(warning))
        section.set_heuristic(7)
        result.add_section(section)

    def _add_iocs(self, result: Result, request: ServiceRequest) -> None:
        with open(request.file_path, "rb") as handle:
            iocs = extract_iocs(handle.read())
        section = ResultTableSection("Cleartext indicators of compromise")
        for kind, tag_type in IOC_TAGS.items():
            for value in iocs[kind][: self.max_iocs]:
                section.add_row(TableRow({"type": kind, "value": value}))
                section.add_tag(tag_type, value)
        if section.body:
            result.add_section(section)

    def _extract_embedded(self, result: Result, request: ServiceRequest) -> None:
        """Carve embedded payloads from decoded streams and resubmit them for analysis.

        Uses pdfstudio's parser in-process to get decoded stream bytes. Fail-soft: an error here
        must not break the core report.
        """
        try:
            from pdfstudio.parser import parse
            pdf = parse(request.file_path, decode_streams=True)
        except Exception as exc:
            self.log.warning(f"pdfstudio in-process parse failed; skipping carving: {exc}")
            return

        section = ResultTableSection("Extracted embedded payloads")
        seen: set[str] = set()
        for obj in getattr(pdf, "objects", None) or []:
            if len(seen) >= self.max_extracted_payloads:
                self.log.info(f"Reached extraction cap ({self.max_extracted_payloads})")
                break
            stream = getattr(obj, "stream", None)
            if stream is None:
                continue
            decoded = getattr(stream, "decoded_bytes", None) or getattr(stream, "raw_bytes", None)
            if not isinstance(decoded, (bytes, bytearray)) or not decoded:
                continue
            data = bytes(decoded)
            sniffed = sniff_embedded(data)
            if not sniffed:
                continue
            sha256 = hashlib.sha256(data).hexdigest()
            if sha256 in seen:
                continue
            seen.add(sha256)

            ext, description = sniffed
            name = f"obj_{getattr(obj, 'index', 'x')}.{ext}"
            path = os.path.join(self.working_directory, f"{sha256[:16]}_{name}")
            with open(path, "wb") as handle:
                handle.write(data)
            try:
                request.add_extracted(path, name, description, safelist_interface=self.api_interface)
            except MaxExtractedExceeded:
                self.log.info("Maximum extracted-file limit reached for this task")
                break
            section.add_row(TableRow({"file": name, "type": description, "size": len(data), "sha256": sha256}))
        if section.body:
            result.add_section(section)

    @staticmethod
    def _add_objects(result: Result, objects: list[dict]) -> None:
        if not objects:
            return
        section = ResultTableSection("PDF objects")
        for obj in objects[:500]:
            section.add_row(TableRow({
                "obj": f"{obj.get('index')} {obj.get('generation')}",
                "kind": obj.get("kind"),
                "labels": ", ".join(obj.get("labels") or []),
                "stream_filters": ", ".join(obj.get("stream_filters") or []),
                "md5": obj.get("md5"),
            }))
        result.add_section(section)
