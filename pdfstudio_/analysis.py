"""Pure analysis helpers. No AssemblyLine imports, so they unit-test without the framework."""

import json
import re

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
_IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
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


def sniff_embedded(data: bytes) -> tuple[str, str] | None:
    """``(extension, description)`` if ``data`` starts with a known payload magic, else None."""
    if not data or len(data) < 8:
        return None
    for magic, ext, description in _EMBEDDED_MAGICS:
        if data.startswith(magic):
            return ext, description
    return None


def heuristic_for_flag(severity: str | None, code: str) -> int:
    """Map a pdfstudio flag ``(severity, code)`` to a manifest heuristic id."""
    if code in CODE_HEURISTIC:
        return CODE_HEURISTIC[code]
    return SEVERITY_HEURISTIC.get((severity or "").upper(), 4)


def has_active_trigger(triggers: list[dict]) -> bool:
    """True if any trigger path reaches active content.

    pdfstudio rates a trigger HIGH only when it leads to a JavaScript or Launch action. Links,
    form widgets and /OpenAction to a page (open at page N) are MED or LOW and common in benign
    documents, so they do not count.
    """
    return any((t.get("severity") or "").upper() == "HIGH" for t in triggers)


def extract_iocs(raw: bytes) -> dict[str, list[str]]:
    """Cleartext IOCs found in raw PDF bytes, with namespace domains removed.

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


def parse_report(stdout: str) -> dict:
    """pdfstudio's --json report. Tolerates noise before or after the JSON object."""
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        start, end = stdout.find("{"), stdout.rfind("}")
        if start != -1 and end > start:
            return json.loads(stdout[start:end + 1])
        raise
