"""Pure analysis helpers. No AssemblyLine imports, so they unit-test without the framework."""

import json
import re
from collections.abc import Iterable

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


def heuristic_for_flag(severity: str | None, code: str, active_trigger: bool) -> int:
    """Map a pdfstudio flag ``(severity, code)`` to a manifest heuristic id.

    ``OPENACTION_JS`` only means /OpenAction and /JavaScript both occur somewhere in the file. It is
    scored only when the trigger walk confirms an automatic path into JavaScript or Launch
    (``active_trigger``); otherwise it is informational.
    """
    if code in CODE_HEURISTIC:
        return CODE_HEURISTIC[code]
    if code == "OPENACTION_JS" and not active_trigger:
        return 4
    return SEVERITY_HEURISTIC.get((severity or "").upper(), 4)


def has_active_trigger(triggers: list[dict]) -> bool:
    """True if any trigger path reaches active content.

    pdfstudio rates a trigger HIGH only when it leads to a JavaScript or Launch action. Links,
    form widgets and /OpenAction to a page (open at page N) are MED or LOW and common in benign
    documents, so they do not count.
    """
    return any((t.get("severity") or "").upper() == "HIGH" for t in triggers)


def urls_in(data: bytes) -> list[str]:
    """Every http/https/ftp URL in ``data``, in order of appearance, namespace domains removed."""
    urls = []
    for match in _URI_RE.findall(data):
        uri = match.decode("latin-1").rstrip(").>")
        dm = _DOMAIN_FROM_URI_RE.match(uri)
        if dm and dm.group(1).lower() in IOC_DOMAIN_SAFELIST:
            continue
        urls.append(uri)
    return urls


def url_host(uri: str) -> str | None:
    """Lower-cased host part of a URL, or None."""
    dm = _DOMAIN_FROM_URI_RE.match(uri)
    return dm.group(1).lower() if dm else None


def is_ip(host: str) -> bool:
    return _IP_RE.fullmatch(host.encode("latin-1", "replace")) is not None


def extract_iocs(raw: bytes) -> dict[str, list[str]]:
    """Cleartext IOCs found in raw PDF bytes, with namespace domains removed.

    Only cleartext is matched here; :func:`find_hidden_urls` covers compressed and encoded URLs.
    """
    uris = set(urls_in(raw))
    domains = {host for host in map(url_host, uris) if host}
    ips = {match.decode("latin-1") for match in _IP_RE.findall(raw)}
    return {"uri": sorted(uris), "domain": sorted(domains), "ip": sorted(ips)}


# --- PDF strings and hidden URLs -------------------------------------------------------

_URI_LITERAL = re.compile(r"/URI\s*\(")
_URI_HEX = re.compile(r"/URI\s*<([0-9A-Fa-f\s]*)>")
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "(": "(", ")": ")", "\\": "\\"}


def _text_string(value: str) -> str:
    """PDF text strings may be UTF-16BE with a byte order mark; everything else is kept as bytes 0-255."""
    if value.startswith("\xfe\xff"):
        return value[2:].encode("latin-1", "replace").decode("utf-16-be", "replace")
    return value


def read_literal_string(text: str, start: int) -> str | None:
    """Decode the PDF literal string that starts just after an opening ``(`` at ``text[start - 1]``.

    Handles nested parentheses, backslash escapes, octal escapes (``\\164`` is ``t``) and
    line continuations. Returns None when the string is not terminated.
    """
    out: list[str] = []
    depth, i, end = 1, start, len(text)
    while i < end:
        char = text[i]
        if char == "\\":
            i += 1
            if i >= end:
                return None
            nxt = text[i]
            if nxt in _ESCAPES:
                out.append(_ESCAPES[nxt])
                i += 1
            elif nxt in "01234567":
                j = i
                while j < end and j - i < 3 and text[j] in "01234567":
                    j += 1
                out.append(chr(int(text[i:j], 8) & 0xFF))
                i = j
            elif nxt == "\r":
                i += 2 if text[i + 1:i + 2] == "\n" else 1
            elif nxt == "\n":
                i += 1
            else:
                out.append(nxt)
                i += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return _text_string("".join(out))
        out.append(char)
        i += 1
    return None


def uri_action_targets(body: str) -> list[str]:
    """Decoded values of every ``/URI`` entry in an object body: literal ``(...)`` and hex ``<...>`` forms."""
    targets = []
    for match in _URI_LITERAL.finditer(body):
        value = read_literal_string(body, match.end())
        if value is not None:
            targets.append(value)
    for match in _URI_HEX.finditer(body):
        digits = re.sub(r"\s", "", match.group(1))
        digits += "0" * (len(digits) % 2)  # an odd final digit is padded with 0 (PDF spec)
        targets.append(_text_string(bytes.fromhex(digits).decode("latin-1")))
    return [t.strip() for t in targets if t.strip()]


def find_hidden_urls(bodies: Iterable[tuple[str, str]], streams: Iterable[tuple[str, bytes]],
                     visible: set[str]) -> list[tuple[str, str]]:
    """URLs that do not appear as plain text in the file, as ``(url, where)`` sorted by URL.

    ``bodies`` are object dictionaries, including objects unpacked from object streams; their
    ``/URI`` values are decoded from literal escapes or hex before matching. ``streams`` are
    decoded stream contents. ``visible`` holds the URLs already found in the raw bytes.
    """
    found: dict[str, str] = {}

    def add(urls: list[str], where: str) -> None:
        for url in urls:
            if url not in visible:
                found.setdefault(url, where)

    for where, body in bodies:
        targets = uri_action_targets(body)
        add([u for t in targets for u in urls_in(t.encode("latin-1", "replace"))], where)
        add(urls_in(body.encode("latin-1", "replace")), where)
    for where, data in streams:
        add(urls_in(data), where)
    return sorted(found.items())


def parse_report(stdout: str) -> dict:
    """pdfstudio's --json report. Tolerates noise before or after the JSON object."""
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        start, end = stdout.find("{"), stdout.rfind("}")
        if start != -1 and end > start:
            return json.loads(stdout[start:end + 1])
        raise
