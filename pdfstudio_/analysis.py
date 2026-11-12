"""Pure analysis helpers. No AssemblyLine imports, so they unit-test without the framework."""

import ipaddress
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from urllib.parse import urlsplit

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

_URI_RE = re.compile(rb"(?:https?|ftp)://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{4,512}")
# A dotted quad that is not part of a longer token: no letter, digit or underscore around it, and no
# further dotted or hyphenated segment ("1.2.3.4.5", "1.2.3.4-beta", "lib-1.2.3.4"). A trailing sentence
# dot or a leading minus sign does not hide it. Octets run 0-255 without leading zeros. Addresses in
# 10/8, 127/8, 0/8 and 255/8 are not indicators and are skipped, as is "N.0.0.0": a network address
# that headless Chrome writes into the Producer string as its version ("HeadlessChrome/150.0.0.0").
_OCTET = rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IP_RE = re.compile(
    rb"(?<![A-Za-z0-9_])(?<![A-Za-z0-9_][.-])(?!(?:10|127)\.\d+\b)(?!0\.)(?!255\.)(?!\d+\.0\.0\.0\b)"
    rb"(?:" + _OCTET + rb"\.){3}" + _OCTET + rb"(?![A-Za-z0-9_]|[.-][A-Za-z0-9])"
)
# Words that introduce a version number ("Adobe PDF Library 15.0.0.1", "Version 1.2.3.4", "v1.2.3.4").
# The leading \b keeps "server", "dev" and "srv" from matching "ver" or "v".
_VERSION_PREFIX_RE = re.compile(
    rb"\b(?:Library|Version|ver|build|release|InDesign|Acrobat|Distiller|PDF|v)[\s:=]*$",
    re.IGNORECASE,
)

# Domains that appear in nearly every PDF (XMP/metadata namespaces, schemas). Tagging
# these as IOCs would only create noise, so they are dropped before tagging.
IOC_DOMAIN_SAFELIST = {
    "www.w3.org", "w3.org", "ns.adobe.com", "www.adobe.com", "adobe.com",
    "purl.org", "iptc.org", "schemas.microsoft.com", "www.aiim.org",
    "poppler.freedesktop.org", "www.color.org", "creativecommons.org",
    "ns.useplus.org", "prismstandard.org", "www.npes.org",
}


def normalize_domains(domains: Iterable[str]) -> frozenset[str]:
    """Lower-cased bare domains: surrounding dots and a leading ``*.`` are dropped."""
    cleaned = (d.strip().lower().removeprefix("*.").strip(".") for d in domains)
    return frozenset(d for d in cleaned if d)


def is_safelisted(host: str, extra_domains: frozenset[str] = frozenset()) -> bool:
    """Built-in safelist entries match exactly; configured domains also match their subdomains."""
    if host in IOC_DOMAIN_SAFELIST or host in extra_domains:
        return True
    return any(host.endswith("." + domain) for domain in extra_domains)


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
    (``active_trigger``); otherwise it is informational. ``AA_JAVASCRIPT`` is not gated: pdfstudio
    raises it for inline JavaScript in an /AA dictionary, which the trigger walk never reports
    together with a HIGH trigger (it only follows indirect /AA actions of pages).
    """
    if code in CODE_HEURISTIC:
        return CODE_HEURISTIC[code]
    if code == "OPENACTION_JS" and not active_trigger:
        return 4
    return SEVERITY_HEURISTIC.get((severity or "").upper(), 4)


# /AA events of form fields that compute, format, validate or filter a field value (K keystroke,
# F format, V validate, C calculate). Every AcroForm number or date field uses them.
_FIELD_VALUE_EVENTS = frozenset({"K", "F", "V", "C"})
_AA_OPEN = re.compile(r"/AA\s*<<")
_PDF_NAME = re.compile(r"/([^\s/<>\[\]()]+)")
_FORM_FIELD = re.compile(r"/FT\s*/|/Subtype\s*/Widget\b")
_FLAG_OBJECT = re.compile(r"\bobj (\d+)\b")


def _skip_string(text: str, start: int) -> int:
    """Index just after the literal string that opens at ``text[start] == '('``."""
    depth = 0
    i = start
    while i < len(text):
        char = text[i]
        if char == "\\":
            i += 2
            continue
        depth += char == "("
        depth -= char == ")"
        i += 1
        if depth == 0:
            break
    return i


def aa_events(body: str) -> set[str]:
    """Names of the events (``O``, ``K``, ``Fo`` ...) of every inline /AA dictionary in an object body."""
    events: set[str] = set()
    for opening in _AA_OPEN.finditer(body):
        depth = 1
        i = opening.end()
        while i < len(body) and depth:
            char = body[i]
            if char == "(":
                i = _skip_string(body, i)
            elif body.startswith("<<", i):
                depth += 1
                i += 2
            elif body.startswith(">>", i):
                depth -= 1
                i += 2
            elif char == "/":
                name = _PDF_NAME.match(body, i)
                if name and depth == 1:
                    events.add(name.group(1))
                i = name.end() if name else i + 1
            else:
                i += 1
    return events


def aa_javascript_signature(flag_message: str, bodies_by_index: Mapping[int, Sequence[str]]) -> str:
    """Score signature of an ``AA_JAVASCRIPT`` flag: ``aa_javascript_field`` or ``aa_javascript``.

    Form fields carry JavaScript in /AA for number, date and validation scripts (``AFNumber_Keystroke``),
    so a field object whose /AA only uses value events (K, F, V, C) is the ordinary case. Every other
    holder (page, document, annotation, or a field event such as mouse-over or focus) fires on user
    or document activity and keeps the full signature. An object that cannot be found keeps it too.
    """
    found = _FLAG_OBJECT.search(flag_message)
    bodies = bodies_by_index.get(int(found.group(1)), ()) if found else ()
    if bodies and all(_FORM_FIELD.search(b) and aa_events(b) <= _FIELD_VALUE_EVENTS for b in bodies):
        return "aa_javascript_field"
    return "aa_javascript"


def has_active_trigger(triggers: list[dict]) -> bool:
    """True if any trigger path reaches active content.

    pdfstudio rates a trigger HIGH only when it leads to a JavaScript or Launch action. Links,
    form widgets and /OpenAction to a page (open at page N) are MED or LOW and common in benign
    documents, so they do not count.
    """
    return any((t.get("severity") or "").upper() == "HIGH" for t in triggers)


def urls_in(data: bytes, extra_domains: frozenset[str] = frozenset()) -> list[str]:
    """Every http/https/ftp URL in ``data``, in order of appearance, safelisted domains removed."""
    urls = []
    for match in _URI_RE.findall(data):
        uri = match.decode("latin-1").rstrip(".,;)>'\"")
        host = url_host(uri)
        if not host or is_safelisted(host, extra_domains):
            continue
        urls.append(uri)
    return urls


def url_host(uri: str) -> str | None:
    """Lower-cased host part of a URL, or None."""
    try:
        host = urlsplit(uri).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
            return None
        return host
    except ValueError:
        return host if "." in host or host.isalpha() else None


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def extract_iocs(raw: bytes, extra_domains: frozenset[str] = frozenset()) -> dict[str, list[str]]:
    """Cleartext IOCs found in raw PDF bytes, with safelisted domains removed.

    Only cleartext is matched here; :func:`find_hidden_urls` covers compressed and encoded URLs.
    """
    uris = set(urls_in(raw, extra_domains))
    hosts = {host for host in map(url_host, uris) if host}
    domains = {host for host in hosts if not is_ip(host)}
    ips = {host for host in hosts if is_ip(host)}
    for m in _IP_RE.finditer(raw):
        prefix = raw[max(0, m.start() - 24):m.start()]
        if _VERSION_PREFIX_RE.search(prefix):
            continue
        candidate = m.group(0).decode("latin-1")
        if is_ip(candidate):
            ips.add(candidate)
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
                     visible: set[str], extra_domains: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
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
        add([u for t in targets for u in urls_in(t.encode("latin-1", "replace"), extra_domains)], where)
        add(urls_in(body.encode("latin-1", "replace"), extra_domains), where)
    for where, data in streams:
        add(urls_in(data, extra_domains), where)
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
