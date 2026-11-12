"""Builds small, harmless PDFs for tests. Object bodies are written exactly as given."""


def build_pdf(objects: dict[int, str], root: int = 1) -> bytes:
    """A PDF with a valid xref table whose objects are ``{number: body}``."""
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out += f"{number} 0 obj\n{objects[number]}\nendobj\n".encode("latin-1")
    size = max(objects) + 1
    xref = len(out)
    out += f"xref\n0 {size}\n".encode()
    out += b"0000000000 65535 f \n"
    for number in range(1, size):
        out += f"{offsets[number]:010d} 00000 n \n".encode() if number in offsets else b"0000000000 65535 f \n"
    out += f"trailer\n<< /Size {size} /Root {root} 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def js_action(script: str) -> str:
    """An inline JavaScript action dictionary; ``script`` must already be PDF-string safe."""
    return f"<< /S /JavaScript /JS ({script}) >>"


_CATALOG = "<< /Type /Catalog /Pages 2 0 R{extra} >>"
_PAGES = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
_PAGE = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200]{extra} >>"
_FIELD = "<< /Type /Annot /Subtype /Widget /FT /Tx /T (amount) /Rect [10 10 100 30]{extra} >>"


def form_with_aa(events: dict[str, str]) -> bytes:
    """A fillable form whose text field has an /AA dictionary ``{event: script}``."""
    aa = " ".join(f"/{name} {js_action(script)}" for name, script in events.items())
    return build_pdf({
        1: _CATALOG.format(extra=" /AcroForm << /Fields [4 0 R] >>"),
        2: _PAGES,
        3: _PAGE.format(extra=" /Annots [4 0 R]"),
        4: _FIELD.format(extra=f" /AA << {aa} >>"),
    })


def page_with_aa(event: str, script: str) -> bytes:
    """A page whose /AA dictionary runs ``script`` on ``event`` (``O`` is page open)."""
    return build_pdf({
        1: _CATALOG.format(extra=""),
        2: _PAGES,
        3: _PAGE.format(extra=f" /AA << /{event} {js_action(script)} >>"),
    })


def document_with_aa(event: str, script: str) -> bytes:
    """A catalog whose /AA dictionary runs ``script`` on a document event (``WC`` is will close)."""
    return build_pdf({
        1: _CATALOG.format(extra=f" /AA << /{event} {js_action(script)} >>"),
        2: _PAGES,
        3: _PAGE.format(extra=""),
    })
