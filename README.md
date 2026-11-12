# Assemblyline service: PdfStudio

Static structural analysis of PDF files for Assemblyline 4, using
[pdfstudio](https://github.com/boredchilada/pdfstudio), a read-only PDF analyser written with
the Python standard library only.

## What it does

For each `document/pdf` file the service runs `pdfstudio --json --objstm`. `--objstm` unpacks
compressed object streams (`/ObjStm`), where modern PDFs, malicious ones included, often keep
their actions and links.

pdfstudio's 30+ structural rules cover embedded executables (`EMBEDDED_PE`, `EMBEDDED_ELF`,
`EMBEDDED_ZIP`), launch actions (`LAUNCH_CMD`), high-entropy streams, object-stream and xref
anomalies, and encryption. Each rule scores once per file and lists every occurrence.
Link-target rules (links to executables, URL shorteners, raw IPs, dynamic-DNS or file-sharing
hosts) score low, because the reader has to click.

The catalog-graph walk lists every trigger chain, such as `/OpenAction` → `/JavaScript`. Only
chains that reach JavaScript or a Launch action are scored, and `OPENACTION_JS` scores only when
such a chain exists. Links, form widgets and open-at-page actions are listed without a score.
Incremental updates that add or rewrite objects are reported per revision, and malformed or
evasive structure as parse anomalies.

URLs, domains and IPs in the raw bytes are tagged as `network.static.*`, with common XMP and
metadata namespaces safelisted. Bare IPv4 addresses are skipped when they are in 10/8, 127/8, 0/8
or 255/8, end in `.0.0.0`, or follow a version word (`Version`, `Library`, `v`). URLs found only
in decoded streams, object streams, or escaped or hex `/URI` values (`h\164tp`, `<687474…>`) are
listed as hidden indicators with their source object, and tagged without a score.

Decoded streams starting with PE, ELF, ZIP, RAR, 7z, OLE or PDF magic are extracted for
Assemblyline's other services, de-duplicated and capped by `max_extracted_payloads`. The full
JSON report is attached as a supplementary file. The service emits tags and heuristics only, no
result ontology part.

The service works offline (`allow_internet_access: false`): pdfstudio's `--hunt` modes are never
used, and no URL is resolved or fetched.

## Heuristics

| ID | Name | Score | Notes |
|----|------|-------|-------|
| 1 | High Severity PDF Indicator | 1000 | Per-rule scores in `signature_score_map` (`uri_to_executable` 300, `openaction_js` 750); ATT&CK T1204 |
| 2 | Medium Severity PDF Indicator | 500 | Link-target rules score 100; `multi_rev` and `encrypted` score 0 |
| 3 | Low Severity PDF Indicator | 100 | |
| 4 | Informational PDF Observation | 0 | |
| 5 | Catalog Trigger Path | 0 | Trigger chains reaching JavaScript or Launch (scored via heuristic 1); ATT&CK T1204 |
| 6 | Multi-Revision Weaponization | 750 | ATT&CK T1027 |
| 7 | PDF Parse Anomaly | 100 | |

### Score changes since 4.7.0.6

| Rule | 4.7.0.6 | Now | Reason |
|---|---|---|---|
| Autorun JavaScript (`openaction_js` with a confirmed trigger path) | 1250 | 750 | `openaction_js` stays 750; heuristic 5 no longer adds 500 for the same chain |
| Heuristic 5, catalog trigger path | 500 | 0 | The action itself is scored under heuristic 1 |
| `aa_javascript`, JavaScript in an `/AA` of a page, document, annotation or a non-value field event | 1000 | 500 | Fires on page or document events, but is also common in forms |
| `aa_javascript_field`, field with only keystroke, format, validate or calculate scripts (`AFNumber_Keystroke`) | 1000 | 100 | Every number or date field in a fillable form has them |
| `js_export_data_object` | 1000 | 750 | |
| `filespec_ext_mismatch` | 1000 | 500 | |
| `not_a_pdf` | 1000 | 100 | The file has no `%PDF-` header, so no PDF structure was analysed |
| `multi_rev` | 500 | 0 | Incremental updates are common in signed and edited documents; cross-revision weaponization scores under heuristic 6 |
| `encrypted` | 500 | 0 | Password-protected PDFs are common and benign |

## Installation

In Assemblyline, open Administration → Services → Add service and paste `service_manifest.yml`.
No API key is needed.

## Settings

| Name | Scope | Default | Range | Effect |
|---|---|---|---|---|
| `internal_timeout` | service setting | `110` | 1 to service `timeout` minus 10 | Seconds before the pdfstudio subprocess is aborted. A higher value is lowered to the limit. |
| `max_iocs` | service setting | `200` | 1 to 5000 | Maximum indicators tagged per type, for cleartext and hidden indicators. |
| `max_extracted_payloads` | service setting | `30` | 1 to 500 | Maximum embedded payloads extracted, or listed when extraction is off, per file. |
| `safelist_domains` | service setting | empty list | list of domains | Domains and their subdomains that are not tagged as IOCs, added to the built-in namespace safelist. |
| `extract_payloads` | submission option | `true` | `true`, `false` | `false` lists carved payloads (type, offset, size, SHA-256) without extracting them. |
| `show_object_table` | submission option | `false` | `true`, `false` | Adds the full PDF object table; always added on deep scans. |

A value of the wrong type falls back to the default and an out-of-range number is clamped; each case
logs one warning at start. The tool version includes a fingerprint of the service settings, so
changing one makes Assemblyline re-analyse cached files. The pdfstudio commit (`PDFSTUDIO_COMMIT`
in the Dockerfile) is part of it too (for example `pdfstudio 0.1.0+75cf957-cfg-1a2b3c4d5e6f`).

## Tests

```bash
bash scripts/build-image.sh al4-pdfstudio:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-pdfstudio:test podman
```

The gate runs Ruff, Pyright and pytest inside the image. The samples in `tests/samples/` are
synthetic, harmless PDFs, including two benign ones that must score 0.

## Layout

```
pdfstudio_/
  analysis.py     flag mapping, indicator extraction, payload sniffing
  service.py      class PdfStudio(ServiceBase)
tests/            tests, samples/ and results/
scripts/          build-image.sh, ci-gate.sh, gentests.py
```
