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
metadata namespaces safelisted. URLs found only in decoded streams, object streams, or escaped
or hex `/URI` values (`h\164tp`, `<687474…>`) are listed as hidden indicators with their source
object, and tagged without a score.

Decoded streams starting with PE, ELF, ZIP, RAR, 7z, OLE or PDF magic are extracted for
Assemblyline's other services, de-duplicated and capped by `max_extracted_payloads`. The full
JSON report is attached as a supplementary file. The service emits tags and heuristics only, no
result ontology part.

The service works offline (`allow_internet_access: false`): pdfstudio's `--hunt` modes are never
used, and no URL is resolved or fetched.

## Heuristics

| ID | Name | Score | Notes |
|----|------|-------|-------|
| 1 | High Severity PDF Indicator | 1000 | Per-rule scores (`uri_to_executable` 300); ATT&CK T1204 |
| 2 | Medium Severity PDF Indicator | 500 | Link-target rules score 100 |
| 3 | Low Severity PDF Indicator | 100 | |
| 4 | Informational PDF Observation | 0 | |
| 5 | Catalog Trigger Path | 500 | Chains reaching JavaScript or Launch; ATT&CK T1204 |
| 6 | Multi-Revision Weaponization | 750 | ATT&CK T1027 |
| 7 | PDF Parse Anomaly | 100 | |

## Installation and configuration

In Assemblyline, open Administration → Services → Add service and paste `service_manifest.yml`.
No API key is needed.

| Setting | Default | Meaning |
|---|---|---|
| `internal_timeout` | `110` | pdfstudio timeout in seconds; keep it below the service `timeout`. |
| `max_iocs` | `200` | Maximum indicators tagged per type. |
| `max_extracted_payloads` | `30` | Maximum embedded payloads extracted per file. |

The submission parameter `show_object_table` (default `false`, on for deep scans) adds a full
PDF object table.

pdfstudio is pinned to a commit (`PDFSTUDIO_COMMIT` in the Dockerfile), reported in the tool
version (for example `pdfstudio 0.1.0+75cf957`), so upgrading it makes Assemblyline re-analyse
cached files.

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
