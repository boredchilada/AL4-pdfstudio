# Assemblyline service: PdfStudio

Static structural analysis of PDF files for Assemblyline v4. The service wraps
[pdfstudio](https://github.com/boredchilada/pdfstudio), a read-only PDF analyzer
written with the Python standard library only, in the style of PEstudio.

## What it does

For every `document/pdf` submission the service runs `pdfstudio --json` and turns
the report into Assemblyline results.

pdfstudio's 30+ structural rules produce detection flags, which the service groups by
severity and scores through heuristics. They cover embedded executables
(`EMBEDDED_PE`, `EMBEDDED_ELF`, `EMBEDDED_ZIP`), launch and command actions
(`LAUNCH_CMD`), auto-executing JavaScript (`OPENACTION_JS`), high-entropy streams,
object-stream and xref anomalies, and encryption.

The catalog-graph walk lists every trigger chain, such as `/OpenAction` →
`/JavaScript`. Heuristic 5 scores only the chains that reach a JavaScript or Launch
action. Links, form widgets and open-at-page actions are common in benign documents,
so they are listed but not scored.

Incremental updates that add or rewrite objects are reported per revision, and
malformed or evasive structure shows up as parse anomalies.

URLs, domains and IPs found in the raw bytes are tagged as `network.static.uri`,
`network.static.domain` and `network.static.ip`. Common XMP and metadata namespaces
are safelisted.

Decoded object streams that start with PE, ELF, ZIP, RAR, 7z, OLE or PDF magic are
carved out with `add_extracted()`, so the rest of the service fleet scans them: an
embedded PDF comes back to this service, an embedded PE goes to your PE and antivirus
services. Carved payloads are de-duplicated by SHA-256 and capped by
`max_extracted_payloads`.

The full JSON report is attached as a supplementary file.

## Machine-readable output and ontology

Findings are exported as tags (`network.static.*`) and as heuristics with a
`signature_score_map` and ATT&CK `attack_id`, which is the machine-readable layer that
fits a static analyzer. The service emits no Result Ontology part. The Assemblyline
ontology models describe observed behaviour (`NetworkConnection`, `Sandbox`,
`Process`, `Antivirus`) or signature-engine hits (`Signature.type` is restricted to
`SURICATA|SIGMA|YARA|CUCKOO`), and none of them fit pdfstudio's structural findings.
The CCCS PDF services (`pdfid`, `peepdf`) omit ontology for the same reason. YARA
scanning is left to Assemblyline's YARA service.

## Network policy

The service works offline: `allow_internet_access` is `false`, and pdfstudio's network
enrichment modes (`--hunt`, `--hunt-vt`, `--hunt-mb`) are never invoked. IOC
extraction is limited to cleartext in the file, so URIs hidden in compressed streams
are not recovered.

## Heuristics

| ID | Name | Score | Notes |
|----|------|-------|-------|
| 1 | High Severity PDF Indicator | 1000 | `signature_score_map` per rule code; ATT&CK T1204 |
| 2 | Medium Severity PDF Indicator | 500 | |
| 3 | Low Severity PDF Indicator | 100 | |
| 4 | Informational PDF Observation | 0 | |
| 5 | Catalog Trigger Path | 500 | Only triggers reaching JavaScript or Launch; ATT&CK T1204 |
| 6 | Multi-Revision Weaponization | 750 | ATT&CK T1027 |
| 7 | PDF Parse Anomaly | 100 | |

## Installation

In Assemblyline, open Administration → Services → Add service and paste
`service_manifest.yml`. The manifest points at the container image built for each
release.

## Submission parameters

- `show_object_table` (bool, default `false`): include a full PDF object table. Deep
  scan submissions enable it automatically.

## Config (`self.config`)

- `internal_timeout` (default `110`): subprocess timeout; keep it below `timeout`.
- `max_iocs` (default `200`): maximum IOCs tagged per type.
- `max_extracted_payloads` (default `30`): maximum embedded payloads carved per file.

## Versioning and releases

The manifest carries `version: $SERVICE_TAG`, and the Dockerfile stamps the real
version at build time. Releases are git tags: `v4.7.0.devN` for test builds and
`v4.7.0.stableN` for releases. CI builds, tests and publishes the image for each tag.

pdfstudio is installed at a pinned commit (`PDFSTUDIO_COMMIT` in the Dockerfile). The
service reports that commit in its tool version, for example `pdfstudio 0.1.0+75cf957`,
so a library upgrade makes Assemblyline re-run cached files.

## Tests

```bash
bash scripts/build-image.sh al4-pdfstudio:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-pdfstudio:test podman
```

The gate runs Ruff, Pyright and pytest inside the built image: unit tests of
`pdfstudio_/analysis.py`, manifest checks, and sample regression tests. The seven
samples in `tests/samples/` are synthetic, harmless PDFs (CaRT-encoded) built with
pdfstudio's own test builders: a minimal PDF, a `/Launch` action, `/OpenAction`
JavaScript, a link to an `.exe`, an `MZ` header stub in a stream, an incremental
update, and a benign PDF with an internal link and an open-at-page action that must
score 0.

## Layout

```
pdfstudio_/
  analysis.py     pure helpers: flag mapping, IOC extraction, payload sniffing
  service.py      class PdfStudio(ServiceBase)
tests/            unit, manifest and sample tests, samples/ and results/
scripts/          build-image.sh, ci-gate.sh, gentests.py
service_manifest.yml, Dockerfile, pkglist.txt, requirements.txt, pyproject.toml
```
