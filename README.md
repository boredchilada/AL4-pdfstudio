# Assemblyline service: PdfStudio

Static structural analysis of PDF files for Assemblyline v4, wrapping
[pdfstudio](https://github.com/boredchilada/pdfstudio) — a read-only, stdlib-only
PDF analyzer ("PEstudio-style" structure browsing).

## What it does

For every `document/pdf` submission the service runs `pdfstudio --json` and turns
the report into Assemblyline results:

- **Detection flags** (30+ structural rules) grouped by severity and scored via
  heuristics — embedded executables (`EMBEDDED_PE`/`ELF`/`ZIP`), launch/command
  actions (`LAUNCH_CMD`), auto-executing JavaScript (`OPENACTION_JS`), high-entropy
  streams, object-stream/xref anomalies, encryption, etc.
- **Catalog trigger paths** — the catalog-graph walk's automatic trigger chains
  (e.g. `/OpenAction` → active content).
- **Per-revision weaponization** — incremental updates that add/rewrite objects.
- **Parse anomalies** — malformed/evasive structure warnings.
- **Cleartext IOCs** — URLs/domains/IPs extracted from raw bytes and tagged
  (`network.static.uri|domain|ip`), with common XMP/metadata namespaces safelisted.
- **Embedded payload extraction** — decoded object streams are sniffed for
  PE/ELF/ZIP/RAR/7z/OLE/PDF magic and carved out via `add_extracted()` so they are
  recursively re-scanned by the rest of the service fleet (an embedded PDF re-enters
  this service, an embedded PE goes to your PE/AV services, etc.). De-duplicated by
  MD5 and capped by `max_extracted_payloads`.
- The full JSON report is attached as a supplementary file.

## Machine-readable output / ontology

This service exports findings as **tags** (`network.static.*`) and **heuristics** with
`signature_score_map` + MITRE `attack_id` — the correct machine-readable layer for a
*static* analyzer (these feed AL's correlation engine and SIEM export). It deliberately
emits **no Result Ontology** part: the AL ontology models describe dynamic/observed
behaviour (`NetworkConnection`, `Sandbox`, `Process`, `Antivirus`) or signature-engine
hits (`Signature.type` is restricted to `SURICATA|SIGMA|YARA|CUCKOO`), none of which fit
pdfstudio's structural heuristics. The closest CCCS PDF services (`pdfid`, `peepdf`)
omit ontology for the same reason. A `Signature` ontology part would only become
appropriate if YARA scanning (`pdfstudio --yara`) were wired to AL's signature updater.

## Network policy

The service is **offline by design**: `allow_internet_access: false` and pdfstudio's
network enrichment modes (`--hunt`, `--hunt-vt`, `--hunt-mb`) are never invoked. IOC
extraction is limited to cleartext in the file; URIs hidden in compressed streams are
not recovered.

## Heuristics

| ID | Name | Score | Notes |
|----|------|-------|-------|
| 1 | High Severity PDF Indicator | 1000 | `signature_score_map` per rule code; ATT&CK T1204 |
| 2 | Medium Severity PDF Indicator | 500 | |
| 3 | Low Severity PDF Indicator | 100 | |
| 4 | Informational PDF Observation | 0 | |
| 5 | Catalog Trigger Path | 500 | ATT&CK T1204 |
| 6 | Multi-Revision Weaponization | 750 | ATT&CK T1027 |
| 7 | PDF Parse Anomaly | 100 | |

## Submission parameters

- `show_object_table` (bool, default `false`) — include a full PDF object table.
  Also enabled automatically on deep-scan submissions.

## Config (`self.config`)

- `internal_timeout` (default `110`) — subprocess timeout; keep below `timeout`.
- `max_iocs` (default `200`) — max IOCs tagged per type.
- `max_extracted_payloads` (default `30`) — max embedded payloads carved per file.

## Versioning

The version is **hardcoded** in `service_manifest.yml` in two places that must always
match: the top-level `version:` and the `docker_config.image:` tag. Bump both together
when releasing. (This differs from upstream CCCS `$SERVICE_TAG` patching, to suit the
in-house CI and AL 4.7 Rust `service_server`, which also requires `attack_id` to be a
YAML list.)

## Build & publish

Pushing to `main` triggers `.github/workflows/docker-publish.yml`, which reads
`version:` from the manifest and pushes `ghcr.io/boredchilada/al4-pdfstudio:<version>`
and `:latest`. (GHCR lowercases the repo name, so `AL4-pdfstudio` → `al4-pdfstudio`.)

Local build:

```bash
docker build -t ghcr.io/boredchilada/al4-pdfstudio:4.7.0.1 .
# Optional reproducible pin of the upstream tool:
#   docker build --build-arg PDFSTUDIO_REF=<commit-sha> -t ghcr.io/boredchilada/al4-pdfstudio:4.7.0.1 .
```

Then register the service in Assemblyline (UI → Administration → Services → Add, paste
the manifest) pointing at the pushed image tag.

## Tests

```bash
pip install -r tests/requirements.txt
# Unit tests (helpers only, no samples needed):
pytest tests/test_pdfstudio_unit.py
# Sample regression: add PDFs to tests/samples/, generate golden results with the
# assemblyline-service-utilities TestHelper, commit tests/results/, then:
pytest tests/test_pdfstudio_samples.py
```

## Layout

```
pdfstudio/
├── Dockerfile
├── service_manifest.yml
├── requirements.txt
├── pkglist.txt
├── pyproject.toml
├── README.md
├── LICENSE
├── pdfstudio_/
│   ├── __init__.py
│   └── pdfstudio_.py        # class PdfStudio(ServiceBase)
└── tests/
    ├── __init__.py
    ├── requirements.txt
    ├── test_pdfstudio_unit.py
    ├── test_pdfstudio_samples.py
    └── results/
```
