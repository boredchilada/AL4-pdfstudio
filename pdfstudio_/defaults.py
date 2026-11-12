"""Default settings. service_manifest.yml repeats these; tests/test_settings.py keeps them equal."""

INTERNAL_TIMEOUT = 110
MAX_IOCS = 200
MAX_EXTRACTED_PAYLOADS = 30
SAFELIST_DOMAINS: list[str] = []

SHOW_OBJECT_TABLE = False
EXTRACT_PAYLOADS = True

# Seconds that must remain between the internal timeout and the service `timeout` in the manifest.
TIMEOUT_HEADROOM = 10
