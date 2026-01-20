# Aegis Forge

Aegis Forge is a **safe-by-default, static forensic analysis tool** for the initial assessment of suspicious files and archives. It is designed to extract **verifiable evidence** (strings, IOCs, structural metadata) **without ever executing the target**.

Aegis Forge is intended to operate as the **static malware analysis component** inside a larger **SOC / DFIR / agentic IR workflow**.

---

## Design Principles

- **Static-only**: No execution, no emulation, no unpacking.
- **Evidence-first**: Outputs facts, not verdicts.
- **Deterministic**: Same input → same output.
- **Bounded & Safe**: Explicit limits on bytes, members, and parsing depth.
- **Forensics-friendly**: Input files are never modified.

---

## Current Capabilities

### Analysis Features
- **File Types**: Raw binaries (PE), ZIP archives, and RAR archives.
- **Strings & IOCs**: ASCII and UTF-16LE extraction with URL, IPv4, and Domain detection.
- **PE Structural Parsing**: Sections, imports, exports, and resource metadata.
- **Fingerprinting**: SHA-256, MD5, and industry-standard **imphash**.
- **Reliability Guardrails**: Protection against zip bombs, large files, and long-running extractions via timeouts and resource limits.

### Archive Handling
- **Non-Invasive**: Streams member bytes **in memory** (no disk extraction).
- **Backend Support**: Utilizes `python-zipfile` and `7z`/`7zz` for RAR and AES-encrypted ZIPs.
- **Provenance Tracking**: Every member's extraction method and encryption status is explicitly recorded.
- **Resource Caps**: Enforces cumulative byte limits and decompression ratio checks.

### Batch Processing
- **Directory Scanning**: Walk entire directories (recursive or flat) to process multiple samples.
- **Resilient Execution**: Individual scan failures do not stop the batch process.
- **Standardized Metadata**: Generates a self-contained ZIP bundle per sample with `manifest.json`, `bundle.json`, and `summary.csv`.

---

## What Aegis Forge Does *Not* Do

- ❌ No dynamic analysis or sandboxing.
- ❌ No exploitation or automatic unpacking.
- ❌ No automatic malware classification or verdicts.
- ❌ No network access or cloud lookups.
- ❌ No recursive archive scanning (only processes the first level of members).

---

## Requirements

- **Python 3.10+**
- **p7zip (`7z` or `7zz`)** required for RAR and AES-ZIP support.

### System Dependencies

#### macOS
```bash
brew install p7zip
```

#### Ubuntu / Debian
```bash
sudo apt update && sudo apt install -y p7zip-full
```

---

## Installation

```bash
# Recommended: use a virtual environment
python -m venv venv
source venv/bin/activate

pip install -e .
```

---

## Usage

### Basic Scan
```bash
aegis scan path/to/sample.exe --outdir ./output
```

### Batch Mode
```bash
aegis scan path/to/samples_dir --recursive --non-interactive --outdir ./batch_results
```

### Archive Passwords
```bash
# Provide a password for encrypted archives
aegis scan sample.zip --password infected
```

---

## Role in an Agentic IR Workflow

Aegis Forge is designed to be the **Forensic Data Producer**. It emits:
- **Evidence Bundles**: Canonical, verifiable JSON artifacts.
- **Deterministic Observations**: Stable facts suitable for downstream analysis agents (e.g., correlation, enrichment, or decision gates).

---

## Versioning Policy

Aegis Forge follows a strict schema versioning policy for its JSON outputs:
- **Major**: Breaking changes to the JSON structure or core logic.
- **Minor**: New fields or backward-compatible schema enhancements.
- **Patch**: Internal fixes that do not affect the output schema.

## Roadmap
- [ ] TOON (Targeted Object Observation Notation) adapter output.
- [ ] Direct integration with YARA scanning rules.
- [ ] Parallelized batch processing for high-volume ingestion.

---

## Disclaimer
Aegis Forge is a defensive analysis tool intended for lawful security research and incident response.
