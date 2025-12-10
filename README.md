# intellisa

> **Project Hub**: [IntelliSA](../00.IntelliSA) > **This repository**: Production-ready CLI toolkit
> See the hub for paper materials, artifact manifest, and links to all repositories.

## Overview

IaC security scanner implementing the **IntelliSA** method

**IntelliSA**: An Intelligent Analyzer for IaC Security Smell Detection via Rule and Neural Inference

**Supported technologies**: Ansible, Chef, Puppet
**Output formats**: SARIF (GitHub Code Scanning), JSONL, CSV, console table

## Quick Start

Requires Python 3.10+.

```bash
# Setup environment
python -m venv .venv && source .venv/bin/activate
pip install -U pip wheel
pip install -e .

# Fetch model weights
python -m intellisa.models.fetch IntelliSA-220m

# Scan a repository
intellisa --path ./examples/sample_repo --tech auto --format sarif --out artifacts/scan.sarif
```

**Exit codes**:

- `0` = no blocking findings
- `1` = findings detected (non-blocking unless `--fail-on-high`)
- `2` = runtime error

## Usage

```bash
intellisa --path /path/to/repo --tech auto --format sarif --out artifacts/scan.sarif
```

**Common options**:

- `--path` - Directory or file to scan (default: current directory)
- `--tech` - Technology: `auto|ansible|chef|puppet` (default: auto)
- `--format` - Output format: `sarif`, `json`, `csv`, `table` (repeatable)
- `--out` - Output path (directory or file prefix)
- `--postfilter` - Model name from `models/registry.yaml` (default: IntelliSA-220m)
- `--threshold` - Override model's default threshold
- `--fail-on-high` - Exit code 1 only for high-severity findings
- `--debug-log` - Write detailed trace to JSONL file

Run `intellisa --help` for all options.

## How IntelliSA Works

1. **Rule-Based Detection** scans IaC files for 9 security rules:

   - High-precision rules (empty password, invalid bind, etc.) → accepted directly
   - Noisy rules (HTTP without TLS, weak crypto, hardcoded secrets, suspicious comments) → neural inference

2. **Neural Inference** scores noisy detections as True Positive or False Positive

3. **Exporters** produce SARIF, JSONL, or CSV with only high-confidence findings

## Troubleshooting

**Stub model warning**:

```
Warning: falling back to deterministic stub model
```

**Fix**: Install PyTorch and transformers

The stub model produces deterministic but artificial scores for testing only.

## Repository Structure

```
├── apps/cli/              # Typer CLI entrypoint
├── packages/
│   ├── glitch_core/       # Rule-based detection engine
│   ├── glitch_adapter/    # Detection adapter
│   ├── postfilter_llm/    # IntelliSA-220m (neural inference)
│   ├── exporters/         # SARIF / JSONL / CSV
│   └── schema/            # Pydantic contracts
├── models/
│   ├── registry.yaml      # Model index
│   └── IntelliSA-220m/    # Champion model metadata
├── tests/
│   ├── unit/              # Module-level tests
│   └── e2e/               # End-to-end tests
└── examples/sample_repo/  # Minimal test repository
```

## Citation

If you use this tool in research, please cite:

```bibtex
PLACEHOLDER
```
