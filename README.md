# appsec-pipeline

A free, production-ready SAST/SCA security scanning pipeline built on GitHub Actions. No GHAS license required. No stored credentials. Runs on every push.

Built from real-world implementation experience securing enterprise GitHub environments.

---

## What It Does

Runs five security scanners in parallel on every push and pull request:

| Tool | What It Catches |
|---|---|
| [Semgrep](https://semgrep.dev) | SAST — code-level security bugs, injection flaws, misconfigurations |
| [Bandit](https://bandit.readthedocs.io) | Python-specific security issues |
| [Betterleaks](https://github.com/search?q=betterleaks) | Secrets and credential detection |
| [pip-audit](https://pypi.org/project/pip-audit/) | Python dependency vulnerabilities (CVE matching) |
| [Checkov](https://www.checkov.io) | IaC misconfigurations — Terraform, CloudFormation, Kubernetes |

Results are uploaded to a configurable storage backend and optionally surfaced in pull request comments.

---

## Architecture

```
push / pull_request
        │
        ▼
┌───────────────────────────────────────┐
│         GitHub Actions Runner          │
│                                       │
│  ┌─────────┐  ┌─────────┐  ┌───────┐ │
│  │ Semgrep │  │ Bandit  │  │ pip-  │ │
│  │         │  │         │  │ audit │ │
│  └────┬────┘  └────┬────┘  └───┬───┘ │
│       │            │           │     │
│  ┌────┴────┐  ┌────┴────┐      │     │
│  │Betterlea│  │ Checkov │      │     │
│  │   ks    │  │         │      │     │
│  └────┬────┘  └────┬────┘      │     │
│       └────────────┴───────────┘     │
│                   │                  │
│          OIDC Auth (no secrets)      │
│                   │                  │
│          Results Storage Backend     │
└───────────────────────────────────────┘
```

---

## Secretless Authentication

This pipeline uses **OIDC/Workload Identity Federation** — no stored credentials, no PATs, no service account keys in GitHub Secrets.

The runner authenticates to your cloud storage backend at runtime using a short-lived OIDC token. See [setup guide](docs/oidc-setup.md) for configuration steps.

---

## Quick Start

### 1. Copy the workflow

```bash
cp .github/workflows/security-scan.yml YOUR_REPO/.github/workflows/
```

### 2. Configure your environment

Set the following in your repository or organization variables:

```
AZURE_CLIENT_ID        # App registration client ID (for Azure backend)
AZURE_TENANT_ID        # Your Azure tenant ID
AZURE_SUBSCRIPTION_ID  # Your Azure subscription ID
STORAGE_ACCOUNT_NAME   # Azure Blob Storage account name
STORAGE_CONTAINER_NAME # Container for scan results
```

### 3. Push and watch it run

Every push to any branch triggers the full scan. Pull requests get a summary comment.

---

## Repository Structure

```
appsec-pipeline/
├── .github/
│   └── workflows/
│       └── security-scan.yml      # Main pipeline workflow
├── config/
│   ├── semgrep-rules.yml          # Custom Semgrep rule configuration
│   ├── bandit.yml                 # Bandit configuration
│   └── checkov-skip.yml           # Checkov skip list for known exceptions
├── docs/
│   ├── oidc-setup.md              # OIDC/WIF setup guide (Azure)
│   ├── results-schema.md          # Output format documentation
│   └── adding-scanners.md         # How to extend the pipeline
├── scripts/
│   └── parse_results.py           # Result aggregation and reporting script
└── README.md
```

---

## Extending the Pipeline

The pipeline is modular. Each scanner runs as an independent job. To add a new scanner:

1. Add a new job block in `security-scan.yml`
2. Add its config file under `config/`
3. Update `parse_results.py` to handle its output format

See [adding-scanners.md](docs/adding-scanners.md) for a full walkthrough.

---

## Why Free Tier?

GitHub Advanced Security (GHAS) costs ~$49/user/month. For organizations that can't justify that spend, this pipeline delivers meaningful SAST/SCA coverage at zero additional licensing cost using open-source tooling and native GitHub Actions.

---

## Background

Built and deployed in a production enterprise environment securing a GitHub Enterprise Cloud organization with multiple repositories and development teams. The pipeline runs on every push with results stored and tracked over time for trend analysis.
