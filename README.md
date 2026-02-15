# Security Pipelines Monorepo

This repository contains 3 independent training/demo projects, each with its own security CI workflows.

## Projects

1. `python/` - Python/Django (PyGoat-based)
2. `php/` - PHP vulnerable app
3. `reactjs/` - ReactJS vulnerable app

## Pipelines

All workflows live in `.github/workflows/` and are path-scoped so changes in one project do not trigger unrelated project pipelines.

| Workflow | Scope | Main Tools |
|---|---|---|
| `python-devsecops.yml` | `python/**` | Unit tests, Flake8, Pylint, Safety, pip-audit, Semgrep, Trivy FS, Trivy Image, Gitleaks, TruffleHog, OWASP ZAP baseline + full(active) |
| `php-devsecops.yml` | `php/VulnerableApp-php/**` | Semgrep, Trivy FS, Trivy Image, Gitleaks, TruffleHog, OWASP ZAP baseline + full(active) |
| `reactjs-devsecops.yml` | `reactjs/**` | npm audit, Semgrep, Trivy FS, Trivy Image, Gitleaks, TruffleHog, OWASP ZAP baseline + full(active) |
| `python-codeql.yml` | `python/**` | GitHub CodeQL |
| `reactjs-codeql.yml` | `reactjs/**` | GitHub CodeQL |
| `python-flake8.yml` | `python/**` | Flake8 |
| `python-hadolint.yml` | Dockerfile-focused checks | Hadolint |

## DevSecOps Workflow Details

### Python (`python-devsecops.yml`)

- SAST:
  - `semgrep` (SARIF)
  - `pylint`
  - `flake8`
- SCA:
  - `safety`
  - `pip-audit`
  - `trivy` filesystem scan (SARIF)
  - `trivy` image scan (table + SARIF)
- Secrets:
  - `gitleaks` (SARIF)
  - `trufflehog` (JSON)
- DAST:
  - OWASP ZAP baseline (passive)
  - OWASP ZAP full scan (active, spider `-m 5`, alpha rules `-a`)
- Reports:
  - baseline copy: `zap-baseline-report.*`, `zap-baseline-warnings.md`
  - full/final: `zap-report.html`, `zap-report.json`, `zap-report.xml`, `zap-warnings.md`
  - consolidated markdown: `summary.md`

### PHP (`php-devsecops.yml`)

- SAST:
  - `semgrep` (SARIF)
- SCA:
  - `trivy` filesystem scan (SARIF)
  - `trivy` image scan (SARIF)
- Secrets:
  - `gitleaks` (SARIF)
  - `trufflehog` (JSON)
- DAST:
  - OWASP ZAP baseline (passive)
  - OWASP ZAP full scan (active, spider `-m 5`, alpha rules `-a`)
- Reports:
  - baseline copy: `zap-baseline-report.*`, `zap-baseline-warnings.md`
  - full/final: `zap-report.html`, `zap-report.json`, `zap-report.xml`, `zap-warnings.md`
  - consolidated markdown: `summary.md`

### ReactJS (`reactjs-devsecops.yml`)

- SAST:
  - `semgrep` (SARIF)
- SCA:
  - `npm audit` (JSON + text)
  - `trivy` filesystem scan (SARIF)
  - `trivy` image scan (SARIF)
- Secrets:
  - `gitleaks` (SARIF)
  - `trufflehog` (JSON)
- DAST:
  - OWASP ZAP baseline (passive)
  - OWASP ZAP full scan (active, spider `-m 5`, alpha rules `-a`)
- Reports:
  - baseline copy: `zap-baseline-report.*`, `zap-baseline-warnings.md`
  - full/final: `zap-report.html`, `zap-report.json`, `zap-report.xml`, `zap-warnings.md`
  - consolidated markdown: `summary.md`

## Notes

- Workflows are currently non-blocking for many security checks (`continue-on-error: true`) to maximize report collection.
- Security findings in these projects can include intentionally vulnerable training scenarios.
