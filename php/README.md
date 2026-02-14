# PHP Project

This directory is reserved for the standalone PHP security pipeline project.

## Workflows

- `.github/workflows/php-devsecops.yml`
- `.github/workflows/php-codeql.yml`

## Planned Tools

- SCA: `composer audit`, `trivy fs`
- SAST: `semgrep`, PHP static analysis/lint tools
- DAST: `OWASP ZAP` (when a runnable PHP web target is added)
- Secrets: `gitleaks`, `trufflehog`
- Container scan: `trivy image` (when Dockerfile/image is added)
