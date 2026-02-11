# PHP Project

This directory is reserved for the standalone PHP security pipeline project.

## Workflows

- `.github/workflows/php-devsecops.yml`

## Tools in Pipeline

- SCA: `composer audit`, `trivy fs`
- SAST: `semgrep`, PHP syntax lint
- DAST: `OWASP ZAP`
- Secrets: `gitleaks`, `trufflehog`
- Container scan: `trivy image`
