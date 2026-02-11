# ReactJS Project

This directory is reserved for the standalone ReactJS security pipeline project.

## Workflows

- `.github/workflows/reactjs-devsecops.yml`
- `.github/workflows/reactjs-codeql.yml`

## Planned Tools

- SCA: `npm audit`, `trivy fs`
- SAST: `semgrep`, `eslint`
- DAST: `OWASP ZAP` (when a runnable React web target is added)
- Secrets: `gitleaks`, `trufflehog`
- Container scan: `trivy image` (when Dockerfile/image is added)
