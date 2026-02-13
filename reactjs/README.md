# ReactJS Project

This directory contains the standalone ReactJS security pipeline project:

- `reactjs/CVE-2025-55182` (cloned from `https://github.com/l4rm4nd/CVE-2025-55182.git`)

## Workflows

- `.github/workflows/reactjs-devsecops.yml`
- `.github/workflows/reactjs-codeql.yml`

## Implemented Tools (DevSecOps)

- SCA: `npm audit`, `trivy fs`
- SAST: `semgrep`
- DAST: `OWASP ZAP baseline`
- Secrets: `gitleaks`, `trufflehog`
- Container scan: `trivy image`

## CodeQL Support

CodeQL supports JavaScript/TypeScript, so `reactjs-codeql.yml` is enabled for this project.
