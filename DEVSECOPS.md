# DevSecOps Pipeline Guide

This project includes a full GitHub Actions pipeline at `.github/workflows/devsecops.yml`.

## Tool coverage in pipeline

- `flake8` (Lint/format checks): code style and basic quality checks.
- `pylint` (SAST): static code analysis for Python issues and insecure patterns.
- `python manage.py test` (Unit tests): validates application behavior.
- `OWASP Dependency-Check` (SCA): detects known CVEs in dependencies.
- `safety` (SCA): checks `requirements.txt` packages for Python vulnerabilities.
- `Trivy fs` (SCA): scans project dependencies (`vuln-type=library`).
- `semgrep` (SAST): rule-based code security checks, exported as SARIF.
- `gitleaks` (Secrets scanning): detects leaked secrets in git/workspace content.
- `trufflehog` (Secrets scanning): finds high-entropy and verified credential leaks.
- `Trivy image` (Container image scanning): scans built Docker image for OS and library vulnerabilities.
- `OWASP ZAP baseline` (DAST): scans a running app endpoint for web vulnerabilities.

## Local run commands

Run these from `python/pygoat` unless noted.

### 1) Install dependencies and tools

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install flake8 pylint "safety<3" semgrep
```

### 2) Linting and unit tests

```bash
flake8 . --statistics --count
pylint challenge introduction pygoat manage.py
python manage.py test --verbosity 2
```

### 3) SCA scans

```bash
safety check -r requirements.txt --full-report
trivy fs --scanners vuln --vuln-type library --severity CRITICAL,HIGH,MEDIUM .
```

For OWASP Dependency-Check locally (example using Docker):

```bash
docker run --rm -v "$PWD:/src" owasp/dependency-check:latest \
  --scan /src --format HTML --out /src/reports/dependency-check
```

### 4) Container build and scan

From repository root (`d:/Pipeline`):

```bash
docker build -t pygoat:ci -f python/pygoat/Dockerfile python/pygoat
trivy image --severity CRITICAL,HIGH,MEDIUM pygoat:ci
```

### 5) Secrets scanning

From repository root (`d:/Pipeline`):

```bash
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest detect \
  --source=/repo --report-format sarif --report-path=/repo/python/pygoat/reports/gitleaks.sarif

docker run --rm -v "$PWD:/pwd" trufflesecurity/trufflehog:latest filesystem \
  --directory=/pwd --json > python/pygoat/reports/trufflehog.json
```

### 6) SAST with Semgrep

```bash
semgrep scan --config auto .
```

### 7) DAST with OWASP ZAP

From repository root (`d:/Pipeline`):

```bash
docker run --rm --name pygoat-migrate pygoat:ci python manage.py migrate --noinput
docker run -d --name pygoat-app -p 8000:8000 pygoat:ci
docker run --rm --network host -v "$PWD/python/pygoat/reports:/zap/wrk" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://127.0.0.1:8000 -r zap-report.html -J zap-report.json -x zap-report.xml
docker rm -f pygoat-app
```

## Report outputs

Pipeline artifacts are uploaded from `python/pygoat/reports/`, including:

- `summary.md` (consolidated findings table for all tools)
- `flake8.txt`
- `pylint.txt`
- `unit-tests.txt`
- `safety.json`, `safety.txt`
- `semgrep.sarif`
- `trivy-deps.sarif`
- `trivy-image.txt`, `trivy-image.sarif`
- `gitleaks.sarif`
- `trufflehog.json`
- `dependency-check/*` (HTML/JSON/JUNIT)
- `zap-report.html`, `zap-report.json`, `zap-report.xml`, `zap-warnings.md`

The same consolidated summary is also published directly in the GitHub Actions run page via the job summary (`$GITHUB_STEP_SUMMARY`).
