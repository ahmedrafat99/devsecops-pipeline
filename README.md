# Security Pipelines Monorepo

This repository is organized as independent security-testing projects.  
Each project has its own CI/CD security workflows and does not depend on the others.

## Projects

- `python/`: Python/Django project (PyGoat-based) with dedicated DevSecOps and CodeQL workflows.
- `php/`: PHP project area with a dedicated DevSecOps workflow.
- `reactjs/`: ReactJS project area with dedicated DevSecOps and CodeQL workflows.

## Workflow Isolation

Workflows are split per project and use path filters:

- Python workflows run only for `python/**`
- PHP workflows run only for `php/**`
- ReactJS workflows run only for `reactjs/**`

Workflows are stored in `.github/workflows/` and prefixed by project name:

- `python-*`
- `php-*`
- `reactjs-*`
