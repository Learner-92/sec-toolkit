\# Web Audit Toolkit (SecToolkit)
[![Security Toolkit CI/CD & SAST Pipeline](https://github.com/Learner-92/sec-toolkit/actions/workflows/audit-pipeline.yml/badge.svg)](https://github.com/Learner-92/sec-toolkit/actions/workflows/audit-pipeline.yml)


A modular, lightweight Python-based command-line security auditing tool designed to automate baseline web application posture assessments.



\## Features

\- \*\*Security Headers Audit\*\*: Checks presence of critical headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).

\- \*\*Cookie Security Analysis\*\*: Flags missing `Secure`, `HttpOnly`, and `SameSite` attributes.

\- \*\*Form \& Input Inspector\*\*: Parses HTML to detect forms, action targets, and exposed `hidden` fields.

\- \*\*Reporting\*\*: Exports structured audit findings to JSON.



\## Installation

```bash

git clone <your-repo-url>

cd sec-tools

pip install -r requirements.txt

