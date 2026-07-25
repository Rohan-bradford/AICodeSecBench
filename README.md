# AICodeSecBench

**Static Analysis of AI-Generated Code**

AICodeSecBench is a small, reproducible benchmark for comparing security findings across
synthetic AI-attributed Python, JavaScript, and TypeScript code snippets.

The project is inspired by the 2025 paper **“Security Vulnerabilities in AI-Generated Code:
A Large-Scale Analysis of Public GitHub Repositories.”** That study analysed 7,703
AI-attributed files from public repositories and used CodeQL to identify 4,241 CWE instances
across 77 vulnerability types. It also reported higher vulnerability rates for Python than
JavaScript and TypeScript in its dataset.

This repository reproduces the workflow safely at a smaller scale:

1. Maintain a small labelled dataset of AI-attributed code snippets.
2. Run static analysis with internal pattern checks.
3. Optionally run Bandit and Semgrep locally.
4. Import CodeQL SARIF output when available.
5. Normalize findings into a common CWE-focused format.
6. Compare vulnerability types by language.
7. Generate JSON, Markdown, CSV, and HTML dashboard reports.

## Quick Start

```bash
git clone https://github.com/Rohan-bradford/AICodeSecBench.git
cd AICodeSecBench
python -m pip install -e ".[dev]"
python -m aicodesecbench.cli run --dataset dataset --out reports
```

Open:

```text
reports/aicodesecbench-report.md
reports/aicodesecbench-dashboard.html
```

## Run Optional Tools

Bandit:

```bash
python -m pip install bandit
python -m aicodesecbench.cli run --dataset dataset --out reports --with-bandit
```

Semgrep:

```bash
python -m pip install semgrep
python -m aicodesecbench.cli run \
  --dataset dataset \
  --out reports \
  --with-semgrep \
  --semgrep-rules rules/semgrep
```

CodeQL:

```bash
python -m aicodesecbench.cli run \
  --dataset dataset \
  --out reports \
  --codeql-sarif path/to/codeql-results.sarif
```

CodeQL is easiest to run through GitHub Actions. See
[.github/workflows/security-tools.yml](.github/workflows/security-tools.yml).

## Dataset

The included dataset is synthetic and intentionally vulnerable. It is not copied from real
repositories and contains no real secrets.

```text
dataset/
  python/
  javascript/
  typescript/
  metadata.json
```

Current sample coverage:

| Language | Example CWE categories |
| --- | --- |
| Python | Command injection, SQL injection, debug mode, hardcoded secret, weak hash, unsafe deserialization |
| JavaScript | Command execution, `eval`, DOM XSS, hardcoded secret |
| TypeScript | Command execution, unvalidated input, hardcoded secret |

## Reports

Generated files:

```text
aicodesecbench-report.json
aicodesecbench-report.md
aicodesecbench-dashboard.html
aicodesecbench-findings.csv
```

The report answers:

- Which language had the most findings?
- Which CWEs appeared most often?
- Which static analysis tool produced each finding?
- Which file and line triggered the result?

## GitHub Actions

The default CI workflow runs:

- package installation
- tests
- internal benchmark scan
- report generation

The optional security workflow runs:

- CodeQL
- Bandit
- Semgrep
- report artifact upload

## Scope

This is a small educational reproduction of the analysis workflow, not a replacement for the
paper’s large-scale empirical dataset. Results from the synthetic seed dataset should not be
generalized to all AI-generated code.

## Verification

```bash
ruff check .
pytest
python -m aicodesecbench.cli run --dataset dataset --out reports
```

## References

- arXiv paper page:
  https://arxiv.org/abs/2510.26103
- CodeQL:
  https://codeql.github.com/
- Bandit:
  https://bandit.readthedocs.io/
- Semgrep:
  https://semgrep.dev/docs/
- CWE:
  https://cwe.mitre.org/

## License

MIT
