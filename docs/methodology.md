# Methodology

## Goal

Build a small benchmark that mirrors the static-analysis workflow used in larger studies of
AI-attributed code:

1. Create or collect labelled code samples.
2. Run multiple static analysis tools.
3. Normalize tool-specific output.
4. Map findings to CWE categories.
5. Compare vulnerability patterns by language.
6. Write a short security report.

## Dataset Design

The committed seed dataset is synthetic. Each sample is labelled as
`ai-attributed-synthetic` and grouped by prompt family. This keeps the project safe and
reproducible while avoiding claims about real-world prevalence.

## Tooling

| Tool | Purpose |
| --- | --- |
| Internal patterns | Always-available baseline checks |
| Bandit | Python-focused security static analysis |
| Semgrep | Multi-language rule-based static analysis |
| CodeQL | Semantic analysis through SARIF import |

## Normalization

Every finding is converted into:

```text
tool
rule_id
CWE
language
file
line
severity
message
```

This allows results from different tools to be counted and compared consistently.

## Limitations

- The internal pattern scanner is deliberately simple.
- Static analysis can miss vulnerabilities and produce false positives.
- CWE mappings vary by tool and rule.
- Synthetic examples are not prevalence data.
- A larger study would require deduplication, provenance checks, and manual validation.

