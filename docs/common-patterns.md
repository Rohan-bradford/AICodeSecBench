# Common Patterns

## Python

- `subprocess` with `shell=True`
- SQL queries built with string interpolation
- Flask debug mode in executable app entrypoints
- hardcoded credential-like values
- weak hash algorithms
- unsafe pickle deserialization

## JavaScript

- `child_process.exec` with untrusted command strings
- `eval`
- `innerHTML` assignment with unsanitized data
- hardcoded credential-like values

## TypeScript

- `execSync`
- unvalidated `any` input
- hardcoded credential-like values

## Review Guidance

For every finding, ask:

- Is the input attacker-controlled?
- Is the code reachable in production?
- Is there validation, escaping, or sandboxing?
- Does the static tool understand the framework context?
- Is the CWE mapping accurate?

