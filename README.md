# Codex and Agents Debug Mode

[![Validate](https://github.com/XGenerationy/codex-agents-debug-mode/actions/workflows/validate.yml/badge.svg)](https://github.com/XGenerationy/codex-agents-debug-mode/actions/workflows/validate.yml)

An independent, community-maintained, evidence-first debugging and GitHub pull-request cleanup
skill for Codex-compatible and Agents-compatible skill loaders.

The workflow follows one rule:

```text
Do not guess -> hypothesize -> instrument -> reproduce -> analyze -> fix -> verify
```

It covers:

- runtime and frontend debugging with an authenticated local evidence collector;
- systematic test, build, and error recovery;
- live GitHub pull-request inspection and cleanup;
- a deterministic 19-check PR closeout gate;
- suppression detection, secret redaction, repository sealing, and race-aware GitHub attestation.

## Project status

The skill implementation is introduced through a reviewed pull request so the public repository
retains a clear, auditable publication history.

## Automatic triggers

The skill declares implicit invocation for:

- `cleanup GitHub` and `clean up GitHub`;
- `bug`, `debug`, and `fix a bug`;
- failing tests, broken builds, and unexpected errors;
- PR cleanup, review comments, and failing PR checks.

## Install

Node.js 20 or newer is required for the bundled collector, closeout runner, and tests.

### PowerShell

```powershell
git clone https://github.com/XGenerationy/codex-agents-debug-mode.git
cd codex-agents-debug-mode
.\tools\install.ps1 -Target Both
```

If a target already exists, rerun with `-Force`. The installer renames the existing target to a
timestamped backup before installing the new copy.

### Bash

```bash
git clone https://github.com/XGenerationy/codex-agents-debug-mode.git
cd codex-agents-debug-mode
bash ./tools/install.sh --target both
```

Use `--force` to preserve an existing target as a timestamped backup and replace it.

Supported targets:

- Codex: `~/.codex/skills/debug`
- Agents: `~/.agents/skills/debug`

Only the skill payload is installed: `SKILL.md`, `agents/`, `assets/`, `references/`, and
`scripts/`. Repository governance and CI files are not copied into the skill directory.

## Validate

The repository has no runtime npm dependencies.

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
npm run validate
npm test
```

CI runs the same checks on Windows and Linux with supported Node.js versions. The repository
validator checks the payload shape, metadata, automatic-trigger contract, JSON assets, JavaScript
syntax, and public-distribution safety.

The 19-check application PR gate is intentionally stricter than this repository's own package
validation. When the skill is used against an application repository, missing Prisma, Redis,
Grafana, Hunter, browser, or independent-review evidence must be reported honestly rather than
converted into a pass.

## Safety

The skill is fail-closed. Missing infrastructure, uncertain process ownership, incomplete GitHub
evidence, skipped checks, warning output, stale artifacts, and unverifiable service health block a
clean result.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with or endorsed by OpenAI, Cursor, or any other referenced product
vendor. See [NOTICE.md](NOTICE.md).
