# Codex and Agents Debug Mode

An evidence-first debugging and GitHub pull-request cleanup skill for Codex-compatible and
Agents-compatible skill loaders.

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

## Safety

The skill is fail-closed. Missing infrastructure, uncertain process ownership, incomplete GitHub
evidence, skipped checks, warning output, stale artifacts, and unverifiable service health block a
clean result.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT. See [LICENSE](LICENSE).
