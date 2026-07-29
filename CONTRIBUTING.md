# Contributing

Contributions must preserve the evidence-first and fail-closed contract.

## Required workflow

1. Reproduce the behavior or demonstrate the validation gap.
2. Add the smallest regression test that fails before the fix.
3. Fix the root cause without weakening a gate or hiding a diagnostic.
4. Run:

   ```bash
   npm ci --ignore-scripts
   npm audit --audit-level=high
   npm run validate
   npm test
   ```

5. Describe the evidence, risk, and verification in the pull request.

Do not commit credentials, personal paths, debug logs, generated evidence reports, or active
diagnostic-suppression directives.
