# Contributing

## Ground rules

1. **This is a port, so semantics change only with evidence.** If you change the
   banned set, the allowed set, a detector, or the classification table, add a
   fixture repository that demonstrates the new behaviour and a test asserting it.
   "Cleaner" is not a reason; `docs/FINDINGS.adoc` shows what each deviation is
   for.
2. **Never fail open.** A new check must be able to fail. Prefer one loud
   `SCAN_FAILED` row over one silently-skipped repository.
3. **Stdlib only.** No new `[deps]`. `TOML` is here because the policy file is
   TOML. If you want linguist-quality detection, argue it in
   `docs/FINDINGS.adoc` §F5 terms: the current design is offline and
   deterministic by choice.
4. **Keep the CSV schema.** The columns and their order are the interface with
   every `estate-triage-report.csv` the estate already holds.

## Before opening a PR

```sh
julia --project=. -e 'using Pkg; Pkg.test()'
julia --project=. bin/proglanging.jl gate .
julia --project=. bin/proglanging.jl doctor
sh tools/check-containerfile.sh
```

Every command must exit 0. A DCO sign-off (`git commit -s`) on each commit.

## Commits

Conventional Commits, as the estate expects: `feat:`, `fix:`, `docs:`,
`chore:`, `ci:`. The body states what was *measured*, not what was intended —
numbers, commands, and the fixture that proves it.
