# Changelog

All notable changes to this project are documented here. The format follows
Keep a Changelog; this project uses Semantic Versioning.

## 0.1.0 — 2026-09-29

First commit to contain anything: the repository had a 24-byte README before
this. See `docs/RECOVERY.adoc` for what was recovered and what was not.

### Added
- `ProglangingLanguages` Julia package (stdlib-only): `Languages`, `Policy`,
  `Detect`, `Classify`, `Report`, `Scan`, `Bench`.
- `bin/proglanging.jl` console — `gate`, `scan`, `report`, `bench`, `doctor`;
  exit codes 0/1/2/3 where 3 means "the scan was incomplete".
- Ported from `metadatastician/cadastra` @ `tools/estate-migration-toolkit`:
  the banned/allowed language sets, the eight anti-pattern detectors, the
  five-outcome classification table, the `.language-policy.toml` schema, and the
  `estate-triage-report.csv` column order.
- `[gate]` policy extensions: `nix_severity`, `strict`, `max_files`, `exclude`.
- CI: pinned-SHA actions with `.github/actions.lock`, tests on Julia 1.10 and
  1.11, self-gate, container floor, workflow YAML parse, benchmark run.
- Estate secret scanner via the `hyperpolymath/standards` reusable, pinned to a
  full commit SHA, with `secrets: inherit`.
- `Containerfile` on a digest-pinned Wolfi base, numeric non-root user;
  `tools/check-containerfile.sh` (7 rules) and `tools/pin-base.sh`.
- `docs/FINDINGS.adoc` (F1–F8, measured), `docs/RECOVERY.adoc` (provenance
  ledger), `docs/ARCHITECTURE.adoc`.
- 151 assertions over 12 fixture repositories, including that this repository
  passes its own gate and that a truncated walk cannot pass.

### Changed
- Nothing yet: this is the baseline.

### Removed
- Nothing. The upstream toolkit stays in `cadastra` untouched; this is a port,
  not a deletion. Any retirement of `rollout-language-gate.sh` should follow
  `docs/FINDINGS.adoc` §F8 as its own decision.
