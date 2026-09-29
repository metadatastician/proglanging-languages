# Reporting a vulnerability

Report privately via the estate's disclosure route rather than a public issue.
This repository ships *policy enforcement* code, so the failure modes that matter
are not memory-safety ones — they are gates that pass when they should not.

## What counts as a security issue here

* A scan that reports `passed` on a tree containing a banned language, or
  `DONE`/`CLEAN` where the upstream scan would have reported a finding.
* Any path where an incomplete scan (failed clone, unreadable directory,
  truncated walk, unparseable policy) is reported as success. `incomplete` and
  `passed` are separate fields for exactly this reason; if you can decouple them
  into a false pass, that is a bug.
* A `.github/actions.lock` entry whose `commit:` does not match the ref used in a
  workflow — that is a moving pin wearing a pin's clothes.
* A `Containerfile` whose base is `:latest`, unpinned, or a digest nobody
  resolved. `tools/check-containerfile.sh` exists so this cannot land quietly.
* Anything that adds a step whose failure is swallowed (`|| true`, `continue-on-error`).

## Known accepted risk

* `Scan.github_org` executes `gh` with arguments built from the org and repo names
  it read back from GitHub. Names are restricted by GitHub to `[A-Za-z0-9._-]`,
  so this is argument-vector-safe today; it is not a shell, and must not become
  one.
* The estate's `EstatePushing` ruleset (10 MB / 200-char path / extension block)
  applies to this private repository, so oversized fixtures are rejected at push
  time by design. Adding a >10 MB fixture is not possible here; if a need arises,
  the need is the finding, not the exception.

## Verification expectations

Reports must be reproducible from a checkout with no network. `proglanging
doctor`, `proglanging gate <repo>`, and `sh tools/check-containerfile.sh` are all
offline; a claim about this tool that cannot be produced by those three commands
plus `Pkg.test()` needs a fixture, not a description.
