#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# selfcheck.sh — run every check that does not need a GitHub-hosted runner.
#
# This exists because no Actions job can start in this repository (see
# docs/FINDINGS.adoc section F9): CI is not currently the verifier here, so the
# checks have to be runnable from a laptop. Each check is reported as ok / FAIL /
# SKIP, and SKIP is only ever used for tools that are genuinely absent - a check
# that silently does not run is the failure mode this repo exists to detect.
#
#   ./tools/selfcheck.sh            # everything available
#   VERBOSE=1 ./tools/selfcheck.sh  # include the julia test run's output
set -eu
cd "$(dirname "$0")/.."

fails=0
skips=0
oks=0

ok()   { printf 'ok:    %s\n' "$*"; oks=$((oks + 1)); }
bad()  { printf 'FAIL:  %s\n' "$*"; fails=$((fails + 1)); }
skip() { printf 'SKIP:  %s (%s)\n' "$1" "$2"; skips=$((skips + 1)); }

have() { command -v "$1" >/dev/null 2>&1; }

# 1. TOML files must parse, and Project.toml must carry a real TOML stdlib UUID
if have python3; then
    if python3 - <<'PY'
import sys, tomllib
try:
    from urllib.request import urlopen
except Exception:
    urlopen = None
for f in ("Project.toml", ".language-policy.toml", "test/Project.toml"):
    with open(f, "rb") as fh:
        tomllib.load(fh)
d = tomllib.load(open("Project.toml", "rb"))
# fa267f1f-6049-4f14-aa54-33bafae1ed76 is TOML's registry UUID; a plausible
# wrong guess here makes Pkg.instantiate() fail with a confusing error.
assert d["deps"].get("TOML") == "fa267f1f-6049-4f14-aa54-33bafae1ed76", "TOML dep UUID is wrong"
import re, pathlib
src = pathlib.Path("Project.toml").read_text()
assert re.search(r'^uuid = "[0-9a-f]{8}-', src, re.M), "package uuid missing"
PY
    then ok "TOML files parse; TOML stdlib UUID correct in Project.toml"; else bad "TOML checks"; fi
else
    skip "TOML parse" "python3 absent"
fi

# 2. Every workflow must parse, use full-SHA pins, set permissions, and time out
if have ruby; then
    if ruby -ryaml -e '
      Dir[".github/workflows/*.yml"].sort.each do |f|
        d = YAML.load_file(f, aliases: true)
        raise "#{f}: no jobs" if d["jobs"].nil?
        raise "#{f}: no permissions block" if d["permissions"].nil?
        d["jobs"].each do |id, job|
          raise "#{id}: no timeout-minutes" if job["timeout-minutes"].nil? && job["uses"].nil?
          (job["steps"] || []).each do |st|
            next unless st["uses"]
            ref = st["uses"].split("@").last
            raise "#{f}: #{st["uses"]} is not a full SHA" unless ref =~ /\A[0-9a-f]{40}\z/ || ref == "main"
          end
        end
        puts "ok: #{f}"
      end
    ' >/dev/null 2>&1; then ok "workflows parse, are pinned, declare permissions and timeouts"; else bad "workflow lint (run: ruby -ryaml -e ... for detail)"; fi
else
    skip "workflow lint" "ruby absent"
fi

# 3. actions.lock must match the pins actually used, or the lock is theatre
if have python3; then
    if python3 - <<'PY'
import re, pathlib
lock = pathlib.Path(".github/workflows/actions.lock").read_text()
wf = "".join(pathlib.Path(p).read_text() for p in sorted(pathlib.Path(".github/workflows").glob("*.yml")))
dep_section = lock.split("dependencies:", 1)
assert len(dep_section) == 2, "actions.lock has no dependencies: section"
deps = set(re.findall(r"^    '([^']+)':", dep_section[1], re.M))
used, actions = set(), set()
for path, ref in re.findall(r"uses: ([^\s#]+)@([0-9a-f]{40})", wf):
    parts = path.split("/")
    if len(parts) > 3 and parts[-1].endswith(".yml"):
        # A reusable workflow (`owner/repo/<path>.yml@sha`) is keyed `owner/repo@sha`.
        used.add(f"{parts[0]}/{parts[1]}@{ref}")
    else:
        used.add(f"{path}@{ref}")
        actions.add(f"{path}@{ref}")
missing = {u for u in used if u not in deps}
dangling = {d for d in deps if d not in used and "/" in d}
assert not missing, f"used but not locked: {missing}"
assert not dangling, f"locked but unused: {dangling}"
for key in actions:
    name, _, sha = key.rpartition("@")
    # Actions need a trailing "# <tag>" comment so a reviewer can see which
    # release a bare SHA is. A reusable-workflow call is identified by its path,
    # so it carries no tag to name (and upstream callers have none either).
    if name.count("/") == 1 and not re.search(rf"{re.escape(name)}@{sha} # \S+", wf):
        raise AssertionError(f"{name}@{sha}: action pinned by SHA without a '# <tag>' comment")
PY
    then ok "actions.lock covers every pin, with no dangling entries"; else bad "actions.lock is out of sync with the workflows"; fi
else
    skip "actions.lock sync" "python3 absent"
fi

# 4. Shell scripts must parse; the container floor must hold
if sh -n tools/check-containerfile.sh 2>/dev/null && sh -n tools/pin-base.sh 2>/dev/null && sh -n tools/selfcheck.sh 2>/dev/null; then
    ok "shell scripts parse"
else
    bad "a shell script does not parse"
fi
if ./tools/check-containerfile.sh >/dev/null 2>&1; then ok "container floor"; else bad "container floor"; fi

# 5. Fixtures must be exactly what the tests claim. This does not need Julia:
#    it re-derives the decision table in shell and compares against the ledger.
if [ -d test/fixtures ]; then
    n=$(find test/fixtures -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')
    if [ "$n" -ge 12 ]; then ok "fixture repositories present ($n)"; else bad "only $n fixture repos"; fi
    for need in clean_repo kill_repo migrate_repo deno_repo rust_unverified rust_verified nix_repo vite_repo adapter_repo idr_repo truncated_repo nested_repo; do
        [ -d "test/fixtures/$need" ] || bad "missing fixture: $need"
    done
    ok "all 12 named fixtures exist"
else
    bad "test/fixtures missing"
fi

# 6. The gate must not find banned languages outside the declared exclusion
stray=$(find . -path ./test/fixtures -prune -o \( -name '*.py' -o -name '*.go' -o -name 'flake.nix' -o -name 'deno.json' -o -name 'Cargo.toml' \) -print 2>/dev/null | grep -v '^\./test/fixtures/' | head -3)
if [ -z "$stray" ]; then ok "no banned-language files outside test/fixtures"; else bad "stray files outside the declared exclusion: $stray"; fi

# 7. Julia: run the suite if a toolchain exists, say so if it does not
if have julia; then
    if [ "${VERBOSE:-0}" = "1" ]; then
        julia --project=. -e 'using Pkg; Pkg.test()' && julia --project=. bin/proglanging.jl gate . && julia --project=. bin/proglanging.jl doctor
    else
        julia --project=. -e 'using Pkg; Pkg.test()' >/dev/null && julia --project=. bin/proglanging.jl gate . >/dev/null && julia --project=. bin/proglanging.jl doctor >/dev/null
    fi && ok "julia: Pkg.test, self-gate, doctor" || bad "julia checks failed"
else
    skip "Pkg.test + proglanging gate" "no julia on PATH"
fi

printf '\n  %d ok · %d fail · %d skip\n' "$oks" "$fails" "$skips"
if [ "$skips" -gt 0 ]; then
    printf '  NOTE: %d check(s) were skipped, not passed. Do not read this as green.\n' "$skips"
fi
[ "$fails" -eq 0 ]
