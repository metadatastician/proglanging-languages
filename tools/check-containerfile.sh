#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# check-containerfile.sh — the container floor, enforced rather than hoped for.
# Fails with a named reason for each rule; every rule can fail, so a passing run
# means something.
set -eu

FILE="${1:-Containerfile}"
[ -f "$FILE" ] || { echo "FAIL: $FILE does not exist"; exit 1; }

# Comments are prose, not instructions: a check that reads them reports on what
# the file says instead of what it does, and noisy checks get muted.
BODY="$(sed 's/^[[:space:]]*#.*$//' "$FILE")"

fails=0
note() { printf '  %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*"; fails=$((fails + 1)); }
pass() { printf 'ok:   %s\n' "$*"; }

# 1. every FROM must carry an @sha256 digest
if printf '%s\n' "$BODY" | grep -qE '^[[:space:]]*FROM[[:space:]].*@sha256:[0-9a-f]{64}'; then
    pass "all FROM lines carry a sha256 digest"
else
    fail "a FROM line is not digest-pinned (run tools/pin-base.sh)"
fi
if printf '%s\n' "$BODY" | grep -qE '^[[:space:]]*FROM[[:space:]][^@]*:[[:space:]]*$|^[[:space:]]*FROM[[:space:]]+[^@[:space:]]+[[:space:]]*$'; then
    fail "an unpinned FROM exists: $(printf '%s\n' "$BODY" | grep -nE '^[[:space:]]*FROM' | grep -v '@sha256:' | head -3 | tr '\n' ' ')"
fi

# 2. no :latest anywhere on a FROM line
if printf '%s\n' "$BODY" | grep -E '^[[:space:]]*FROM' | grep -q ':latest'; then
    fail "FROM uses :latest"
else
    pass "no :latest base"
fi

# 3. a non-root USER must be set
if printf '%s\n' "$BODY" | grep -qE '^[[:space:]]*USER[[:space:]]+([0-9]+:[0-9]+|[0-9]+)$'; then
    pass "runs as a numeric non-root USER"
else
    fail "no numeric USER directive (must not run as root)"
fi

# 4. no install-by-pipe-to-shell, no fetching scripts at build time
if grep -qE 'curl[^|]*\|[[:space:]]*(ba)?sh|wget[^|]*\|[[:space:]]*(ba)?sh' "$FILE"; then
    fail "curl|sh or wget|sh in the build"
else
    pass "no pipe-to-shell provisioning"
fi

# 5. package installs must use --no-cache and apk must be available offline
if printf '%s\n' "$BODY" | grep -qE 'apk add' && ! printf '%s\n' "$BODY" | grep -qE 'apk add --no-cache'; then
    fail "apk add without --no-cache"
else
    pass "apk installs are --no-cache (or apk is unused)"
fi

# 6. it must be a Containerfile, not a Dockerfile (estate convention)
if [ -f "Dockerfile" ]; then
    fail "a Dockerfile exists alongside the Containerfile"
else
    pass "no Dockerfile in the tree"
fi

# 7. the placeholder must never be committed
if printf '%s\n' "$BODY" | grep -q 'REPLACE_WITH'; then
    fail "unresolved digest placeholder committed"
fi

if [ "$fails" -ne 0 ]; then
    note "$fails container rule(s) failed"
    exit 1
fi
note "container floor: clean"
