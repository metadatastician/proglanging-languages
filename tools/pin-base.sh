#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# pin-base.sh — rewrite the Wolfi base image digest in Containerfile to the
# current digest for the given tag. Run this, review the one-line diff, commit it.
#
#   ./tools/pin-base.sh                 # pin to today's wolfi-base:latest
#   ./tools/pin-base.sh 20260920        # pin a specific Wolfi version tag
#
# Requires exactly one of: crane, skopeo, or podman. It deliberately refuses to
# write a digest it could not resolve, because a fabricated digest is worse than
# an unpinned one: it looks like a supply-chain control and verifies nothing.
set -eu

REPO="${BASE_REPO:-cgr.dev/chainguard/wolfi-base}"
if [ "$#" -gt 0 ]; then
    TAG="$1"
else
    TAG="latest"
fi
FILE="${CONTAINERFILE:-Containerfile}"

resolve() {
    if command -v crane >/dev/null 2>&1; then
        crane digest "${REPO}:${TAG}"
    elif command -v skopeo >/dev/null 2>&1; then
        skopeo inspect --format '{{.Digest}}' "docker://${REPO}:${TAG}"
    elif command -v podman >/dev/null 2>&1; then
        podman image inspect --format '{{.RepoDigests}}' "${REPO}:${TAG}" 2>/dev/null |
            tr ' ' '\n' | grep -o 'sha256:[0-9a-f]*' | head -1
    else
        return 127
    fi
}

DIGEST="$(resolve || true)"
if [ -z "${DIGEST}" ]; then
    echo "ERROR: could not resolve ${REPO}:${TAG} (need crane, skopeo, or podman)" >&2
    echo "       Nothing was written. Do not hand-edit the digest." >&2
    exit 1
fi

TMP="$(mktemp)"
sed "s|${REPO}@sha256:[0-9a-f]*|${REPO}@${DIGEST}|" "${FILE}" > "${TMP}"
if cmp -s "${TMP}" "${FILE}"; then
    echo "already pinned to ${DIGEST}"
    rm -f "${TMP}"
    exit 0
fi
mv "${TMP}" "${FILE}"
echo "pinned ${REPO} -> ${DIGEST} in ${FILE}"
echo "next: commit the one-line change, and re-run the container build."
