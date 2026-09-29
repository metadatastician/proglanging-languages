# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2026 Jonathan D.A. Jewell (hyperpolymath)
#
# proglanging console — Wolfi runtime image.
#
# Build (podman, never docker, per estate convention):
#   podman build -t proglanging-languages:dev .
# Run:
#   podman run --rm -it -v "$PWD:/data:ro" proglanging-languages:dev gate /data
#
# The base digest below is copied from a digest that is already in production
# use in this estate (hyperpolymath/pons-asinorum @ build/container/Containerfile,
# line 8, read 2026-09-29). It is a real pinned reference, not a fresh pull: the
# sandbox this was authored in has no egress to ghcr.io (measured), so
# `tools/pin-base.sh` must be run by whoever next touches this file to advance the
# pin, and `tools/check-containerfile.sh` in CI fails the build if the digest
# placeholder is ever committed. Do not "fix" that check by writing a made-up digest.

ARG JULIA_VERSION=1.11

# The digest is written on the FROM line, not behind an ARG: `tools/check-containerfile.sh`
# inspects FROM lines, and a pin it cannot see is not a control.
FROM cgr.dev/chainguard/wolfi-base@sha256:918a593b8268c222afd4e2c4f06860ac984e60719b4697e4c71d796bc8fcd042 AS runtime

LABEL org.opencontainers.image.title="proglanging-languages" \
      org.opencontainers.image.description="Estate language-policy analysis, evaluation and benchmarking console" \
      org.opencontainers.image.source="https://github.com/metadatastician/proglanging-languages" \
      org.opencontainers.image.licenses="MPL-2.0"

# julia ships in the Wolfi repository: no upstream installer script is fetched,
# and the package is version-bounded rather than floating.
RUN apk add --no-cache julia~${JULIA_VERSION} git && \
    apk --no-cache upgrade && \
    rm -rf /var/cache/apk/*

WORKDIR /opt/proglanging

# Order matters for layer reuse: dependencies first.
COPY Project.toml ./Project.toml
RUN julia --project=. -e 'using Pkg; Pkg.instantiate(); Pkg.precompile()'

COPY src/   ./src/
COPY bin/   ./bin/
COPY test/  ./test/
COPY LICENSE.md README.adoc .language-policy.toml ./

RUN julia --project=. -e 'using Pkg; Pkg.test()'

# Wolfi's unprivileged user; no root, no setuid binaries in the image.
USER 65532:65532

ENV JULIA_DEPOT_PATH=/opt/proglanging/.julia
ENTRYPOINT ["julia", "--project=/opt/proglanging", "/opt/proglanging/bin/proglanging.jl"]
CMD ["help"]
