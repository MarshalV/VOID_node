#!/usr/bin/env bash
# Backwards-compatible entry point for deployment.
exec "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/deploy-linux.sh" "$@"\n