#!/bin/sh
set -eu
if command -v mise >/dev/null 2>&1; then
  exec mise exec -- cargo "$@"
fi
exec cargo "$@"
