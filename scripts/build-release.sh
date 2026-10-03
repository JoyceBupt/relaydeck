#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
[ "$(uname -s)" = Linux ] || { echo 'Build Linux releases on Linux.' >&2; exit 1; }
target=$(rustc -vV | sed -n 's/^host: //p')
case "$target" in x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu) ;; *) echo 'Unsupported release target.' >&2; exit 1;; esac
(cd frontend && npm ci && npm test && npm run build)
cargo build --release --locked
python3 scripts/manage.py package --target "$target" --output "${1:-dist}"
