#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -x "$project_dir/.tooling/cargo/bin/cargo" ]; then
  export CARGO_HOME="$project_dir/.tooling/cargo"
  export RUSTUP_HOME="$project_dir/.tooling/rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
exec cargo "$@"
