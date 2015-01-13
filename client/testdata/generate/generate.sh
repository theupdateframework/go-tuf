#!/bin/bash
#
# A script to generate TUF repository files using the Python implementation.
#
# A list of generated files is printed to STDERR and a tar of the files to STDOUT.

set -e

main() {
  local dir="$(mktemp -d)"
  trap "rm -rf ${dir}" EXIT

  pushd "${dir}" >/dev/null
  /generate.py
  list_files >&2
  tar c .
  popd >/dev/null
}

list_files() {
  echo "Files generated:"
  tree
}

main $@
