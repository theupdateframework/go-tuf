#!/bin/sh

set -eu

cd `dirname $0`

for d in consistent-snapshot-false consistent-snapshot-true; do
	if [[ -e $d ]]; then
		rm -r $d
	fi
done

go run generate.go
go run ../tools/linkify-metadata.go
