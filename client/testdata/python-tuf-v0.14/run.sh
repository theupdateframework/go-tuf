#!/bin/sh

set -eux

cd `pwd $0`

if [[ ! -e venv ]]; then
	python3 -m venv venv
fi

./venv/bin/pip3 install -r requirements.txt
./venv/bin/python3 ./generate.py
