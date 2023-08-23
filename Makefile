# Copyright 2023 VMware, Inc.
#
# This product is licensed to you under the BSD-2 license (the "License").
# You may not use this product except in compliance with the BSD-2 License.
# This product may include a number of subcomponents with separate copyright
# notices and license terms. Your use of these subcomponents is subject to
# the terms and conditions of the subcomponent's license, as noted in the
# LICENSE file.
# 
# SPDX-License-Identifier: BSD-2-Clause

# We want to use bash
SHELL:=/bin/bash

# Set environment variables
CLIS:=tuf-client # tuf

# Default target
.PHONY: default
default: build

#####################
# build section
#####################

# Build
.PHONY: build
build: $(addprefix build-, $(CLIS))

# Target for building a Go binary
.PHONY: build-%
build-%:
	@echo "Building $*"
	@go build -o $* examples/cli/$*/main.go

#####################
# test section
#####################

# Test target
.PHONY: test
test: 
	go test -race -covermode atomic ./...

#####################
# lint section
#####################

.PHONY: lint
lint: 
	golangci-lint run

#####################
# examples section
#####################

# Target for running all examples
.PHONY: example-all
example-all: example-client example-repository example-multirepo example-tuf-client-cli example-root-signing

# Target for demoing the examples/client/client_example.go
.PHONY: example-client
example-client: 
	@echo "Executing the following example - client/client_example.go"
	@cd examples/client/ && go run .

# Target for demoing the examples/repository/basic_repository.go
.PHONY: example-repository
example-repository: 
	@echo "Executing the following example - repository/basic_repository.go"
	@cd examples/repository/ && go run .

# Target for demoing the examples/multirepo/client/client_example.go
.PHONY: example-multirepo
example-multirepo:
	@echo "Executing the following example - multirepo/client/client_example.go"
	@cd examples/multirepo/client/ && go run .

# Target for demoing the tuf-client cli
.PHONY: example-tuf-client-cli
example-tuf-client-cli: build-tuf-client
	@echo "Clearing any leftover artifacts..."
	./tuf-client reset --force
	@echo "Initializing the following https://jku.github.io/tuf-demo/ TUF repository"
	@sleep 2
	./tuf-client init --url https://jku.github.io/tuf-demo/metadata
	@echo "Downloading the following target file - file1.txt"
	@sleep 2
	./tuf-client get --url https://jku.github.io/tuf-demo/metadata --turl https://jku.github.io/tuf-demo/targets file1.txt

# Target for demoing the tuf-client cli with root-signing repo
.PHONY: example-root-signing
example-root-signing: build-tuf-client
	@echo "Clearing any leftover artifacts..."
	./tuf-client reset --force
	@echo "Downloading the initial root of trust"
	@curl -L "https://sigstore-tuf-root.storage.googleapis.com/5.root.json" > root.json
	@echo "Initializing the following https://sigstore-tuf-root.storage.googleapis.com TUF repository"
	@sleep 2
	./tuf-client init --url https://sigstore-tuf-root.storage.googleapis.com --file root.json
	@echo "Downloading the following target file - rekor.pub"
	@sleep 2
	./tuf-client get --url https://sigstore-tuf-root.storage.googleapis.com --turl https://sigstore-tuf-root.storage.googleapis.com/targets rekor.pub

# Clean target
.PHONY: clean
clean:
	@rm -rf examples/multirepo/client/bootstrap/
	@rm -rf examples/multirepo/client/download/
	@rm -rf examples/multirepo/client/metadata/
	@rm -rf examples/repository/tmp*
	@rm -rf examples/client/tmp*
	@rm -rf tuf_download
	@rm -rf tuf_metadata
	@rm -f tuf-client
	@rm -f root.json

