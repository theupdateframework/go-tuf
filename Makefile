# Copyright 2022-2023 VMware, Inc.
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

# Build
.PHONY: build
build: $(addprefix build-, $(CLIS))

# Target for building a Go binary
.PHONY: build-%
build-%:
	@echo "Building $*"
	@go build -o $* cli/$*/main.go

# Test target
.PHONY: test
test: 
	@go test ./...

# Linting target
.PHONY: lint
lint: 
	@golangci-lint run

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

# Target for demoing the tuf-client cli
.PHONY: example-tuf-client-cli
example-tuf-client-cli: build-tuf-client
	@echo "Clearing any leftover artifacts..."
	@./tuf-client reset --force
	@echo "Initializing the following https://jku.github.io/tuf-demo/ TUF repository"
	@sleep 2
	@./tuf-client init --url https://jku.github.io/tuf-demo/metadata
	@echo "Downloading the following target file - demo/succinctly-delegated-5.txt"
	@sleep 2
	@./tuf-client get --url https://jku.github.io/tuf-demo/metadata -t https://jku.github.io/tuf-demo/targets demo/succinctly-delegated-5.txt


