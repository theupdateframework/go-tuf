#
# Copyright 2024 The Update Framework Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
#
# SPDX-License-Identifier: Apache-2.0

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
	GODEBUG=rsa1024min=0 go test -race -covermode atomic ./...

#####################
# lint section
#####################

.PHONY: lint
lint:
	golangci-lint run

.PHONY: fmt
fmt:
	go fmt ./...

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
	@echo "Downloading the following target file - rdimitrov/artifact-example.md"
	@sleep 2
	./tuf-client get --url https://jku.github.io/tuf-demo/metadata --turl https://jku.github.io/tuf-demo/targets rdimitrov/artifact-example.md

# Target for demoing the tuf-client cli with root-signing repo
.PHONY: example-root-signing
example-root-signing: build-tuf-client
	@echo "Clearing any leftover artifacts..."
	./tuf-client reset --force
	@echo "Downloading the initial root of trust"
	@curl -L "https://tuf-repo-cdn.sigstore.dev/5.root.json" > root.json
	@echo "Initializing the following https://tuf-repo-cdn.sigstore.dev TUF repository"
	@sleep 2
	./tuf-client init --url https://tuf-repo-cdn.sigstore.dev --file root.json
	@echo "Downloading the following target file - rekor.pub"
	@sleep 2
	./tuf-client get --url https://tuf-repo-cdn.sigstore.dev --turl https://tuf-repo-cdn.sigstore.dev/targets rekor.pub

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
