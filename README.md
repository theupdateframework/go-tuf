![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/rdimitrov/go-tuf-metadata/ci.yml?branch=main)
[![codecov](https://codecov.io/github/rdimitrov/go-tuf-metadata/branch/main/graph/badge.svg?token=2ZUA68ZL13)](https://codecov.io/github/rdimitrov/go-tuf-metadata)
[![Go Reference](https://pkg.go.dev/badge/github.com/rdimitrov/go-tuf-metadata.svg)](https://pkg.go.dev/github.com/rdimitrov/go-tuf-metadata)
[![Go Report Card](https://goreportcard.com/badge/github.com/rdimitrov/go-tuf-metadata)](https://goreportcard.com/report/github.com/rdimitrov/go-tuf-metadata)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)

# <img src="https://cdn.rawgit.com/theupdateframework/artwork/3a649fa6/tuf-logo.svg" height="100" valign="middle" alt="TUF"/> A Framework for Securing Software Update Systems

----------------------------
[The Update Framework (TUF)](https://theupdateframework.io/) is a framework for
secure content delivery and updates. It protects against various types of
supply chain attacks and provides resilience to compromise.

go-tuf-metadata is started from the idea of providing a Go implementation of TUF that is heavily influenced by the
design decisions made in [python-tuf](https://github.com/theupdateframework/python-tuf).

## About The Update Framework

----------------------------
The Update Framework (TUF) design helps developers maintain the security of a
software update system, even against attackers that compromise the repository
or signing keys.
TUF provides a flexible
[specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
defining functionality that developers can use in any software update system or
re-implement to fit their needs.

TUF is hosted by the [Linux Foundation](https://www.linuxfoundation.org/) as
part of the [Cloud Native Computing Foundation](https://www.cncf.io/) (CNCF)
and its design is [used in production](https://theupdateframework.io/adoptions/)
by various tech companies and open source organizations.

Please see [TUF's website](https://theupdateframework.com/) for more information about TUF!

## Overview

----------------------------

The `go-tuf-metadata` project provides the following functionality:

* creation, reading and writing of metadata
* easy and straightforward object oriented approach for interacting with metadata
* consistent snapshots
* signing and verifying metadata
* ED25519, RSA and ECDSA key types referenced by the latest TUF specification
* top-level role delegation
* target delegation via standard and hash bin delegations
* use of succinct hash bin delegations which significantly reduce the size of metadata
* support for unrecognized fields within the metadata (preserved and accessible through `root.Signed.UnrecognizedFields["some-unknown-field"]`, also used for verifying/signing (if included in the Signed portion of the metadata))

## CLI

----------------------------

* [tuf-client](cli/tuf-client/) - a CLI tool that implements the client workflow specified by The Update Framework (TUF) specification. To try it - run `make example-tuf-client-cli`

## Examples

----------------------------

* [basic_repository.go](examples/repository/basic_repository.go) example which demonstrates how to *manually* create and
maintain repository metadata using the low-level Metadata API. To try it - run `make example-repository` (the artifacts will be located at `examples/repository/`).

* [client_example.go](examples/client/client_example.go) which demonstrates how to implement a client using the [updater](metadata/updater/updater.go) package. To try it - run `make example-client` (the artifacts will be located at `examples/client/`)

## Package details

----------------------------

### The `metadata` package

* The `metadata` package provides access to a Metadata file abstraction that closely
follows the TUF specification’s document formats. This API handles de/serialization
to and from files and bytes, covers also the process to create and verify metadata
signatures and makes it easier to access and modify metadata content. It is purely
focused on individual pieces of Metadata and provides no concepts like “repository”
or “update workflow”.

### The `trustedmetadata` package

* A `TrustedMetadata` instance ensures that the collection of metadata in it is valid
and trusted through the whole client update workflow. It provides easy ways to update
the metadata with the caller making decisions on what is updated.

### The `config` package

* The `config` package is used to store configuration for an ``Updater`` instance.

### The `fetcher` package

* The `fetcher` package defines an interface for abstract network download.

### The `updater` package

* The `updater` package provides an implementation of the TUF client workflow.
It provides ways to query and download target files securely, while handling the
TUF update workflow behind the scenes. It is implemented on top of the Metadata API
and can be used to implement various TUF clients with relatively little effort.

## Documentation

----------------------------

* [go-tuf-metadata documentation](https://pkg.go.dev/github.com/rdimitrov/go-tuf-metadata)

* [Introduction to TUF's Design](https://theupdateframework.io/overview/)

* [The TUF Specification](https://theupdateframework.github.io/specification/latest/)

## Contact

----------------------------

Questions, feedback, and suggestions are welcomed on the [#tuf](https://cloud-native.slack.com/archives/C8NMD3QJ3) channel on
[CNCF Slack](https://slack.cncf.io/).

We strive to make the specification easy to implement, so if you come across
any inconsistencies or experience any difficulty, do let us know by sending an
email, or by reporting an issue in the GitHub [specification
repo](https://github.com/theupdateframework/specification/issues).
