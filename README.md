![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/theupdateframework/go-tuf/ci.yml?branch=master)
[![codecov](https://codecov.io/github/theupdateframework/go-tuf/branch/master/graph/badge.svg?token=2ZUA68ZL13)](https://codecov.io/github/theupdateframework/go-tuf)
[![Go Reference](https://pkg.go.dev/badge/github.com/theupdateframework/go-tuf.svg)](https://pkg.go.dev/github.com/theupdateframework/go-tuf)
[![Go Report Card](https://goreportcard.com/badge/github.com/theupdateframework/go-tuf)](https://goreportcard.com/report/github.com/theupdateframework/go-tuf)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# <img src="https://cdn.rawgit.com/theupdateframework/artwork/3a649fa6/tuf-logo.svg" height="100" valign="middle" alt="TUF"/> go-tuf/v2 - Framework for Securing Software Update Systems

----------------------------

[The Update Framework (TUF)](https://theupdateframework.io/) is a framework for
secure content delivery and updates. It protects against various types of
supply chain attacks and provides resilience to compromise.

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
by various tech companies and open-source organizations.

Please see [TUF's website](https://theupdateframework.com/) for more information about TUF!

## Overview

----------------------------

The go-tuf v2 project provides a lightweight library with the following functionality:

* creation, reading, and writing of TUF metadata
* an easy object-oriented approach for interacting with TUF metadata
* consistent snapshots
* signing and verifying TUF metadata
* ED25519, RSA, and ECDSA key types referenced by the latest TUF specification
* top-level role delegation
* target delegation via standard and hash bin delegations
* support of [succinct hash bin delegations](https://github.com/theupdateframework/taps/blob/master/tap15.md) which significantly reduce the size of the TUF metadata
* support for unrecognized fields within the metadata (i.e. preserved and accessible through `root.Signed.UnrecognizedFields["some-unknown-field"]`, also used for verifying/signing (if included in the Signed portion of the metadata))
* TUF client API
* TUF multi-repository client API (implements [TAP 4 - Multiple repository consensus on entrusted targets](https://github.com/theupdateframework/taps/blob/master/tap4.md))

## Examples

----------------------------

There are several examples that can act as a guideline on how to use the library and its features. Some of which are:

* [basic_repository.go](examples/repository/basic_repository.go) example which demonstrates how to *manually* create and
maintain repository metadata using the low-level Metadata API.

To try it - run `make example-repository` (the artifacts will be located at `examples/repository/`).

* [client_example.go](examples/client/client_example.go) which demonstrates how to implement a client using the [updater](metadata/updater/updater.go) package.

To try it - run `make example-client` (the artifacts will be located at `examples/client/`)

* [tuf-client CLI](examples/cli/tuf-client/) - a CLI tool that implements the client workflow specified by The Update Framework (TUF) specification.

To try it - run `make example-tuf-client-cli`

* [multi-repository client example (TAP4)](examples/multirepo/client/client_example.go) which demonstrates how to implement a multi-repository TUF client using the [multirepo](metadata/multirepo/multirepo.go) package.

To try it - run `make example-multirepo`

## Package details

----------------------------

### The `metadata` package

* The `metadata` package provides access to a Metadata file abstraction that closely
follows the TUF specification’s document formats. This API handles de/serialization
to and from files and bytes. It also covers the process of creating and verifying metadata
signatures and makes it easier to access and modify metadata content. It is purely
focused on individual pieces of Metadata and provides no concepts like “repository”
or “update workflow”.

### The `trustedmetadata` package

* A `TrustedMetadata` instance ensures that the collection of metadata in it is valid
and trusted through the whole client update workflow. It provides easy ways to update
the metadata with the caller making decisions on what is updated.

### The `config` package

* The `config` package stores configuration for an ``Updater`` instance.

### The `fetcher` package

* The `fetcher` package defines an interface for abstract network download.

### The `updater` package

* The `updater` package provides an implementation of the TUF client workflow.
It provides ways to query and download target files securely while handling the
TUF update workflow behind the scenes. It is implemented on top of the Metadata API
and can be used to implement various TUF clients with relatively little effort.

### The `multirepo` package

* The `multirepo` package provides an implementation of [TAP 4 - Multiple repository consensus on entrusted targets](https://github.com/theupdateframework/taps/blob/master/tap4.md). It provides a secure search for particular targets across multiple repositories. It provides the functionality for how multiple repositories with separate roots of trust can be required to sign off on the same targets, effectively creating an AND relation and ensuring any files obtained can be trusted. It offers a way to initialize multiple repositories using a `map.json` file and also mechanisms to query and download target files securely. It is implemented on top of the Updater API and can be used to implement various multi-repository TUF clients with relatively little effort.

## Documentation

----------------------------

* [Documentation](https://pkg.go.dev/github.com/theupdateframework/go-tuf/v2)

* [Introduction to TUF's Design](https://theupdateframework.io/overview/)

* [The TUF Specification](https://theupdateframework.github.io/specification/latest/)

## History - legacy go-tuf vs go-tuf/v2

The [legacy go-tuf (v0.7.0)](https://github.com/theupdateframework/go-tuf/tree/v0.7.0) codebase was difficult to maintain and prone to errors due to its initial design decisions. Now it is considered deprecated in favour of go-tuf v2 (originaly from [rdimitrov/go-tuf-metadata](https://github.com/rdimitrov/go-tuf-metadata)) which started from the idea of providing a Go implementation of TUF that is heavily influenced by the design decisions made in [python-tuf](https://github.com/theupdateframework/python-tuf).

## Contact

----------------------------

Questions, feedback, and suggestions are welcomed on the [#tuf](https://cloud-native.slack.com/archives/C8NMD3QJ3) and/or [#go-tuf](https://cloud-native.slack.com/archives/C02D577GX54) channels on
[CNCF Slack](https://slack.cncf.io/).

We strive to make the specification easy to implement, so if you come across
any inconsistencies or experience any difficulty, do let us know by sending an
email, or by reporting an issue in the GitHub [specification
repo](https://github.com/theupdateframework/specification/issues).
