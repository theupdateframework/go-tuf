# Examples

----------------------------

## Repository

----------------------------

See the [basic_repository.go](repository/basic_repository.go) example which demonstrates how to *manually* create and
maintain repository metadata using the low-level Metadata API.

The example highlights the following functionality supported by the metadata API:

* creation of top-level metadata
* target file handling
* consistent snapshots
* support a mixture of key types - ED25519, RSA and ECDSA
* top-level delegation and signing thresholds
* metadata verification
* target delegation
* in-band and out-of-band metadata signing
* writing and reading metadata files
* root key rotation

## Client

----------------------------
There's also a [client_example.go](client/client_example.go) which demonstrates how to implement a client using the [updater](metadata/updater/updater.go) package.

* it uses [https://jku.github.io/tuf-demo](https://jku.github.io/tuf-demo), a live TUF repository hosted on GitHub
* shows an example of how to initialize a client
* shows an example of how to download a target file
* the repository is based on python-tuf so it also highlights the interoperability between the two implementations

## Multi-repository client

----------------------------
There's a [client_example.go](multirepo/client/client_example.go) which demonstrates how to implement a multi-repository client using the [multirepo](metadata/multirepo/multirepo.go) package which implements [TAP 4 - Multiple repository consensus on entrusted targets](https://github.com/theupdateframework/taps/blob/master/tap4.md). The example consists of the following:

* The `map.json` along with the root files for each repository are distributed via a trusted repository used for initialization
  * The metadata, these target files and the script generating them are located in the [examples/multirepo/repository](../repository/) folder
* These files are then used to bootstrap the multi-repository TUF client
* Shows the API provided by the `multirepo` package

## CLI tools

----------------------------

The following CLIs are experimental replacements of the CLI tools provided by the go-tuf package. At some point these will be moved to a separate repository.

* [tuf-client](cli/tuf-client/README.md) - a CLI tool that implements the client workflow specified by The Update Framework (TUF) specification

* [tuf](cli/tuf/README.md) - Not implemented
