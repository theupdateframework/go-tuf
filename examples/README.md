# Examples

----------------------------

## Basic repository

----------------------------

See the [basic_repository.go](repository/basic_repository.go) example which demonstrates how to *manually* create and
maintain repository metadata using the low-level Metadata API.

The example highlights the following functionality supported by the metadata API:

* creation of top-level metadata
* target file handling
* consistent snapshots
* key management (supports ED25519, RSA and ECDSA key types)
* top-level delegation and signing thresholds
* metadata verification
* target delegation
* in-band and out-of-band metadata signing
* writing and reading metadata files
* root key rotation

## Client example

----------------------------
There's also a [client_example.go](client/client_example.go) which demonstrates how to implement a client using the [updater](metadata/updater/updater.go) package.

* it uses [https://jku.github.io/tuf-demo](https://jku.github.io/tuf-demo), a live TUF repository hosted on GitHub
* shows an example of how to initialize a client
* shows an example of how to download a target file
* the repository is based on python-tuf so it also highlights the interoperability between the two implementations
