# Notes

* Check fuzzing - https://go.dev/doc/tutorial/fuzz 
* Add the option to set custom key ID
* Add creating a metadata from init struct
* Support for hashbin delegations and succint roles
* Verify we don't discard custom fields when converting, i.e. for keys and such
* Verify and fix if needed the format of which keys are stored - ed25519 should be hex only
* Revisit the design - should we use generics or just 4 different types for each metadata?
* Investigate whether depending on `sigstore/signatures` can cause dependency cycle and if so, how to avoid it?
* Add support for storing/loading metadata and target files from AWS S3 buckets
