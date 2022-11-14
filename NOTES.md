# Notes

* Check fuzzing - https://go.dev/doc/tutorial/fuzz 
* Add the option to set custom key ID
* Add creating a metadata from init struct
* Support for hashbin delegations and succint roles
* Make sure to not discard custom fields when converting, i.e. for keys and such
* Verify and fix how rsa and ecdsa keys are stored
* Revisit the design - should we use generics or just 4 different structs for each metadata type?
* Investigate whether depending on `sigstore/signatures` can cause dependency cycle and if so, how to avoid it?
