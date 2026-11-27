# Verification-only build and caller-supplied verifiers

The proposed `tuf_client` tag omits signing and SDK adapters. Its default adapter
uses native Go verification for the algorithms supported today. That set is not
a restriction on TUF's workflow: an application can supply another adapter for a
new key type or codec without changing this library's state machine.

The extension is one small `metadata.Verifier` interface and an ordinary
constructor function. `UpdaterConfig.NewVerifier`, `MultiRepoConfig.NewVerifier`,
and `trustedmetadata.NewWithVerifier` accept that constructor; nil selects
`metadata.NewVerifier`. `VerifyDelegateWithVerifier` is available for direct use.
No registry, global setting or algorithm policy framework is added.

Applications can wrap the default constructor to require their chosen algorithm
or allow a migration set. They can also construct a different implementation.
The same constructor applies to bootstrap, both sides of root rotation, and all
top-level and delegated metadata (including diamond-delegation cache checks).
When `NewVerifier` rejects a key, that key does not contribute toward the role's
threshold while other allowed keys on the role can still satisfy it; if the
threshold is not met, `VerifyDelegateWithVerifier` returns `*metadata.ErrUnsignedMetadata`
wrapping the constructor error(s). Note that a per-client `NewVerifier` policy
only constrains what that client accepts—on a shared repository, clients using
the default verifier will still accept any key authorized by the role unless the
role's threshold requires all required key types. TUF still owns signature
thresholds, key alias deduplication, rotation, expiry and rollback checks.

An adapter must verify the signature over canonical metadata using its scheme's
required domain separation. PublicKeyBytes must return a canonical encoding of
the actual underlying public key, independent of key IDs, scheme aliases,
signatures and payloads; use SubjectPublicKeyInfo when defined. Equivalent keys
must use the same encoding across adapters so aliases cannot inflate thresholds.
Only install trusted verifier implementations, as with any cryptographic adapter.

```go
cfg.NewVerifier = func(key *metadata.Key) (metadata.Verifier, error) {
    if key.Type != metadata.KeyTypeMLDSA {
        return nil, errors.New("ML-DSA required")
    }
    return metadata.NewVerifier(key)
}
```

This example is application policy, not a library default. Applications can make
a different choice or delegate to their own verifier/codec.

```sh
go test ./...
go test -tags tuf_client ./metadata/clientprofile
go build -tags tuf_client ./metadata/updater
go list -tags tuf_client -deps ./metadata/updater
```

The default suite retains signing-based coverage. The independent client suite
covers built-in algorithms, tampering, per-instance restrictions, root rotation,
a caller-defined key type, and alias-resistant thresholds across adapters.
