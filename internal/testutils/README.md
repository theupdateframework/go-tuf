# testutils

Internal test utilities for the go-tuf project.

## Directory layout

```
internal/testutils/
├── README.md                        # this file
├── setup.go                         # legacy setup helpers (compatibility)
├── helpers/
│   ├── helpers.go                   # core test helper functions
│   ├── fuzz.go                      # fuzz data generation utilities
│   └── updater.go                   # updater-specific test helpers
├── fixtures/                        # verified static fixture regeneration
├── rsapss/                          # RSA-PSS signing utilities
├── signer/                          # generic signing test utilities
└── simulator/
    ├── config.go
    ├── repository_simulator.go      # HTTP-free TUF repository simulator
    ├── repository_simulator_setup.go
    ├── util.go
    ├── builder.go                   # SimulatorBuilder fluent API
    └── test_repository.go           # TestRepository — isolated test state
```

## helpers package

### Core utilities (`helpers.go`)

```go
// File I/O
helpers.WriteTestFile(t, dir, "file.json", data) // writes and returns path
helpers.ReadTestFile(t, path)                     // reads or fatals

// JSON
helpers.CompareJSON(t, got, want)          // normalise whitespace then compare
helpers.MustMarshal(t, v)                  // marshal or fatal
helpers.MustUnmarshal[T](t, data)          // unmarshal or fatal

// Assertions
helpers.AssertNoError(t, err)              // fatal on non-nil error
helpers.AssertErrorContains(t, err, msg)   // fatal if err is nil or missing msg

// Keys
helpers.GenerateTestKeyPair(t)             // Ed25519 pub/priv or fatal

// Miscellaneous
helpers.StripWhitespace(data)              // strip ASCII whitespace from bytes
helpers.CreateInvalidJSON()                // map of named invalid JSON snippets
```

### JSON fixture builders (`helpers.go`)

These functions do **not** require `*testing.T`, making them safe to use in
fuzz seed setup (`f.Add(...)`) without the `&testing.T{}` anti-pattern:

```go
helpers.BuildRootJSON()      // []byte — minimal valid root.json
helpers.BuildTargetsJSON()   // []byte — minimal valid targets.json
helpers.BuildSnapshotJSON()  // []byte — minimal valid snapshot.json
helpers.BuildTimestampJSON() // []byte — minimal valid timestamp.json
```

`CreateTest{Root,Targets,Snapshot,Timestamp}JSON(t)` are thin `t.Helper()`
wrappers around the builders, kept for backwards compatibility.

### Fuzz utilities (`fuzz.go`)

```go
gen := helpers.NewFuzzDataGenerator(seed1, seed2 uint64)

gen.GenerateRandomString(length int) string
gen.GenerateRandomBytes(n int) []byte
gen.GenerateRandomInt(max int) int
gen.GenerateRandomTime() time.Time
gen.GenerateRandomJSON() []byte
gen.GenerateCorruptedJSON() []byte
gen.GenerateRandomMetadataFields() map[string]any
gen.GenerateRandomSignature() map[string]any
gen.GenerateRandomKey() map[string]any
gen.CreateFuzzTestMetadata(metadataType string) []byte

// Register standard seeds and run f.Fuzz:
helpers.FuzzMetadataOperations(f, func(data []byte) error { ... })
```

### Updater utilities (`updater.go`)

```go
helpers.ContainsTargetWithPrefix(targets []string, prefix string) bool
helpers.AssertTargetDownloaded(t, targetDir, targetName string)
helpers.AssertTargetNotDownloaded(t, targetDir, targetName string)
```

## simulator package

### TestRepository

`TestRepository` wraps a `RepositorySimulator` with isolated temporary
directories (created via `t.TempDir()` — auto-cleaned when the test ends).

```go
repo := simulator.NewTestRepository(t)
defer repo.Cleanup() // no-op; kept for call-site clarity

// Updater configuration
cfg, err := repo.GetUpdaterConfig()
cfg, err := repo.GetUnsafeUpdaterConfig()

// Metadata manipulation
repo.PublishRoot()
repo.BumpVersion(role)      // root: also calls PublishRoot
repo.SetExpired(role)
repo.SetExpiresAt(role, t)
repo.SetVersion(role, v)
repo.GetVersion(role) int64
repo.RemoveSigners(role)
repo.RotateKeys(role)
repo.AddTarget(role, content, path)
repo.UpdateSnapshot()
repo.UpdateTimestamp()
repo.EnableComputeHashesAndLength()
repo.DisableComputeHashesAndLength()
repo.ReloadRootBytes() error
repo.WriteRoot(version int) error
repo.SetSnapshotMeta(role string, version int64)
repo.SetTimestampSnapshotMeta(version int64)
repo.PastTime() time.Time

// Assertions
repo.AssertFilesExist(roles []string)
repo.AssertFilesExact(roles []string)
repo.AssertVersionEquals(role string, expectedVersion int64)
repo.AssertContentEquals(role string, version *int)
```

### SimulatorBuilder

A fluent builder for constructing pre-configured simulators:

```go
sim := simulator.NewSimulator().
    WithConsistentSnapshot(false).
    WithTarget("path/to/file.txt", []byte("content")).
    WithExpiredRole(metadata.TIMESTAMP).
    WithRootRotations(2).
    Build(t)

repo := simulator.NewTestRepositoryWithBuilder(t, simulator.NewSimulator().
    WithTarget("artifact.txt", []byte("data")))
```

Builder options apply to the initial published root. `WithVersion` sets the
initial version; explicit version bumps and `WithRootRotations` are applied on
top. For example, root version 7 with two root updates bootstraps at 7 and serves
8 and 9 to the updater. `WithRootRotations` publishes new versions using the same
keys; use `RotateKeys` for actual key replacement. Snapshot/timestamp versions
are not implicitly incremented by `Build`. Dependency references and optional
hashes/lengths are computed after configuration. An expired or unsigned root
option intentionally creates an invalid repository for rejection tests.

Assertions read cached metadata without changing the simulated remote state.
Use `AssertContentEquals` when the exact downloaded bytes must be preserved,
not just a version number or a file's existence.

## Static fixtures (`repository_data/`)

`repository_data/` holds a pre-signed TUF repository used by the tests in
`metadata/` and `metadata/trustedmetadata/`. Other packages (e.g.
`metadata/updater/`) now build their fixtures in memory via the
`simulator` package and do not depend on these files.

```
repository_data/
├── keystore/        # top-level PEM keys + encrypted legacy delegation key
└── repository/
    ├── metadata/    # signed root/targets/snapshot/timestamp/role1/role2 JSON
    └── targets/     # dummy target files (file1.txt, file2.txt, file3.txt)
```

### Regenerating the static repository

From the repository root, after editing a metadata fixture or a target file:

```bash
make fixtures
make check-fixtures
make test
```

Only Go and the dependencies in `go.mod` are needed. To work on a copy:

```bash
make fixtures FIXTURE_DIR=/path/to/copied/repository_data
```

`make fixtures` recalculates target hashes/lengths, updates snapshot's references
for every targets role, and updates timestamp's snapshot reference. It recomputes
optional metadata hashes/lengths when those fields are present, signs the result,
and verifies the full signature/dependency chain and target contents before
writing metadata. Invalid inputs fail without writing metadata. Each output
file is replaced atomically; the directory as a whole is not a transactional
update. An unchanged valid repository is a no-op, including its signatures.

Versions and expiration dates are intentional fixture inputs: edit them in the
JSON when your scenario requires different values. The command preserves them
and updates parent references to match. For example, changing targets to version
2 also changes snapshot's `targets.json` reference to version 2. It does not
choose new versions or extend expired fixtures automatically. Add new delegated
roles to their parent's `delegations` and to snapshot's `meta` before regenerating.

Top-level roles use the existing RSA-PSS test keys in `keystore/`. Delegated roles
are re-signed with public, deterministic **test-only** Ed25519 keys derived from
the role name; the generator updates their parents' key declarations as well.
This avoids the encrypted legacy `delegation_key`. The static generator supports
explicit delegated roles with threshold 1; use the simulator for threshold/key
rotation or succinct-role scenarios. This tool and its keys are only for tests.

The historical `1.root.json` is a separate parse-only fixture, with different
keys from `root.json`. Regeneration leaves it untouched. The single-file tool in
`signer/` remains available for specialized cases, but signing a file alone does
not repair its parents' versions, lengths or hashes.

For most new scenarios prefer `simulator.TestRepository` and `SimulatorBuilder`:
they produce fresh signed metadata in isolated temporary directories and avoid
editing static fixtures altogether.

## Running tests

```bash
# All tests
make test

# Include the opt-in external fetcher tests on branches that still have them
GO_TUF_NETWORK_TESTS=1 make test

# Specific packages
go test ./metadata/...
go test ./metadata/updater/...

# Fuzz tests (run for a fixed duration)
make test-fuzz FUZZ=FuzzRootFromBytes FUZZTIME=30s

# Benchmarks
make test-bench
```
