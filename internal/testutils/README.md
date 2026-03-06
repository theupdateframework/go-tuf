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

## Running tests

```bash
# All tests (RSA-1024 compat needed for test fixtures)
GODEBUG=rsa1024min=0 go test -race ./...

# Specific packages
go test ./metadata/...
go test ./metadata/updater/...

# Fuzz tests (run for a fixed duration)
go test -fuzz=FuzzRootFromBytes -fuzztime=30s ./metadata/

# Benchmarks
go test -bench=. ./metadata/
```
