# go-tuf [![Build Status](https://travis-ci.org/flynn/go-tuf.svg?branch=master)](https://travis-ci.org/flynn/go-tuf)

This is a Go implementation of [The Update Framework (TUF)](http://theupdateframework.com/),
a framework for securing software update systems.

## Directory layout

A TUF repository has the following directory layout:

```
.
├── keys
├── repository
│   └── targets
└── staged
    └── targets
```

The directories contain the following files:

* `keys/` - signing keys with filename pattern `ROLE-KEYID.json`
* `repository/` - signed manifests
* `repository/targets/` - hashed target files
* `staged/` - either signed, unsigned or partially signed manifests
* `staged/targets/` - unhashed target files

## CLI

`go-tuf` provides a CLI for managing a local TUF repository.

### Install

```
go get github.com/flynn/go-tuf/cmd/tuf
```

### Commands

#### `tuf init [--consistent-snapshot=false]`

Initializes a new repository.

This is only required if the repository should not generate consistent
snapshots (i.e. by passing `--consistent-snapshot=false`). If consistent
snapshots should be generated, the repository will be implicitly
initialized to do so when generating keys.

#### `tuf gen-key <role>`

Generates a new signing key, serializes it to JSON and writes it to the `keys`
directory. It also stages the addition of the new key to the `root` manifest.

#### `tuf add <path>`

Hashes a file at `staged/targets/<path>`, then updates and stages the `targets`
manifest.

#### `tuf remove <path>`

Stages the removal of `<path>` from the `targets` manifest (it gets removed
from the filesystem when the change is committed).

#### `tuf snapshot [--compression=<format>]`

Expects a staged, fully signed `targets` manifest and stages an appropriate
`snapshot` manifest. It optionally compresses the staged `targets` manifest.

#### `tuf timestamp`

Stages an appropriate `timestamp` manifest. If a `snapshot` manifest is staged,
it must be fully signed.

#### `tuf sign ROLE`

Signs the given role's staged manifest with all keys present in the `keys`
directory for that role.

#### `tuf commit`

Verifies that all staged changes contain the correct information and are signed
to the correct threshold, then moves the staged files into the `repository`
directory. It also removes any target files which are not in the `targets`
manifest.

#### `tuf regenerate [--consistent-snapshot=false]`

Recreates the `targets` manifest based on the files in `repository/targets`.

#### `tuf clean`

Removes all staged manifests and targets.

#### `tuf root-keys`

Outputs a JSON serialized array of root keys to STDOUT. The resulting JSON
should be distributed to clients for performing initial updates.

For a list of supported commands, run `tuf help` from the command line.

### Examples

The following are example workflows for managing a TUF repository with the CLI.

The `tree` commands do not need to be run, but their output serve as an
illustration of what files should exist after performing certain commands.

Although only two machines are referenced (i.e. the "root" and "repo" boxes),
the workflows can be trivially extended to many signing machines by copying
staged changes and signing on each machine in turn before finally committing.

Some key IDs are truncated for illustrative purposes.

#### Create signed root manifest

Generate a root key on the root box:

```
$ tuf gen-key root

$ tree .
.
├── keys
│   └── root-184b133f.json
├── repository
└── staged
    └── root.json
```

Copy `staged/root.json` from the root box to the repo box and generate targets,
snapshot and timestamp keys:

```
$ tree .
.
├── keys
├── repository
└── staged
    └── root.json

$ tuf gen-key targets
$ tuf gen-key snapshot
$ tuf gen-key timestamp

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
└── staged
    └── root.json
```

Copy `staged/root.json` from the repo box back to the root box and sign it:

```
$ tree .
.
├── keys
│   ├── root-184b133f.json
├── repository
└── staged
    └── root.json

$ tuf sign root.json
```

The staged `root.json` can now be copied back to the repo box ready to be
committed alongside other manifests.

#### Add a target file

Assuming a staged, signed `root` manifest and the file to add exists at
`staged/targets/foo/bar/baz.txt`:

```
$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
└── staged
    ├── root.json
    └── targets
        └── foo
            └── bar
                └── baz.txt

$ tuf add foo/bar/baz.txt

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
└── staged
    ├── root.json
    ├── targets
    │   └── foo
    │       └── bar
    │           └── baz.txt
    └── targets.json

$ tuf snapshot
$ tuf timestamp

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
└── staged
    ├── root.json
    ├── snapshot.json
    ├── targets
    │   └── foo
    │       └── bar
    │           └── baz.txt
    ├── targets.json
    └── timestamp.json

$ tuf commit

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
```

#### Remove a target file

Assuming the file to remove is at `repository/targets/foo/bar/baz.txt`:

```
$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged

$ tuf remove foo/bar/baz.txt

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
    └── targets.json

$ tuf snapshot
$ tuf timestamp

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
    ├── snapshot.json
    ├── targets.json
    └── timestamp.json

$ tuf commit

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets.json
│   └── timestamp.json
└── staged
```

#### Regenerate manifests based on targets tree

```
$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged

$ tuf regenerate

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
    └── targets.json

$ tuf snapshot
$ tuf timestamp

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
    ├── snapshot.json
    ├── targets.json
    └── timestamp.json

$ tuf commit

$ tree .
.
├── keys
│   ├── snapshot-3e070e53.json
│   ├── targets-8cf4810c.json
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
```

#### Update timestamp.json

```
$ tree .
.
├── keys
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged

$ tuf timestamp

$ tree .
.
├── keys
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
    └── timestamp.json

$ tuf commit

$ tree .
.
├── keys
│   └── timestamp-a3768063.json
├── repository
│   ├── root.json
│   ├── snapshot.json
│   ├── targets
│   │   └── foo
│   │       └── bar
│   │           └── baz.txt
│   ├── targets.json
│   └── timestamp.json
└── staged
```

#### Modify key thresholds

TODO

## Client

TODO
