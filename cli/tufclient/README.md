# go-tuf-metadata client CLI

## Overview

The CLI provides three commands:

* `tuf-client init` - Initialize the client with trusted root.json metadata (Trust-On-First-Use)
* `tuf-client get` - Download a target file
* `tuf-client reset` - Resets the local environment. Warning: this deletes both the metadata and download folders and all of their contents

All commands except reset require the URL of the TUF repository passed as a flag via `--url/u`

Run `tuf-client help` from the command line to get more detailed usage
information.

## Examples

```bash
# Initialize by providing a root.json
$ tuf-client init --url https://jku.github.io/tuf-demo/metadata -f root.json

# Initialize without providing a root.json
$ tuf-client init --url https://jku.github.io/tuf-demo/metadata

# Get a target 
$ tuf-client get --url https://jku.github.io/tuf-demo/metadata demo/succinctly-delegated-5.txt

# Get a target by providing a URL of where target files are located
$ tuf-client get --url https://jku.github.io/tuf-demo/metadata -t https://jku.github.io/tuf-demo/targets demo/succinctly-delegated-5.txt

# Reset your local environment
$ tuf-client reset
```
