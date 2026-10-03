# tuf-client CLI

----------------------------

## Overview

----------------------------

`tuf-client` is a CLI tool that implements the client workflow specified by The Update Framework (TUF) specification.

The tuf-client can be used to query for available targets and to download them in a secure manner.

All downloaded files are verified by signed metadata.

The CLI provides three commands:

* `tuf-client init` - Initialize the client with trusted root.json metadata
* `tuf-client get` - Download a target file
* `tuf-client reset` - Resets the local environment. Warning: this deletes both the metadata and download folders and all of their contents

All commands except `reset` require the URL of the TUF repository passed as a flag via `--url/u`

Run `tuf-client help` from the command line to get more detailed usage information.

## Usage

----------------------------

```bash
# Initialize by providing a root.json
#  
# Usage: tuf-client init --url <https://path/to/repository/metadata> -f root.json
#
$ tuf-client init --url https://jku.github.io/tuf-demo/metadata -f root.json

# Initialize without providing a root.json
#
# Usage: tuf-client init --url <https://path/to/repository/metadata>
#
$ tuf-client init --url https://jku.github.io/tuf-demo/metadata

# Get a target
#
# Usage: tuf-client get --url <https://path/to/repository/metadata> <targetfile_to_download>
#
# Note: This example wouldn't work properly. See another example with --turl(-t) option below.
#
$ tuf-client get --url https://jku.github.io/tuf-demo/metadata rdimitrov/artifact-example.md

# Get a target by providing a URL of where target files are located
#
# Usage: tuf-client get --url <https://path/to/repository/metadata> -t <https://path/to/targetfiles/location> <targetfile_to_download> 
#
# Note: You can use --nonprefixed for non-prefixed target files. This example works properly without it.
#
$ tuf-client get --url https://jku.github.io/tuf-demo/metadata -t https://jku.github.io/tuf-demo/targets rdimitrov/artifact-example.md

# Reset your local environment
$ tuf-client reset
```
