# Example repository used for bootstrapping a multi repository TUF client (TAP 4)

The following is a helper TUF repository that serves several targets:

- `map.json` which holds repository mappings and can be used to bootstrap a TUF client supporting multiple repositories
- A set of trusted root files for each repository listed in the `map.json` file
- The `examples/multirepo/client/client_example.go`(../client/client_example.go) is a client which uses this repository to bootstrap a multi-repository TUF client

## Usage

To regenerate the multi-repo repository,
run the following command from inside the `examples/multirepo/repository` directory:

```bash
go run .
```

This should generate the necessary metadata files in the `metadata` directory and the `map.json` file.
It will also copy the new `root.json` files to the `client` directory.
