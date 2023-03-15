# Example repository used for bootstrapping a multi repository TUF client (TAP 4)

The following is a helper TUF repository which serves several targets:

- `map.json` which holds repository mappings and can be used to bootstrap a TUF client supporting multiple repositories
- A set of trusted root files for each repository listed in the `map.json` file
- The `examples/multirepo/client/client_example.go`(../client/client_example.go) is a client which uses this repository to bootstrap a multi-repository TUF client
