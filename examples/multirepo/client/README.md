# Example repository showing a multi repository TUF client (TAP 4)

The following is a TUF multi-repository client example of the `multirepo` package which implements [TAP 4 - Multiple repository consensus on entrusted targets](https://github.com/theupdateframework/taps/blob/master/tap4.md):

- The `map.json` along with the root files for each repository are distributed via a trusted repository used for initialization
  - The metadata, these target files and the script generating them are located in the [examples/multirepo/repository](../repository/) folder
- These files are then used to bootstrap the multi-repository TUF client
- Shows the API provided by the `multirepo` package
