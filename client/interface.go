package client

import "github.com/theupdateframework/go-tuf/data"

type TUFClient interface {
	// Update downloads and verifies remote metadata and returns updated targets.
	// It always performs root update (5.2 and 5.3) section of the v1.0.19 spec.
	Update() (data.TargetFiles, error)

	// Download downloads the given target file from remote storage into dest.
	//
	// dest will be deleted and an error returned in the following situations:
	//
	//   - The target does not exist in the local targets.json
	//   - Failed to fetch the chain of delegations accessible from local snapshot.json
	//   - The target does not exist in any targets
	//   - Metadata cannot be generated for the downloaded data
	//   - Generated metadata does not match local metadata for the given file
	Download(name string, dest Destination) (err error)

	VerifyDigest(digest string, digestAlg string, length int64, path string) error

	// Target returns the target metadata for a specific target if it
	// exists, searching from top-level level targets then through
	// all delegations. If it does not, ErrNotFound will be returned.
	Target(name string) (data.TargetFileMeta, error)

	// Targets returns the complete list of available top-level targets.
	Targets() (data.TargetFiles, error)
}
