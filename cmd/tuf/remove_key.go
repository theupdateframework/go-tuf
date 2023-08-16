package main

import (
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf"
	"github.com/flynn/go-docopt"
)

func init() {
	register("remove-key", cmdRemoveKey, `
usage: tuf remove-key [--expires=<days>] <role> <id>

Remove a signing key

Before the key is removed the key will be first revoked
The key will then be removed from the root metadata file and if the key is present in 
"keys" directory it will also be removed
Options:
  --expires=<days>   Set the root metadata file to expire <days> days from now.
`)
}

func cmdRemoveKey(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<roles>"]
	keyID := args.String["<id>"]

	// Extract the --ecpires option value
	expires, _ := args.Int("--expires")

	// Revoke the key 
	if err := repo.RevokeKey(role, keyID); err != nil {
		return err
	}

	// Update expiration vaalue if --expires is provided 
	if expires > 0 {
		rooMetadata := repo.Root()
		if rootMetadata != nil {
			newExpires := time.Now().Add(time.Duration(expires) * 24 * time.Hour)
			rootMetadata.Expires = &newExpires 
			if err := repo.Commit(); err != nil {
				return err
			}
		}
	}

	keyPath := filepath.Join("keys", keyID)
	if _, err := os.Stat(keyPath); err == nil {
		if err := os.Remove(keyPath); err != nil {
			return err
		}
	}
	return nil
}
