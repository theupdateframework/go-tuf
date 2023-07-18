package main

import (
	"errors"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
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

func cmdRemoveKey(args *docpct.Args, repo *tuf.Repo) error {
	//check if the --ecpires argument is provided 
	if arg := args.String["--expires"]; arg != "" {
		// Parse the expiration argument 
		expires, err := parseExpires(arg)
		if err != nil {
			return err
		}
		// Revoke the key with the secified role, ID, and expiration 
		return repo.RevokeKeyWithExpires(args.String["<role>"], args.String["<id>"], expires)
	}
	//Check if the key is present in the "keys" directory
	KeysDirect, err := repo.KeysDirect()
	if err != nil {
		return err
	}
	//Construct the key path by joining the "keysDirect" directory and the key ID 
	keyPath := filepath.Join(repo.KeysDirect, args.String("<id>"))

	//Checks if the key file or directory exists
	if _, err := os.Stat(keyPath); err == nil {
		
		//Remove the key with the specified role and ID
		err = repo.RemoveKey(args.String("<role>"), args.String("<id>"))
		if err != nil {
			return err
		}
	}
	return nil
}