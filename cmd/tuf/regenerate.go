package main

import (
	"log"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("regenerate", cmdRegenerate, `
usage: tuf regenerate [--consistent-snapshot=false]

Recreate the targets manifest. Important: Not supported yet

Alternatively, passphrases can be set via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE
`)
}

func cmdRegenerate(args *docopt.Args, repo *tuf.Repo) error {
	// TODO: implement this
	log.Println("Not supported yet")
	return nil
}
