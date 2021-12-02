package main

import (
	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("change-passphrase", cmdChangePassphrase, `
usage: tuf change-passphrase <role>

Changes the passphrase for given role keys file.

Alternatively, passphrases can be passed via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE for existing ones and
TUF_NEW_{{ROLE}}_PASSPHRASE for setting new ones.
`)
}

func cmdChangePassphrase(args *docopt.Args, repo *tuf.Repo) error {
	return repo.ChangePassphrase(args.String["<role>"])
}
