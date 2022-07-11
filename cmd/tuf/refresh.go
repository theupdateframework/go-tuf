package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("refresh", cmdRefresh, `
usage: tuf refresh [--snapshot-threshold=<hours> --timestamp-threshold=<hours>]

Resign the snapshot and/or timestamp metadata if needed. If either metadata
is expiring in less than the number of hours given by the threshold, its 
metadata expiration will be refreshed and the change(s) will be committed.

Alternatively, passphrases can be set via environment variables in the
form of TUF_{{ROLE}}_PASSPHRASE

Options:
  --snapshot-threshold=<hours>   Set the threshold for when to resign expiring
                                 snapshot metadata.
  --timestamp-threshold=<hours>  Set the threshold for when to resign expiring
                                 timestamp metadata
`)
}

func cmdRefresh(args *docopt.Args, repo *tuf.Repo) error {
	ssThreshold := time.Now().Add(time.Hour * -1)
	tsThreshold := time.Now().Add(time.Hour * -1)

	if arg := args.String["--snapshot-threshold"]; arg != "" {
		hours, err := strconv.Atoi(arg)
		if err != nil {
			return fmt.Errorf("failed to parse --snapshot-threshold arg: %s", err)
		}
		ssThreshold = time.Now().Add(time.Hour * time.Duration(hours) * -1)
	}
	if arg := args.String["--timestamp-threshold"]; arg != "" {
		hours, err := strconv.Atoi(arg)
		if err != nil {
			return fmt.Errorf("failed to parse --timestamp-threshold arg: %s", err)
		}
		tsThreshold = time.Now().Add(time.Hour * time.Duration(hours) * -1)
	}
	return repo.RefreshExpires(ssThreshold, tsThreshold)
}
