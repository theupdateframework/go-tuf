package main

import (
	"fmt"
	"strconv"

	"github.com/flynn/go-docopt"
	"github.com/theupdateframework/go-tuf"
)

func init() {
	register("set-threshold", cmdSetThreshold, `
usage: tuf set-threshold <role> <threshold>

Set the threshold for a role.  
`)
}

func cmdSetThreshold(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	thresholdStr := args.String["<threshold>"]
	threshold, err := strconv.Atoi(thresholdStr)
	if err != nil {
		return err
	}

	if err := repo.SetThreshold(role, threshold); err != nil {
		return err
	}

	fmt.Println("Set ", role, "threshold to", threshold)
	return nil
}
