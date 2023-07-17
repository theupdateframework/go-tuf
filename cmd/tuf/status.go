package main

import (
	"fmt"
	"time"

	"github.com/DataDog/go-tuf"
	"github.com/flynn/go-docopt"
)

func init() {
	register("status", cmdStatus, `
usage: tuf status --valid-at=<date> <role>

Check if the role's metadata will be expired on the given date.

The command's exit status will be 1 if the role has expired, 0 otherwise.

Example:
  # See if timestamp metadata is expiring in the next hour:
  tuf status --valid-at "$(date -d '+1 hour')" timestamp || echo "Time to refresh"

Options:
  --valid-at=<date>   Must be in one of the formats:
                      * RFC3339  - 2006-01-02T15:04:05Z07:00
                      * RFC822   - 02 Jan 06 15:04 MST
                      * UnixDate - Mon Jan _2 15:04:05 MST 2006
`)
}

func cmdStatus(args *docopt.Args, repo *tuf.Repo) error {
	role := args.String["<role>"]
	validAtStr := args.String["--valid-at"]

	formats := []string{
		time.RFC3339,
		time.RFC822,
		time.UnixDate,
	}
	for _, fmt := range formats {
		validAt, err := time.Parse(fmt, validAtStr)
		if err == nil {
			return repo.CheckRoleUnexpired(role, validAt)
		}
	}
	return fmt.Errorf("failed to parse --valid-at arg")
}
