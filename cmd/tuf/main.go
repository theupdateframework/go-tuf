package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	docopt "github.com/flynn/go-docopt"
	tuf "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/util"
	"golang.org/x/term"
)

func main() {
	log.SetFlags(0)

	usage := `usage: tuf [-h|--help] [-d|--dir=<dir>] [--insecure-plaintext] <command> [<args>...]

Options:
  -h, --help
  -d <dir>              The path to the repository (defaults to the current working directory)
  --insecure-plaintext  Don't encrypt signing keys

Commands:
  help               Show usage for a specific command
  init               Initialize a new repository
  gen-key            Generate a new signing key for a specific metadata file
  revoke-key         Revoke a signing key
  add                Add target file(s)
  remove             Remove a target file
  snapshot           Update the snapshot metadata file
  timestamp          Update the timestamp metadata file
  payload            Output a role's metadata file for signing
  add-signatures     Adds signatures generated offline
  sign               Sign a role's metadata file
  sign-payload       Sign a file from the "payload" command.
  status             Check if a role's metadata has expired
  commit             Commit staged files to the repository
  regenerate         Recreate the targets metadata file [Not supported yet]
  set-threshold      Sets the threshold for a role
  get-threshold      Outputs the threshold for a role
  change-passphrase  Changes the passphrase for given role keys file
  root-keys          Output a JSON serialized array of root keys to STDOUT
  clean              Remove all staged metadata files

See "tuf help <command>" for more information on a specific command
`

	args, _ := docopt.Parse(usage, nil, true, "", true)
	cmd := args.String["<command>"]
	cmdArgs := args.All["<args>"].([]string)

	if cmd == "help" {
		if len(cmdArgs) == 0 { // `tuf help`
			fmt.Fprint(os.Stdout, usage)
			return
		} else { // `tuf help <command>`
			cmd = cmdArgs[0]
			cmdArgs = []string{"--help"}
		}
	}

	dir, ok := args.String["-d"]
	if !ok {
		dir = args.String["--dir"]
	}
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := runCommand(cmd, cmdArgs, dir, args.Bool["--insecure-plaintext"]); err != nil {
		log.Fatalln("ERROR:", err)
	}
}

type cmdFunc func(*docopt.Args, *tuf.Repo) error

type command struct {
	usage string
	f     cmdFunc
}

var commands = make(map[string]*command)

func register(name string, f cmdFunc, usage string) {
	commands[name] = &command{usage: usage, f: f}
}

func runCommand(name string, args []string, dir string, insecure bool) error {
	argv := make([]string, 1, 1+len(args))
	argv[0] = name
	argv = append(argv, args...)

	cmd, ok := commands[name]
	if !ok {
		return fmt.Errorf("%s is not a tuf command. See 'tuf help'", name)
	}

	parsedArgs, err := docopt.Parse(cmd.usage, argv, true, "", true)
	if err != nil {
		return err
	}

	var p util.PassphraseFunc
	if !insecure {
		p = getPassphrase
	}
	logger := log.New(os.Stdout, "", 0)
	storeOpts := tuf.StoreOpts{Logger: logger, PassFunc: p}

	repo, err := tuf.NewRepoWithOpts(tuf.FileSystemStoreWithOpts(dir, storeOpts),
		tuf.WithLogger(logger))
	if err != nil {
		return err
	}
	return cmd.f(parsedArgs, repo)
}

func parseExpires(arg string) (time.Time, error) {
	days, err := strconv.Atoi(arg)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse --expires arg: %s", err)
	}
	return time.Now().AddDate(0, 0, days).UTC(), nil
}

func getPassphrase(role string, confirm bool, change bool) ([]byte, error) {
	// In case of change we need to prompt explicitly for a new passphrase
	// and not read it from the environment variable, if present
	if pass := os.Getenv(fmt.Sprintf("TUF_%s_PASSPHRASE", strings.ToUpper(role))); pass != "" && !change {
		return []byte(pass), nil
	}
	// Alter role string if we are prompting for a passphrase change
	if change {
		// Check if environment variable for new passphrase exist
		if new_pass := os.Getenv(fmt.Sprintf("TUF_NEW_%s_PASSPHRASE", strings.ToUpper(role))); new_pass != "" {
			// If so, just read the new passphrase from it and return
			return []byte(new_pass), nil
		}
		// No environment variable set, so proceed prompting for new passphrase
		role = fmt.Sprintf("new %s", role)
	}
	fmt.Fprintf(os.Stderr, "Enter %s keys passphrase: ", role)
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if !confirm {
		return passphrase, nil
	}

	fmt.Fprintf(os.Stderr, "Repeat %s keys passphrase: ", role)
	confirmation, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(passphrase, confirmation) {
		return nil, errors.New("the entered passphrases do not match")
	}
	return passphrase, nil
}
