package client

import (
	"errors"
	"io"
	"time"

	"github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/data"
)

var (
	ErrNotFound   = errors.New("tuf: file not found")
	ErrLatest     = errors.New("tuf: the current version is the latest")
	ErrWrongSize  = errors.New("tuf: unexpected file size")
	ErrNoRootKeys = errors.New("tuf: no root keys found in local meta store")
)

type RemoteStore interface {
	Get(name string, size int64) (io.ReadCloser, error)
}

type Client struct {
	repo   *tuf.Repo
	remote RemoteStore
}

// TODO: Client needs root keys
func NewClient(local tuf.LocalStore, remote RemoteStore) (*Client, error) {
	repo, err := tuf.NewRepo(local)
	if err != nil {
		return nil, err
	}
	return &Client{repo, remote}, nil
}

func (c *Client) Update() error {
	// check for root keys

	// if no meta, get root.json
	// if meta, get timestamp.json
	// if new, get snapshot.json
	// if new root.json, restart
	// if new targets.json update
	// fully check all signatures

	/*
		If at any point in the following process there is a problem (e.g., only expired
		metadata can be retrieved), the Root file is downloaded and the process starts
		over. Optionally, the software update system using the framework can decide how
		to proceed rather than automatically downloading a new Root file.

			TUF downloads and verifies timestamp.json.

			If timestamp.json indicates that snapshot.json has changed, TUF downloads
			and verifies snapshot.json.

			TUF determines which metadata files listed in snapshot.json differ from
			those described in the last snapshot.json that TUF has seen. If root.json
			has changed, the update process starts over using the new root.json.

			TUF provides the software update system with a list of available files
			according to targets.json.
	*/

	return nil
}

func (c *Client) Expires() time.Time {
	return time.Time{}
}

func (c *Client) Version() int {
	return 0
}

func (c *Client) Files() data.Files {
	return nil
}

type Destination interface {
	io.Writer
	Size() (int, error)
	Delete() error
}

func (c *Client) Download(name string, dest Destination) error {
	/*
		The software update system instructs TUF to download a specific target file.

		TUF downloads and verifies the file and then makes the file available to the
		software update system.
	*/
	return nil
}
