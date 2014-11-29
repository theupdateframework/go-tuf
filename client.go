package tuf

import (
	"encoding/json"
	"errors"
	"io"
	"time"
)

var (
	ErrLatest    = errors.New("tuf: the current version is the latest")
	ErrNotFound  = errors.New("tuf: file not found")
	ErrWrongSize = errors.New("tuf: unexpected file size")
)

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(map[string]json.RawMessage) error
}

type RemoteStore interface {
	Get(name string, size int64) (io.ReadCloser, error)
}

type Repo struct {
	rootKey *Key
	local   LocalStore
	remote  RemoteStore
}

func NewRepo(rootKey *Key, local LocalStore, remote RemoteStore) *Repo {
	return &Repo{
		rootKey: rootKey,
		local:   local,
		remote:  remote,
	}
}

func (r *Repo) Update() error {
	// get current meta if not decoded yet
	// fully check all signatures
	// if no meta, get root.json
	// if meta, get timestamp.json
	// if new, get snapshot.json
	// if new root.json, restart
	// if new targets.json update

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

func (r *Repo) Expires() time.Time {
	return time.Time{}
}

func (r *Repo) Version() int {
	return 0
}

func (r *Repo) Files() Files {
	return nil
}

type Destination interface {
	io.Writer
	Size() (int, error)
	Delete() error
}

func (r *Repo) Download(name string, dest Destination) error {
	/*
		The software update system instructs TUF to download a specific target file.

		TUF downloads and verifies the file and then makes the file available to the
		software update system.
	*/
	return nil
}
