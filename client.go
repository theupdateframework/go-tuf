package tuf

import (
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
)

var (
	ErrLatest     = errors.New("tuf: the current version is the latest")
	ErrNotFound   = errors.New("tuf: file not found")
	ErrWrongSize  = errors.New("tuf: unexpected file size")
	ErrNoRootKeys = errors.New("tuf: no root keys found in local meta store")
)

type LocalStore interface {
	GetMeta() (map[string]json.RawMessage, error)
	SetMeta(map[string]json.RawMessage) error
}

type RemoteStore interface {
	Get(name string, size int64) (io.ReadCloser, error)
}

type Repo struct {
	local  LocalStore
	remote RemoteStore

	db   *keys.DB
	meta map[string]json.RawMessage

	root      *data.Root
	snapshot  *data.Snapshot
	targets   *data.Targets
	timestamp *data.Timestamp
}

func NewRepo(local LocalStore, remote RemoteStore) *Repo {
	return &Repo{
		local:  local,
		remote: remote,
		db:     keys.NewDB(),
	}
}

func (r *Repo) getLocalMeta() error {
	if r.meta == nil {
		var err error
		r.meta, err = r.local.GetMeta()
		if err != nil {
			return err
		}
	}

	if rootKeyJSON, ok := r.meta["root-keys"]; ok {
		var rootKeys []*data.Key
		if err := json.Unmarshal(rootKeyJSON, &rootKeys); err != nil {
			return err
		}
		if len(rootKeys) == 0 {
			return ErrNoRootKeys
		}

		rootKeyIDs := make([]string, len(rootKeys))
		for i, k := range rootKeys {
			id := k.ID()
			rootKeyIDs[i] = id
			if err := r.db.AddKey(id, k); err != nil {
				return err
			}
		}
		r.db.AddRole("root", &data.Role{Threshold: 1, KeyIDs: rootKeyIDs})
	} else {
		return ErrNoRootKeys
	}

	if rootJSON, ok := r.meta["root"]; ok {
		s := &data.Signed{}
		if err := json.Unmarshal(rootJSON, s); err != nil {
			return err
		}
		if err := r.decodeRoot(s); err != nil {
			return err
		}
	}

	if snapshotJSON, ok := r.meta["snapshot"]; ok {
		s := &data.Signed{}
		if err := json.Unmarshal(snapshotJSON, s); err != nil {
			return err
		}
		if err := r.decodeSnapshot(s); err != nil {
			return err
		}
	}

	if targetsJSON, ok := r.meta["targets"]; ok {
		s := &data.Signed{}
		if err := json.Unmarshal(targetsJSON, s); err != nil {
			return err
		}
		if err := r.decodeTargets(s); err != nil {
			return err
		}
	}

	if timestampJSON, ok := r.meta["timestamp"]; ok {
		s := &data.Signed{}
		if err := json.Unmarshal(timestampJSON, s); err != nil {
			return err
		}
		if err := r.decodeTimestamp(s); err != nil {
			return err
		}
	}

	return nil
}

func (r *Repo) decodeRoot(s *data.Signed) error {
	var minVer int
	if r.root != nil {
		minVer = r.root.Version
	}
	root := &data.Root{}
	if err := signed.Unmarshal(s, root, "root", minVer, r.db); err != nil {
		return err
	}

	for id, k := range root.Keys {
		if err := r.db.AddKey(id, k); err != nil {
			return err
		}
	}
	for name, role := range root.Roles {
		if err := r.db.AddRole(name, role); err != nil {
			return err
		}
	}
	r.root = root
	return nil
}

func (r *Repo) decodeSnapshot(s *data.Signed) error {
	snapshot := &data.Snapshot{}
	if err := signed.Unmarshal(s, snapshot, "snapshot", r.root.Version, r.db); err != nil {
		return err
	}
	r.snapshot = snapshot
	return nil
}

func (r *Repo) decodeTargets(s *data.Signed) error {
	targets := &data.Targets{}
	if err := signed.Unmarshal(s, targets, "targets", r.root.Version, r.db); err != nil {
		return err
	}
	r.targets = targets
	return nil
}

func (r *Repo) decodeTimestamp(s *data.Signed) error {
	timestamp := &data.Timestamp{}
	if err := signed.Unmarshal(s, timestamp, "timestamp", r.root.Version, r.db); err != nil {
		return err
	}
	r.timestamp = timestamp
	return nil
}

func (r *Repo) Update() error {
	if err := r.getLocalMeta(); err != nil {
		return err
	}
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

func (r *Repo) Expires() time.Time {
	return time.Time{}
}

func (r *Repo) Version() int {
	return 0
}

func (r *Repo) Files() data.Files {
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
