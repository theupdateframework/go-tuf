package verify

import (
	"io"
	"log"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/internal/roles"
	"github.com/theupdateframework/go-tuf/pkg/keys"
)

type Role struct {
	KeyIDs    map[string]struct{}
	Threshold int
}

func (r *Role) ValidKey(id string) bool {
	_, ok := r.KeyIDs[id]
	return ok
}

type DB struct {
	roles     map[string]*Role
	verifiers map[string]keys.Verifier
	logger    *log.Logger
}

type DBOpts func(db *DB)

func WithLogger(logger *log.Logger) DBOpts {
	return func(db *DB) {
		db.logger = logger
	}
}

func NewDB(opts ...DBOpts) *DB {
	db := &DB{
		roles:     make(map[string]*Role),
		verifiers: make(map[string]keys.Verifier),
		logger:    log.New(io.Discard, "", 0),
	}
	for _, opt := range opts {
		opt(db)
	}
	return db
}

// NewDBFromDelegations returns a DB that verifies delegations
// of a given Targets.
func NewDBFromDelegations(d *data.Delegations, opts ...DBOpts) (*DB, error) {
	db := NewDB(opts...)
	for _, r := range d.Roles {
		if _, ok := roles.TopLevelRoles[r.Name]; ok {
			return nil, ErrInvalidDelegatedRole
		}
		role := &data.Role{Threshold: r.Threshold, KeyIDs: r.KeyIDs}
		if err := db.AddRole(r.Name, role); err != nil {
			return nil, err
		}
	}
	for id, k := range d.Keys {
		if err := db.AddKey(id, k); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *DB) AddKey(id string, k *data.PublicKey) error {
	opts := make([]keys.VerifierOpts, 0)
	if db.logger != nil {
		opts = append(opts, keys.WithLogger(db.logger))
	}
	verifier, err := keys.GetVerifier(k, opts...)
	if err != nil {
		return err // ErrInvalidKey
	}

	// TUF is considering in TAP-12 removing the
	// requirement that the keyid hash algorithm be derived
	// from the public key. So to be forwards compatible,
	// we allow any key ID, rather than checking k.ContainsID(id)
	//
	// AddKey should be idempotent, so we allow re-adding the same PublicKey.
	//
	// TAP-12: https://github.com/theupdateframework/taps/blob/master/tap12.md
	if oldVerifier, exists := db.verifiers[id]; exists && oldVerifier.Public() != verifier.Public() {
		return ErrRepeatID{id}
	}

	db.verifiers[id] = verifier
	return nil
}

func (db *DB) AddRole(name string, r *data.Role) error {
	if r.Threshold < 1 {
		return ErrInvalidThreshold
	}

	role := &Role{
		KeyIDs:    make(map[string]struct{}),
		Threshold: r.Threshold,
	}
	for _, id := range r.KeyIDs {
		role.KeyIDs[id] = struct{}{}
	}

	db.roles[name] = role
	return nil
}

func (db *DB) GetVerifier(id string) (keys.Verifier, error) {
	k, ok := db.verifiers[id]
	if !ok {
		return nil, ErrMissingKey
	}
	return k, nil
}

func (db *DB) GetRole(name string) *Role {
	return db.roles[name]
}
