// Package keys implements an in-memory public key database for TUF.
package keys

import (
	"errors"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/signed"
)

var (
	ErrWrongType        = errors.New("tuf: invalid key type")
	ErrExists           = errors.New("tuf: key already in db")
	ErrWrongID          = errors.New("tuf: key id mismatch")
	ErrInvalidKey       = errors.New("tuf: invalid key")
	ErrInvalidRole      = errors.New("tuf: invalid role")
	ErrInvalidKeyID     = errors.New("tuf: invalid key id")
	ErrInvalidThreshold = errors.New("tuf: invalid role threshold")
)

type Key struct {
	ID     string
	Type   string
	Public []byte
}

func (k *Key) Serialize() *data.Key {
	return &data.Key{
		Type:  k.Type,
		Value: data.KeyValue{Public: k.Public[:]},
	}
}

type Role struct {
	KeyIDs    map[string]struct{}
	Threshold int
}

func (r *Role) ValidKey(id string) bool {
	_, ok := r.KeyIDs[id]
	return ok
}

type DB struct {
	roles map[string]*Role
	keys  map[string]*Key
}

func NewDB() *DB {
	return &DB{
		roles: make(map[string]*Role),
		keys:  make(map[string]*Key),
	}
}

func (db *DB) AddKey(id string, k *data.Key) error {
	v, ok := signed.Verifiers[k.Type]
	if !ok {
		return nil
	}
	if id != k.ID() {
		return ErrWrongID
	}
	if !v.ValidKey(k.Value.Public) {
		return ErrInvalidKey
	}

	db.keys[id] = &Key{
		ID:     k.ID(),
		Type:   k.Type,
		Public: k.Value.Public,
	}

	return nil
}

var validRoles = map[string]struct{}{
	"root":      {},
	"targets":   {},
	"snapshot":  {},
	"timestamp": {},
}

func ValidRole(name string) bool {
	_, ok := validRoles[name]
	return ok
}

func (db *DB) AddRole(name string, r *data.Role) error {
	if !ValidRole(name) {
		return ErrInvalidRole
	}
	if r.Threshold < 1 {
		return ErrInvalidThreshold
	}

	role := &Role{
		KeyIDs:    make(map[string]struct{}),
		Threshold: r.Threshold,
	}
	for _, id := range r.KeyIDs {
		if len(id) != data.KeyIDLength {
			return ErrInvalidKeyID
		}
		role.KeyIDs[id] = struct{}{}
	}

	db.roles[name] = role
	return nil
}

func (db *DB) GetKey(id string) *Key {
	return db.keys[id]
}

func (db *DB) GetRole(name string) *Role {
	return db.roles[name]
}
