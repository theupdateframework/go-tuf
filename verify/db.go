package verify

import (
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/keys"
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
	roles map[string]*Role
	keys  map[string]*keys.Verifier
}

func NewDB() *DB {
	return &DB{
		roles: make(map[string]*Role),
		keys:  make(map[string]*keys.Verifier),
	}
}

type DelegationsVerifier struct {
	DB *DB
}

func (d *DelegationsVerifier) Unmarshal(b []byte, v interface{}, role string, minVersion int) error {
	return d.DB.Unmarshal(b, v, role, minVersion)
}

// NewDelegationsVerifier returns a DelegationsVerifier that verifies delegations
// of a given Targets. It reuses the DB struct to leverage verified keys, roles
// unmarshals.
func NewDelegationsVerifier(d *data.Delegations) (DelegationsVerifier, error) {
	db := &DB{
		roles: make(map[string]*Role, len(d.Roles)),
		keys:  make(map[string]*keys.Verifier, len(d.Keys)),
	}
	for _, r := range d.Roles {
		if _, ok := topLevelRoles[r.Name]; ok {
			return DelegationsVerifier{}, ErrInvalidDelegatedRole
		}
		role := &data.Role{Threshold: r.Threshold, KeyIDs: r.KeyIDs}
		if err := db.addRole(r.Name, role); err != nil {
			return DelegationsVerifier{}, err
		}
	}
	for id, k := range d.Keys {
		if err := db.AddKey(id, k); err != nil {
			return DelegationsVerifier{}, err
		}
	}
	return DelegationsVerifier{db}, nil
}

func (db *DB) AddKey(id string, k *data.Key) error {
	vt, ok := keys.KeyMap.Load(k.Type)
	if !ok {
		return nil
	}
	if !k.ContainsID(id) {
		return ErrWrongID{}
	}
	v := vt.(func() keys.SignerVerifier)()
	if v.Verifier == nil || !v.Verifier.ValidKey(k.Value) {
		return ErrInvalidKey
	}
	if err := v.Verifier.UnmarshalKey(k); err != nil {
		return ErrInvalidKey
	}
	db.keys[id] = &v.Verifier

	return nil
}

var topLevelRoles = map[string]struct{}{
	"root":      {},
	"targets":   {},
	"snapshot":  {},
	"timestamp": {},
}

// ValidRole checks if a role is a top level role.
func ValidRole(name string) bool {
	return isTopLevelRole(name)
}

func isTopLevelRole(name string) bool {
	_, ok := topLevelRoles[name]
	return ok
}

func (db *DB) AddRole(name string, r *data.Role) error {
	if !isTopLevelRole(name) {
		return ErrInvalidRole
	}
	return db.addRole(name, r)
}

func (db *DB) addRole(name string, r *data.Role) error {
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

func (db *DB) GetKey(id string) *keys.Verifier {
	return db.keys[id]
}

func (db *DB) GetRole(name string) *Role {
	return db.roles[name]
}
