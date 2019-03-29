package data

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	cjson "github.com/tent/canonical-json-go"
)

const (
	KeyIDLength            = sha256.Size * 2
	KeyTypeEd25519         = "ed25519"
	KeyTypeECDSA_SHA2_P256 = "ecdsa-sha2-nistp256"
)

type Signed struct {
	Signed     json.RawMessage `json:"signed"`
	Signatures []Signature     `json:"signatures"`
}

type Signature struct {
	KeyID     string   `json:"keyid"`
	Method    string   `json:"method"`
	Signature HexBytes `json:"sig"`
}

type Key struct {
	Type  string   `json:"keytype"`
	Value KeyValue `json:"keyval"`

	ids    []string
	idOnce sync.Once
}

func (k *Key) IDs() []string {
	k.idOnce.Do(func() {
		data, _ := cjson.Marshal(k)
		digest := sha256.Sum256(data)
		k.ids = []string{hex.EncodeToString(digest[:])}
	})
	return k.ids
}

func (k *Key) ContainsID(id string) bool {
	for _, keyid := range k.IDs() {
		if id == keyid {
			return true
		}
	}
	return false
}

type KeyValue struct {
	Public HexBytes `json:"public"`
}

func DefaultExpires(role string) time.Time {
	var t time.Time
	switch role {
	case "root":
		t = time.Now().AddDate(1, 0, 0)
	case "targets":
		t = time.Now().AddDate(0, 3, 0)
	case "snapshot":
		t = time.Now().AddDate(0, 0, 7)
	case "timestamp":
		t = time.Now().AddDate(0, 0, 1)
	}
	return t.UTC().Round(time.Second)
}

type Root struct {
	Type    string           `json:"_type"`
	Version int              `json:"version"`
	Expires time.Time        `json:"expires"`
	Keys    map[string]*Key  `json:"keys"`
	Roles   map[string]*Role `json:"roles"`

	ConsistentSnapshot bool `json:"consistent_snapshot"`
}

func NewRoot() *Root {
	return &Root{
		Type:               "Root",
		Expires:            DefaultExpires("root"),
		Keys:               make(map[string]*Key),
		Roles:              make(map[string]*Role),
		ConsistentSnapshot: true,
	}
}

func (r *Root) AddKey(key *Key) {
	for _, id := range key.IDs() {
		r.Keys[id] = key
	}
}

// We might have multiple keyids that correspond to the same key, so
// make sure we only return unique keys.
func (r Root) UniqueKeys() []*Key {
	seen := make(map[string]struct{})
	keys := []*Key{}
	for _, key := range r.Keys {
		found := false
		for _, id := range key.IDs() {
			if _, ok := seen[id]; ok {
				found = true
				break
			}
		}

		if !found {
			for _, id := range key.IDs() {
				seen[id] = struct{}{}
			}
			keys = append(keys, key)
		}
	}

	return keys
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type Files map[string]FileMeta

type FileMeta struct {
	Length int64            `json:"length",omitempty`
	Hashes Hashes           `json:"hashes",ompitempty`
	Custom *json.RawMessage `json:"custom,omitempty"`
}

type Hashes map[string]HexBytes

func (f FileMeta) HashAlgorithms() []string {
	funcs := make([]string, 0, len(f.Hashes))
	for name := range f.Hashes {
		funcs = append(funcs, name)
	}
	return funcs
}

type SnapshotFileMeta struct {
	FileMeta
	Version int `json:"version"`
}

type SnapshotFiles map[string]SnapshotFileMeta

type Snapshot struct {
	Type    string        `json:"_type"`
	Version int           `json:"version"`
	Expires time.Time     `json:"expires"`
	Meta    SnapshotFiles `json:"meta"`
}

func NewSnapshot() *Snapshot {
	return &Snapshot{
		Type:    "Snapshot",
		Expires: DefaultExpires("snapshot"),
		Meta:    make(SnapshotFiles),
	}
}

type TargetFiles map[string]TargetFileMeta

type TargetFileMeta struct {
	FileMeta
}

func (f TargetFileMeta) HashAlgorithms() []string {
	return f.FileMeta.HashAlgorithms()
}

type Targets struct {
	Type    string      `json:"_type"`
	Version int         `json:"version"`
	Expires time.Time   `json:"expires"`
	Targets TargetFiles `json:"targets"`
}

func NewTargets() *Targets {
	return &Targets{
		Type:    "Targets",
		Expires: DefaultExpires("targets"),
		Targets: make(TargetFiles),
	}
}

type TimestampFileMeta struct {
	FileMeta
	Version int `json:"version"`
}

type TimestampFiles map[string]TimestampFileMeta

type Timestamp struct {
	Type    string         `json:"_type"`
	Version int            `json:"version"`
	Expires time.Time      `json:"expires"`
	Meta    TimestampFiles `json:"meta"`
}

func NewTimestamp() *Timestamp {
	return &Timestamp{
		Type:    "Timestamp",
		Expires: DefaultExpires("timestamp"),
		Meta:    make(TimestampFiles),
	}
}
