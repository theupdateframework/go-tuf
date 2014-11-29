package tuf

import (
	"encoding/json"
	"time"
)

type SignedJSON struct {
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
}

type KeyValue struct {
	Public  HexBytes `json:"public"`
	Private HexBytes `json:"-"`
}

type Root struct {
	Type    string         `json:"_type"`
	Version int            `json:"version"`
	Expires time.Time      `json:"expires"`
	Keys    map[string]Key `json:"keys"`
	Roles   []Role         `json:"role"`

	ConsistentSnapshot bool `json:"consistent_snapshot"`
}

type Role struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type Files map[string]FileMeta

type Snapshot struct {
	Type    string    `json:"_type"`
	Version int       `json:"version"`
	Expires time.Time `json:"expires"`
	Meta    Files     `json:"meta"`
}

type FileMeta struct {
	Length int64                  `json:"length"`
	Hashes map[string]HexBytes    `json:"hashes"`
	Custom map[string]interface{} `json:"custom,omitempty"`
}

type Targets struct {
	Type    string    `json:"_type"`
	Version int       `json:"version"`
	Expires time.Time `json:"expires"`
	Targets Files     `json:"targets"`
}

type Timestamp struct {
	Type    string    `json:"_type"`
	Version int       `json:"version"`
	Expires time.Time `json:"expires"`
	Meta    Files     `json:"meta"`
}
