package signed

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/agl/ed25519"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/tent/canonical-json-go"
)

var (
	ErrMissingKey    = errors.New("tuf: missing key")
	ErrNoSignatures  = errors.New("tuf: data has no signatures")
	ErrInvalid       = errors.New("tuf: signature verification failed")
	ErrWrongMethod   = errors.New("tuf: invalid signature type")
	ErrUnknownRole   = errors.New("tuf: unknown role")
	ErrRoleThreshold = errors.New("tuf: valid signatures did not meet threshold")
	ErrLowVersion    = errors.New("tuf: version is lower than current version")
	ErrWrongType     = errors.New("tuf: meta file has wrong type")
)

type signedMeta struct {
	Type    string    `json:"_type"`
	Expires time.Time `json:"expires"`
	Version int       `json:"version"`
}

func Verify(s *data.Signed, role string, minVersion int, db *keys.DB) error {
	if len(s.Signatures) == 0 {
		return ErrNoSignatures
	}

	roleData := db.GetRole(role)
	if roleData == nil {
		return ErrUnknownRole
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(s.Signed, &decoded); err != nil {
		return err
	}
	msg, err := cjson.Marshal(decoded)
	if err != nil {
		return err
	}

	valid := make(map[string]struct{})
	var sigBytes [ed25519.SignatureSize]byte
	for _, sig := range s.Signatures {
		if sig.Method != "ed25519" {
			return ErrWrongMethod
		}
		if len(sig.Signature) != len(sigBytes) {
			return ErrInvalid
		}

		if !roleData.ValidKey(sig.KeyID) {
			continue
		}
		key := db.GetKey(sig.KeyID)
		if key == nil {
			continue
		}

		copy(sigBytes[:], sig.Signature)
		if !ed25519.Verify(&key.Public, msg, &sigBytes) {
			return ErrInvalid
		}
		valid[sig.KeyID] = struct{}{}
	}
	if len(valid) < roleData.Threshold {
		return ErrRoleThreshold
	}

	sm := &signedMeta{}
	if err := json.Unmarshal(s.Signed, sm); err != nil {
		return err
	}
	if sm.Type != role {
		return ErrWrongType
	}
	if err := checkExpires(sm.Expires); err != nil {
		return err
	}
	if sm.Version < minVersion {
		return ErrLowVersion
	}

	return nil
}

var checkExpires = func(t time.Time) error {
	return nil
}

func Unmarshal(s *data.Signed, v interface{}, role string, minVersion int, db *keys.DB) error {
	if err := Verify(s, role, minVersion, db); err != nil {
		return err
	}
	return json.Unmarshal(s.Signed, v)
}
