package util

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/go-tuf/data"
)

var ErrWrongLength = errors.New("wrong length")

type ErrWrongHash struct {
	Type     string
	Expected data.HexBytes
	Actual   data.HexBytes
}

func (e ErrWrongHash) Error() string {
	return fmt.Sprintf("wrong %s hash, expected %s got %s", e.Type, hex.EncodeToString(e.Expected), hex.EncodeToString(e.Actual))
}

type ErrNoCommonHash struct {
	Expected map[string]data.HexBytes
	Actual   map[string]data.HexBytes
}

func (e ErrNoCommonHash) Error() string {
	types := func(a map[string]data.HexBytes) []string {
		t := make([]string, 0, len(a))
		for typ := range a {
			t = append(t, typ)
		}
		return t
	}
	return fmt.Sprintf("no common hash function, expected one of %s, got %s", types(e.Expected), types(e.Actual))
}

func FileMetaEqual(actual data.FileMeta, expected data.FileMeta) error {
	if actual.Length != expected.Length {
		return ErrWrongLength
	}
	hashChecked := false
	for typ, hash := range expected.Hashes {
		if h, ok := actual.Hashes[typ]; ok {
			hashChecked = true
			if !hmac.Equal(h, hash) {
				return ErrWrongHash{typ, hash, h}
			}
		}
	}
	if !hashChecked {
		return ErrNoCommonHash{expected.Hashes, actual.Hashes}
	}
	return nil
}

func GenerateFileMeta(r io.Reader) (data.FileMeta, error) {
	h := sha512.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return data.FileMeta{}, err
	}
	return data.FileMeta{
		Length: n,
		Hashes: map[string]data.HexBytes{"sha512": h.Sum(nil)},
	}, nil
}
